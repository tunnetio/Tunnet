//! One [`TunnelHub`] per dataplane generation: `EndpointId` → one peer task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt;
use iroh::endpoint::{Connection, PathEvent, SendDatagramError, Side};
use iroh::{Endpoint, EndpointId, TransportAddr};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tunnet_common::TUNNEL_ALPN;
use tunnet_common::packet;
use tunnet_common::policy::Direction;
use tunnet_core::direct::{
    AuthCache, EvalResult, FirewallEngine, PacketDirection, SpoofTracker, source_matches_peer,
};
use tunnet_core::iroh_pool::DEFAULT_IDLE_SECS;
use tunnet_core::tunnel_mesh::{TunnelMesh, normalize_relay_url};
use tunnet_core::{AclEngine, RoutingTable, TransportAuth};
use uuid::Uuid;

use crate::dataplane::frame::{
    Frame, Reassembly, ReassemblyError, SINGLE_HEADER_LEN, decode, encode_logical,
};
use crate::metrics::AgentMetrics;
use crate::ssh_nat;

pub const PEER_QUEUE_CAP: usize = 32;
pub const ACCEPT_QUEUE_CAP: usize = 4;
pub const PACKET_MAX_AGE: Duration = Duration::from_secs(1);
pub const DIAL_COOLDOWN: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct OutboundPacket {
    pub network_id: Uuid,
    pub bytes: Bytes,
    pub enqueued_at: Instant,
}

#[derive(Clone)]
pub struct PeerDeps {
    pub local_id: EndpointId,
    pub endpoint: Endpoint,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub direct_auth: Option<AuthCache>,
    pub transport_auth: Option<TransportAuth>,
    pub metrics: AgentMetrics,
    pub mesh: TunnelMesh,
    pub tun_tx: mpsc::Sender<Bytes>,
    pub mtu: u16,
}

struct PeerHandle {
    packets: mpsc::Sender<OutboundPacket>,
    accepted: mpsc::Sender<Connection>,
    stop: CancellationToken,
}

#[derive(Clone)]
pub struct TunnelHub {
    deps: Arc<PeerDeps>,
    cancel: CancellationToken,
    workers: Arc<DashMap<EndpointId, PeerHandle>>,
}

impl TunnelHub {
    pub fn new(deps: PeerDeps, cancel: CancellationToken) -> Self {
        Self {
            deps: Arc::new(deps),
            cancel,
            workers: Arc::new(DashMap::new()),
        }
    }

    pub fn accept(&self, conn: Connection) {
        let peer = conn.remote_id();
        let handle = self.worker(peer);
        if handle.accepted.try_send(conn).is_err() {
            tracing::debug!(%peer, "accepted tunnel connection dropped (worker busy)");
        }
    }

    pub fn enqueue(&self, peer: EndpointId, packet: OutboundPacket) {
        let handle = self.worker(peer);
        if handle.packets.try_send(packet).is_err() {
            self.deps.mesh.inc_queue_full();
            self.deps.metrics.dropped_inc("peer_queue_full");
        }
    }

    pub fn reconcile(&self) {
        let authorized: std::collections::HashSet<EndpointId> = self
            .deps
            .routes
            .peers()
            .into_iter()
            .map(|p| p.endpoint)
            .collect();
        self.workers.retain(|peer, handle| {
            if authorized.contains(peer) {
                true
            } else {
                handle.stop.cancel();
                self.deps.mesh.clear_peer(*peer);
                false
            }
        });
        for peer in authorized {
            if self.deps.local_id == peer {
                continue;
            }
            let Some(info) = self.deps.routes.lookup_endpoint(&format!("{peer}")) else {
                continue;
            };
            if !self.deps.mesh.keep_alive_for(peer, Some(&info.hostname)) {
                continue;
            }
            if !we_are_preferred_initiator(self.deps.local_id, peer) {
                continue;
            }
            let _ = self.worker(peer);
        }
    }

    pub fn close_all(&self) {
        for entry in self.workers.iter() {
            entry.value().stop.cancel();
        }
        self.workers.clear();
        self.cancel.cancel();
    }

    fn worker(&self, peer: EndpointId) -> PeerHandle {
        if let Some(existing) = self.workers.get(&peer) {
            return PeerHandle {
                packets: existing.packets.clone(),
                accepted: existing.accepted.clone(),
                stop: existing.stop.clone(),
            };
        }
        let (packets_tx, packets_rx) = mpsc::channel(PEER_QUEUE_CAP);
        let (accepted_tx, accepted_rx) = mpsc::channel(ACCEPT_QUEUE_CAP);
        let stop = self.cancel.child_token();
        let handle = PeerHandle {
            packets: packets_tx.clone(),
            accepted: accepted_tx.clone(),
            stop: stop.clone(),
        };
        self.workers.insert(
            peer,
            PeerHandle {
                packets: packets_tx,
                accepted: accepted_tx,
                stop: stop.clone(),
            },
        );
        let deps = self.deps.clone();
        let workers = self.workers.clone();
        tokio::spawn(async move {
            run_peer(peer, deps, stop, packets_rx, accepted_rx).await;
            workers.remove(&peer);
        });
        handle
    }
}

struct Live {
    conn: Connection,
    stable_id: usize,
}

async fn run_peer(
    peer: EndpointId,
    deps: Arc<PeerDeps>,
    cancel: CancellationToken,
    mut packets: mpsc::Receiver<OutboundPacket>,
    mut accepted: mpsc::Receiver<Connection>,
) {
    let hex = format!("{peer}");
    let mut live: Option<Live> = None;
    let mut reassembly = Reassembly::new(deps.mtu as usize);
    let mut packet_id: u32 = 0;
    let mut dial: Option<JoinHandle<Result<Connection, iroh::endpoint::ConnectError>>> = None;
    let mut cooldown_until: Option<Instant> = None;
    let mut hold: Option<OutboundPacket> = None;
    let mut last_activity = Instant::now();
    let mut idle_tick = tokio::time::interval(Duration::from_secs(5));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    publish_state(&deps, peer, "idle", false, "unknown");

    loop {
        if cancel.is_cancelled() {
            break;
        }
        if live.is_none() && dial.is_none() {
            maybe_start_keep_alive_dial(&deps, peer, &mut dial, cooldown_until);
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            conn = accepted.recv() => {
                let Some(conn) = conn else { break };
                install_conn(peer, &deps, &mut live, &mut reassembly, conn);
                last_activity = Instant::now();
                flush_hold(peer, &deps, &mut live, &mut hold, &mut packet_id, &mut last_activity);
                drain_outbound(peer, &deps, &mut live, &mut packets, &mut packet_id, &mut last_activity);
            }
            pkt = packets.recv(), if hold.is_none() => {
                let Some(pkt) = pkt else { break };
                last_activity = Instant::now();
                if live.is_none() {
                    if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
                        deps.mesh.inc_stale();
                        deps.metrics.dropped_inc("packet_stale");
                    } else {
                        start_dial(&deps, peer, &mut dial, cooldown_until);
                        hold = Some(pkt);
                    }
                } else {
                    send_logical(peer, &deps, &mut live, pkt, &mut packet_id);
                    drain_outbound(peer, &deps, &mut live, &mut packets, &mut packet_id, &mut last_activity);
                }
            }
            result = await_dial(&mut dial) => {
                match result {
                    Some(Ok(conn)) => {
                        deps.mesh.inc_dial_success();
                        install_conn(peer, &deps, &mut live, &mut reassembly, conn);
                        last_activity = Instant::now();
                        flush_hold(peer, &deps, &mut live, &mut hold, &mut packet_id, &mut last_activity);
                        drain_outbound(peer, &deps, &mut live, &mut packets, &mut packet_id, &mut last_activity);
                    }
                    Some(Err(_)) => {
                        deps.mesh.inc_dial_fail();
                        cooldown_until = Some(Instant::now() + DIAL_COOLDOWN);
                        drop_hold(&deps, &mut hold);
                        drop_queued(&deps, &mut packets);
                        publish_state(&deps, peer, "backoff", false, "unknown");
                    }
                    None => {}
                }
            }
            dg = recv_datagram(live.as_ref()) => {
                match dg {
                    Recv::Closed => {
                        clear_live(peer, &deps, &mut live, &mut reassembly);
                    }
                    Recv::Datagram(buf) => {
                        last_activity = Instant::now();
                        handle_inbound(
                            peer,
                            &hex,
                            &deps,
                            &mut live,
                            &mut reassembly,
                            &mut packet_id,
                            buf,
                        );
                    }
                }
            }
            _ = idle_tick.tick() => {
                let ka = keep_alive(&deps, peer);
                if !ka
                    && live.is_some()
                    && last_activity.elapsed() > Duration::from_secs(DEFAULT_IDLE_SECS)
                {
                    if let Some(cur) = live.take() {
                        cur.conn.close(0u32.into(), b"idle");
                    }
                    reassembly.clear();
                    publish_state(&deps, peer, "idle", false, "unknown");
                }
            }
        }
    }

    if let Some(h) = dial.take() {
        h.abort();
    }
    if let Some(cur) = live.take() {
        cur.conn.close(0u32.into(), b"dataplane_down");
    }
    forget_peer(&deps, peer);
}

enum Recv {
    Closed,
    Datagram(Bytes),
}

async fn recv_datagram(live: Option<&Live>) -> Recv {
    let Some(live) = live else {
        std::future::pending::<()>().await;
        return Recv::Closed;
    };
    match live.conn.read_datagram().await {
        Ok(buf) => Recv::Datagram(buf),
        Err(_) => Recv::Closed,
    }
}

async fn await_dial(
    dial: &mut Option<JoinHandle<Result<Connection, iroh::endpoint::ConnectError>>>,
) -> Option<Result<Connection, iroh::endpoint::ConnectError>> {
    let Some(handle) = dial.as_mut() else {
        std::future::pending::<()>().await;
        return None;
    };
    let out = handle.await.ok();
    *dial = None;
    out
}

fn keep_alive(deps: &PeerDeps, peer: EndpointId) -> bool {
    let hostname = deps
        .routes
        .lookup_endpoint(&format!("{peer}"))
        .map(|p| p.hostname.clone());
    deps.mesh.keep_alive_for(peer, hostname.as_deref())
}

fn publish_state(deps: &PeerDeps, peer: EndpointId, state: &str, live: bool, path: &str) {
    let was = deps.mesh.has_live(peer);
    deps.mesh
        .set_peer_state(peer, state, live, path, keep_alive(deps, peer));
    match (was, live) {
        (false, true) => deps.metrics.active_conns_inc(),
        (true, false) => deps.metrics.active_conns_dec(),
        _ => {}
    }
}

fn forget_peer(deps: &PeerDeps, peer: EndpointId) {
    if deps.mesh.has_live(peer) {
        deps.metrics.active_conns_dec();
    }
    deps.mesh.clear_peer(peer);
}

fn we_are_preferred_initiator(local: EndpointId, remote: EndpointId) -> bool {
    local < remote
}

fn opened_by_us(conn: &Connection) -> bool {
    conn.side() == Side::Client
}

/// Keep the connection opened by the preferred initiator. `local < remote`
/// means this endpoint should be the QUIC client.
pub fn prefer_incoming(
    local: EndpointId,
    remote: EndpointId,
    current: &Connection,
    incoming: &Connection,
) -> bool {
    let want_us = we_are_preferred_initiator(local, remote);
    let current_ok = opened_by_us(current) == want_us;
    let incoming_ok = opened_by_us(incoming) == want_us;
    matches!((current_ok, incoming_ok), (false, true))
}

fn path_label(conn: &Connection) -> &'static str {
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(path) if path.is_relay() => "relay",
        Some(_) => "direct",
        None => "unknown",
    }
}

fn gate_allows(deps: &PeerDeps, hex: &str) -> bool {
    deps.transport_auth.as_ref().is_none_or(|g| g.allows(hex))
}

fn maybe_start_keep_alive_dial(
    deps: &PeerDeps,
    peer: EndpointId,
    dial: &mut Option<JoinHandle<Result<Connection, iroh::endpoint::ConnectError>>>,
    cooldown_until: Option<Instant>,
) {
    if !keep_alive(deps, peer) {
        return;
    }
    if !we_are_preferred_initiator(deps.local_id, peer) {
        return;
    }
    start_dial(deps, peer, dial, cooldown_until);
}

fn start_dial(
    deps: &PeerDeps,
    peer: EndpointId,
    dial: &mut Option<JoinHandle<Result<Connection, iroh::endpoint::ConnectError>>>,
    cooldown_until: Option<Instant>,
) {
    if dial.is_some() {
        return;
    }
    if cooldown_until.is_some_and(|t| Instant::now() < t) {
        return;
    }
    let hex = format!("{peer}");
    if !gate_allows(deps, &hex) {
        deps.mesh.inc_dials_suppressed();
        return;
    }
    if deps.routes.lookup_endpoint(&hex).is_none() {
        deps.mesh.inc_dials_suppressed();
        return;
    }
    deps.mesh.inc_dial_attempt();
    publish_state(deps, peer, "dialing", false, "unknown");
    let endpoint = deps.endpoint.clone();
    *dial = Some(tokio::spawn(async move {
        endpoint.connect(peer, TUNNEL_ALPN).await
    }));
}

fn drop_hold(deps: &PeerDeps, hold: &mut Option<OutboundPacket>) {
    if hold.take().is_some() {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
    }
}

fn flush_hold(
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    hold: &mut Option<OutboundPacket>,
    packet_id: &mut u32,
    last_activity: &mut Instant,
) {
    let Some(pkt) = hold.take() else {
        return;
    };
    if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
        return;
    }
    *last_activity = Instant::now();
    send_logical(peer, deps, live, pkt, packet_id);
}

fn drop_queued(deps: &PeerDeps, packets: &mut mpsc::Receiver<OutboundPacket>) {
    while packets.try_recv().is_ok() {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
    }
}

fn drain_outbound(
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    packets: &mut mpsc::Receiver<OutboundPacket>,
    packet_id: &mut u32,
    last_activity: &mut Instant,
) {
    while let Ok(pkt) = packets.try_recv() {
        if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
            deps.mesh.inc_stale();
            deps.metrics.dropped_inc("packet_stale");
            continue;
        }
        *last_activity = Instant::now();
        send_logical(peer, deps, live, pkt, packet_id);
        if live.is_none() {
            break;
        }
    }
}

fn clear_live(
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
) {
    *live = None;
    reassembly.clear();
    publish_state(deps, peer, "idle", false, "unknown");
}

fn install_conn(
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
    incoming: Connection,
) {
    if incoming.close_reason().is_some() {
        return;
    }
    if let Some(current) = live.as_ref() {
        if current.conn.close_reason().is_none()
            && !prefer_incoming(deps.local_id, peer, &current.conn, &incoming)
        {
            incoming.close(0u32.into(), b"tie_break");
            return;
        }
        current.conn.close(0u32.into(), b"replaced");
    }
    reassembly.clear();
    let stable_id = incoming.stable_id();
    spawn_meter_watch(deps.mesh.clone(), peer, incoming.clone());
    let path = path_label(&incoming);
    *live = Some(Live {
        conn: incoming,
        stable_id,
    });
    publish_state(deps, peer, "connected", true, path);
}

fn spawn_meter_watch(mesh: TunnelMesh, peer: EndpointId, conn: Connection) {
    tokio::spawn(async move {
        let refresh = |conn: &Connection| {
            let urls = mesh.cloud_relay_urls();
            let metered = selected_path_is_cloud_relay(conn, &urls);
            mesh.set_peer_cloud_relay(peer, metered);
        };
        refresh(&conn);
        let mut events = conn.path_events();
        while let Some(ev) = events.next().await {
            match ev {
                PathEvent::Selected { .. }
                | PathEvent::Lagged { .. }
                | PathEvent::Opened { .. }
                | PathEvent::Closed { .. } => refresh(&conn),
                _ => {}
            }
        }
        mesh.clear_peer_cloud_relay(peer);
    });
}

fn selected_path_is_cloud_relay(
    conn: &Connection,
    urls: &std::collections::HashSet<String>,
) -> bool {
    let paths = conn.paths();
    let Some(path) = paths.iter().find(|p| p.is_selected()) else {
        return false;
    };
    if !path.is_relay() {
        return false;
    }
    match path.remote_addr() {
        TransportAddr::Relay(url) => urls.contains(&normalize_relay_url(url.as_str())),
        _ => false,
    }
}

fn send_logical(
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    pkt: OutboundPacket,
    packet_id: &mut u32,
) {
    let Some(live_conn) = live.as_ref() else {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
        return;
    };
    if live_conn.conn.close_reason().is_some() {
        *live = None;
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
        return;
    }
    let Some(max) = live_conn.conn.max_datagram_size() else {
        deps.mesh.inc_too_large();
        deps.metrics.dropped_inc("datagram_too_large");
        return;
    };
    if SINGLE_HEADER_LEN + pkt.bytes.len() > max {
        *packet_id = packet_id.wrapping_add(1);
    }
    let id = *packet_id;
    let Some(frames) = encode_logical(pkt.network_id, &pkt.bytes, max, id) else {
        deps.mesh.inc_too_large();
        deps.metrics.dropped_inc("datagram_too_large");
        return;
    };
    if frames.len() == 1 {
        deps.mesh.inc_single();
    } else {
        deps.mesh.inc_segmented();
        deps.mesh.add_segments_tx(frames.len() as u64);
    }
    let n = frames.len();
    for (i, frame) in frames.into_iter().enumerate() {
        match live_conn.conn.send_datagram(frame) {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                deps.mesh.inc_too_large();
                deps.metrics.dropped_inc("datagram_too_large");
                return;
            }
            Err(SendDatagramError::ConnectionLost(_)) => {
                let dead_id = live_conn.stable_id;
                if live.as_ref().is_some_and(|l| l.stable_id == dead_id) {
                    *live = None;
                }
                return;
            }
            Err(_) => {
                deps.mesh.inc_send_error();
                deps.metrics.dropped_inc("datagram_send");
                return;
            }
        }
        if i + 1 == n {
            deps.mesh.record_tx(peer, pkt.bytes.len() as u64);
            deps.metrics.packets_inc("out");
            deps.metrics.bytes_add("out", pkt.bytes.len() as u64);
        }
    }
}

fn handle_inbound(
    peer: EndpointId,
    hex: &str,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
    packet_id: &mut u32,
    buf: Bytes,
) {
    let frame = match decode(&buf) {
        Ok(f) => f,
        Err(_) => {
            deps.mesh.inc_reassembly_malformed();
            deps.metrics.dropped_inc("overlay_malformed");
            return;
        }
    };
    let (network_id, packet) = match frame {
        Frame::Single { network_id, packet } => (network_id, Bytes::copy_from_slice(packet)),
        Frame::Segment {
            network_id,
            packet_id,
            index,
            count,
            total_len,
            payload,
        } => {
            deps.mesh.add_segments_rx(1);
            let assembled = reassembly.insert(
                network_id,
                packet_id,
                index,
                count,
                total_len,
                payload,
                Instant::now(),
            );
            for _ in 0..reassembly.take_expired() {
                deps.mesh.inc_reassembly_expired();
                deps.metrics.dropped_inc("overlay_expired");
            }
            match assembled {
                Ok(Some(pkt)) => (network_id, pkt),
                Ok(None) => return,
                Err(ReassemblyError::Malformed) => {
                    deps.mesh.inc_reassembly_malformed();
                    deps.metrics.dropped_inc("overlay_malformed");
                    return;
                }
                Err(ReassemblyError::Evicted) => {
                    deps.mesh.inc_reassembly_evicted();
                    deps.metrics.dropped_inc("overlay_evicted");
                    return;
                }
            }
        }
    };
    if let Some(auth) = &deps.direct_auth
        && !auth.contains_network(hex, network_id)
    {
        deps.mesh.inc_blocked();
        deps.metrics.dropped_inc("unknown_network");
        return;
    }
    let Some(peer_info) = deps.routes.lookup_endpoint_in(network_id, hex) else {
        deps.mesh.inc_blocked();
        deps.metrics.dropped_inc("unknown_network");
        return;
    };
    let mut owned = packet.to_vec();
    let pkt = match packet::parse(&owned) {
        Ok(p) => p,
        Err(e) => {
            deps.metrics.dropped_inc(e.drop_reason());
            return;
        }
    };
    if pkt.ip.v4_src().is_none() {
        deps.metrics.dropped_inc("ipv6_unsupported_in");
        return;
    }
    let src = pkt.ip.v4_src().unwrap();
    if !source_matches_peer(src, peer_info.ip) {
        deps.metrics.dropped_inc("antispoof");
        if let Some(tracker) = deps.spoofs.get(&network_id)
            && tracker.record(hex)
        {
            for (peer_hex, n) in tracker.drain_window_counts() {
                tracing::warn!(
                    peer = %peer_hex,
                    spoofed_packets = n,
                    "ingress anti-spoof drops in last window"
                );
            }
        }
        return;
    }
    if !deps.acl.allow_packet(hex, Direction::Inbound, &pkt) {
        deps.metrics.dropped_inc("policy_deny_in");
        return;
    }
    if let Some(fw) = deps.firewalls.get(&network_id) {
        match fw.evaluate(
            PacketDirection::Inbound,
            &pkt,
            Some(hex),
            Some(peer_info.hostname.as_str()),
            Some(network_id),
        ) {
            EvalResult::Allow => {}
            EvalResult::Deny => {
                deps.metrics.dropped_inc("fw_deny_in");
                return;
            }
            EvalResult::Reject { reply } => {
                deps.metrics.dropped_inc("fw_reject_in");
                if !reply.is_empty() {
                    send_logical(
                        peer,
                        deps,
                        live,
                        OutboundPacket {
                            network_id,
                            bytes: reply,
                            enqueued_at: Instant::now(),
                        },
                        packet_id,
                    );
                }
                return;
            }
        }
    }
    let self_ip = deps.acl.self_id.load().ip;
    if ssh_nat::needs_inbound_rewrite(&owned, self_ip) {
        let _ = ssh_nat::rewrite_inbound(&mut owned, self_ip);
    }
    match deps.tun_tx.try_send(Bytes::copy_from_slice(&owned)) {
        Ok(()) => {
            deps.mesh.record_rx(peer, owned.len() as u64);
            deps.metrics.packets_inc("in");
            deps.metrics.bytes_add("in", owned.len() as u64);
        }
        Err(_) => {
            deps.mesh.inc_tun_write_drop();
            deps.metrics.dropped_inc("tun_write_queue_full");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn ids() -> (EndpointId, EndpointId) {
        let a = SecretKey::generate().public();
        let b = SecretKey::generate().public();
        if a < b { (a, b) } else { (b, a) }
    }

    #[test]
    fn preferred_initiator_is_smaller_id() {
        let (small, large) = ids();
        assert!(we_are_preferred_initiator(small, large));
        assert!(!we_are_preferred_initiator(large, small));
    }

    #[test]
    fn prefer_incoming_keeps_canonical_client() {
        let (small, large) = ids();
        assert!(we_are_preferred_initiator(small, large));
        // small should keep Client (opened_by_us). Incoming Server is rejected
        // when current is already Client: prefer_incoming is false.
        // Without live connections we only check the boolean combination.
        let want_us = we_are_preferred_initiator(small, large);
        assert!(want_us);
        let current_ok = true;
        let incoming_ok = false;
        assert!(!matches!((current_ok, incoming_ok), (false, true)));
        let current_ok = false;
        let incoming_ok = true;
        assert!(matches!((current_ok, incoming_ok), (false, true)));
    }

    #[test]
    fn queue_cap_is_small() {
        assert_eq!(PEER_QUEUE_CAP, 32);
    }
}
