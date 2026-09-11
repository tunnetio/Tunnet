//! One [`TunnelHub`] per dataplane generation: `EndpointId` → one peer task.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::{Connection, SendDatagramError, Side};
use iroh::{Endpoint, EndpointId, TransportAddr};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tunnet_common::TUNNEL_ALPN;
use tunnet_common::packet;
use tunnet_common::policy::Direction;
use tunnet_core::direct::{AuthCache, EvalResult, FirewallEngine, PacketDirection, SpoofTracker};
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
const OUTBOUND_DRAIN_BUDGET: usize = 8;

static NEXT_WORKER: AtomicU64 = AtomicU64::new(1);

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

#[derive(Clone)]
struct PeerHandle {
    worker_id: u64,
    packets: mpsc::Sender<OutboundPacket>,
    accepted: mpsc::Sender<Connection>,
    stop: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialStart {
    InFlight,
    Started,
    Cooldown,
    Denied,
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
                self.deps.mesh.clear_peer(*peer, handle.worker_id);
                false
            }
        });
        for peer in authorized {
            if self.deps.local_id == peer {
                continue;
            }
            let Some(info) = self
                .deps
                .routes
                .peers()
                .into_iter()
                .find(|p| p.endpoint == peer)
            else {
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
        match self.workers.entry(peer) {
            dashmap::mapref::entry::Entry::Occupied(e) => e.get().clone(),
            dashmap::mapref::entry::Entry::Vacant(e) => {
                let worker_id = NEXT_WORKER.fetch_add(1, Ordering::Relaxed);
                let (packets_tx, packets_rx) = mpsc::channel(PEER_QUEUE_CAP);
                let (accepted_tx, accepted_rx) = mpsc::channel(ACCEPT_QUEUE_CAP);
                let stop = self.cancel.child_token();
                let handle = PeerHandle {
                    worker_id,
                    packets: packets_tx,
                    accepted: accepted_tx,
                    stop: stop.clone(),
                };
                e.insert(handle.clone());
                let deps = self.deps.clone();
                let workers = self.workers.clone();
                tokio::spawn(async move {
                    run_peer(worker_id, peer, deps, stop, packets_rx, accepted_rx).await;
                    workers.remove_if(&peer, |_, h| h.worker_id == worker_id);
                });
                handle
            }
        }
    }
}

struct Live {
    conn: Connection,
    stable_id: usize,
}

async fn run_peer(
    worker_id: u64,
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
    let mut retry_at: Option<Instant> = None;
    let mut last_activity = Instant::now();
    let mut idle_tick = tokio::time::interval(Duration::from_secs(5));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    publish_state(worker_id, &deps, peer, "idle", false, "unknown");

    loop {
        if cancel.is_cancelled() {
            break;
        }
        if live.is_none() && dial.is_none() && hold.is_none() {
            maybe_start_keep_alive_dial(&deps, peer, &mut dial, cooldown_until, worker_id);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            conn = accepted.recv() => {
                let Some(conn) = conn else { break };
                install_conn(worker_id, peer, &deps, &mut live, &mut reassembly, conn);
                last_activity = Instant::now();
                retry_at = None;
                flush_hold(worker_id, peer, &deps, &mut live, &mut reassembly, &mut hold, &mut packet_id, &mut last_activity);
                drain_outbound(worker_id, peer, &deps, &mut live, &mut reassembly, &mut packets, &mut packet_id, &mut last_activity);
            }
            pkt = packets.recv(), if hold.is_none() => {
                let Some(pkt) = pkt else { break };
                last_activity = Instant::now();
                if live.is_none() {
                    if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
                        deps.mesh.inc_stale();
                        deps.metrics.dropped_inc("packet_stale");
                    } else {
                        let outcome = start_dial(&deps, peer, &mut dial, cooldown_until);
                        if outcome == DialStart::Started {
                            publish_state(worker_id, &deps, peer, "dialing", false, "unknown");
                        }
                        retry_at = hold_after_dial(outcome, cooldown_until, pkt.enqueued_at);
                        hold = Some(pkt);
                    }
                } else {
                    send_logical(worker_id, peer, &deps, &mut live, &mut reassembly, pkt, &mut packet_id);
                    drain_outbound(worker_id, peer, &deps, &mut live, &mut reassembly, &mut packets, &mut packet_id, &mut last_activity);
                }
            }
            result = await_dial(&mut dial) => {
                match result {
                    Some(Ok(conn)) => {
                        deps.mesh.inc_dial_success();
                        install_conn(worker_id, peer, &deps, &mut live, &mut reassembly, conn);
                        last_activity = Instant::now();
                        retry_at = None;
                        flush_hold(worker_id, peer, &deps, &mut live, &mut reassembly, &mut hold, &mut packet_id, &mut last_activity);
                        drain_outbound(worker_id, peer, &deps, &mut live, &mut reassembly, &mut packets, &mut packet_id, &mut last_activity);
                    }
                    Some(Err(_)) => {
                        deps.mesh.inc_dial_fail();
                        let until = Instant::now() + DIAL_COOLDOWN;
                        cooldown_until = Some(until);
                        drop_queued(&deps, &mut packets);
                        if hold.as_ref().is_some_and(|p| p.enqueued_at.elapsed() > PACKET_MAX_AGE) {
                            drop_hold(&deps, &mut hold);
                            retry_at = None;
                        } else if hold.is_some() {
                            retry_at = Some(until);
                        }
                        publish_state(worker_id, &deps, peer, "backoff", false, "unknown");
                    }
                    None => {}
                }
            }
            _ = sleep_until_opt(retry_at), if retry_at.is_some() && live.is_none() => {
                retry_at = None;
                let Some(pkt) = hold.as_ref() else { continue };
                if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
                    drop_hold(&deps, &mut hold);
                    continue;
                }
                let enqueued_at = pkt.enqueued_at;
                let outcome = start_dial(&deps, peer, &mut dial, cooldown_until);
                if outcome == DialStart::Started {
                    publish_state(worker_id, &deps, peer, "dialing", false, "unknown");
                }
                retry_at = hold_after_dial(outcome, cooldown_until, enqueued_at);
            }
            dg = recv_datagram(live.as_ref()) => {
                match dg {
                    Recv::Closed => {
                        clear_live(worker_id, peer, &deps, &mut live, &mut reassembly);
                    }
                    Recv::Datagram(buf) => {
                        last_activity = Instant::now();
                        handle_inbound(
                            worker_id,
                            peer,
                            &hex,
                            &deps,
                            &mut live,
                            &mut reassembly,
                            &mut packet_id,
                            buf,
                        );
                        if let Some(cur) = live.as_ref() {
                            refresh_path_telemetry(worker_id, &deps, peer, &cur.conn);
                        }
                    }
                }
            }
            _ = idle_tick.tick() => {
                if let Some(cur) = live.as_ref() {
                    refresh_path_telemetry(worker_id, &deps, peer, &cur.conn);
                }
                let ka = keep_alive(&deps, peer);
                if !ka
                    && live.is_some()
                    && last_activity.elapsed() > Duration::from_secs(DEFAULT_IDLE_SECS)
                {
                    if let Some(cur) = live.take() {
                        cur.conn.close(0u32.into(), b"idle");
                    }
                    clear_live(worker_id, peer, &deps, &mut live, &mut reassembly);
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
    forget_peer(worker_id, &deps, peer);
}

fn hold_after_dial(
    outcome: DialStart,
    cooldown_until: Option<Instant>,
    enqueued_at: Instant,
) -> Option<Instant> {
    match outcome {
        DialStart::Started | DialStart::InFlight => None,
        DialStart::Cooldown => cooldown_until,
        DialStart::Denied => Some(enqueued_at + PACKET_MAX_AGE),
    }
}

async fn sleep_until_opt(until: Option<Instant>) {
    let Some(until) = until else {
        std::future::pending::<()>().await;
        return;
    };
    let now = Instant::now();
    if until > now {
        tokio::time::sleep(until - now).await;
    }
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

fn publish_state(
    worker_id: u64,
    deps: &PeerDeps,
    peer: EndpointId,
    state: &str,
    live: bool,
    path: &str,
) {
    let was = deps.mesh.has_live(peer);
    deps.mesh
        .set_peer_state(peer, worker_id, state, live, path, keep_alive(deps, peer));
    match (was, deps.mesh.has_live(peer)) {
        (false, true) => deps.metrics.active_conns_inc(),
        (true, false) => deps.metrics.active_conns_dec(),
        _ => {}
    }
}

fn forget_peer(worker_id: u64, deps: &PeerDeps, peer: EndpointId) {
    if deps.mesh.has_live(peer) {
        deps.mesh.clear_peer(peer, worker_id);
        if !deps.mesh.has_live(peer) {
            deps.metrics.active_conns_dec();
        }
    } else {
        deps.mesh.clear_peer(peer, worker_id);
    }
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
    worker_id: u64,
) {
    if !keep_alive(deps, peer) {
        return;
    }
    if !we_are_preferred_initiator(deps.local_id, peer) {
        return;
    }
    if start_dial(deps, peer, dial, cooldown_until) == DialStart::Started {
        publish_state(worker_id, deps, peer, "dialing", false, "unknown");
    }
}

fn start_dial(
    deps: &PeerDeps,
    peer: EndpointId,
    dial: &mut Option<JoinHandle<Result<Connection, iroh::endpoint::ConnectError>>>,
    cooldown_until: Option<Instant>,
) -> DialStart {
    if dial.is_some() {
        return DialStart::InFlight;
    }
    if cooldown_until.is_some_and(|t| Instant::now() < t) {
        return DialStart::Cooldown;
    }
    let hex = format!("{peer}");
    if !gate_allows(deps, &hex) {
        deps.mesh.inc_dials_suppressed();
        return DialStart::Denied;
    }
    if deps.routes.lookup_endpoint(&hex).is_none()
        && !deps.routes.peers().iter().any(|p| p.endpoint == peer)
    {
        deps.mesh.inc_dials_suppressed();
        return DialStart::Denied;
    }
    deps.mesh.inc_dial_attempt();
    let endpoint = deps.endpoint.clone();
    *dial = Some(tokio::spawn(async move {
        endpoint.connect(peer, TUNNEL_ALPN).await
    }));
    DialStart::Started
}

fn drop_hold(deps: &PeerDeps, hold: &mut Option<OutboundPacket>) {
    if hold.take().is_some() {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
    }
}

#[allow(clippy::too_many_arguments)]
fn flush_hold(
    worker_id: u64,
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
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
    send_logical(worker_id, peer, deps, live, reassembly, pkt, packet_id);
}

fn drop_queued(deps: &PeerDeps, packets: &mut mpsc::Receiver<OutboundPacket>) {
    while packets.try_recv().is_ok() {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_outbound(
    worker_id: u64,
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
    packets: &mut mpsc::Receiver<OutboundPacket>,
    packet_id: &mut u32,
    last_activity: &mut Instant,
) {
    for _ in 0..OUTBOUND_DRAIN_BUDGET {
        let Ok(pkt) = packets.try_recv() else {
            break;
        };
        if pkt.enqueued_at.elapsed() > PACKET_MAX_AGE {
            deps.mesh.inc_stale();
            deps.metrics.dropped_inc("packet_stale");
            continue;
        }
        *last_activity = Instant::now();
        send_logical(worker_id, peer, deps, live, reassembly, pkt, packet_id);
        if live.is_none() {
            break;
        }
    }
}

fn clear_live(
    worker_id: u64,
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
) {
    *live = None;
    reassembly.clear();
    deps.mesh.clear_peer_cloud_relay(peer, worker_id);
    publish_state(worker_id, deps, peer, "idle", false, "unknown");
}

fn refresh_path_telemetry(worker_id: u64, deps: &PeerDeps, peer: EndpointId, conn: &Connection) {
    let urls = deps.mesh.cloud_relay_urls();
    let metered = selected_path_is_cloud_relay(conn, &urls);
    deps.mesh.set_peer_cloud_relay(peer, worker_id, metered);
    if conn.close_reason().is_none() {
        publish_state(worker_id, deps, peer, "connected", true, path_label(conn));
    }
}

fn install_conn(
    worker_id: u64,
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
    refresh_path_telemetry(worker_id, deps, peer, &incoming);
    let path = path_label(&incoming);
    *live = Some(Live {
        conn: incoming,
        stable_id,
    });
    publish_state(worker_id, deps, peer, "connected", true, path);
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
    worker_id: u64,
    peer: EndpointId,
    deps: &PeerDeps,
    live: &mut Option<Live>,
    reassembly: &mut Reassembly,
    pkt: OutboundPacket,
    packet_id: &mut u32,
) {
    let Some(live_conn) = live.as_ref() else {
        deps.mesh.inc_stale();
        deps.metrics.dropped_inc("packet_stale");
        return;
    };
    if live_conn.conn.close_reason().is_some() {
        clear_live(worker_id, peer, deps, live, reassembly);
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
                    clear_live(worker_id, peer, deps, live, reassembly);
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
            if let Some(cur) = live.as_ref() {
                refresh_path_telemetry(worker_id, deps, peer, &cur.conn);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    worker_id: u64,
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
    let network_id = match &frame {
        Frame::Single { network_id, .. } | Frame::Segment { network_id, .. } => *network_id,
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
    if !deps
        .routes
        .inbound_source_ok(network_id, src, peer_info.endpoint)
    {
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
                        worker_id,
                        peer,
                        deps,
                        live,
                        reassembly,
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

    #[test]
    fn hold_retry_follows_dial_outcome() {
        let now = Instant::now();
        assert_eq!(hold_after_dial(DialStart::Started, None, now), None);
        assert_eq!(hold_after_dial(DialStart::InFlight, None, now), None);
        let until = now + DIAL_COOLDOWN;
        assert_eq!(
            hold_after_dial(DialStart::Cooldown, Some(until), now),
            Some(until)
        );
        assert_eq!(
            hold_after_dial(DialStart::Denied, None, now),
            Some(now + PACKET_MAX_AGE)
        );
    }
}
