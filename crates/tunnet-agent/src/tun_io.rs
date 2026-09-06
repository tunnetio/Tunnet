//! Parse, route, authorize, and move packets between TUN I/O and peer transports.
//! QUIC readers enqueue complete IP packets without waiting for the OS writer.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use bytes::Bytes;
use futures_util::FutureExt as _;
use iroh::endpoint::Connection;
use tun_rs::{AsyncDevice, DeviceBuilder};
use tunnet_common::packet::LogicalPacket;
use tunnet_common::policy::Direction;
use tunnet_core::AclEngine;
use tunnet_core::direct::{AuthCache, SpoofTracker, source_matches_peer};
use tunnet_core::peers::{PeerIdentity, PeerMembershipState, PeerRegistry};
use tunnet_core::policy_runtime::{PolicyRuntime, PolicyVerdict};
use tunnet_core::routing::{RouteDecision, RoutingTable};
use uuid::Uuid;

use crate::metrics::AgentMetrics;
use crate::peer_transport::{PeerSender, PeerTransports, enqueue_packet};
use crate::ssh_nat;
use crate::tun_fast;
use crate::tun_writer::TunWriterHandle;
pub const INBOUND_DRAIN_BUDGET: usize = 32;

pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    let mtu = mtu.clamp(576, tunnet_common::packet::DEFAULT_VIRTUAL_MTU as u16);
    let builder = DeviceBuilder::new()
        .name(ifname)
        .ipv4(ipv4, prefix, None)
        .mtu(mtu);
    #[cfg(target_os = "linux")]
    let builder = builder.offload(true);
    #[cfg(windows)]
    let builder = {
        let path = crate::wintun::materialize()?;
        builder
            .wintun_file(path.display().to_string())
            .wintun_log(true)
    };
    let dev = builder.build_async().context("build_async TUN device")?;
    tracing::info!(%ipv4, prefix, mtu, "TUN device up (fast path)");
    Ok(dev)
}

pub struct OutboundDeps {
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub metrics: AgentMetrics,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub mtu: u16,
    pub transports: PeerTransports,
    pub tun_writer: TunWriterHandle,
}
fn handle_outbound_one(packet: LogicalPacket, ctx: &mut OutboundCtx<'_>) {
    let mut packet = packet;
    let routes = ctx.routes;
    let runtime = ctx.runtime;
    let metrics = ctx.metrics;
    let transports = ctx.transports;
    let tun_writer = ctx.tun_writer;
    let bufs = ctx.bufs;
    let self_ip = ctx.self_ip;
    let frags: &mut crate::frag_hold::DeferredFragments = ctx.frags;
    let meta = packet.meta;
    if ssh_nat::needs_outbound_rewrite_with_meta(&meta, self_ip) {
        let Some(bytes) = packet_owner_bytes_mut(&mut packet, bufs) else {
            metrics.dropped_inc("nat_materialize");
            return;
        };
        if !ssh_nat::rewrite_outbound_with_meta(bytes, &meta, self_ip) {
            metrics.dropped_inc("nat_invalid");
            return;
        }
        if let tunnet_common::packet::Transport::Tcp { src_port, .. } = &mut packet.meta.transport {
            *src_port = ssh_nat::SSH_EXTERNAL_PORT;
        }
    }
    let meta = packet.meta;
    let Some(dst) = packet.meta.dst_v4 else {
        metrics.dropped_inc("ipv6_unsupported");
        return;
    };
    let fast = match routes.route_once(&dst) {
        RouteDecision::LocalMagic => {
            metrics.dropped_inc("magic_dns_local");
            return;
        }
        RouteDecision::LocalAdvertised => {
            metrics.dropped_inc("local_subnet");
            return;
        }
        RouteDecision::NoRoute => {
            metrics.dropped_inc("no_route");
            return;
        }
        RouteDecision::Peer(h) => h.peer.fast.clone(),
    };

    if fast.identity.read().ip == self_ip {
        metrics.dropped_inc("self");
        return;
    }
    let ident: Arc<PeerIdentity> = fast.identity.read().clone();
    let slot = fast.policy.load();
    let net = ident.network_id;
    let check = |m: &tunnet_common::packet::PacketMeta| {
        runtime.check(
            m,
            Direction::Outbound,
            &ident.endpoint_hex,
            &ident.tags,
            Some(ident.hostname.as_str()),
            Some(ident.network_id),
            &slot,
            &slot.counters,
        )
    };
    let has_context = || {
        runtime
            .fragment_context(&meta, net, Direction::Outbound)
            .is_some()
    };
    let (outcome, expired) = frags.eval(net, Direction::Outbound, meta, packet, has_context, check);
    if expired > 0 {
        metrics.dropped_add("frag_expired", expired);
    }
    match outcome {
        crate::frag_hold::FragOutcome::Immediate(PolicyVerdict::Allow, packet) => {
            enqueue_packet(transports, &fast, packet);
        }
        crate::frag_hold::FragOutcome::Immediate(PolicyVerdict::Deny, _) => {
            metrics.dropped_inc("policy_deny");
        }
        crate::frag_hold::FragOutcome::Immediate(PolicyVerdict::Reject, packet) => {
            metrics.dropped_inc("fw_reject_out");
            send_reject_reply(tun_writer, &packet, metrics);
        }
        crate::frag_hold::FragOutcome::Held => {}
        crate::frag_hold::FragOutcome::Released(items) => {
            for (verdict, packet) in items {
                match verdict {
                    PolicyVerdict::Allow => enqueue_packet(transports, &fast, packet),
                    PolicyVerdict::Deny => metrics.dropped_inc("policy_deny"),
                    PolicyVerdict::Reject => {
                        metrics.dropped_inc("fw_reject_out");
                        send_reject_reply(tun_writer, &packet, metrics);
                    }
                }
            }
        }
    }
}

struct OutboundCtx<'a> {
    routes: &'a RoutingTable,
    runtime: &'a PolicyRuntime,
    metrics: &'a AgentMetrics,
    transports: &'a PeerTransports,
    tun_writer: &'a TunWriterHandle,
    bufs: &'a Arc<tunnet_common::packet::PacketPool>,
    self_ip: std::net::Ipv4Addr,
    frags: &'a mut crate::frag_hold::DeferredFragments,
}
fn send_reject_framed(
    reply: Bytes,
    member: &Arc<PeerMembershipState>,
    sender: &PeerSender,
    metrics: &AgentMetrics,
) {
    let Some(packet) = LogicalPacket::from_shared(reply) else {
        metrics.dropped_inc("malformed_transport");
        return;
    };
    sender.enqueue(member, packet);
}
fn send_reject_reply(writer: &TunWriterHandle, packet: &LogicalPacket, metrics: &AgentMetrics) {
    use tunnet_common::packet as packet_mod;
    let reply = packet_mod::synthesize_reject(&packet.meta, packet.owner.as_bytes());
    let Some(reply) = reply.filter(|r| !r.is_empty()) else {
        return;
    };
    if !writer.try_enqueue(reply) {
        metrics.dropped_inc("tun_write_queue_full");
    }
}
fn packet_owner_bytes_mut<'a>(
    packet: &'a mut LogicalPacket,
    pool: &Arc<tunnet_common::packet::PacketPool>,
) -> Option<&'a mut [u8]> {
    if matches!(packet.owner, tunnet_common::packet::PacketOwner::Shared(_))
        && !packet.materialize(pool)
    {
        return None;
    }
    match &mut packet.owner {
        tunnet_common::packet::PacketOwner::Pooled(b) => {
            let len = b.len();
            Some(&mut b.recv_region(len)[..len])
        }
        tunnet_common::packet::PacketOwner::Shared(_) => None,
    }
}
pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        routes,
        runtime,
        metrics,
        bufs,
        mtu,
        transports,
        tun_writer,
    } = deps;

    let self_ip = runtime.self_ip();
    metrics.mtu_set(mtu as u64);

    #[cfg(target_os = "linux")]
    let mut batch = tun_fast::LinuxBatchEngine::new(bufs.clone(), mtu as usize);

    tracing::info!("outbound TUN reader loop started");
    let mut frags = crate::frag_hold::DeferredFragments::new();
    loop {
        #[cfg(target_os = "linux")]
        {
            let packets = batch.recv_batch(&tun).await?;
            metrics.tun_syscall_inc("recv_batch");
            if packets.is_empty() {
                continue;
            }
            let mut ctx = OutboundCtx {
                routes: &routes,
                runtime: &runtime,
                metrics: &metrics,
                transports: &transports,
                tun_writer: &tun_writer,
                bufs: &bufs,
                self_ip,
                frags: &mut frags,
            };
            for packet in packets {
                if packet.len() > mtu as usize {
                    metrics.dropped_inc("oversize_mtu");
                    continue;
                }
                metrics.tun_rx_packets_inc(packet.len());
                handle_outbound_one(packet, &mut ctx);
            }
            continue;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let Some(packet) = tun_fast::recv_one(&tun, &bufs, mtu as usize).await? else {
                continue;
            };
            metrics.tun_syscall_inc("recv");
            let mut ctx = OutboundCtx {
                routes: &routes,
                runtime: &runtime,
                metrics: &metrics,
                transports: &transports,
                tun_writer: &tun_writer,
                bufs: &bufs,
                self_ip,
                frags: &mut frags,
            };
            {
                if packet.len() > mtu as usize {
                    metrics.dropped_inc("oversize_mtu");
                    continue;
                }
                metrics.tun_rx_packets_inc(packet.len());
                handle_outbound_one(packet, &mut ctx);
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderExit {
    GenerationDone,
    MembershipGone,
    ConnFailed,
}

pub struct InboundDeps {
    pub conn: Connection,
    pub tun_writer: TunWriterHandle,
    pub sender: PeerSender,
    pub cancel: tokio_util::sync::CancellationToken,
    pub context: InboundContext,
}

#[derive(Clone)]
pub struct InboundContext {
    pub pool: tunnet_core::ConnPool,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub acl: AclEngine,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub metrics: AgentMetrics,
    pub auth: Option<AuthCache>,
}
pub async fn serve_tunnel_connection(deps: InboundDeps) -> ReaderExit {
    let InboundDeps {
        conn,
        tun_writer,
        sender,
        cancel: generation_cancel,
        context,
    } = deps;
    let InboundContext {
        routes,
        runtime,
        acl,
        spoofs,
        bufs,
        metrics,
        auth,
        pool: _,
    } = context;
    let remote_id = conn.remote_id();
    let remote_hex = format!("{remote_id}");
    if !acl.allow_inbound_peer(&remote_hex) {
        tracing::warn!(%remote_id, "policy denied inbound peer");
        conn.close(1u32.into(), b"policy_deny");
        return ReaderExit::MembershipGone;
    }
    tracing::info!(%remote_id, "peer connected");
    let registry = routes.peer_registry().clone();
    if !registry.has_any_membership(remote_id) && routes.lookup_endpoint(&remote_hex).is_none() {
        tracing::debug!(%remote_id, "unknown peer at admission; closing");
        conn.close(1u32.into(), b"no_route");
        return ReaderExit::MembershipGone;
    }
    let mut fast_state: Option<Arc<PeerMembershipState>> = None;
    let mut fast_net = Uuid::nil();
    let mut fast_epoch = 0u64;
    let mut route_gen = routes.version();
    let mut frags = crate::frag_hold::DeferredFragments::new();

    let exit = loop {
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        let first = tokio::select! {
            biased;
            _ = generation_cancel.cancelled() => break ReaderExit::GenerationDone,
            res = conn.read_datagram() => match res {
                Ok(dg) => dg,
                Err(e) => {
                    tracing::debug!(?e, "read_datagram closed");
                    break ReaderExit::ConnFailed;
                }
            },
        };
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        metrics.datagram_inc("in", first.len());
        let mut batch: Vec<Bytes> = vec![first];
        for _ in 0..INBOUND_DRAIN_BUDGET {
            match conn.read_datagram().now_or_never() {
                Some(Ok(dg)) => {
                    metrics.datagram_inc("in", dg.len());
                    batch.push(dg);
                }
                _ => break,
            }
        }
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        let route_version = routes.version();
        if route_version != route_gen {
            route_gen = route_version;
            fast_state = None;
            if !registry.has_any_membership(remote_id) {
                tracing::info!(%remote_id, "peer removed from all networks; closing ingress reader");
                conn.close(1u32.into(), b"membership_removed");
                break ReaderExit::MembershipGone;
            }
        }
        if let Some(fast) = &fast_state
            && fast.epoch.load(Ordering::Relaxed) != fast_epoch
        {
            tracing::info!(%remote_id, "membership deactivated; re-resolving");
            fast_state = None;
        }
        let self_ip = runtime.self_ip();
        for dg in batch {
            let frame = match tunnet_common::packet::decode_frame(&dg) {
                Ok(f) => f,
                Err(_) => {
                    metrics.dropped_inc("malformed_frame");
                    continue;
                }
            };
            let net = match &frame {
                tunnet_common::packet::Frame::Single { net, .. } => *net,
            };
            if fast_state.is_none() || net != fast_net {
                match resolve_membership(
                    &registry,
                    &routes,
                    &remote_id,
                    &remote_hex,
                    net,
                    auth.as_ref(),
                ) {
                    Some(next) => {
                        fast_epoch = next.epoch.load(Ordering::Relaxed);
                        fast_net = net;
                        fast_state = Some(next);
                    }
                    None => {
                        metrics.dropped_inc("unknown_network");
                        continue;
                    }
                }
            }
            let fast = fast_state.as_ref().expect("resolved");
            if fast.epoch.load(Ordering::Relaxed) != fast_epoch {
                fast_state = None;
                metrics.dropped_inc("membership_revoked");
                continue;
            }
            handle_inbound_one(
                &dg,
                frame,
                fast,
                &runtime,
                &routes,
                &spoofs,
                &bufs,
                &metrics,
                &tun_writer,
                &sender,
                self_ip,
                &mut frags,
            );
        }
        tokio::task::yield_now().await;
    };
    tracing::info!(%remote_id, "peer disconnected");
    exit
}
fn resolve_membership(
    registry: &PeerRegistry,
    routes: &RoutingTable,
    remote: &iroh::EndpointId,
    remote_hex: &str,
    net: Uuid,
    auth: Option<&AuthCache>,
) -> Option<Arc<PeerMembershipState>> {
    if let Some(auth) = auth
        && !auth.contains_network(remote_hex, net)
    {
        return None;
    }
    if let Some(fast) = registry.get_membership(*remote, net) {
        return Some(fast);
    }
    let info = routes.lookup_membership(remote_hex, net)?;
    if let Some(auth) = auth
        && !auth.contains_network(remote_hex, info.network_id)
    {
        return None;
    }
    let fast = registry.ensure_membership(Arc::new(tunnet_core::peers::PeerIdentity {
        endpoint: info.endpoint,
        endpoint_hex: info.endpoint_hex.clone(),
        hostname: info.hostname.clone(),
        ip: info.ip,
        tags: info.tags.clone(),
        network_id: info.network_id,
        network_name: info.network_name.clone(),
    }));
    if let Some(slot) = routes.policy_slot_for(info.network_id) {
        fast.policy.store(slot);
    }
    Some(fast)
}
#[allow(clippy::too_many_arguments)]
fn handle_inbound_one(
    dg: &Bytes,
    frame: tunnet_common::packet::Frame<'_>,
    fast: &Arc<PeerMembershipState>,
    runtime: &PolicyRuntime,
    routes: &RoutingTable,
    spoofs: &HashMap<Uuid, SpoofTracker>,
    pool_bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
    tun_writer: &TunWriterHandle,
    sender: &PeerSender,
    self_ip: std::net::Ipv4Addr,
    frags: &mut crate::frag_hold::DeferredFragments,
) {
    let tunnet_common::packet::Frame::Single { payload, .. } = frame;
    let off = payload.as_ptr() as usize - dg.as_ptr() as usize;
    let Some(logical) = LogicalPacket::from_shared(dg.slice(off..off + payload.len())) else {
        metrics.dropped_inc("malformed_transport");
        return;
    };
    metrics.overlay_rx_logical_inc();
    let Some(src) = logical.meta.src_v4 else {
        metrics.dropped_inc("ipv6_unsupported_in");
        return;
    };
    let ident: Arc<PeerIdentity> = fast.identity.read().clone();
    if src == self_ip
        || (!source_matches_peer(src, ident.ip)
            && !routes.accepts_gateway_source(ident.network_id, ident.endpoint, src))
    {
        metrics.dropped_inc("antispoof");
        if let Some(tracker) = spoofs.get(&ident.network_id)
            && tracker.record(&ident.endpoint_hex)
        {
            for (peer, n) in tracker.drain_window_counts() {
                tracing::warn!(
                    peer = %peer,
                    spoofed_packets = n,
                    "ingress anti-spoof drops in last window"
                );
            }
        }
        return;
    }
    let slot = fast.policy.load();
    let net = ident.network_id;
    let in_meta = logical.meta;
    let check = |m: &tunnet_common::packet::PacketMeta| {
        runtime.check(
            m,
            Direction::Inbound,
            &ident.endpoint_hex,
            &ident.tags,
            Some(ident.hostname.as_str()),
            Some(ident.network_id),
            &slot,
            &slot.counters,
        )
    };
    let has_context = || {
        runtime
            .fragment_context(&in_meta, net, Direction::Inbound)
            .is_some()
    };
    let (outcome, expired) = frags.eval(
        net,
        Direction::Inbound,
        in_meta,
        logical,
        has_context,
        check,
    );
    if expired > 0 {
        metrics.dropped_add("frag_expired", expired);
    }
    match outcome {
        crate::frag_hold::FragOutcome::Immediate(verdict, packet) => {
            apply_inbound_verdict(
                verdict, packet, fast, pool_bufs, metrics, tun_writer, sender, self_ip,
            );
        }
        crate::frag_hold::FragOutcome::Held => {}
        crate::frag_hold::FragOutcome::Released(items) => {
            for (verdict, packet) in items {
                apply_inbound_verdict(
                    verdict, packet, fast, pool_bufs, metrics, tun_writer, sender, self_ip,
                );
            }
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn apply_inbound_verdict(
    verdict: PolicyVerdict,
    logical: LogicalPacket,
    fast: &Arc<PeerMembershipState>,
    pool_bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
    tun_writer: &TunWriterHandle,
    sender: &PeerSender,
    self_ip: std::net::Ipv4Addr,
) {
    let mut logical = logical;
    match verdict {
        PolicyVerdict::Allow => {}
        PolicyVerdict::Deny => {
            metrics.dropped_inc("policy_deny_in");
            return;
        }
        PolicyVerdict::Reject => {
            metrics.dropped_inc("fw_reject_in");
            let reply =
                tunnet_common::packet::synthesize_reject(&logical.meta, logical.owner.as_bytes());
            if let Some(reply) = reply.filter(|r| !r.is_empty()) {
                send_reject_framed(reply, fast, sender, metrics);
            }
            return;
        }
    }
    if ssh_nat::needs_inbound_rewrite_with_meta(&logical.meta, self_ip) {
        if !logical.materialize(pool_bufs) {
            metrics.dropped_inc("nat_materialize");
            return;
        }
        let meta = logical.meta;
        let Some(region) = packet_owner_bytes_mut(&mut logical, pool_bufs) else {
            metrics.dropped_inc("nat_materialize");
            return;
        };
        if !ssh_nat::rewrite_inbound_with_meta(region, &meta, self_ip) {
            metrics.dropped_inc("nat_invalid");
            return;
        }
        if let tunnet_common::packet::Transport::Tcp { dst_port, .. } = &mut logical.meta.transport
        {
            *dst_port = ssh_nat::SSH_INTERNAL_PORT;
        }
    }
    let n = logical.len() as u64;
    let bytes = match logical.owner {
        tunnet_common::packet::PacketOwner::Shared(b) => b,
        tunnet_common::packet::PacketOwner::Pooled(b) => Bytes::from_owner(b),
    };
    if tun_writer.try_enqueue(bytes) {
        fast.transport.record_rx(n);
        metrics.packets_inc("in");
        metrics.bytes_add("in", n);
    } else {
        metrics.dropped_inc("tun_write_queue_full");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_A: Uuid = Uuid::from_u128(0x0a0a);
    const NET_B: Uuid = Uuid::from_u128(0x0b0b);

    fn two_net_routes() -> (RoutingTable, iroh::EndpointId, String) {
        use tunnet_common::{DnsConfig, PeerEntry};
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let ep_hex = "b".repeat(64);
        let mk = |ip: &str| PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: ep_hex.clone(),
            hostname: "gw".into(),
            tags: vec![],
            ssh_host_key: None,
        };
        table.replace_network(
            NET_A,
            0,
            std::slice::from_ref(&mk("10.7.0.5")),
            &DnsConfig::default(),
            "neta",
            &self_id,
            1,
        );
        table.replace_network(
            NET_B,
            1,
            std::slice::from_ref(&mk("10.7.1.5")),
            &DnsConfig::default(),
            "netb",
            &self_id,
            2,
        );
        let ep: iroh::EndpointId = ep_hex.parse().unwrap();
        (table, ep, ep_hex)
    }

    #[test]
    fn resolve_binds_exact_membership_and_auth() {
        let (table, ep, ep_hex) = two_net_routes();
        let registry = table.peer_registry().clone();
        let auth = AuthCache::new();
        auth.insert(ep_hex.clone(), NET_A);
        let a = resolve_membership(&registry, &table, &ep, &ep_hex, NET_A, Some(&auth))
            .expect("A resolves");
        assert_eq!(a.identity.read().network_id, NET_A);
        assert_eq!(a.identity.read().ip, std::net::Ipv4Addr::new(10, 7, 0, 5));
        assert!(
            resolve_membership(&registry, &table, &ep, &ep_hex, NET_B, Some(&auth)).is_none(),
            "endpoint authed only for A must not claim B"
        );
        auth.insert(ep_hex.clone(), NET_B);
        let b = resolve_membership(&registry, &table, &ep, &ep_hex, NET_B, Some(&auth))
            .expect("B resolves once authed");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(b.identity.read().ip, std::net::Ipv4Addr::new(10, 7, 1, 5));
        assert!(
            resolve_membership(&registry, &table, &ep, &ep_hex, Uuid::from_u128(0xcc), None)
                .is_none()
        );
    }
}
