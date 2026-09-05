//! TUN reader (outbound) and QUIC ingress readers (inbound).
//!
//! Ownership split:
//! - The outbound task reads the OS TUN, runs NAT/routing/policy, and
//!   enqueues accepted packets into the endpoint TX registry. It never
//!   touches QUIC connections or the TUN writer.
//! - QUIC ingress readers (`serve_tunnel_connection`) decode frames,
//!   authorize per frame network, reassemble, and enqueue COMPLETE logical
//!   IP packets into the generation-owned TUN writer. They never await TUN
//!   write capacity and never call TUN write operations.

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

use crate::endpoint_tx::{EndpointTxRegistry, enqueue_packet};
use crate::metrics::AgentMetrics;
use crate::ssh_nat;
use crate::tun_fast;
use crate::tun_writer::TunWriterHandle;

/// Opportunistic inbound drain budget: after each awaited datagram, drain
/// already-ready datagrams without busy-polling.
pub const INBOUND_DRAIN_BUDGET: usize = 32;

pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    // Fast-path builder: Linux enables offload; Windows uses the Wintun ring.
    // Diagnostic override for tests: TUNNET_TUN_OFFLOAD=0 disables tun-rs
    // offload+GSO (plain single-packet TUN I/O instead). Correctness never
    // depends on this switch.
    #[cfg(target_os = "linux")]
    let offload = std::env::var("TUNNET_TUN_OFFLOAD")
        .map(|v| {
            !matches!(
                v.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true);
    let builder = DeviceBuilder::new()
        .name(ifname)
        .ipv4(ipv4, prefix, None)
        .mtu(mtu);
    #[cfg(target_os = "linux")]
    let builder = if offload {
        builder.offload(true)
    } else {
        builder
    };
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
    pub tx_registry: EndpointTxRegistry,
    pub tun_writer: TunWriterHandle,
}

/// Handle one owned logical packet through the outbound pipeline.
/// Parse-once: `packet` already carries metadata; NAT refreshes it only when
/// a rewrite actually mutated the bytes. Policy uses the shared runtime with
/// the peer's stable network slot — no per-packet map lookups. Accepted
/// packets feed the endpoint TX queue; every shed packet is counted here.
fn handle_outbound_one(packet: LogicalPacket, ctx: &mut OutboundCtx<'_>) {
    let mut packet = packet;
    let routes = ctx.routes;
    let runtime = ctx.runtime;
    let metrics = ctx.metrics;
    let tx_registry = ctx.tx_registry;
    let tun_writer = ctx.tun_writer;
    let bufs = ctx.bufs;
    let self_ip = ctx.self_ip;
    let frags: &mut crate::frag_hold::DeferredFragments = ctx.frags;
    // SSH NAT consumes existing metadata (no second parse) — and ONLY takes
    // the mutable/materializing path when metadata proves a rewrite is
    // required. Common packets stay immutable: zero copy.
    let meta = packet.meta;
    if ssh_nat::needs_outbound_rewrite_with_meta(&meta, self_ip) {
        let Some(bytes) = packet_owner_bytes_mut(&mut packet, bufs) else {
            metrics.dropped_inc("nat_materialize");
            return;
        };
        if ssh_nat::rewrite_outbound_with_meta(bytes, &meta, self_ip) && !packet.refresh() {
            // Rewrite applied but re-parse failed: fail closed.
            metrics.dropped_inc("nat_reparse");
            return;
        }
    }
    let Some(dst) = packet.meta.dst_v4 else {
        metrics.dropped_inc("ipv6_unsupported");
        return;
    };

    // Single immutable-snapshot route decision; the handle carries the
    // stable membership (no peer map lookup after routing).
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

    // One compiled verdict against the shared runtime. The firewall
    // snapshot loads from the peer's STABLE network slot inside check()
    // (ACL-then-firewall order) — publication swaps it in place, so no
    // relink is ever needed. Later IP fragments without a first-fragment
    // context hold briefly (unordered transport); the first fragment's
    // verdict releases or discards them in offset order.
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
            // Into the endpoint TX queue (tail-rejection counted by the reporter).
            enqueue_packet(tx_registry, &fast, packet);
        }
        crate::frag_hold::FragOutcome::Immediate(PolicyVerdict::Deny, _) => {
            metrics.dropped_inc("policy_deny");
        }
        crate::frag_hold::FragOutcome::Immediate(PolicyVerdict::Reject, packet) => {
            metrics.dropped_inc("fw_reject_out");
            send_reject_reply(tun_writer, &packet, metrics);
        }
        crate::frag_hold::FragOutcome::Held => {
            // Waiting for the first fragment; resolves on release/expiry
            // (both counted there). Not a drop.
        }
        crate::frag_hold::FragOutcome::Released(items) => {
            for (verdict, packet) in items {
                match verdict {
                    PolicyVerdict::Allow => enqueue_packet(tx_registry, &fast, packet),
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
    tx_registry: &'a EndpointTxRegistry,
    tun_writer: &'a TunWriterHandle,
    bufs: &'a Arc<tunnet_common::packet::PacketPool>,
    self_ip: std::net::Ipv4Addr,
    frags: &'a mut crate::frag_hold::DeferredFragments,
}

/// Reject replies are rare, but they must be protocol-correct: the peer
/// expects every tunnel DATAGRAM to begin with 0x30/0x31 with its bound
/// network. Route the reply through the endpoint TX queue like any other
/// packet (the worker frames/segments it).
fn send_reject_framed(
    reply: Bytes,
    member: &Arc<PeerMembershipState>,
    tx_registry: &EndpointTxRegistry,
    metrics: &AgentMetrics,
) {
    // Zero-copy: the synthesized reply bytes ride straight into the
    // endpoint queue; the worker frames/segments them like any packet.
    let Some(packet) = LogicalPacket::from_shared(reply) else {
        metrics.dropped_inc("malformed_transport");
        return;
    };
    enqueue_packet(tx_registry, member, packet);
}

/// Outbound reject replies go to the LOCAL TUN device (raw IP framing —
/// correct there: TUN is not the tunnel wire). Rare: synthesize and enqueue
/// to the generation-owned writer — never a side-channel TUN write.
fn send_reject_reply(writer: &TunWriterHandle, packet: &LogicalPacket, metrics: &AgentMetrics) {
    use tunnet_common::packet as packet_mod;
    let reply = packet_mod::parse(packet.owner.as_bytes())
        .ok()
        .and_then(|p| packet_mod::synthesize_reject(&p));
    let Some(reply) = reply.filter(|r| !r.is_empty()) else {
        return;
    };
    if !writer.try_enqueue(reply) {
        metrics.dropped_inc("tun_write_queue_full");
    }
}

/// Mutable packet bytes for NAT, materializing pooled/shared storage.
/// Returns None only when materialization fails (counts as drop).
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

/// Outbound task: OS TUN -> routing/policy -> endpoint TX queues. Owns no
/// queue state (enqueue is synchronous and non-blocking), so the actor may
/// abort it on teardown. Any `Err` return is abnormal (device failure).
pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        routes,
        runtime,
        metrics,
        bufs,
        mtu,
        tx_registry,
        tun_writer,
    } = deps;

    let self_ip = runtime.self_ip();
    metrics.mtu_set(mtu as u64);

    #[cfg(target_os = "linux")]
    let mut batch = tun_fast::LinuxBatchEngine::new(bufs.clone(), mtu as usize);

    tracing::info!("outbound TUN reader loop started");
    // One deferred-fragment table for the outbound path (per-task bounds;
    // keys are network+direction scoped).
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
                tx_registry: &tx_registry,
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
                metrics.tun_rx_packets_inc();
                handle_outbound_one(packet, &mut ctx);
            }
            continue;
        }

        #[allow(unreachable_code)]
        {
            // Windows + fallback: burst-drain the ring into pooled buffers.
            let burst =
                tun_fast::windows_recv_burst(&tun, &bufs, mtu as usize, tun_fast::BURST_BUDGET)
                    .await?;
            metrics.tun_syscall_inc("recv_burst");
            if burst.is_empty() {
                continue;
            }
            let mut ctx = OutboundCtx {
                routes: &routes,
                runtime: &runtime,
                metrics: &metrics,
                tx_registry: &tx_registry,
                tun_writer: &tun_writer,
                bufs: &bufs,
                self_ip,
                frags: &mut frags,
            };
            for packet in burst {
                if packet.len() > mtu as usize {
                    metrics.dropped_inc("oversize_mtu");
                    continue;
                }
                metrics.tun_rx_packets_inc();
                handle_outbound_one(packet, &mut ctx);
            }
        }
    }
}

/// How a QUIC ingress reader ended (for lifecycle supervision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderExit {
    /// Dataplane generation cancelled: normal shutdown, no action.
    GenerationDone,
    /// Endpoint lost all memberships or the membership was revoked: the
    /// connection is closed by us, no invalidation needed.
    MembershipGone,
    /// Read failed while still canonical: the pool must invalidate this
    /// exact connection so reconnect starts clean (never a readerless live
    /// connection).
    ConnFailed { stable_id: usize },
}

pub struct InboundDeps {
    pub conn: Connection,
    pub tun_writer: TunWriterHandle,
    pub tx_registry: EndpointTxRegistry,
    pub cancel: tokio_util::sync::CancellationToken,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub acl: AclEngine,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub metrics: AgentMetrics,
    /// Per-network auth bindings for inbound packet authorization. None in
    /// managed mode (ACL admission governs); enforced per frame network
    /// when present. MUST be identical for accepted and dialed connections.
    pub auth: Option<AuthCache>,
}

/// Network-ingress task ONLY: read DATAGRAMs continuously, decode, resolve
/// the exact membership/network, authenticate the exact network, reassemble,
/// anti-spoof, policy, NAT if required, and enqueue COMPLETE logical IP
/// packets to the TUN writer. Never awaits TUN write capacity; never calls
/// any TUN write operation.
///
/// The connection is already canonical (installed by the single install
/// path before this reader starts); this function never adopts.
pub async fn serve_tunnel_connection(deps: InboundDeps) -> ReaderExit {
    let InboundDeps {
        conn,
        tun_writer,
        tx_registry,
        cancel: generation_cancel,
        routes,
        runtime,
        acl,
        spoofs,
        bufs,
        metrics,
        auth,
    } = deps;
    let remote_id = conn.remote_id();
    let remote_hex = format!("{remote_id}");
    let stable_id = conn.stable_id();
    if !acl.allow_inbound_peer(&remote_hex) {
        tracing::warn!(%remote_id, "policy denied inbound peer");
        conn.close(1u32.into(), b"policy_deny");
        return ReaderExit::MembershipGone;
    }
    tracing::info!(%remote_id, "peer connected");
    metrics.active_conns_inc();
    // Membership resolution is lazy and per frame network: the first
    // datagram's bound network selects the (endpoint, network) membership;
    // the cached Arc is reused while frames carry the same network. Never
    // infer network identity from insertion order.
    let registry = routes.peer_registry().clone();
    // Truly unknown endpoints still close at admission (no membership in
    // any network); known endpoints resolve per frame network below.
    if registry.get(remote_id).is_none() && routes.lookup_endpoint(&remote_hex).is_none() {
        tracing::debug!(%remote_id, "unknown peer at admission; closing");
        conn.close(1u32.into(), b"no_route");
        metrics.active_conns_dec();
        return ReaderExit::MembershipGone;
    }
    let mut fast_state: Option<Arc<PeerMembershipState>> = None;
    let mut fast_net = Uuid::nil();
    let mut fast_epoch = 0u64;
    let mut route_gen = routes.version();
    // One deferred-fragment table per reader (per-task bounds; keys are
    // network+direction scoped).
    let mut frags = crate::frag_hold::DeferredFragments::new();

    let exit = loop {
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        // Await one datagram (cancellation-first), then opportunistically
        // drain already-ready datagrams up to a bounded budget.
        let first = tokio::select! {
            biased;
            _ = generation_cancel.cancelled() => break ReaderExit::GenerationDone,
            res = conn.read_datagram() => match res {
                Ok(dg) => dg,
                Err(e) => {
                    tracing::debug!(?e, "read_datagram closed");
                    break ReaderExit::ConnFailed { stable_id };
                }
            },
        };
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        metrics.datagram_inc("in");
        let mut batch: Vec<Bytes> = vec![first];
        // Opportunistic drain: ReadDatagram::poll serves buffered datagrams
        // synchronously first, so polling a fresh future once is a safe
        // non-waiting drain probe (dropping a Pending future only drops its
        // waker registration; no shared state is disturbed).
        for _ in 0..INBOUND_DRAIN_BUDGET {
            match conn.read_datagram().now_or_never() {
                Some(Ok(dg)) => {
                    metrics.datagram_inc("in");
                    batch.push(dg);
                }
                _ => break,
            }
        }
        if generation_cancel.is_cancelled() {
            break ReaderExit::GenerationDone;
        }
        // Routing generation check (one atomic load per batch): when
        // membership changed, drop the cached membership (per-packet
        // resolve below re-resolves or drops). If the endpoint holds NO
        // membership in any network anymore, the connection is dead:
        // close and exit instead of forwarding through stale state.
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
        // Deactivation without a generation change: drop the cached
        // membership; per-packet resolve re-resolves or, when nothing
        // remains, the generation check above exits.
        if let Some(fast) = &fast_state
            && fast.epoch.load(Ordering::Relaxed) != fast_epoch
        {
            tracing::info!(%remote_id, "membership deactivated; re-resolving");
            fast_state = None;
        }
        let self_ip = runtime.self_ip();
        for dg in batch {
            // Decode the frame header first (no allocation): it binds the
            // network this packet belongs to.
            let frame = match tunnet_common::packet::decode_frame(&dg) {
                Ok(f) => f,
                Err(_) => {
                    metrics.dropped_inc("malformed_frame");
                    metrics.reassembly_inc("malformed");
                    continue;
                }
            };
            let net = match &frame {
                tunnet_common::packet::Frame::Single { net, .. } => *net,
                tunnet_common::packet::Frame::Segment { net, .. } => *net,
            };
            // Resolve/switch the (endpoint, network) membership. A frame
            // claiming a network with no membership — or a network the
            // endpoint is not authenticated for — is dropped, never
            // evaluated under another network's state.
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
            // Membership revoked mid-batch: drop the cache; the next
            // packet re-resolves (or drops when nothing remains).
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
                &spoofs,
                &bufs,
                &metrics,
                &tun_writer,
                &tx_registry,
                self_ip,
                &mut frags,
            );
        }
    };
    metrics.active_conns_dec();
    tracing::info!(%remote_id, "peer disconnected");
    exit
}

/// Slow-path resolve of the exact (endpoint, network) membership:
/// registry first, else build from route info. Assigns the network's
/// stable firewall slot on created states, like routing rebuilds do.
/// Returns None when the endpoint has no such membership OR is not
/// authenticated for that network — the packet is then dropped, never
/// evaluated under another network's identity/policy.
fn resolve_membership(
    registry: &PeerRegistry,
    routes: &RoutingTable,
    remote: &iroh::EndpointId,
    remote_hex: &str,
    net: Uuid,
    auth: Option<&AuthCache>,
) -> Option<Arc<PeerMembershipState>> {
    // Authenticated membership binding: the endpoint must be authenticated
    // FOR THIS NETWORK, not merely known for any network.
    if let Some(auth) = auth
        && !auth.contains_network(remote_hex, net)
    {
        return None;
    }
    if let Some(fast) = registry.get_membership(*remote, net) {
        return Some(fast);
    }
    // First packet after a rebuild race: construct from route info.
    let info = routes.lookup_membership(remote_hex, net)?;
    // Recheck auth for race-constructed states (membership data and auth
    // cache update on different paths).
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

/// Handle one inbound DATAGRAM: reassemble → parse → antispoof → policy
/// (with unordered-fragment tolerance) → NAT → enqueue the COMPLETE
/// logical packet to the TUN writer. The frame (already decoded by the
/// caller, which used its bound network to resolve `fast`) and the
/// membership are passed in.
#[allow(clippy::too_many_arguments)]
fn handle_inbound_one(
    dg: &Bytes,
    frame: tunnet_common::packet::Frame<'_>,
    fast: &Arc<PeerMembershipState>,
    runtime: &PolicyRuntime,
    spoofs: &HashMap<Uuid, SpoofTracker>,
    pool_bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
    tun_writer: &TunWriterHandle,
    tx_registry: &EndpointTxRegistry,
    self_ip: std::net::Ipv4Addr,
    frags: &mut crate::frag_hold::DeferredFragments,
) {
    use tunnet_core::reassembly::InsertOut;
    let now = std::time::Instant::now();
    let logical: LogicalPacket = match frame {
        tunnet_common::packet::Frame::Single { payload: p, .. } => {
            // Zero-copy: retain the DATAGRAM's storage.
            let off = p.as_ptr() as usize - dg.as_ptr() as usize;
            let owned = dg.slice(off..off + p.len());
            match LogicalPacket::from_shared(owned) {
                Some(pkt) => {
                    metrics.reassembly_inc("single");
                    pkt
                }
                None => {
                    metrics.dropped_inc("malformed_transport");
                    return;
                }
            }
        }
        tunnet_common::packet::Frame::Segment {
            header: h, payload, ..
        } => {
            let off = payload.as_ptr() as usize - dg.as_ptr() as usize;
            let owned = dg.slice(off..off + payload.len());
            let mut table = fast.reassembly.lock();
            match table.insert(h, owned, now) {
                InsertOut::Complete(logical) => {
                    metrics.reassembly_inc("complete");
                    match LogicalPacket::from_vec(logical) {
                        Some(pkt) => pkt,
                        None => {
                            metrics.dropped_inc("malformed_transport");
                            return;
                        }
                    }
                }
                InsertOut::Pending => {
                    metrics.reassembly_inc("pending");
                    return;
                }
                InsertOut::Duplicate => {
                    metrics.reassembly_inc("duplicate");
                    return;
                }
                InsertOut::Dropped(reason) => {
                    metrics.reassembly_inc("dropped");
                    metrics.dropped_inc(match reason {
                        tunnet_core::reassembly::ReassemblyDrop::Conflict => "reasm_conflict",
                        tunnet_core::reassembly::ReassemblyDrop::OverBytes => "reasm_bytes",
                        tunnet_core::reassembly::ReassemblyDrop::TooManyEntries => "reasm_entries",
                        _ => "reasm_malformed",
                    });
                    return;
                }
            }
        }
    };
    metrics.overlay_rx_logical_inc();
    // Anti-spoof against the connection's stable identity (exact match).
    let Some(src) = logical.meta.src_v4 else {
        metrics.dropped_inc("ipv6_unsupported_in");
        return;
    };
    let ident: Arc<PeerIdentity> = fast.identity.read().clone();
    if !source_matches_peer(src, ident.ip) {
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
    // Snapshot the policy slot (guards are not Send; Arcs are). check()
    // loads the firewall snapshot after the ACL snapshot inside, matching
    // publish order — always current, no relink, no tear. Later IP
    // fragments without a first-fragment context hold briefly (unordered
    // transport); the first fragment's verdict releases or discards them.
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
                verdict,
                packet,
                fast,
                pool_bufs,
                metrics,
                tun_writer,
                tx_registry,
                self_ip,
            );
        }
        crate::frag_hold::FragOutcome::Held => {
            // Waiting for the first fragment; resolves on release/expiry
            // (both counted there). Not a drop.
        }
        crate::frag_hold::FragOutcome::Released(items) => {
            for (verdict, packet) in items {
                apply_inbound_verdict(
                    verdict,
                    packet,
                    fast,
                    pool_bufs,
                    metrics,
                    tun_writer,
                    tx_registry,
                    self_ip,
                );
            }
        }
    }
}

/// Apply one inbound policy verdict: NAT (allowed only) then stage to the
/// TUN writer, or count/reply the deny/reject.
#[allow(clippy::too_many_arguments)]
fn apply_inbound_verdict(
    verdict: PolicyVerdict,
    logical: LogicalPacket,
    fast: &Arc<PeerMembershipState>,
    pool_bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
    tun_writer: &TunWriterHandle,
    tx_registry: &EndpointTxRegistry,
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
            // Reject replies travel the overlay (framed, net-bound) via the
            // endpoint TX queue — never a side-channel TUN write.
            let reply = tunnet_common::packet::parse(logical.owner.as_bytes())
                .ok()
                .and_then(|p| tunnet_common::packet::synthesize_reject(&p));
            if let Some(reply) = reply.filter(|r| !r.is_empty()) {
                send_reject_framed(reply, fast, tx_registry, metrics);
            }
            return;
        }
    }
    if ssh_nat::needs_inbound_rewrite_with_meta(&logical.meta, self_ip) {
        if !logical.materialize(pool_bufs) {
            metrics.dropped_inc("nat_materialize");
            return;
        }
        // PacketMeta is Copy: snapshot before the mutable borrow.
        let meta = logical.meta;
        let Some(region) = packet_owner_bytes_mut(&mut logical, pool_bufs) else {
            metrics.dropped_inc("nat_materialize");
            return;
        };
        ssh_nat::rewrite_inbound_with_meta(region, &meta, self_ip);
    }
    let n = logical.len() as u64;
    let bytes = match logical.owner {
        tunnet_common::packet::PacketOwner::Shared(b) => b,
        tunnet_common::packet::PacketOwner::Pooled(b) => Bytes::from_owner(b),
    };
    // The ONLY TUN write path: complete packet into the writer queue.
    // Full drops explicitly at this boundary (never blocks the reader).
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
    use crate::actors::test_support::test_metrics;
    use crate::endpoint_tx::EndpointTxRegistry;
    use tunnet_core::ConnPool;

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
        // One endpoint in networks A and B: frames resolve to the EXACT
        // (endpoint, network) membership, and an endpoint authenticated
        // only for A cannot claim B — on ANY connection (accepted or
        // dialed: both paths build the same context with the same cache).
        let (table, ep, ep_hex) = two_net_routes();
        let registry = table.peer_registry().clone();
        let auth = AuthCache::new();
        auth.insert(ep_hex.clone(), NET_A);
        // Bound to A: A's membership (its own IP/identity).
        let a = resolve_membership(&registry, &table, &ep, &ep_hex, NET_A, Some(&auth))
            .expect("A resolves");
        assert_eq!(a.identity.read().network_id, NET_A);
        assert_eq!(a.identity.read().ip, std::net::Ipv4Addr::new(10, 7, 0, 5));
        // Bound to B without B-auth: rejected (no cross evaluation).
        assert!(
            resolve_membership(&registry, &table, &ep, &ep_hex, NET_B, Some(&auth)).is_none(),
            "endpoint authed only for A must not claim B"
        );
        // With B-auth: B's own membership, distinct object and IP.
        auth.insert(ep_hex.clone(), NET_B);
        let b = resolve_membership(&registry, &table, &ep, &ep_hex, NET_B, Some(&auth))
            .expect("B resolves once authed");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(b.identity.read().ip, std::net::Ipv4Addr::new(10, 7, 1, 5));
        // Unknown network: rejected even without an auth cache
        // (membership existence gates).
        assert!(
            resolve_membership(&registry, &table, &ep, &ep_hex, Uuid::from_u128(0xcc), None)
                .is_none()
        );
    }

    /// End-to-end loopback ping: machine A (10.7.0.1) sends a real ICMP echo
    /// to machine B (10.7.0.2) and back over loopback QUIC through the REAL
    /// outbound policy + endpoint TX worker, REAL datagram transport, and
    /// the REAL inbound handler (decode → membership → antispoof → policy →
    /// TUN writer queue, no TUN device). Times out (RED) exactly when user
    /// ping would: no frames arrive, or the inbound path drops everything.
    struct Loopback {
        conn_a: iroh::endpoint::Connection,
        conn_b: iroh::endpoint::Connection,
        reg_a: PeerRegistry,
        reg_b: PeerRegistry,
        rt_a: PolicyRuntime,
        rt_b: PolicyRuntime,
        pool_a: ConnPool,
        pool_b: ConnPool,
        id_a: iroh::EndpointId,
        id_b: iroh::EndpointId,
        hex_a: String,
        hex_b: String,
        net: Uuid,
    }

    async fn loopback_fixture() -> Loopback {
        use iroh::endpoint::presets::N0;
        use tunnet_common::TUNNEL_ALPN;
        let alpn = TUNNEL_ALPN;
        let ep_a = iroh::Endpoint::builder(N0)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let ep_b = iroh::Endpoint::builder(N0)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let id_a = ep_a.id();
        let id_b = ep_b.id();
        let addr_b = ep_b.addr();
        let ep_b2 = ep_b.clone();
        let accept_b = tokio::spawn(async move { ep_b2.accept().await.unwrap().await.unwrap() });
        let conn_a = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ep_a.connect(addr_b, alpn),
        )
        .await
        .expect("dial A->B must succeed")
        .unwrap();
        let conn_b = tokio::time::timeout(std::time::Duration::from_secs(10), accept_b)
            .await
            .expect("accept on B")
            .unwrap();

        let mk_self = |hex: String, ip: std::net::Ipv4Addr| tunnet_core::acl::SelfIdentity {
            endpoint_hex: hex,
            ip,
            tags: vec![],
            network: "net".into(),
        };
        let rt_a = PolicyRuntime::bootstrap(
            &Default::default(),
            &Default::default(),
            &mk_self(format!("{id_a}"), std::net::Ipv4Addr::new(10, 7, 0, 1)),
            true,
            false,
        );
        let rt_b = PolicyRuntime::bootstrap(
            &Default::default(),
            &Default::default(),
            &mk_self(format!("{id_b}"), std::net::Ipv4Addr::new(10, 7, 0, 2)),
            true,
            false,
        );
        let net = Uuid::from_u128(0xE2E);
        let reg_a = PeerRegistry::new();
        let reg_b = PeerRegistry::new();
        // A knows B (10.7.0.2), B knows A (10.7.0.1), same network.
        reg_a.ensure_membership(Arc::new(PeerIdentity {
            endpoint: id_b,
            endpoint_hex: format!("{id_b}"),
            hostname: "b".into(),
            ip: std::net::Ipv4Addr::new(10, 7, 0, 2),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }));
        reg_b.ensure_membership(Arc::new(PeerIdentity {
            endpoint: id_a,
            endpoint_hex: format!("{id_a}"),
            hostname: "a".into(),
            ip: std::net::Ipv4Addr::new(10, 7, 0, 1),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }));
        reg_a.relink_policy(&rt_a);
        reg_b.relink_policy(&rt_b);
        let pool_a = ConnPool::new(ep_a, alpn);
        let pool_b = ConnPool::new(ep_b, alpn);
        // Link pools to registries (slow path, as bootstrap does) so the
        // canonical install mirrors the live conn into the transport.
        pool_a.set_peer_registry(Arc::new(reg_a.clone()));
        pool_b.set_peer_registry(Arc::new(reg_b.clone()));
        // Install the live conns as canonical (slow path, as the pool does).
        use tunnet_core::InstallOutcome;
        assert!(matches!(
            pool_a.install_canonical(id_b, conn_a.clone(), true).await,
            InstallOutcome::Canonical(_)
        ));
        assert!(matches!(
            pool_b.install_canonical(id_a, conn_b.clone(), false).await,
            InstallOutcome::Canonical(_)
        ));
        Loopback {
            conn_a,
            conn_b,
            reg_a,
            reg_b,
            rt_a,
            rt_b,
            pool_a,
            pool_b,
            id_a,
            id_b,
            hex_a: format!("{id_a}"),
            hex_b: format!("{id_b}"),
            net,
        }
    }

    fn icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src, dst, 64).icmpv4_echo_request(7, 1);
        let mut o = Vec::new();
        b.write(&mut o, &[0xABu8; 32]).unwrap();
        o
    }

    /// One directed leg: outbound policy + endpoint TX worker on the sender;
    /// real QUIC datagrams; decode + membership + full inbound handler on
    /// the receiver, staged into a TUN writer channel. Returns the payload.
    struct Leg<'a> {
        tx_reg: &'a PeerRegistry,
        tx_rt: &'a PolicyRuntime,
        tx_pool: &'a ConnPool,
        tx_peer: iroh::EndpointId,
        tx_hex: &'a str,
        tx_host: &'a str,
        rx_conn: &'a iroh::endpoint::Connection,
        rx_reg: &'a PeerRegistry,
        rx_rt: &'a PolicyRuntime,
        rx_self_ip: std::net::Ipv4Addr,
        net: Uuid,
        raw: Vec<u8>,
    }

    async fn directed_leg(leg: Leg<'_>) -> Vec<u8> {
        use tokio::sync::mpsc;
        use tunnet_common::packet::PacketPool;
        let Leg {
            tx_reg,
            tx_rt,
            tx_pool,
            tx_peer,
            tx_hex,
            tx_host,
            rx_conn,
            rx_reg,
            rx_rt,
            rx_self_ip,
            net,
            raw,
        } = leg;
        // Outbound policy through the sender's membership slot.
        let member = tx_reg
            .get_membership(tx_peer, net)
            .expect("sender membership");
        let pkt = LogicalPacket::from_vec(raw.clone()).expect("valid test packet");
        let slot = member.policy.load();
        assert_eq!(
            tx_rt.check(
                &pkt.meta,
                Direction::Outbound,
                tx_hex,
                &[],
                Some(tx_host),
                Some(net),
                &slot,
                &slot.counters
            ),
            PolicyVerdict::Allow,
            "outbound policy must allow the echo"
        );
        // Endpoint TX worker (real framing over the real connection).
        let bufs = PacketPool::new(8);
        let metrics = test_metrics();
        let tx_registry = EndpointTxRegistry::new(
            tokio_util::sync::CancellationToken::new(),
            tx_pool.clone(),
            Arc::new(tx_reg.clone()),
            metrics.clone(),
            bufs.clone(),
            tunnet_core::CloudRelayMeter::new(),
        );
        crate::endpoint_tx::enqueue_packet(&tx_registry, &member, pkt);
        // Receiver: real datagrams until the full logical packet stages
        // into the writer channel.
        let (wtx, mut wrx) = mpsc::channel::<Bytes>(64);
        let writer = TunWriterHandle::new(wtx, metrics.clone());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // Pump the receiver until a complete packet lands in the writer.
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "receiver got nothing within 10s (ping would time out)"
            );
            let dg = tokio::time::timeout_at(deadline.into(), rx_conn.read_datagram())
                .await
                .expect("frame must arrive")
                .unwrap();
            let frame = tunnet_common::packet::decode_frame(&dg).expect("must decode");
            let got_net = match &frame {
                tunnet_common::packet::Frame::Single { net, .. } => *net,
                tunnet_common::packet::Frame::Segment { net, .. } => *net,
            };
            assert_eq!(got_net, net, "frame bound to the membership network");
            let rx_member = rx_reg
                .get_membership(rx_conn.remote_id(), got_net)
                .expect("receiver must resolve the membership");
            assert_eq!(rx_member.identity.read().network_id, net);
            let mut frags = crate::frag_hold::DeferredFragments::new();
            handle_inbound_one(
                &dg,
                frame,
                &rx_member,
                rx_rt,
                &std::collections::HashMap::new(),
                &bufs,
                &metrics,
                &writer,
                &tx_registry,
                rx_self_ip,
                &mut frags,
            );
            if let Ok(staged) = wrx.try_recv() {
                assert_eq!(&staged[..], &raw[..]);
                break;
            }
            // Segmented packet: keep draining until completion.
        }
        // The sender worker exits on registry drop; stop it explicitly.
        tx_registry.shutdown().await;
        raw
    }

    #[tokio::test]
    async fn loopback_ping_round_trip() {
        let fx = loopback_fixture().await;
        let raw_ab = icmp_echo([10, 7, 0, 1], [10, 7, 0, 2]);
        // Verify the staged payload equals what was sent (single-frame
        // path stages the exact bytes).
        let _ = directed_leg(Leg {
            tx_reg: &fx.reg_a,
            tx_rt: &fx.rt_a,
            tx_pool: &fx.pool_a,
            tx_peer: fx.id_b,
            tx_hex: &fx.hex_b,
            tx_host: "b",
            rx_conn: &fx.conn_b,
            rx_reg: &fx.reg_b,
            rx_rt: &fx.rt_b,
            rx_self_ip: std::net::Ipv4Addr::new(10, 7, 0, 2),
            net: fx.net,
            raw: raw_ab,
        })
        .await;
        // Reply direction (ping needs both ways).
        let raw_ba = icmp_echo([10, 7, 0, 2], [10, 7, 0, 1]);
        let _ = directed_leg(Leg {
            tx_reg: &fx.reg_b,
            tx_rt: &fx.rt_b,
            tx_pool: &fx.pool_b,
            tx_peer: fx.id_a,
            tx_hex: &fx.hex_a,
            tx_host: "a",
            rx_conn: &fx.conn_a,
            rx_reg: &fx.reg_a,
            rx_rt: &fx.rt_a,
            rx_self_ip: std::net::Ipv4Addr::new(10, 7, 0, 1),
            net: fx.net,
            raw: raw_ba,
        })
        .await;
    }

    fn jumbo_udp(src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src, dst, 64).udp(40000, 443);
        let mut o = Vec::new();
        b.write(&mut o, &vec![0xABu8; payload]).unwrap();
        o
    }

    #[tokio::test]
    async fn loopback_jumbo_segments_and_reassembles() {
        // Explicitly configured jumbo MTUs still segment/reassemble: a
        // 2700-byte logical packet cannot fit one DATAGRAM on loopback, so
        // it must arrive complete via segments with identical bytes.
        let fx = loopback_fixture().await;
        let raw = jumbo_udp([10, 7, 0, 1], [10, 7, 0, 2], 2700 - 28);
        assert_eq!(raw.len(), 2700);
        let staged = directed_leg(Leg {
            tx_reg: &fx.reg_a,
            tx_rt: &fx.rt_a,
            tx_pool: &fx.pool_a,
            tx_peer: fx.id_b,
            tx_hex: &fx.hex_b,
            tx_host: "b",
            rx_conn: &fx.conn_b,
            rx_reg: &fx.reg_b,
            rx_rt: &fx.rt_b,
            rx_self_ip: std::net::Ipv4Addr::new(10, 7, 0, 2),
            net: fx.net,
            raw: raw.clone(),
        })
        .await;
        assert_eq!(staged, raw);
    }

    #[tokio::test]
    async fn loopback_congestion_waits_with_tiny_buffer() {
        // A 4 KiB QUIC DATAGRAM buffer under flood: the endpoint worker
        // must WAIT for buffer space, never displace old queued DATAGRAMs.
        // No packet may disappear because of transport congestion.
        use tunnet_common::packet::PacketPool;
        use tunnet_core::transport_profile::TunnetTransportProfile;
        let alpn = tunnet_common::TUNNEL_ALPN;
        let profile = TunnetTransportProfile::default().with_send_buffer(4096);
        let ep_a = profile
            .apply(iroh::Endpoint::builder(iroh::endpoint::presets::N0))
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let ep_b = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let id_a = ep_a.id();
        let id_b = ep_b.id();
        let addr_b = ep_b.addr();
        let ep_b2 = ep_b.clone();
        let accept_b = tokio::spawn(async move { ep_b2.accept().await.unwrap().await.unwrap() });
        let conn_a = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ep_a.connect(addr_b, alpn),
        )
        .await
        .expect("dial must succeed")
        .unwrap();
        let conn_b = tokio::time::timeout(std::time::Duration::from_secs(10), accept_b)
            .await
            .expect("accept")
            .unwrap();

        let net = Uuid::from_u128(0xE4E);
        let reg_a = PeerRegistry::new();
        let reg_b = PeerRegistry::new();
        let member_a = reg_a.ensure_membership(Arc::new(PeerIdentity {
            endpoint: id_b,
            endpoint_hex: format!("{id_b}"),
            hostname: "b".into(),
            ip: std::net::Ipv4Addr::new(10, 7, 0, 2),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }));
        reg_b.ensure_membership(Arc::new(PeerIdentity {
            endpoint: id_a,
            endpoint_hex: format!("{id_a}"),
            hostname: "a".into(),
            ip: std::net::Ipv4Addr::new(10, 7, 0, 1),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }));
        let pool_a = ConnPool::new(ep_a, alpn);
        pool_a.set_peer_registry(Arc::new(reg_a.clone()));
        use tunnet_core::InstallOutcome;
        assert!(matches!(
            pool_a.install_canonical(id_b, conn_a.clone(), true).await,
            InstallOutcome::Canonical(_)
        ));

        // Flood: 120 back-to-back 1200-byte packets into a 4 KiB pipe.
        let bufs = PacketPool::new(8);
        let metrics = test_metrics();
        let tx_registry = EndpointTxRegistry::new(
            tokio_util::sync::CancellationToken::new(),
            pool_a.clone(),
            Arc::new(reg_a.clone()),
            metrics.clone(),
            bufs.clone(),
            tunnet_core::CloudRelayMeter::new(),
        );
        const N: usize = 120;
        let raws: Vec<Vec<u8>> = (0..N)
            .map(|i| jumbo_udp([10, 7, 0, 1], [10, 7, 0, 2], 1200 - 28 + (i % 7)))
            .collect();
        for raw in &raws {
            let pkt = LogicalPacket::from_vec(raw.clone()).expect("valid");
            crate::endpoint_tx::enqueue_packet(&tx_registry, &member_a, pkt);
        }
        // Drain the receiver until every packet stages complete.
        let (wtx, mut wrx) = tokio::sync::mpsc::channel::<Bytes>(256);
        let writer = TunWriterHandle::new(wtx, metrics.clone());
        let rx_rt = PolicyRuntime::bootstrap(
            &Default::default(),
            &Default::default(),
            &tunnet_core::acl::SelfIdentity {
                endpoint_hex: format!("{id_b}"),
                ip: std::net::Ipv4Addr::new(10, 7, 0, 2),
                tags: vec![],
                network: "net".into(),
            },
            true,
            false,
        );
        let mut staged = 0usize;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while staged < N {
            assert!(
                std::time::Instant::now() < deadline,
                "lost packets under congestion: staged {staged}/{N}"
            );
            let dg = tokio::time::timeout_at(deadline.into(), conn_b.read_datagram())
                .await
                .expect("datagrams must keep arriving")
                .unwrap();
            let frame = tunnet_common::packet::decode_frame(&dg).expect("must decode");
            let rx_member = reg_b
                .get_membership(conn_b.remote_id(), net)
                .expect("receiver membership");
            let mut frags = crate::frag_hold::DeferredFragments::new();
            handle_inbound_one(
                &dg,
                frame,
                &rx_member,
                &rx_rt,
                &std::collections::HashMap::new(),
                &bufs,
                &metrics,
                &writer,
                &tx_registry,
                std::net::Ipv4Addr::new(10, 7, 0, 2),
                &mut frags,
            );
            while wrx.try_recv().is_ok() {
                staged += 1;
            }
        }
        assert_eq!(staged, N, "every flooded packet must arrive complete");
        tx_registry.shutdown().await;
    }

    #[tokio::test]
    async fn canonical_lifecycle_invalidate() {
        // Canonical replacement leaves one reader slot; the slot reports
        // its stable id; unexpected death of the CURRENT connection
        // invalidates it (transport cleared, memberships NOT deactivated);
        // a stale id invalidates nothing; same-connection install is
        // idempotent.
        use tunnet_core::InstallOutcome;
        let fx = loopback_fixture().await;
        let stable = fx.conn_a.stable_id();
        // Same connection installs idempotently (no second reader owed).
        assert!(matches!(
            fx.pool_a
                .install_canonical(fx.id_b, fx.conn_a.clone(), true)
                .await,
            InstallOutcome::Canonical(_)
        ));
        assert_eq!(fx.pool_a.canonical_stable_id(fx.id_b).await, Some(stable));
        assert!(fx.pool_a.has_live(fx.id_b));
        // Exactly one path watcher per canonical connection: the fixture
        // install plus this re-install must not spawn a second one.
        assert_eq!(
            fx.pool_a.on_demand_stats().path_watchers_spawned,
            1,
            "one watcher per canonical connection"
        );
        let member = fx.reg_a.get_membership(fx.id_b, fx.net).unwrap();
        let epoch0 = member.epoch.load(std::sync::atomic::Ordering::Relaxed);
        // Stale id: nothing happens.
        assert!(
            !fx.pool_a
                .invalidate_canonical(fx.id_b, stable.wrapping_add(1))
                .await
        );
        assert!(fx.pool_a.has_live(fx.id_b));
        // Current connection dies unexpectedly: invalidated, transport
        // cleared, memberships untouched (worker holds packets + redials).
        assert!(fx.pool_a.invalidate_canonical(fx.id_b, stable).await);
        assert!(!fx.pool_a.has_live(fx.id_b));
        let transport = fx.reg_a.get_transport(fx.id_b).unwrap();
        assert!(transport.live_conn().is_none());
        assert_eq!(
            member.epoch.load(std::sync::atomic::Ordering::Relaxed),
            epoch0,
            "invalidation must not deactivate memberships"
        );
        assert!(fx.reg_a.get_membership(fx.id_b, fx.net).is_some());
    }
}
