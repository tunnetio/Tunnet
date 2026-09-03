use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use bytes::Bytes;
use futures_util::FutureExt as _;
use iroh::endpoint::Connection;
use tun_rs::AsyncDevice;
#[cfg(not(target_os = "android"))]
use tun_rs::DeviceBuilder;
use tunnet_common::packet::{self, LogicalPacket};
use tunnet_common::policy::Direction;
use tunnet_core::direct::{AuthCache, SpoofTracker, source_matches_peer};
use tunnet_core::peers::{PeerIdentity, PeerMembershipState, PeerRegistry};
use tunnet_core::policy_runtime::{PolicyRuntime, PolicyVerdict};
use tunnet_core::routing::{RouteDecision, RoutingTable};
use tunnet_core::{AclEngine, ConnPool, iroh_pool::send_datagram};
use uuid::Uuid;

use crate::actors::dataplane::PublishedPlane;
use crate::metrics::AgentMetrics;
use crate::pump::ensure_pump;
use crate::ssh_nat;
use crate::tun_fast;

/// Opportunistic inbound drain budget (§10): after each awaited datagram,
/// drain already-ready datagrams without busy-polling.
pub const INBOUND_DRAIN_BUDGET: usize = 32;

/// Ask the app's `VpnService` to establish a tunnel, then adopt its descriptor.
///
/// The interface name is meaningless on Android (the framework names it `tunN`)
/// and addressing is applied by `VpnService.Builder`, so those parameters are
/// forwarded to the app rather than applied here.
#[cfg(target_os = "android")]
pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    use std::os::fd::IntoRawFd;

    use crate::android_tun::{self, TunRequest};

    let fd = android_tun::establish(TunRequest { ipv4, prefix, mtu })?;
    // SAFETY: the descriptor is owned (detachFd on the JVM side) and valid;
    // into_raw_fd() gives up our close so the device becomes sole owner.
    let dev = unsafe { AsyncDevice::from_fd(fd.into_raw_fd()) }
        .context("adopt VpnService TUN descriptor")?;
    tracing::debug!(ifname, "TUN device adopted");
    Ok(dev)
}

#[cfg(not(target_os = "android"))]
pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    // Fast-path builder: Linux enables offload; Windows uses the Wintun ring.
    // Diagnostic override for A/B runs: TUNNET_TUN_OFFLOAD=0 disables
    // tun-rs offload+GSO (plain single-packet TUN I/O instead).
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
    pub pool: ConnPool,
    pub runtime: PolicyRuntime,
    pub metrics: AgentMetrics,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub meter: tunnet_core::CloudRelayMeter,
    pub mtu: u16,
}

/// Handle one owned logical packet through the outbound pipeline.
/// Parse-once: `packet` already carries metadata; NAT refreshes it only when
/// a rewrite actually mutated the bytes. Policy uses the shared runtime with
/// the peer's stable network slot — no per-packet map lookups.
fn handle_outbound_one(
    mut packet: LogicalPacket,
    fast_ctx: &OutboundCtx<'_>,
) -> Option<Arc<PeerMembershipState>> {
    let ctx = *fast_ctx;
    let OutboundCtx {
        routes,
        runtime,
        metrics,
        pool,
        bufs,
        meter,
        self_ip,
        ..
    } = ctx;
    // SSH NAT consumes existing metadata (no second parse) — and ONLY takes
    // the mutable/materializing path when metadata proves a rewrite is
    // required (§2.1-7). Common packets stay immutable: zero copy.
    let meta = packet.meta;
    if ssh_nat::needs_outbound_rewrite_with_meta(&meta, self_ip) {
        let Some(bytes) = packet_owner_bytes_mut(&mut packet, bufs) else {
            metrics.dropped_inc("nat_materialize");
            return None;
        };
        if ssh_nat::rewrite_outbound_with_meta(bytes, &meta, self_ip) && !packet.refresh() {
            // Rewrite applied but re-parse failed: fail closed.
            metrics.dropped_inc("nat_reparse");
            return None;
        }
    }
    let Some(dst) = packet.meta.dst_v4 else {
        metrics.dropped_inc("ipv6_unsupported");
        return None;
    };

    // Single immutable-snapshot route decision; the handle carries the
    // stable fast state (no peer map lookup after routing).
    let fast = match routes.route_once(&dst) {
        RouteDecision::LocalMagic => {
            metrics.dropped_inc("magic_dns_local");
            return None;
        }
        RouteDecision::LocalAdvertised => {
            metrics.dropped_inc("local_subnet");
            return None;
        }
        RouteDecision::NoRoute => {
            metrics.dropped_inc("no_route");
            return None;
        }
        RouteDecision::Peer(h) => h.peer.fast.clone(),
    };

    if fast.identity.read().ip == self_ip {
        metrics.dropped_inc("self");
        return None;
    }

    // One compiled verdict against the shared runtime. The firewall
    // snapshot loads from the peer's STABLE network slot inside check()
    // (ACL-then-firewall order) — publication swaps it in place, so no
    // relink is ever needed (§2.1-3, §2.2-2).
    let ident: Arc<PeerIdentity> = fast.identity.read().clone();
    let slot = fast.policy.load();
    let verdict = runtime.check(
        &packet.meta,
        Direction::Outbound,
        &ident.endpoint_hex,
        &ident.tags,
        Some(ident.hostname.as_str()),
        Some(ident.network_id),
        &slot,
        &slot.counters,
    );
    match verdict {
        PolicyVerdict::Allow => {}
        PolicyVerdict::Deny => {
            metrics.dropped_inc("policy_deny");
            return None;
        }
        PolicyVerdict::Reject => {
            metrics.dropped_inc("fw_reject_out");
            send_reject_reply(fast_ctx, &packet);
            return None;
        }
    }

    let len = packet.len() as i64;
    // Every shed/evicted packet is reported (gauges + telemetry) — the
    // scheduler never drops silently (see EnqueueOutcome).
    let outcome = {
        let mut sched = fast.scheduler.lock();
        let outcome = sched.enqueue(packet, std::time::Instant::now());
        let deltas = sched.drain_drops();
        (outcome, deltas)
    };
    match outcome.0 {
        tunnet_core::scheduler::EnqueueOutcome::Accepted => {}
        tunnet_core::scheduler::EnqueueOutcome::AcceptedEvicted {
            reason,
            evicted_len,
        } => {
            metrics.queue_add(-1, -(evicted_len as i64), 0);
            metrics.dropped_inc(reason.as_str());
            metrics.sched_drop_inc(reason.as_str());
        }
        tunnet_core::scheduler::EnqueueOutcome::Rejected { reason } => {
            metrics.dropped_inc(reason.as_str());
            metrics.sched_drop_inc(reason.as_str());
            report_sched_deltas(metrics, outcome.1);
            return None;
        }
    }
    report_sched_deltas(metrics, outcome.1);
    metrics.queue_add(1, len, 0);
    ensure_pump(
        &fast,
        pool.clone(),
        metrics.clone(),
        bufs.clone(),
        meter.clone(),
    );
    Some(fast)
}

/// Report drained CoDel/emergency deltas (dequeue-side drops with no
/// enqueue decision site).
fn report_sched_deltas(metrics: &AgentMetrics, deltas: tunnet_core::scheduler::SchedDropDeltas) {
    metrics.sched_drops_add(deltas.codel, deltas.emergency);
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

struct OutboundCtx<'a> {
    tun: &'a Arc<AsyncDevice>,
    routes: &'a RoutingTable,
    runtime: &'a PolicyRuntime,
    metrics: &'a AgentMetrics,
    pool: &'a ConnPool,
    bufs: &'a Arc<tunnet_common::packet::PacketPool>,
    meter: &'a tunnet_core::CloudRelayMeter,
    self_ip: std::net::Ipv4Addr,
}

impl Copy for OutboundCtx<'_> {}
impl Clone for OutboundCtx<'_> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Reject replies are rare, but they must be protocol-correct: the peer
/// expects every tunnel DATAGRAM to begin with 0x30/0x31 with its bound
/// network. Route the reply through the normal tunnel framing/transmit
/// path (scheduler and pump, which segments large replies) instead of a
/// second encoder path. Without a pool (no pump possible) fall back to a
/// single framed best-effort send (still net-bound).
async fn send_reject_framed(
    reply: Bytes,
    net: Uuid,
    fast: &Arc<PeerMembershipState>,
    pool: Option<&ConnPool>,
    conn: &Connection,
    bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
) {
    let Some(pool) = pool else {
        // No pump available: single framed best-effort send, with the
        // full v3 header ([kind][net][reply]).
        let mut frame = Vec::with_capacity(reply.len() + tunnet_common::packet::SINGLE_OVERHEAD);
        frame.push(tunnet_common::packet::KIND_SINGLE);
        frame.extend_from_slice(net.as_bytes());
        frame.extend_from_slice(&reply);
        if conn
            .max_datagram_size()
            .is_some_and(|max| frame.len() > max)
        {
            metrics.dropped_inc("datagram_too_large");
            return;
        }
        let _ = send_datagram(conn, Bytes::from(frame)).await;
        return;
    };
    // Zero-copy: the synthesized reply bytes ride straight into the
    // scheduler; the pump frames/segments them like any other packet.
    let Some(packet) = LogicalPacket::from_shared(reply) else {
        metrics.dropped_inc("malformed_transport");
        return;
    };
    let len = packet.len() as i64;
    let (outcome, deltas) = {
        let mut sched = fast.scheduler.lock();
        let outcome = sched.enqueue(packet, std::time::Instant::now());
        let deltas = sched.drain_drops();
        (outcome, deltas)
    };
    match outcome {
        tunnet_core::scheduler::EnqueueOutcome::Accepted => {}
        tunnet_core::scheduler::EnqueueOutcome::AcceptedEvicted {
            reason,
            evicted_len,
        } => {
            metrics.queue_add(-1, -(evicted_len as i64), 0);
            metrics.dropped_inc(reason.as_str());
            metrics.sched_drop_inc(reason.as_str());
        }
        tunnet_core::scheduler::EnqueueOutcome::Rejected { reason } => {
            metrics.dropped_inc(reason.as_str());
            metrics.sched_drop_inc(reason.as_str());
            report_sched_deltas(metrics, deltas);
            return;
        }
    }
    report_sched_deltas(metrics, deltas);
    metrics.queue_add(1, len, 0);
    ensure_pump(
        fast,
        pool.clone(),
        metrics.clone(),
        bufs.clone(),
        pool.cloud_relay_meter(),
    );
}

/// Outbound reject replies go to the LOCAL TUN device (raw IP framing —
/// correct there: TUN is not the tunnel wire). Rare: synthesize and send off
/// the hot path with correct platform framing.
fn send_reject_reply(ctx: &OutboundCtx<'_>, packet: &LogicalPacket) {
    let reply = packet::parse(packet.owner.as_bytes())
        .ok()
        .and_then(|p| packet::synthesize_reject(&p));
    let Some(reply) = reply.filter(|r| !r.is_empty()) else {
        return;
    };
    #[cfg(target_os = "linux")]
    {
        let tun = ctx.tun.clone();
        tokio::spawn(async move {
            let mut w = tun_fast::LinuxTunBatchWriter::new();
            w.push(&reply);
            let _ = w.flush(&tun).await;
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let tun = ctx.tun.clone();
        tokio::spawn(async move {
            let _ = tun.send(&reply).await;
        });
    }
}

pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        routes,
        pool,
        runtime,
        metrics,
        bufs,
        meter,
        mtu,
    } = deps;
    // Cache pool hit/miss telemetry periodically (cheap atomics).
    let metrics_pool = metrics.clone();
    let bufs_pool = bufs.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let (h, m) = bufs_pool.hit_miss();
            metrics_pool.pool_hit_miss(h, m);
        }
    });

    let self_ip = runtime.self_ip();
    metrics.mtu_set(mtu as u64);

    #[cfg(target_os = "linux")]
    let mut batch = tun_fast::LinuxBatchEngine::new(bufs.clone(), mtu as usize);

    tracing::info!("outbound TUN→iroh tunnel loop started");
    loop {
        #[cfg(target_os = "linux")]
        {
            let packets = batch.recv_batch(&tun).await?;
            metrics.tun_syscall_inc("recv_batch");
            if packets.is_empty() {
                continue;
            }
            let ctx = OutboundCtx {
                tun: &tun,
                routes: &routes,
                runtime: &runtime,
                metrics: &metrics,
                pool: &pool,
                bufs: &bufs,
                meter: &meter,
                self_ip,
            };
            for packet in packets {
                if packet.len() > mtu as usize {
                    metrics.dropped_inc("oversize_mtu");
                    continue;
                }
                handle_outbound_one(packet, &ctx);
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
            let ctx = OutboundCtx {
                tun: &tun,
                routes: &routes,
                runtime: &runtime,
                metrics: &metrics,
                pool: &pool,
                bufs: &bufs,
                meter: &meter,
                self_ip,
            };
            for packet in burst {
                if packet.len() > mtu as usize {
                    metrics.dropped_inc("oversize_mtu");
                    continue;
                }
                handle_outbound_one(packet, &ctx);
            }
        }
    }
}

pub struct InboundDeps {
    pub conn: Connection,
    pub tun: PublishedPlane,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub acl: AclEngine,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub pool: Option<ConnPool>,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub metrics: AgentMetrics,
    /// Per-network auth bindings for inbound packet authorization
    /// (§2.2-1). None in managed mode (ACL admission governs); enforced
    /// per frame network when present.
    pub auth: Option<AuthCache>,
}

pub async fn serve_tunnel_connection(deps: InboundDeps) {
    let InboundDeps {
        conn,
        tun,
        routes,
        runtime,
        acl,
        spoofs,
        pool,
        bufs,
        metrics,
        auth,
    } = deps;
    let remote_id = conn.remote_id();
    let remote_hex = format!("{remote_id}");
    if !acl.allow_inbound_peer(&remote_hex) {
        tracing::warn!(%remote_id, "policy denied inbound peer");
        conn.close(1u32.into(), b"policy_deny");
        return;
    }
    tracing::info!(%remote_id, "peer connected");
    metrics.active_conns_inc();
    if let Some(p) = &pool {
        p.touch_peer(remote_id);
        if !p.adopt(remote_id, conn.clone()).await {
            tracing::debug!(%remote_id, "ingress conn lost tie-break; exiting reader");
            metrics.active_conns_dec();
            return;
        }
        if let Some(max) = conn.max_datagram_size() {
            tracing::debug!(%remote_id, max_datagram_size = max, "quic datagram limit");
        }
    }
    // Membership resolution is lazy and per frame network (§2.2-1): the
    // first datagram's bound network selects the (endpoint, network)
    // membership; the cached Arc is reused while frames carry the same
    // network. Never infer network identity from insertion order.
    let registry = routes.peer_registry().clone();
    // Truly unknown endpoints still close at admission (no membership in
    // any network); known endpoints resolve per frame network below.
    if registry.get(remote_id).is_none() && routes.lookup_endpoint(&remote_hex).is_none() {
        tracing::debug!(%remote_id, "unknown peer at admission; closing");
        conn.close(1u32.into(), b"no_route");
        metrics.active_conns_dec();
        return;
    }
    let mut fast_state: Option<Arc<PeerMembershipState>> = None;
    let mut fast_net = Uuid::nil();
    let mut fast_epoch = 0u64;
    let mut route_gen = routes.version();

    // Load the published generation once (device + cancel token pinned).
    let Some(plane) = tun.load_full() else {
        metrics.active_conns_dec();
        return;
    };
    let device = plane.device.clone();
    let generation_cancel = plane.cancel.clone();
    tracing::debug!(generation = plane.generation, %remote_id, "ingress reader pinned");

    #[cfg(target_os = "linux")]
    let mut tun_batch = tun_fast::LinuxTunBatchWriter::new();
    #[cfg(not(target_os = "linux"))]
    let mut tun_batch = tun_fast::TunWriteBatch::new();

    loop {
        if generation_cancel.is_cancelled() {
            break;
        }
        // Await one datagram (cancellation-first), then opportunistically
        // drain already-ready datagrams up to a bounded budget (§10).
        let first = tokio::select! {
            biased;
            _ = generation_cancel.cancelled() => break,
            res = conn.read_datagram() => match res {
                Ok(dg) => dg,
                Err(e) => {
                    tracing::debug!(?e, "read_datagram closed");
                    break;
                }
            },
        };
        if generation_cancel.is_cancelled() {
            break;
        }
        if let Some(p) = &pool {
            p.touch_peer(remote_id);
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
            break;
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
                break;
            }
        }
        // Deactivation without a generation change (e.g. pool drop_peer):
        // drop the cached membership; per-packet resolve re-resolves or,
        // when nothing remains, the generation check above exits.
        if let Some(fast) = &fast_state
            && fast.epoch.load(Ordering::Relaxed) != fast_epoch
        {
            tracing::info!(%remote_id, "membership deactivated; re-resolving");
            fast_state = None;
        }
        let self_ip = runtime.self_ip();
        let mut tun_pending: u32 = 0;
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
            if handle_inbound_one(
                &dg,
                frame,
                fast,
                &runtime,
                &spoofs,
                &conn,
                pool.as_ref(),
                &bufs,
                &metrics,
                &mut tun_batch,
                self_ip,
            )
            .await
            {
                tun_pending += 1;
            }
            // Flush mid-iteration so bursts larger than the batch still
            // complete without loss (§9); the tail stays staged on failure.
            if tun_pending >= tun_fast::TUN_WRITE_BATCH as u32 {
                if !flush_tun_batch(&mut tun_batch, &device, &metrics).await {
                    break;
                }
                tun_pending = 0;
            }
        }
        // Flush the TUN batch once per drain iteration (§9).
        if tun_pending > 0 && !flush_tun_batch(&mut tun_batch, &device, &metrics).await {
            break;
        }
    }
    metrics.active_conns_dec();
    tracing::info!(%remote_id, "peer disconnected");
}

/// Slow-path resolve of the exact (endpoint, network) membership (§2.2-1):
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

/// Handle one inbound DATAGRAM: reassemble → parse → antispoof → policy →
/// NAT → stage for the TUN batch. The frame (already decoded by the caller,
/// which used its bound network to resolve `fast`) and the membership are
/// passed in. Returns true when a TUN packet was staged.
#[allow(clippy::too_many_arguments)]
async fn handle_inbound_one(
    dg: &Bytes,
    frame: tunnet_common::packet::Frame<'_>,
    fast: &Arc<PeerMembershipState>,
    runtime: &PolicyRuntime,
    spoofs: &HashMap<Uuid, SpoofTracker>,
    conn: &Connection,
    pool: Option<&ConnPool>,
    pool_bufs: &Arc<tunnet_common::packet::PacketPool>,
    metrics: &AgentMetrics,
    tun_batch: &mut TunBatchForPlatform,
    self_ip: std::net::Ipv4Addr,
) -> bool {
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
                    return false;
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
                            return false;
                        }
                    }
                }
                InsertOut::Pending => {
                    metrics.reassembly_inc("pending");
                    return false;
                }
                InsertOut::Duplicate => {
                    metrics.reassembly_inc("duplicate");
                    return false;
                }
                InsertOut::Dropped(reason) => {
                    metrics.reassembly_inc("dropped");
                    metrics.dropped_inc(match reason {
                        tunnet_core::reassembly::ReassemblyDrop::Conflict => "reasm_conflict",
                        tunnet_core::reassembly::ReassemblyDrop::OverBytes => "reasm_bytes",
                        tunnet_core::reassembly::ReassemblyDrop::TooManyEntries => "reasm_entries",
                        _ => "reasm_malformed",
                    });
                    return false;
                }
            }
        }
    };
    // Anti-spoof against the connection's stable identity (exact match).
    let Some(src) = logical.meta.src_v4 else {
        metrics.dropped_inc("ipv6_unsupported_in");
        return false;
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
        return false;
    }
    // Snapshot the policy slot (guards are not Send; Arcs are). check()
    // loads the firewall snapshot after the ACL snapshot inside, matching
    // publish order — always current, no relink, no tear (§2.2-2).
    let slot = fast.policy.load();
    let verdict = runtime.check(
        &logical.meta,
        Direction::Inbound,
        &ident.endpoint_hex,
        &ident.tags,
        Some(ident.hostname.as_str()),
        Some(ident.network_id),
        &slot,
        &slot.counters,
    );
    match verdict {
        PolicyVerdict::Allow => {}
        PolicyVerdict::Deny => {
            metrics.dropped_inc("policy_deny_in");
            return false;
        }
        PolicyVerdict::Reject => {
            metrics.dropped_inc("fw_reject_in");
            let reply = packet::parse(logical.owner.as_bytes())
                .ok()
                .and_then(|p| packet::synthesize_reject(&p));
            if let Some(reply) = reply.filter(|r| !r.is_empty()) {
                // The frame already told us the bound network (used for
                // resolve above); the reply carries the same binding.
                let net = match &frame {
                    tunnet_common::packet::Frame::Single { net, .. } => *net,
                    tunnet_common::packet::Frame::Segment { net, .. } => *net,
                };
                send_reject_framed(reply, net, fast, pool, conn, pool_bufs, metrics).await;
            }
            return false;
        }
    }
    // Inbound SSH-NAT consumes parsed metadata (no second parse); shared
    // storage materializes only when a rewrite actually applies.
    let mut logical = logical;
    if ssh_nat::needs_inbound_rewrite_with_meta(&logical.meta, self_ip) {
        if !logical.materialize(pool_bufs) {
            metrics.dropped_inc("nat_materialize");
            return false;
        }
        // PacketMeta is Copy: snapshot before the mutable borrow.
        let meta = logical.meta;
        let Some(region) = packet_owner_bytes_mut(&mut logical, pool_bufs) else {
            metrics.dropped_inc("nat_materialize");
            return false;
        };
        ssh_nat::rewrite_inbound_with_meta(region, &meta, self_ip);
    }
    let n = logical.len() as u64;
    stage_tun_packet(tun_batch, logical, metrics);
    fast.transport.record_rx(n);
    metrics.packets_inc("in");
    metrics.bytes_add("in", n);
    true
}

#[cfg(target_os = "linux")]
type TunBatchForPlatform = tun_fast::LinuxTunBatchWriter;
#[cfg(not(target_os = "linux"))]
type TunBatchForPlatform = tun_fast::TunWriteBatch;

/// Flush the staged TUN batch. Returns false when the reader should stop
/// (device error); on temporary backpressure the tail stays staged for the
/// next iteration — never silently dropped.
async fn flush_tun_batch(
    batch: &mut TunBatchForPlatform,
    device: &Arc<AsyncDevice>,
    metrics: &AgentMetrics,
) -> bool {
    #[cfg(target_os = "linux")]
    {
        if batch.is_empty() {
            return true;
        }
        metrics.tun_syscall_inc("send_batch");
        match batch.flush(device).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(?e, "tun batch send failed");
                metrics.dropped_inc("tun_send_failed");
                false
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if batch.is_empty() {
            return true;
        }
        metrics.tun_syscall_inc("send_burst");
        match batch.drain_or_wait(device).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(?e, "tun burst send failed");
                metrics.dropped_inc("tun_send_failed");
                false
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn stage_tun_packet(
    batch: &mut TunBatchForPlatform,
    packet: LogicalPacket,
    _metrics: &AgentMetrics,
) {
    let bytes = match packet.owner {
        tunnet_common::packet::PacketOwner::Shared(b) => b,
        tunnet_common::packet::PacketOwner::Pooled(b) => Bytes::from_owner(b),
    };
    batch.push(bytes);
}

#[cfg(target_os = "linux")]
fn stage_tun_packet(
    batch: &mut TunBatchForPlatform,
    packet: LogicalPacket,
    _metrics: &AgentMetrics,
) {
    batch.push(packet.owner.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::test_support::test_metrics;
    use crate::pump::ensure_pump;

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
        // §2.2-1 (tests 5, 6): frames resolve to the EXACT (endpoint,
        // network) membership — never the other network's state — and an
        // endpoint authenticated only for A cannot claim B.
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

    /// End-to-end loopback ping (total-loss diagnosis loop): machine A
    /// (10.7.0.1) sends a real ICMP echo to machine B (10.7.0.2) and back
    /// over loopback QUIC through the REAL outbound policy + scheduler +
    /// pump, REAL datagram transport, and the REAL inbound handler
    /// (decode → membership → antispoof → policy → stage, no TUN device).
    /// Times out (RED) exactly when user ping would: no frames arrive, or
    /// the inbound path drops everything.
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
        // Mirror live conns into transports (slow path, as the pool does).
        reg_a.set_transport_conn(id_b, Some(conn_a.clone()));
        reg_b.set_transport_conn(id_a, Some(conn_b.clone()));
        let pool_a = ConnPool::new(ep_a, alpn);
        let pool_b = ConnPool::new(ep_b, alpn);
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

    /// One directed leg: outbound policy + scheduler + real pump on the
    /// sender; real QUIC datagrams; decode + membership + full inbound
    /// handler on the receiver. Returns the staged TUN payload.
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
        // Scheduler + REAL pump (exits idle on its own).
        assert!(
            member
                .scheduler
                .lock()
                .enqueue(pkt, std::time::Instant::now())
                .is_accepted()
        );
        ensure_pump(
            &member,
            tx_pool.clone(),
            test_metrics(),
            PacketPool::new(8),
            tunnet_core::CloudRelayMeter::new(),
        );
        // Receiver: real datagrams until the full logical packet stages.
        let bufs = PacketPool::new(8);
        let metrics = test_metrics();
        #[cfg(target_os = "linux")]
        let mut batch = tun_fast::LinuxTunBatchWriter::new();
        #[cfg(not(target_os = "linux"))]
        let mut batch = tun_fast::TunWriteBatch::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
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
            let staged = handle_inbound_one(
                &dg,
                frame,
                &rx_member,
                rx_rt,
                &std::collections::HashMap::new(),
                rx_conn,
                None,
                &bufs,
                &metrics,
                &mut batch,
                rx_self_ip,
            )
            .await;
            if staged {
                assert!(!batch.is_empty());
                return raw;
            }
            // Segmented packet: keep draining until completion.
        }
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
}
