use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tun_rs::AsyncDevice;
#[cfg(not(target_os = "android"))]
use tun_rs::DeviceBuilder;
use tunnet_core::forward::{
    FRAME_OVERHEAD, InDecision, OutDecision, frame, inbound_frame, outbound,
};
use tunnet_core::peer::{SessionCtl, send_datagram};
use tunnet_core::{ForwardingStore, PeerManager, PolicyEngine};

use crate::actors::dataplane::PublishedPlane;
use crate::metrics::AgentMetrics;

const INGRESS_BATCH: usize = 32;
const OUTBOUND_DRAIN_MAX: usize = 64;
const DNS_QUEUE: usize = 64;
const DNS_WORKERS: usize = 4;

#[cfg(target_os = "android")]
pub fn build_tun_multi(
    ifname: &str,
    addrs: &[std::net::Ipv4Addr],
    routes: &[ipnet::Ipv4Net],
    _prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    use std::os::fd::AsRawFd;

    use crate::platform::tun::{self, TunRequest};

    anyhow::ensure!(!addrs.is_empty(), "at least one local address required");
    anyhow::ensure!(
        !routes.is_empty(),
        "at least one route required: without one the tunnel captures nothing"
    );
    anyhow::ensure!(
        (576..=9000).contains(&mtu),
        "mtu {mtu} is outside 576..=9000"
    );

    let fd = tun::establish(TunRequest {
        addrs: addrs.to_vec(),
        routes: android_vpn_capture_routes(routes),
        dns: vec![tunnet_common::VirtualResolverEndpoint::IP],
        mtu,
        allow_ipv6_passthrough: true,
        inherit_underlying_metered: true,
    })?;
    let raw = fd.as_raw_fd();
    let dev = match unsafe { AsyncDevice::from_fd(raw) } {
        Ok(dev) => {
            std::mem::forget(fd);
            dev
        }
        Err(e) => return Err(e).context("adopt VpnService TUN descriptor"),
    };
    tracing::debug!(ifname, "TUN device adopted");
    Ok(dev)
}

#[cfg(any(target_os = "android", test))]
pub(crate) fn android_vpn_capture_routes(peer_cidrs: &[ipnet::Ipv4Net]) -> Vec<ipnet::Ipv4Net> {
    let dns = tunnet_common::VirtualResolverEndpoint::IP;
    let host = tunnet_common::VirtualResolverEndpoint::host_route();
    let mut out: Vec<_> = peer_cidrs
        .iter()
        .copied()
        .filter(|net| net.prefix_len() != 0)
        .collect();
    if !out.iter().any(|r| r.contains(&dns)) {
        out.push(host);
    }
    out
}

#[cfg(not(target_os = "android"))]
pub fn build_tun_multi(
    ifname: &str,
    addrs: &[std::net::Ipv4Addr],
    _routes: &[ipnet::Ipv4Net],
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    let first = addrs
        .first()
        .copied()
        .context("at least one local address required")?;
    let builder = DeviceBuilder::new()
        .name(ifname)
        .ipv4(first, prefix, None)
        .mtu(mtu);
    #[cfg(windows)]
    let builder = {
        let path = crate::wintun::materialize()?;
        builder
            .wintun_file(path.display().to_string())
            .wintun_log(true)
    };
    let dev = builder.build_async().context("build_async TUN device")?;
    for extra in addrs.iter().skip(1) {
        dev.add_address_v4(*extra, 32)
            .with_context(|| format!("add required TUN address {extra}/32"))?;
    }
    tracing::info!(addrs = ?addrs, prefix, mtu, "TUN device up");
    Ok(dev)
}

#[derive(Clone)]
pub struct DnsPool {
    tx: tokio::sync::mpsc::Sender<Bytes>,
}

impl DnsPool {
    pub fn new(device: Arc<AsyncDevice>, dns: Arc<tunnet_core::dns::InTun>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(DNS_QUEUE);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for _ in 0..DNS_WORKERS {
            let rx = rx.clone();
            let device = device.clone();
            let dns = dns.clone();
            tokio::spawn(async move {
                loop {
                    let query: Option<Bytes> = rx.lock().await.recv().await;
                    let Some(query) = query else { break };
                    for reply in dns.handle(&query).await {
                        if device.send(&reply).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
        Self { tx }
    }

    pub fn submit(&self, query: Bytes) -> bool {
        self.tx.try_send(query).is_ok()
    }
}

pub struct OutboundDeps {
    pub tun: Arc<AsyncDevice>,
    pub peers: PeerManager,
    pub policy: PolicyEngine,
    pub forwarding: ForwardingStore,
    pub metrics: AgentMetrics,
    pub dns: DnsPool,
}

pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        peers,
        policy,
        forwarding,
        metrics,
        dns,
    } = deps;

    let mut buf = vec![0u8; 65_536];
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(OUTBOUND_DRAIN_MAX);
    let mut by_peer: std::collections::HashMap<EndpointId, Vec<Bytes>> =
        std::collections::HashMap::new();
    tracing::info!("outbound TUN→iroh loop started");
    loop {
        batch.clear();
        drain_tun(&tun, &mut buf, &mut pool, &mut batch);
        if batch.is_empty() {
            let n = tun.recv(&mut buf).await?;
            if n > 0 {
                batch.push(take_packet(&mut pool, &buf[..n]));
            }
            drain_tun(&tun, &mut buf, &mut pool, &mut batch);
        }
        if batch.is_empty() {
            continue;
        }
        metrics.batch_observe("tun_read", batch.len() as u64);
        let snap = forwarding.load();
        let tun_mtu = snap.tun_mtu;
        by_peer.clear();
        let mut admitted = 0u64;
        let mut admitted_bytes = 0u64;
        for mut raw in batch.drain(..) {
            let decision = loop {
                match outbound(&snap, &policy, &raw) {
                    OutDecision::RewriteSsh(rewrite) => {
                        raw[rewrite.port_offset] = (rewrite.port >> 8) as u8;
                        raw[rewrite.port_offset + 1] = (rewrite.port & 0xff) as u8;
                        tunnet_common::packet::set_tcp_ipv4_checksum(
                            &mut raw,
                            rewrite.ip_header_len,
                        );
                    }
                    d => break d,
                }
            };
            match decision {
                OutDecision::Forward { peer, network } => {
                    let framed_len = raw.len() + FRAME_OVERHEAD;
                    let max_dg = peers.conn_max_datagram_size(peer);
                    if let Some(max) = max_dg
                        && framed_len > max
                    {
                        let mtu = (max.saturating_sub(FRAME_OVERHEAD).max(576) as u16).min(tun_mtu);
                        metrics.dropped_inc("datagram_too_large");
                        if let Some(reply) =
                            tunnet_common::packet::synthesize_frag_needed(&raw, mtu)
                        {
                            let _ = tun.send(&reply).await;
                        }
                    } else {
                        let budget = max_dg
                            .map(|m| m.saturating_sub(FRAME_OVERHEAD + 40))
                            .unwrap_or(tun_mtu as usize - 58);
                        let mss = budget.clamp(536, 9000) as u16;
                        tunnet_common::packet::clamp_tcp_mss(&mut raw, mss);
                        by_peer.entry(peer).or_default().push(frame(network, &raw));
                    }
                }
                OutDecision::LocalDns => {
                    if !dns.submit(Bytes::copy_from_slice(&raw)) {
                        metrics.dropped_inc("dns_queue_full");
                    }
                }
                OutDecision::RewriteSsh(_) => {}
                OutDecision::Reject { reply } => {
                    metrics.dropped_inc("fw_reject_out");
                    if !reply.is_empty() {
                        let _ = tun.send(&reply).await;
                    }
                }
                OutDecision::Drop { reason } => metrics.dropped_inc(reason),
            }
            pool.push(raw);
        }
        let mut queue_full = 0u64;
        for (peer, packets) in by_peer.drain() {
            let outcome = peers.send_batch(peer, packets);
            admitted += outcome.admitted as u64;
            admitted_bytes += outcome.admitted_bytes;
            queue_full += outcome.queue_full as u64;
            if outcome.blocked {
                metrics.dropped_inc("policy_deny");
            }
            if outcome.closed {
                metrics.dropped_inc("dataplane_down");
            }
        }
        if queue_full > 0 {
            metrics.dropped_add("queue_full", queue_full);
        }
        if admitted > 0 {
            metrics.packets_add("out", admitted);
            metrics.bytes_add("out", admitted_bytes);
        }
        tokio::task::yield_now().await;
    }
}

fn take_packet(pool: &mut Vec<Vec<u8>>, data: &[u8]) -> Vec<u8> {
    let mut owned = pool.pop().unwrap_or_default();
    owned.clear();
    owned.extend_from_slice(data);
    owned
}

fn drain_tun(
    tun: &Arc<AsyncDevice>,
    buf: &mut [u8],
    pool: &mut Vec<Vec<u8>>,
    batch: &mut Vec<Vec<u8>>,
) {
    while batch.len() < OUTBOUND_DRAIN_MAX {
        match tun.try_recv(buf) {
            Ok(m) if m > 0 => batch.push(take_packet(pool, &buf[..m])),
            _ => break,
        }
    }
}

#[derive(Clone)]
pub struct SessionInbound {
    pub tun: PublishedPlane,
    pub peers: PeerManager,
    pub policy: PolicyEngine,
    pub forwarding: ForwardingStore,
    pub metrics: AgentMetrics,
}

pub async fn serve_tunnel_connection(
    peer: EndpointId,
    conn: Connection,
    ctl: SessionCtl,
    deps: SessionInbound,
) {
    serve_tunnel_connection_inner(peer, conn, &ctl, deps).await;
    ctl.finished();
}

async fn serve_tunnel_connection_inner(
    peer: EndpointId,
    conn: Connection,
    ctl: &SessionCtl,
    deps: SessionInbound,
) {
    let SessionInbound {
        tun,
        peers,
        policy,
        forwarding,
        metrics,
    } = deps;
    let remote_id = conn.remote_id();
    debug_assert_eq!(peer, remote_id);
    tracing::info!(%remote_id, "peer connected");
    metrics.active_conns_inc();
    if let Some(max) = conn.max_datagram_size() {
        tracing::debug!(%remote_id, max_datagram_size = max, "quic datagram limit");
    }

    let Some(plane) = tun.load_full() else {
        metrics.active_conns_dec();
        return;
    };
    let device = plane.device.clone();
    let generation_cancel = plane.cancel.clone();
    tracing::debug!(generation = plane.generation, %remote_id, "ingress reader pinned");

    let mut batch: [Bytes; INGRESS_BATCH] = std::array::from_fn(|_| Bytes::new());
    let mut scratch: Vec<u8> = Vec::new();
    'read: loop {
        if generation_cancel.is_cancelled() {
            break;
        }
        let received = tokio::select! {
            biased;
            _ = generation_cancel.cancelled() => break,
            _ = async {
                match ctl.cancel() {
                    Some(cancel) => cancel.cancelled().await,
                    None => std::future::pending().await,
                }
            } => break,
            res = conn.read_many_datagrams(&mut batch) => match res {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(?e, "read_datagram closed");
                    break 'read;
                }
            },
        };
        if generation_cancel.is_cancelled() {
            break;
        }
        batch[received..].fill(Bytes::new());
        if received > 0 {
            metrics.batch_observe("quic_read", received as u64);
        }
        let snap = forwarding.load();
        let mut admitted = 0u64;
        let mut admitted_bytes = 0u64;
        for dg in &batch[..received] {
            match inbound_frame(&snap, &policy, dg, remote_id) {
                InDecision::ToTun { ip, ssh } => {
                    let n = ip.len() as u64;
                    if generation_cancel.is_cancelled() {
                        break 'read;
                    }
                    let payload: &[u8] = match ssh {
                        Some(rewrite) => {
                            scratch.clear();
                            scratch.extend_from_slice(ip);
                            scratch[rewrite.port_offset] = (rewrite.port >> 8) as u8;
                            scratch[rewrite.port_offset + 1] = (rewrite.port & 0xff) as u8;
                            tunnet_common::packet::set_tcp_ipv4_checksum(
                                &mut scratch,
                                rewrite.ip_header_len,
                            );
                            &scratch
                        }
                        None => ip,
                    };
                    if device.send(payload).await.is_err() {
                        tracing::debug!("tun send failed");
                        metrics.dropped_inc("tun_send_failed");
                        continue;
                    }
                    admitted += 1;
                    admitted_bytes += n;
                }
                InDecision::Reject { reply } => {
                    metrics.dropped_inc("fw_reject_in");
                    if !reply.is_empty() {
                        let _ = send_datagram(&conn, reply).await;
                    }
                }
                InDecision::Spoof { network } => {
                    metrics.dropped_inc("antispoof");
                    if policy.record_spoof(network, &remote_id.to_string()) {
                        for (p, n) in policy.drain_spoof(network) {
                            tracing::warn!(
                                peer = %p,
                                spoofed_packets = n,
                                "ingress anti-spoof drops in last window"
                            );
                        }
                    }
                }
                InDecision::Drop { reason } => metrics.dropped_inc(reason),
            }
        }
        if admitted > 0 {
            metrics.packets_add("in", admitted);
            metrics.bytes_add("in", admitted_bytes);
            peers.record_bytes_in(remote_id, admitted_bytes);
        }
    }
    metrics.active_conns_dec();
    tracing::info!(%remote_id, "peer disconnected");
}

#[cfg(test)]
mod android_vpn_route_tests {
    use super::android_vpn_capture_routes;

    #[test]
    fn capture_routes_are_overlay_plus_virtual_dns_not_default() {
        use std::net::Ipv4Addr;

        let overlay: ipnet::Ipv4Net = "10.38.0.0/16".parse().unwrap();
        let routes = android_vpn_capture_routes(&[overlay]);
        assert!(routes.contains(&overlay));
        assert!(routes.contains(&tunnet_common::VirtualResolverEndpoint::host_route()));
        assert!(
            routes.iter().all(|r| r.prefix_len() != 0),
            "default route would swallow iroh underlay"
        );
        let public = Ipv4Addr::new(1, 1, 1, 1);
        let lan = Ipv4Addr::new(192, 168, 1, 20);
        assert!(!routes.iter().any(|r| r.contains(&public)));
        assert!(!routes.iter().any(|r| r.contains(&lan)));
        assert!(
            routes
                .iter()
                .any(|r| r.contains(&tunnet_common::VirtualResolverEndpoint::IP))
        );
    }

    #[test]
    fn default_peer_cidr_is_stripped() {
        let default: ipnet::Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let overlay: ipnet::Ipv4Net = "10.9.0.0/16".parse().unwrap();
        let routes = android_vpn_capture_routes(&[default, overlay]);
        assert!(!routes.iter().any(|r| r.prefix_len() == 0));
        assert!(routes.contains(&overlay));
    }
}
