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
use tunnet_core::peer::{AuthorizedPacket, SessionCtl};
use tunnet_core::{ForwardingStore, PeerManager, PolicyEngine};

use crate::actors::dataplane::PublishedDataPlane;
use crate::metrics::AgentMetrics;

const INGRESS_BATCH: usize = 32;
const OUTBOUND_DRAIN_MAX: usize = 64;
const DNS_QUEUE: usize = 64;
const DNS_WORKERS: usize = 4;
const WRITE_QUEUE: usize = 128;

#[derive(Clone)]
pub struct TunWriter {
    tx: tokio::sync::mpsc::Sender<TunWrite>,
    cancel: tokio_util::sync::CancellationToken,
}

struct TunWrite {
    packet: Bytes,
    authorization: Option<IngressAuthorization>,
}

pub struct IngressAuthorization {
    network: uuid::Uuid,
    peer: EndpointId,
    epoch: tunnet_core::forward::snapshot::AuthorizationEpoch,
    posture: Arc<bool>,
    proof: Option<tunnet_core::forward::PostureAuthorization>,
    cancel: tokio_util::sync::CancellationToken,
}

impl TunWriter {
    pub fn spawn(
        device: Arc<AsyncDevice>,
        cancel: tokio_util::sync::CancellationToken,
        metrics: AgentMetrics,
        forwarding: ForwardingStore,
        on_unexpected_end: Box<dyn FnOnce() + Send>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<TunWrite>(WRITE_QUEUE);
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let _exit = crate::dataplane::TaskExit {
                cancel: task_cancel.clone(),
                notify: Some(on_unexpected_end),
            };
            loop {
                let packet = tokio::select! {
                    biased;
                    _ = task_cancel.cancelled() => return,
                    packet = rx.recv() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                };
                let result = loop {
                    let attempt = {
                        let gate = forwarding.authorization_gate();
                        let _guard = gate.read();
                        let allowed = !task_cancel.is_cancelled()
                            && packet.authorization.as_ref().is_none_or(|auth| {
                                let current = forwarding.load();
                                !auth.cancel.is_cancelled()
                                    && current.auth_epoch(auth.network) == auth.epoch
                                    && current.allows_network(auth.network, auth.peer)
                                    && Arc::ptr_eq(&auth.posture, &current.posture_ok.load_full())
                                    && auth.proof.is_none_or(|proof| {
                                        proof.allows(&current, auth.network, auth.peer)
                                    })
                            });
                        if !allowed {
                            metrics.dropped_inc("authorization_changed");
                            break Ok(0);
                        }
                        device.try_send(&packet.packet)
                    };
                    match attempt {
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            tokio::select! {
                                biased;
                                _ = task_cancel.cancelled() => return,
                                result = wait_writable(&device) => if let Err(e) = result { break Err(e); },
                            }
                        }
                        other => break other,
                    }
                };
                match result {
                    Ok(0) => {}
                    Ok(n) if n == packet.packet.len() => {
                        metrics.packets_add("tun_write", 1);
                        metrics.bytes_add("tun_write", n as u64);
                    }
                    _ => {
                        metrics.dropped_inc("tun_send_failed");
                        break;
                    }
                }
            }
        });
        (Self { tx, cancel }, task)
    }

    pub async fn send(&self, packet: Bytes) -> bool {
        self.submit(TunWrite {
            packet,
            authorization: None,
        })
        .await
    }

    pub fn try_send(&self, packet: Bytes) -> bool {
        !self.cancel.is_cancelled()
            && !packet.is_empty()
            && packet.len() <= 65_535
            && self
                .tx
                .try_send(TunWrite {
                    packet,
                    authorization: None,
                })
                .is_ok()
    }

    pub async fn send_authorized(
        &self,
        packet: Bytes,
        authorization: IngressAuthorization,
    ) -> bool {
        self.submit(TunWrite {
            packet,
            authorization: Some(authorization),
        })
        .await
    }

    async fn submit(&self, packet: TunWrite) -> bool {
        if packet.packet.is_empty() || packet.packet.len() > 65_535 {
            return false;
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => false,
            result = self.tx.send(packet) => result.is_ok(),
        }
    }
}

async fn wait_writable(device: &AsyncDevice) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let _ = device;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        Ok(())
    }
    #[cfg(not(windows))]
    device.writable().await
}

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
    inner: Arc<DnsWorkers>,
}

struct DnsWorkers {
    tx: tokio::sync::mpsc::Sender<Bytes>,
    cancel: tokio_util::sync::CancellationToken,
    tasks: parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for DnsWorkers {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

impl DnsPool {
    pub fn new(
        writer: TunWriter,
        dns: Arc<tunnet_core::dns::InTun>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(DNS_QUEUE);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let mut tasks = Vec::with_capacity(DNS_WORKERS);
        for _ in 0..DNS_WORKERS {
            let rx = rx.clone();
            let writer = writer.clone();
            let dns = dns.clone();
            let cancel = cancel.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let query: Option<Bytes> = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        query = async { rx.lock().await.recv().await } => query,
                    };
                    let Some(query) = query else { break };
                    let replies = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        replies = dns.handle(&query) => replies,
                    };
                    for reply in replies {
                        if !writer.send(Bytes::from(reply)).await {
                            break;
                        }
                    }
                }
            }));
        }
        Self {
            inner: Arc::new(DnsWorkers {
                tx,
                cancel,
                tasks: parking_lot::Mutex::new(tasks),
            }),
        }
    }

    pub fn submit(&self, query: Bytes) -> bool {
        !self.inner.cancel.is_cancelled() && self.inner.tx.try_send(query).is_ok()
    }

    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let tasks = std::mem::take(&mut *self.inner.tasks.lock());
        for mut task in tasks {
            if tokio::time::timeout(std::time::Duration::from_secs(3), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

pub struct OutboundDeps {
    pub tun: Arc<AsyncDevice>,
    pub writer: TunWriter,
    pub peers: PeerManager,
    pub policy: PolicyEngine,
    pub forwarding: ForwardingStore,
    pub metrics: AgentMetrics,
    pub dns: DnsPool,
}

pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        writer,
        peers,
        policy,
        forwarding,
        metrics,
        dns,
    } = deps;

    let mut buf = vec![0u8; 65_536];
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(OUTBOUND_DRAIN_MAX);
    let mut by_peer: std::collections::HashMap<EndpointId, Vec<AuthorizedPacket>> =
        std::collections::HashMap::new();
    tracing::info!("outbound TUN→iroh loop started");
    loop {
        batch.clear();
        drain_tun(&tun, &mut buf, &mut pool, &mut batch)?;
        if batch.is_empty() {
            let n = tun.recv(&mut buf).await?;
            if n > 0 {
                batch.push(take_packet(&mut pool, &buf[..n]));
            }
            drain_tun(&tun, &mut buf, &mut pool, &mut batch)?;
        }
        if batch.is_empty() {
            continue;
        }
        metrics.batch_observe("tun_read", batch.len() as u64);
        metrics.packets_add("tun_read", batch.len() as u64);
        metrics.bytes_add("tun_read", batch.iter().map(|p| p.len() as u64).sum());
        let (snap, auth_tokens, posture) = batch_authorization(&forwarding);
        by_peer.clear();
        let mut admitted = 0u64;
        let mut admitted_bytes = 0u64;
        for mut raw in batch.drain(..) {
            let decision = loop {
                match outbound(&snap, &policy, &raw) {
                    OutDecision::RewriteSsh(rewrite) => {
                        if !tunnet_common::packet::rewrite_tcp_port(
                            &mut raw,
                            rewrite.ip_header_len,
                            rewrite.port_offset,
                            rewrite.port,
                        ) {
                            break OutDecision::Drop {
                                reason: "ssh_rewrite_invalid",
                            };
                        }
                    }
                    d => break d,
                }
            };
            match decision {
                OutDecision::Forward {
                    peer,
                    network,
                    posture: proof,
                } => {
                    metrics.packets_add("authorized_out", 1);
                    metrics.bytes_add("authorized_out", raw.len() as u64);
                    let Some(epoch) = auth_tokens.get(&network).copied() else {
                        metrics.dropped_inc("authorization_changed");
                        pool.push(raw);
                        continue;
                    };
                    by_peer.entry(peer).or_default().push(AuthorizedPacket {
                        packet: frame(network, &raw),
                        epoch,
                        local_posture: posture.clone(),
                        proof,
                    });
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
                        let _ = writer.send(reply).await;
                    }
                }
                OutDecision::Drop { reason } => metrics.dropped_inc(reason),
            }
            pool.push(raw);
        }
        let mut queue_full = 0u64;
        for (peer, packets) in by_peer.drain() {
            let outcome = peers.send_batch_authorized(peer, packets);
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
            metrics.packets_add("queue_admitted", admitted);
            metrics.bytes_add("queue_admitted", admitted_bytes);
        }
        tokio::task::yield_now().await;
    }
}

fn batch_authorization(
    forwarding: &ForwardingStore,
) -> (
    Arc<tunnet_core::ForwardingSnapshot>,
    std::collections::HashMap<uuid::Uuid, tunnet_core::forward::snapshot::AuthorizationEpoch>,
    Arc<bool>,
) {
    let gate = forwarding.authorization_gate();
    let _guard = gate.read();
    let snap = forwarding.load();
    let epochs = snap
        .auth
        .keys()
        .map(|net| (*net, snap.auth_epoch(*net)))
        .collect();
    let posture = snap.posture_ok.load_full();
    (snap, epochs, posture)
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
) -> std::io::Result<()> {
    while batch.len() < OUTBOUND_DRAIN_MAX {
        match tun.try_recv(buf) {
            Ok(m) if m > 0 => batch.push(take_packet(pool, &buf[..m])),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
            Ok(_) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct SessionInbound {
    pub plane: Arc<PublishedDataPlane>,
    pub peers: tunnet_core::peer::WeakPeerManager,
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
}

async fn serve_tunnel_connection_inner(
    peer: EndpointId,
    conn: Connection,
    ctl: &SessionCtl,
    deps: SessionInbound,
) {
    let SessionInbound {
        plane,
        peers,
        policy,
        forwarding,
        metrics,
    } = deps;
    let remote_id = conn.remote_id();
    debug_assert_eq!(peer, remote_id);
    tracing::info!(%remote_id, "peer connected");
    metrics.active_conns_inc();
    let _metrics = ActiveConnection(metrics.clone());
    if let Some(max) = conn.max_datagram_size() {
        tracing::debug!(%remote_id, max_datagram_size = max, "quic datagram limit");
    }

    let writer = plane.writer.clone();
    let generation_cancel = plane.cancel.clone();
    let connection_cancel = ctl.cancel();
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
            _ = connection_cancel.cancelled() => break,
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
            metrics.packets_add("quic_read", received as u64);
            metrics.bytes_add(
                "quic_read",
                batch[..received]
                    .iter()
                    .map(|packet| packet.len() as u64)
                    .sum(),
            );
        }
        let (snap, auth_tokens, posture) = batch_authorization(&forwarding);
        let mut admitted = 0u64;
        let mut admitted_bytes = 0u64;
        for dg in &batch[..received] {
            match inbound_frame(&snap, &policy, dg, remote_id) {
                InDecision::ToTun {
                    ip,
                    ssh,
                    network,
                    posture: proof,
                } => {
                    let Some(epoch) = auth_tokens.get(&network).copied() else {
                        continue;
                    };
                    let n = ip.len() as u64;
                    if generation_cancel.is_cancelled() {
                        break 'read;
                    }
                    let payload: &[u8] = match ssh {
                        Some(rewrite) => {
                            scratch.clear();
                            scratch.extend_from_slice(ip);
                            if !tunnet_common::packet::rewrite_tcp_port(
                                &mut scratch,
                                rewrite.ip_header_len,
                                rewrite.port_offset,
                                rewrite.port,
                            ) {
                                metrics.dropped_inc("ssh_rewrite_invalid");
                                continue;
                            }
                            &scratch
                        }
                        None => ip,
                    };
                    let packet = if ssh.is_some() {
                        Bytes::copy_from_slice(payload)
                    } else {
                        dg.slice(FRAME_OVERHEAD..FRAME_OVERHEAD + ip.len())
                    };
                    if !writer
                        .send_authorized(
                            packet,
                            IngressAuthorization {
                                network,
                                peer: remote_id,
                                epoch,
                                posture: posture.clone(),
                                proof,
                                cancel: connection_cancel.clone(),
                            },
                        )
                        .await
                    {
                        tracing::debug!("tun send failed");
                        metrics.dropped_inc("tun_send_failed");
                        continue;
                    }
                    admitted += 1;
                    admitted_bytes += n;
                }
                InDecision::Reject { reply, network } => {
                    metrics.dropped_inc("fw_reject_in");
                    if !reply.is_empty()
                        && let Some(epoch) = auth_tokens.get(&network).copied()
                        && let Some(peers) = peers.upgrade()
                    {
                        let _ = peers.send_authorized(
                            remote_id,
                            AuthorizedPacket {
                                packet: frame(network, &reply),
                                epoch,
                                local_posture: posture.clone(),
                                proof: None,
                            },
                        );
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
            metrics.packets_add("authorized_in", admitted);
            metrics.bytes_add("authorized_in", admitted_bytes);
            if let Some(peers) = peers.upgrade() {
                peers.record_bytes_in(remote_id, admitted_bytes);
            }
        }
    }
    tracing::info!(%remote_id, "peer disconnected");
}

struct ActiveConnection(AgentMetrics);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.active_conns_dec();
    }
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
