//! Platform TUN reader and a dedicated writer that never blocks QUIC ingress.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tun_rs::AsyncDevice;
#[cfg(not(target_os = "android"))]
use tun_rs::DeviceBuilder;
use tunnet_common::packet::{self, Packet};
use tunnet_common::policy::Direction;
use tunnet_core::direct::{EvalResult, FirewallEngine, PacketDirection};
use uuid::Uuid;

use crate::dataplane::peer::{OutboundPacket, TunnelHub};
use crate::metrics::AgentMetrics;
use crate::ssh_nat;
use tunnet_core::{AclEngine, RoutingTable};

pub const TUN_WRITE_QUEUE: usize = 64;
#[cfg(windows)]
pub const WINDOWS_BURST: usize = 32;

/// Ask the app's `VpnService` to establish a tunnel, then adopt its descriptor.
#[cfg(target_os = "android")]
pub fn build_tun_multi(
    ifname: &str,
    addrs: &[std::net::Ipv4Addr],
    routes: &[ipnet::Ipv4Net],
    _prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    use std::os::fd::AsRawFd;

    use crate::android_tun::{self, TunRequest};

    anyhow::ensure!(!addrs.is_empty(), "at least one local address required");
    anyhow::ensure!(
        !routes.is_empty(),
        "at least one route required: without one the tunnel captures nothing"
    );

    let fd = android_tun::establish(TunRequest {
        addrs: addrs.to_vec(),
        routes: routes.to_vec(),
        dns: Vec::new(),
        mtu,
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
    // Linux offload (IFF_VNET_HDR + recv_multiple) is not enabled here.
    // tun-rs can leave VNET_HDR set after TUNSETOFFLOAD fails while
    // reporting vnet_hdr=false, and a virtio parse error used to panic the
    // dataplane actor. Use the same recv/send path as the previous TUN I/O.
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

pub struct ReaderDeps {
    pub tun: Arc<AsyncDevice>,
    pub hub: TunnelHub,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub firewalls: std::collections::HashMap<Uuid, FirewallEngine>,
    pub metrics: AgentMetrics,
    pub mesh: tunnet_core::TunnelMesh,
    pub tun_tx: mpsc::Sender<Bytes>,
    pub mtu: u16,
    pub cancel: CancellationToken,
}

pub async fn run_reader(deps: ReaderDeps) -> anyhow::Result<()> {
    #[cfg(all(windows, not(target_os = "android")))]
    {
        run_reader_windows(deps).await
    }
    #[cfg(not(all(windows, not(target_os = "android"))))]
    {
        run_reader_generic(deps).await
    }
}

fn handle_outbound(deps: &ReaderDeps, packet: &mut [u8]) {
    if packet.is_empty() {
        return;
    }
    deps.mesh.record_tun_rx(packet.len() as u64);
    let self_ip = deps.acl.self_id.load().ip;
    let _ = ssh_nat::rewrite_outbound(packet, self_ip);
    let pkt = match packet::parse(packet) {
        Ok(p) => p,
        Err(e) => {
            deps.metrics.dropped_inc(e.drop_reason());
            return;
        }
    };
    let Some(pkt) = require_ipv4(&deps.metrics, pkt, false) else {
        return;
    };
    let dst = pkt.ip.v4_dst().unwrap();
    if deps.routes.is_advertised_destination(&dst) {
        deps.metrics.dropped_inc("local_subnet");
        return;
    }
    let Some(peer) = deps.routes.lookup_ip(&dst) else {
        deps.metrics.dropped_inc("no_route");
        return;
    };
    if peer.ip == self_ip {
        deps.metrics.dropped_inc("self");
        return;
    }
    if !deps
        .acl
        .allow_packet(&peer.endpoint_hex, Direction::Outbound, &pkt)
    {
        deps.metrics.dropped_inc("policy_deny");
        return;
    }
    if let Some(fw) = deps.firewalls.get(&peer.network_id) {
        match fw.evaluate(
            PacketDirection::Outbound,
            &pkt,
            Some(&peer.endpoint_hex),
            Some(&peer.hostname),
            Some(peer.network_id),
        ) {
            EvalResult::Allow => {}
            EvalResult::Deny => {
                deps.metrics.dropped_inc("fw_deny_out");
                return;
            }
            EvalResult::Reject { reply } => {
                deps.metrics.dropped_inc("fw_reject_out");
                if !reply.is_empty() {
                    let _ = deps.tun_tx.try_send(reply);
                }
                return;
            }
        }
    }
    deps.hub.enqueue(
        peer.endpoint,
        OutboundPacket {
            network_id: peer.network_id,
            bytes: Bytes::copy_from_slice(packet),
            enqueued_at: Instant::now(),
        },
    );
}

fn require_ipv4<'a>(metrics: &AgentMetrics, pkt: Packet<'a>, inbound: bool) -> Option<Packet<'a>> {
    if pkt.ip.v4_src().is_none() {
        metrics.dropped_inc(if inbound {
            "ipv6_unsupported_in"
        } else {
            "ipv6_unsupported"
        });
        return None;
    }
    Some(pkt)
}

#[cfg(not(all(windows, not(target_os = "android"))))]
async fn run_reader_generic(deps: ReaderDeps) -> anyhow::Result<()> {
    let mut buf = vec![0u8; (deps.mtu as usize).max(1280) + 256];
    loop {
        tokio::select! {
            biased;
            _ = deps.cancel.cancelled() => return Ok(()),
            res = deps.tun.recv(&mut buf) => {
                let n = res?;
                if n == 0 {
                    continue;
                }
                handle_outbound(&deps, &mut buf[..n]);
            }
        }
    }
}

#[cfg(windows)]
async fn run_reader_windows(deps: ReaderDeps) -> anyhow::Result<()> {
    let mut buf = vec![0u8; (deps.mtu as usize).max(1280) + 256];
    loop {
        tokio::select! {
            biased;
            _ = deps.cancel.cancelled() => return Ok(()),
            res = deps.tun.recv(&mut buf) => {
                let n = res?;
                if n > 0 {
                    handle_outbound(&deps, &mut buf[..n]);
                }
                drain_windows_burst(&deps, &mut buf);
            }
        }
    }
}

#[cfg(windows)]
fn drain_windows_burst(deps: &ReaderDeps, buf: &mut [u8]) {
    for _ in 0..WINDOWS_BURST {
        match deps.tun.try_recv(buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => handle_outbound(deps, &mut buf[..n]),
        }
    }
}

/// Drain `try_recv` until WouldBlock or `max` packets. Used by tests.
#[cfg(test)]
pub fn drain_ready_burst<F>(max: usize, mut try_recv: F) -> usize
where
    F: FnMut() -> std::io::Result<usize>,
{
    let mut n = 0;
    for _ in 0..max {
        match try_recv() {
            Ok(0) => break,
            Ok(_) => n += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    n
}

/// Linux `recv_multiple` slot: `AsRef`/`AsMut` always expose full capacity.
#[cfg(any(test, target_os = "linux"))]
pub struct RecvSlot {
    buf: Vec<u8>,
}

#[cfg(any(test, target_os = "linux"))]
impl RecvSlot {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: vec![0u8; cap],
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
impl AsRef<[u8]> for RecvSlot {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(any(test, target_os = "linux"))]
impl AsMut<[u8]> for RecvSlot {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

pub async fn run_writer(
    tun: Arc<AsyncDevice>,
    mut rx: mpsc::Receiver<Bytes>,
    mesh: tunnet_core::TunnelMesh,
    metrics: AgentMetrics,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    run_writer_generic(tun, &mut rx, mesh, metrics, cancel).await
}

async fn run_writer_generic(
    tun: Arc<AsyncDevice>,
    rx: &mut mpsc::Receiver<Bytes>,
    mesh: tunnet_core::TunnelMesh,
    metrics: AgentMetrics,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            pkt = rx.recv() => {
                let Some(pkt) = pkt else { return Ok(()) };
                write_one(&tun, &pkt, &mesh, &metrics).await?;
                while let Ok(more) = rx.try_recv() {
                    write_one(&tun, &more, &mesh, &metrics).await?;
                }
            }
        }
    }
}

async fn write_one(
    tun: &AsyncDevice,
    pkt: &[u8],
    mesh: &tunnet_core::TunnelMesh,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        match tun.try_send(pkt) {
            Ok(_) => {
                mesh.record_tun_tx(pkt.len() as u64);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                metrics.dropped_inc("tun_send_failed");
                return Err(e.into());
            }
        }
    }
    match tun.send(pkt).await {
        Ok(_) => {
            mesh.record_tun_tx(pkt.len() as u64);
            Ok(())
        }
        Err(e) => {
            metrics.dropped_inc("tun_send_failed");
            Err(e.into())
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
pub fn stage_virtio(pkt: &[u8]) -> Vec<u8> {
    #[cfg(target_os = "linux")]
    {
        use tun_rs::VIRTIO_NET_HDR_LEN;
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + pkt.len()];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(pkt);
        buf
    }
    #[cfg(not(target_os = "linux"))]
    {
        pkt.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_slot_satisfies_tun_rs_contract() {
        let cap = 1280;
        let mut slot = RecvSlot::with_capacity(cap);
        assert_eq!(
            slot.as_ref().len(),
            cap,
            "AsRef must report receive capacity"
        );
        assert_eq!(
            slot.as_mut().len(),
            cap,
            "AsMut must expose the receive area"
        );
        slot.as_mut()[..40].fill(0x45);
        assert_eq!(
            slot.as_ref().len(),
            cap,
            "recycled slot must still report full capacity"
        );
        let mut slot3 = RecvSlot::with_capacity(9000);
        slot3.as_mut()[..20].fill(1);
        assert!(slot3.as_ref().len() >= 9000);
        assert!(slot3.as_mut().len() >= 9000);
    }

    #[test]
    fn tun_batch_writer_stages_virtio_layout() {
        let pkt = {
            let mut p = vec![0u8; 40];
            p[0] = 0x45;
            p
        };
        let staged = stage_virtio(&pkt);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(staged.len(), tun_rs::VIRTIO_NET_HDR_LEN + pkt.len());
            assert!(staged[..tun_rs::VIRTIO_NET_HDR_LEN].iter().all(|b| *b == 0));
            assert_eq!(&staged[tun_rs::VIRTIO_NET_HDR_LEN..], pkt.as_slice());
            assert_eq!(staged[tun_rs::VIRTIO_NET_HDR_LEN], 0x45);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(staged, pkt);
        }
    }

    #[test]
    fn windows_burst_stops_on_would_block() {
        let mut n = 0;
        let got = drain_ready_burst(32, || {
            n += 1;
            if n <= 3 {
                Ok(40)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
        });
        assert_eq!(got, 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a real kernel TUN"]
    fn linux_recv_multiple_uses_full_capacity_slots() {
        let cap = 1280;
        let slot = RecvSlot::with_capacity(cap);
        assert_eq!(slot.as_ref().len(), cap);
    }
}
