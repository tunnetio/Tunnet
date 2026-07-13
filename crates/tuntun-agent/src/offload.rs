#![cfg(target_os = "linux")]
#![allow(dead_code, clippy::too_many_arguments)]

use std::sync::Arc;

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, bounded};
use iroh::EndpointId;
use tun_rs::{DeviceBuilder, SyncDevice};

use crate::ip;
use crate::metrics::AgentMetrics;
use tuntun_common::policy::Direction;
use tuntun_core::{AclEngine, ConnPool, RoutingTable, iroh_pool::send_datagram};

pub struct OffloadedTun {
    pub queues: Vec<Arc<SyncDevice>>,
}

pub fn is_enabled() -> bool {
    std::env::var("TUNTUN_OFFLOAD").ok().as_deref() == Some("1")
}

pub fn build(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
    queues: usize,
) -> anyhow::Result<OffloadedTun> {
    let dev = DeviceBuilder::new()
        .name(ifname)
        .ipv4(ipv4, prefix, None)
        .mtu(mtu)
        .offload(true)
        .multi_queue(true)
        .build_sync()?;
    let primary = Arc::new(dev);
    let mut all = vec![primary.clone()];
    for _ in 1..queues {
        match primary.try_clone() {
            Ok(q) => all.push(Arc::new(q)),
            Err(e) => {
                tracing::warn!(?e, "try_clone queue failed; stopping at {}", all.len());
                break;
            }
        }
    }
    Ok(OffloadedTun { queues: all })
}

pub fn spawn_outbound_threads(
    tun: OffloadedTun,
    routes: RoutingTable,
    acl: AclEngine,
    pool: ConnPool,
    metrics: AgentMetrics,
    runtime: tokio::runtime::Handle,
) {
    let peer_senders: Arc<dashmap::DashMap<EndpointId, Sender<Bytes>>> =
        Arc::new(dashmap::DashMap::new());

    for (idx, queue) in tun.queues.into_iter().enumerate() {
        let routes = routes.clone();
        let acl = acl.clone();
        let pool = pool.clone();
        let metrics = metrics.clone();
        let runtime = runtime.clone();
        let peer_senders = peer_senders.clone();

        std::thread::Builder::new()
            .name(format!("tuntun-tun-q{idx}"))
            .spawn(move || {
                run_outbound_thread(
                    idx,
                    queue,
                    routes,
                    acl,
                    pool,
                    metrics,
                    runtime,
                    peer_senders,
                );
            })
            .expect("spawn tun queue thread");
    }
}

fn run_outbound_thread(
    idx: usize,
    tun: Arc<SyncDevice>,
    routes: RoutingTable,
    acl: AclEngine,
    pool: ConnPool,
    metrics: AgentMetrics,
    runtime: tokio::runtime::Handle,
    peer_senders: Arc<dashmap::DashMap<EndpointId, Sender<Bytes>>>,
) {
    tracing::info!(queue = idx, "TUN outbound thread started (offload path)");
    // NOTE: This is the shape of the fast path. `recv_multiple` requires a
    // virtio-net header + per-frame buffers; consult tun-rs docs for the
    // exact layout. We deliberately keep this scaffold portable rather than
    // hard-coding sizes that may drift between tun-rs versions.
    let mut buf = vec![0u8; 65_536];
    loop {
        let n = match tun.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(queue = idx, ?e, "tun recv failed");
                return;
            }
        };
        if n == 0 {
            continue;
        }
        let packet = &buf[..n];
        let Some(parsed) = ip::parse_ipv4(packet) else {
            metrics.dropped.with_label_values(&["non_ipv4"]).inc();
            continue;
        };
        if routes.is_advertised_destination(&parsed.dst) {
            metrics.dropped.with_label_values(&["local_subnet"]).inc();
            continue;
        }
        let Some(peer) = routes.lookup_ip(&parsed.dst) else {
            metrics.dropped.with_label_values(&["no_route"]).inc();
            continue;
        };
        if !acl.allow_packet(
            &peer.endpoint_hex,
            Some(parsed.dst),
            parsed.dst_port,
            parsed.protocol,
            Direction::Outbound,
        ) {
            metrics.dropped.with_label_values(&["policy_deny"]).inc();
            continue;
        }

        let sender = peer_senders
            .entry(peer.endpoint)
            .or_insert_with(|| {
                let (tx, rx) = bounded::<Bytes>(2048);
                spawn_peer_drain(
                    runtime.clone(),
                    pool.clone(),
                    peer.endpoint,
                    rx,
                    metrics.clone(),
                );
                tx
            })
            .clone();

        let pkt = Bytes::copy_from_slice(packet);
        let n = pkt.len() as u64;
        match sender.try_send(pkt) {
            Ok(()) => {
                metrics.packets.with_label_values(&["out"]).inc();
                metrics.bytes.with_label_values(&["out"]).inc_by(n);
            }
            Err(_) => metrics
                .dropped
                .with_label_values(&["peer_queue_full"])
                .inc(),
        }
    }
}

fn spawn_peer_drain(
    rt: tokio::runtime::Handle,
    pool: ConnPool,
    peer: EndpointId,
    rx: Receiver<Bytes>,
    metrics: AgentMetrics,
) {
    rt.spawn(async move {
        let conn = match pool.get(peer).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%peer, ?e, "peer drain: dial failed");
                return;
            }
        };
        loop {
            match rx.try_recv() {
                Ok(pkt) => {
                    if let Err(e) = send_datagram(&conn, pkt) {
                        tracing::warn!(%peer, ?e, "peer drain: send failed");
                        metrics.dropped.with_label_values(&["send_failed"]).inc();
                        break;
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }
    });
}
