//! Per-peer Byte-DRR outbound scheduler for mesh IP datagrams.
//!
//! One canonical QUIC connection per peer; latency / normal / bulk queues feed a
//! single sender. Deficit is counted in **bytes**, not packets.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use dashmap::DashMap;
use iroh::EndpointId;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tun_rs::AsyncDevice;
use tunnet_core::ConnPool;
use tunnet_core::iroh_pool::DatagramTooLarge;

use crate::metrics::AgentMetrics;
use tunnet_common::packet::{Packet, TcpFlags, Transport};

const CAP_LATENCY: usize = 64;
const CAP_NORMAL: usize = 256;
const CAP_BULK: usize = 512;

/// Packet quantum is one configured TUN MTU.
fn quanta(mtu: usize) -> (usize, usize, usize) {
    (8 * mtu, 4 * mtu, mtu)
}

/// Packets at or above this fraction of MTU are treated as bulk.
fn bulk_threshold(mtu: usize) -> usize {
    mtu.saturating_sub(80).max(512)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Latency,
    Normal,
    Bulk,
}

impl Class {
    fn quantum(self, mtu: usize) -> usize {
        let (lat, norm, bulk) = quanta(mtu);
        match self {
            Self::Latency => lat,
            Self::Normal => norm,
            Self::Bulk => bulk,
        }
    }
}

/// Classify using validated parser metadata (not backing-buffer length).
pub fn classify(packet: &Packet<'_>, mtu: u16) -> Class {
    let mtu = mtu.max(576) as usize;
    let bulk = bulk_threshold(mtu);
    let size = packet.wire_len;
    match packet.transport {
        Transport::Icmpv4 { .. } | Transport::Icmpv6 { .. } => Class::Latency,
        Transport::Tcp {
            flags,
            payload_len,
            src_port,
            dst_port,
            ..
        } => {
            if flags.0 & (TcpFlags::SYN | TcpFlags::FIN | TcpFlags::RST) != 0 {
                return Class::Latency;
            }
            if flags.ack() && payload_len == 0 {
                return Class::Latency;
            }
            if src_port == 53 || dst_port == 53 {
                return Class::Latency;
            }
            if size >= bulk {
                return Class::Bulk;
            }
            Class::Normal
        }
        Transport::Udp {
            src_port, dst_port, ..
        } => {
            if src_port == 53 || dst_port == 53 {
                return Class::Latency;
            }
            if size >= bulk {
                Class::Bulk
            } else {
                Class::Normal
            }
        }
        Transport::LaterFragment { .. } | Transport::Other { .. } => {
            if size >= bulk {
                Class::Bulk
            } else {
                Class::Normal
            }
        }
    }
}

struct PeerState {
    latency: Mutex<VecDeque<Bytes>>,
    normal: Mutex<VecDeque<Bytes>>,
    bulk: Mutex<VecDeque<Bytes>>,
    notify: Notify,
    running: AtomicBool,
}

impl PeerState {
    fn new() -> Self {
        Self {
            latency: Mutex::new(VecDeque::new()),
            normal: Mutex::new(VecDeque::new()),
            bulk: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            running: AtomicBool::new(false),
        }
    }

    fn queue(&self, class: Class) -> &Mutex<VecDeque<Bytes>> {
        match class {
            Class::Latency => &self.latency,
            Class::Normal => &self.normal,
            Class::Bulk => &self.bulk,
        }
    }

    fn cap(class: Class) -> usize {
        match class {
            Class::Latency => CAP_LATENCY,
            Class::Normal => CAP_NORMAL,
            Class::Bulk => CAP_BULK,
        }
    }

    fn is_empty(&self) -> bool {
        self.latency.lock().is_empty()
            && self.normal.lock().is_empty()
            && self.bulk.lock().is_empty()
    }

    /// Enqueue with drop policy: prefer dropping bulk, then normal, before latency.
    fn try_enqueue(&self, class: Class, packet: Bytes) -> Result<(), ()> {
        {
            let mut q = self.queue(class).lock();
            if q.len() < Self::cap(class) {
                q.push_back(packet);
                return Ok(());
            }
        }
        // Target class full: try to free bulk first, then normal.
        if class != Class::Bulk {
            let mut bulk = self.bulk.lock();
            if !bulk.is_empty() {
                bulk.pop_front();
                drop(bulk);
                let mut q = self.queue(class).lock();
                if q.len() < Self::cap(class) {
                    q.push_back(packet);
                    return Ok(());
                }
            }
        }
        if class == Class::Latency {
            let mut normal = self.normal.lock();
            if !normal.is_empty() {
                normal.pop_front();
                drop(normal);
                let mut q = self.latency.lock();
                if q.len() < CAP_LATENCY {
                    q.push_back(packet);
                    return Ok(());
                }
            }
        }
        Err(())
    }
}

/// Fan-out TUN packets to per-peer Byte-DRR senders.
#[derive(Clone)]
pub struct OutboundScheduler {
    peers: Arc<DashMap<EndpointId, Arc<PeerState>>>,
    pool: ConnPool,
    metrics: AgentMetrics,
    mtu: u16,
    tun: Arc<AsyncDevice>,
}

impl OutboundScheduler {
    /// `tun` receives ICMP "fragmentation needed" for packets the connection
    /// cannot carry, so senders shrink their path MTU instead of retransmitting
    /// into a drop.
    pub fn new(pool: ConnPool, metrics: AgentMetrics, mtu: u16, tun: Arc<AsyncDevice>) -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            pool,
            metrics,
            mtu: mtu.max(576),
            tun,
        }
    }

    pub fn enqueue(&self, peer: EndpointId, class: Class, packet: Bytes) {
        let state = self
            .peers
            .entry(peer)
            .or_insert_with(|| Arc::new(PeerState::new()))
            .clone();

        if state.try_enqueue(class, packet).is_err() {
            self.metrics.dropped_inc(match class {
                Class::Latency => "qos_latency_full",
                Class::Normal => "qos_normal_full",
                Class::Bulk => "qos_bulk_full",
            });
            return;
        }

        if !state.running.swap(true, Ordering::AcqRel) {
            let pool = self.pool.clone();
            let metrics = self.metrics.clone();
            let peers = self.peers.clone();
            let mtu = self.mtu;
            let tun = self.tun.clone();
            tokio::spawn(async move {
                run_peer_sender(peer, state, pool, metrics, mtu, tun).await;
                peers.remove(&peer);
            });
        } else {
            state.notify.notify_one();
        }
    }
}

async fn run_peer_sender(
    peer: EndpointId,
    state: Arc<PeerState>,
    pool: ConnPool,
    metrics: AgentMetrics,
    mtu: u16,
    tun: Arc<AsyncDevice>,
) {
    let mut deficit = [0usize; 3]; // latency, normal, bulk
    loop {
        let mut sent_any = false;
        for (idx, class) in [Class::Latency, Class::Normal, Class::Bulk]
            .into_iter()
            .enumerate()
        {
            {
                let q = state.queue(class).lock();
                if q.is_empty() {
                    deficit[idx] = 0;
                    continue;
                }
            }
            deficit[idx] = deficit[idx].saturating_add(class.quantum(mtu as usize));
            loop {
                let packet = {
                    let mut q = state.queue(class).lock();
                    let Some(head) = q.front() else { break };
                    if head.len() > deficit[idx] {
                        break;
                    }
                    q.pop_front().expect("front checked")
                };
                let n = packet.len();
                deficit[idx] -= n;
                sent_any = true;
                match pool.send_or_buffer(peer, packet.clone()).await {
                    Ok(()) => {
                        metrics.packets_inc("out");
                        metrics.bytes_add("out", n as u64);
                        pool.record_bytes_out(peer, n as u64);
                    }
                    Err(e) => match e.downcast_ref::<DatagramTooLarge>() {
                        Some(too_large) => {
                            metrics.dropped_inc("datagram_too_large");
                            let mtu = u16::try_from(too_large.max).unwrap_or(u16::MAX);
                            if let Some(ptb) =
                                tunnet_common::packet::synthesize_frag_needed(&packet, mtu)
                            {
                                let _ = tun.send(&ptb).await;
                            }
                        }
                        None => {
                            tracing::debug!(%peer, ?e, "send/buffer failed");
                            metrics.dropped_inc("send_failed");
                        }
                    },
                }
            }
        }

        if state.is_empty() {
            // Wait for more work or exit if idle after notify timeout.
            tokio::select! {
                _ = state.notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if state.is_empty() {
                        state.running.store(false, Ordering::Release);
                        // Race: packet enqueued after is_empty check.
                        if !state.is_empty()
                            && !state.running.swap(true, Ordering::AcqRel)
                        {
                            continue;
                        }
                        if state.is_empty() {
                            return;
                        }
                    }
                }
            }
            if !sent_any && state.is_empty() {
                // Spurious wake with empty queues.
            }
        }
    }
}

/// Run one Byte-DRR round over in-memory queues (unit tests / saturation checks).
#[cfg(test)]
fn drr_round_drain(
    latency: &mut VecDeque<Bytes>,
    normal: &mut VecDeque<Bytes>,
    bulk: &mut VecDeque<Bytes>,
    deficit: &mut [usize; 3],
    out: &mut Vec<(Class, usize)>,
) {
    for (idx, (class, q)) in [
        (Class::Latency, &mut *latency),
        (Class::Normal, &mut *normal),
        (Class::Bulk, &mut *bulk),
    ]
    .into_iter()
    .enumerate()
    {
        if q.is_empty() {
            deficit[idx] = 0;
            continue;
        }
        deficit[idx] = deficit[idx].saturating_add(class.quantum(1280));
        while let Some(head) = q.front() {
            if head.len() > deficit[idx] {
                break;
            }
            let pkt = q.pop_front().expect("front");
            deficit[idx] -= pkt.len();
            out.push((class, pkt.len()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(n: usize) -> Bytes {
        Bytes::from(vec![0u8; n])
    }

    #[test]
    fn byte_drr_prefers_latency_but_bulk_progresses() {
        let mut latency = VecDeque::from([pkt(100), pkt(100), pkt(100)]);
        let mut normal: VecDeque<Bytes> = VecDeque::new();
        let mut bulk = VecDeque::from([pkt(1200), pkt(1200), pkt(1200)]);
        let mut deficit = [0usize; 3];
        let mut out = Vec::new();

        drr_round_drain(&mut latency, &mut normal, &mut bulk, &mut deficit, &mut out);

        let lat_bytes: usize = out
            .iter()
            .filter(|(c, _)| *c == Class::Latency)
            .map(|(_, n)| n)
            .sum();
        let bulk_bytes: usize = out
            .iter()
            .filter(|(c, _)| *c == Class::Bulk)
            .map(|(_, n)| n)
            .sum();
        assert!(lat_bytes >= 300, "latency should drain small packets");
        assert!(
            bulk_bytes >= 1200,
            "bulk must still send at least one quantum"
        );
        assert!(latency.is_empty());
        assert_eq!(bulk.len(), 2);
    }

    #[test]
    fn empty_queue_zeros_deficit() {
        let mut latency: VecDeque<Bytes> = VecDeque::new();
        let mut normal: VecDeque<Bytes> = VecDeque::new();
        let mut bulk: VecDeque<Bytes> = VecDeque::new();
        let mut deficit = [50_000, 0, 0];
        let mut out = Vec::new();
        drr_round_drain(&mut latency, &mut normal, &mut bulk, &mut deficit, &mut out);
        assert_eq!(deficit[0], 0);
        assert!(out.is_empty());
    }

    #[test]
    fn classifies_from_validated_packets() {
        let icmp = {
            let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
                .icmpv4_echo_request(1, 1);
            let mut o = Vec::new();
            b.write(&mut o, &[]).unwrap();
            o
        };
        let dns = {
            let b =
                etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 53);
            let mut o = Vec::new();
            b.write(&mut o, &[0; 32]).unwrap();
            o
        };
        let large = {
            let b =
                etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 5201);
            let mut o = Vec::new();
            b.write(&mut o, &[0; 1200]).unwrap();
            o
        };
        let ordinary = {
            let b =
                etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
            let mut o = Vec::new();
            b.write(&mut o, &[0; 200]).unwrap();
            o
        };
        assert_eq!(
            classify(&tunnet_common::packet::parse(&icmp).unwrap(), 1280),
            Class::Latency
        );
        assert_eq!(
            classify(&tunnet_common::packet::parse(&dns).unwrap(), 1280),
            Class::Latency
        );
        assert_eq!(
            classify(&tunnet_common::packet::parse(&large).unwrap(), 1280),
            Class::Bulk
        );
        assert_eq!(
            classify(&tunnet_common::packet::parse(&ordinary).unwrap(), 1280),
            Class::Normal
        );

        let mut padded = ordinary.clone();
        padded.extend_from_slice(&[0u8; 2000]);
        assert_eq!(
            classify(&tunnet_common::packet::parse(&padded).unwrap(), 1280),
            Class::Normal,
            "trailing buffer must not change class"
        );
        assert_eq!(
            classify(&tunnet_common::packet::parse(&large).unwrap(), 9000),
            Class::Normal,
            "configured MTU raises bulk threshold"
        );
    }
}
