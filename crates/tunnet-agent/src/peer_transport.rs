//! One task owns each peer's connection, reader, sender, and bounded TX queue.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use tunnet_common::packet::{LogicalPacket, PacketOwner, SINGLE_OVERHEAD, encode_single_prefix};
use tunnet_core::peers::PeerMembershipState;

use crate::metrics::AgentMetrics;
use crate::tun_io::{InboundContext, InboundDeps, serve_tunnel_connection};
use crate::tun_writer::TunWriterHandle;

const QUEUE_BYTES: usize = 256 * 1024;
const QUEUE_PACKETS: usize = 512;

struct Queued {
    packet: LogicalPacket,
    member: Arc<PeerMembershipState>,
    epoch: u64,
    loss: Option<PacketLoss>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Queued>,
    bytes: usize,
}

#[derive(Clone)]
pub struct PeerSender {
    queue: Arc<Mutex<Queue>>,
    ready: Arc<Notify>,
    cancel: CancellationToken,
    metrics: AgentMetrics,
}

impl PeerSender {
    pub fn enqueue(&self, member: &Arc<PeerMembershipState>, packet: LogicalPacket) {
        let mut queue = self.queue.lock();
        if self.cancel.is_cancelled() {
            self.metrics.dropped_inc("generation_end");
            return;
        }
        if queue.bytes + packet.len() > QUEUE_BYTES || queue.packets.len() == QUEUE_PACKETS {
            self.metrics.dropped_inc("peer_queue_full");
            return;
        }
        let len = packet.len();
        queue.bytes += len;
        queue.packets.push_back(Queued {
            packet,
            member: member.clone(),
            epoch: member.epoch.load(Ordering::Acquire),
            loss: None,
        });
        self.metrics.queue_add(1, len as i64);
        self.ready.notify_one();
    }

    async fn next(&self) -> Queued {
        loop {
            let notified = self.ready.notified();
            {
                let mut queue = self.queue.lock();
                if let Some(mut packet) = queue.packets.pop_front() {
                    queue.bytes -= packet.packet.len();
                    self.metrics.queue_add(-1, -(packet.packet.len() as i64));
                    packet.loss = Some(PacketLoss {
                        counter: self.metrics.interrupted_counter(),
                        armed: true,
                    });
                    return packet;
                }
            }
            notified.await;
        }
    }

    fn clear(&self) {
        let mut queue = self.queue.lock();
        self.metrics
            .queue_add(-(queue.packets.len() as i64), -(queue.bytes as i64));
        self.metrics
            .dropped_add("generation_end", queue.packets.len() as u64);
        queue.packets.clear();
        queue.bytes = 0;
    }
}

struct Peer {
    sender: PeerSender,
    incoming: mpsc::Sender<Candidate>,
    task: tokio::task::JoinHandle<()>,
}

/// Closing on drop also covers cancellation during handoff and task panics.
struct Candidate {
    conn: Connection,
    dialed: bool,
}

impl Drop for Candidate {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"connection_released");
    }
}

struct Inner {
    peers: Mutex<HashMap<EndpointId, Peer>>,
    endpoint: Endpoint,
    context: InboundContext,
    writer: TunWriterHandle,
    cancel: CancellationToken,
    fatal: Arc<dyn Fn(String) + Send + Sync>,
}

#[derive(Clone)]
pub struct PeerTransports(Arc<Inner>);

impl PeerTransports {
    pub fn new(
        endpoint: Endpoint,
        context: InboundContext,
        writer: TunWriterHandle,
        cancel: CancellationToken,
        fatal: Arc<dyn Fn(String) + Send + Sync>,
    ) -> Self {
        Self(Arc::new(Inner {
            peers: Mutex::new(HashMap::new()),
            endpoint,
            context,
            writer,
            cancel,
            fatal,
        }))
    }

    fn peer(&self, endpoint: EndpointId) -> Option<(PeerSender, mpsc::Sender<Candidate>)> {
        let mut peers = self.0.peers.lock();
        if self.0.cancel.is_cancelled() {
            return None;
        }
        if let Some(peer) = peers.get(&endpoint).filter(|peer| !peer.task.is_finished()) {
            return Some((peer.sender.clone(), peer.incoming.clone()));
        }
        peers.retain(|_, p| !p.task.is_finished());
        let peer = peers.entry(endpoint).or_insert_with(|| {
            let sender = PeerSender {
                queue: Arc::new(Mutex::new(Queue::default())),
                ready: Arc::new(Notify::new()),
                cancel: self.0.cancel.child_token(),
                metrics: self.0.context.metrics.clone(),
            };
            let (incoming, rx) = mpsc::channel(1);
            let local = self.0.endpoint.clone();
            let context = self.0.context.clone();
            let writer = self.0.writer.clone();
            let worker_sender = sender.clone();
            let fatal = self.0.fatal.clone();
            let task = tokio::spawn(async move {
                let result = std::panic::AssertUnwindSafe(run_peer(
                    local,
                    endpoint,
                    worker_sender.clone(),
                    rx,
                    context,
                    writer,
                ))
                .catch_unwind()
                .await;
                worker_sender.clear();
                if result.is_err() && !worker_sender.cancel.is_cancelled() {
                    fatal(format!("peer transport {endpoint} panicked"));
                }
                worker_sender.cancel.cancel();
            });
            Peer {
                sender,
                incoming,
                task,
            }
        });
        Some((peer.sender.clone(), peer.incoming.clone()))
    }

    pub fn accept(&self, conn: Connection) {
        let candidate = Candidate {
            conn,
            dialed: false,
        };
        let remote = candidate.conn.remote_id();
        if !self
            .0
            .context
            .routes
            .peer_registry()
            .has_any_membership(remote)
            || !self.0.context.acl.allow_inbound_peer(&remote.to_string())
        {
            return;
        }
        if let Some((_, incoming)) = self.peer(candidate.conn.remote_id()) {
            let _ = incoming.try_send(candidate);
        }
    }

    pub fn connected_count(&self) -> u32 {
        self.0.context.routes.peer_registry().heartbeat_counters().0
    }

    pub async fn shutdown(&self) {
        self.0.cancel.cancel();
        let peers = std::mem::take(&mut *self.0.peers.lock());
        for (_, peer) in peers {
            let mut task = peer.task;
            if tokio::time::timeout(Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
            peer.sender.clear();
        }
    }
}

pub fn enqueue_packet(
    transports: &PeerTransports,
    member: &Arc<PeerMembershipState>,
    packet: LogicalPacket,
) {
    let endpoint = member.identity.read().endpoint;
    if let Some((sender, _)) = transports.peer(endpoint) {
        sender.enqueue(member, packet);
    }
}

fn prefer_candidate(
    local: EndpointId,
    remote: EndpointId,
    current_dialed: bool,
    candidate_dialed: bool,
) -> bool {
    let preferred = local < remote;
    if current_dialed != candidate_dialed {
        candidate_dialed == preferred
    } else {
        !candidate_dialed
    }
}

async fn run_peer(
    endpoint: Endpoint,
    remote: EndpointId,
    sender: PeerSender,
    mut incoming: mpsc::Receiver<Candidate>,
    context: InboundContext,
    writer: TunWriterHandle,
) {
    let stats = context.routes.peer_registry().ensure_transport(remote);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut current = None;
    let mut first = None;
    loop {
        if sender.cancel.is_cancelled()
            || !context.routes.peer_registry().has_any_membership(remote)
        {
            return;
        }
        if current.is_none() {
            tokio::select! {
                biased;
                _ = sender.cancel.cancelled() => return,
                candidate = incoming.recv() => current = candidate,
                packet = sender.next() => first = Some(packet),
                _ = tick.tick() => continue,
            }
            if current.is_none() {
                metrics::counter!("tunnet_dial_attempts_total").increment(1);
                let dial = tokio::time::timeout(
                    Duration::from_secs(5),
                    endpoint.connect(remote, tunnet_common::TUNNEL_ALPN),
                );
                tokio::select! {
                    biased;
                    _ = sender.cancel.cancelled() => return,
                    candidate = incoming.recv() => current = candidate,
                    result = dial => match result {
                        Ok(Ok(conn)) => current = Some(Candidate { conn, dialed: true }),
                        _ => {
                            metrics::counter!("tunnet_dial_failures_total").increment(1);
                            sender.metrics.dropped_inc("dial_failed");
                            if let Some(item) = first.as_mut() { item.loss.as_mut().expect("dequeued").armed = false; }
                            first = None;
                            continue;
                        }
                    }
                }
            }
        }
        let replacement = {
            let Some(chosen) = current.as_ref() else {
                continue;
            };
            let _observation = Observation::new(stats.clone(), sender.metrics.clone());
            stats.relay.store(
                chosen
                    .conn
                    .paths()
                    .iter()
                    .any(|p| p.is_selected() && p.is_relay()),
                Ordering::Relaxed,
            );
            let mut paths = chosen.conn.path_events();
            let reader = serve_tunnel_connection(InboundDeps {
                conn: chosen.conn.clone(),
                tun_writer: writer.clone(),
                sender: sender.clone(),
                cancel: sender.cancel.clone(),
                context: context.clone(),
            });
            let writer_future = send_packets(&chosen.conn, &sender, &context.pool, first.take());
            tokio::pin!(reader, writer_future);
            let replacement = loop {
                tokio::select! {
                    biased;
                    _ = sender.cancel.cancelled() => return,
                    candidate = incoming.recv() => {
                        let Some(candidate) = candidate else { return; };
                        if prefer_candidate(endpoint.id(), remote, chosen.dialed, candidate.dialed) {
                            break Some(candidate);
                        }
                    }
                    _ = tick.tick() => {
                        if !context.routes.peer_registry().has_any_membership(remote) { return; }
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                        if !context.pool.peer_keep_alive(remote) && now.saturating_sub(stats.last_activity_ms.load(Ordering::Relaxed)) > context.pool.idle_timeout().as_millis() as u64 { break None; }
                    }
                    Some(_) = paths.next() => {
                        stats.relay.store(chosen.conn.paths().iter().any(|p| p.is_selected() && p.is_relay()), Ordering::Relaxed);
                    }
                    result = &mut reader => {
                        if matches!(result, crate::tun_io::ReaderExit::ConnFailed) {
                            metrics::counter!("tunnet_quic_connection_failures_total").increment(1);
                        }
                        break None;
                    },
                    _ = &mut writer_future => break None,
                }
            };
            // Dropping these futures drops the current packet. Nothing is replayed.
            replacement
        };
        current = replacement;
    }
}

async fn send_packets(
    conn: &Connection,
    sender: &PeerSender,
    pool: &tunnet_core::ConnPool,
    mut first: Option<Queued>,
) {
    loop {
        let mut item = match first.take() {
            Some(item) => item,
            None => sender.next().await,
        };
        if item.member.epoch.load(Ordering::Acquire) != item.epoch {
            item.loss.as_mut().expect("dequeued").armed = false;
            sender.metrics.dropped_inc("membership_revoked");
            continue;
        }
        let net = item.member.identity.read().network_id;
        let len = item.packet.len();
        let frame = match item.packet.owner {
            PacketOwner::Pooled(mut buffer) => {
                encode_single_prefix(
                    buffer.header_slot(SINGLE_OVERHEAD).expect("frame headroom"),
                    net,
                );
                Bytes::from_owner(buffer)
            }
            PacketOwner::Shared(bytes) => {
                let mut frame = Vec::with_capacity(SINGLE_OVERHEAD + bytes.len());
                frame.resize(SINGLE_OVERHEAD, 0);
                encode_single_prefix(&mut frame, net);
                frame.extend_from_slice(&bytes);
                Bytes::from(frame)
            }
        };
        if conn.max_datagram_size().is_none_or(|max| frame.len() > max) {
            item.loss.as_mut().expect("dequeued").armed = false;
            sender.metrics.dropped_inc("datagram_too_large");
            continue;
        }
        let frame_len = frame.len();
        let metered = pool.uses_cloud_relay(conn);
        if conn.send_datagram_wait(frame).await.is_err() {
            metrics::counter!("tunnet_quic_connection_failures_total").increment(1);
            return;
        }
        item.loss.as_mut().expect("dequeued").armed = false;
        if metered {
            pool.cloud_relay_meter().record(len as u64);
        }
        item.member.transport.record_tx(len as u64);
        sender.metrics.packets_inc("out");
        sender.metrics.bytes_add("out", len as u64);
        sender.metrics.overlay_tx_logical_add(1);
        sender.metrics.overlay_tx_datagrams_add(1, frame_len);
    }
}

struct PacketLoss {
    counter: metrics::Counter,
    armed: bool,
}
impl Drop for PacketLoss {
    fn drop(&mut self) {
        if self.armed {
            self.counter.increment(1);
        }
    }
}
struct Observation {
    stats: Arc<tunnet_core::peers::PeerTransportState>,
    metrics: AgentMetrics,
}
impl Observation {
    fn new(stats: Arc<tunnet_core::peers::PeerTransportState>, metrics: AgentMetrics) -> Self {
        stats.connected.store(true, Ordering::Relaxed);
        stats.touch();
        metrics.active_conns_inc();
        Self { stats, metrics }
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        self.stats.connected.store(false, Ordering::Relaxed);
        self.metrics.active_conns_dec();
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        for peer in self.peers.get_mut().values() {
            peer.task.abort();
            peer.sender.clear();
        }
    }
}

#[cfg(test)]
#[path = "peer_transport_tests.rs"]
mod tests;
