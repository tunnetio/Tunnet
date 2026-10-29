use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::FutureExt;
use iroh::TransportAddr;
use iroh::endpoint::{
    ConnectError, ConnectWithOptsError, ConnectingError, Connection, ConnectionError,
};
use iroh::{Endpoint, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cloud_relay_meter::CloudRelayMeter;
use crate::transport_auth::{TransportAuth, is_authorization_close};

pub(crate) const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_BASE: Duration = Duration::from_millis(200);
const BACKOFF_CAP: Duration = Duration::from_secs(30);
const REMOTE_RETRY_BASE_SECS: u64 = 10;
const REMOTE_RETRY_CAP: Duration = Duration::from_secs(300);
const REMOTE_RETRY_MAX_SHIFT: u32 = 5;

pub const MAX_QUEUE_PACKETS: usize = 512;
pub const MAX_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub const QUEUE_TTL: Duration = Duration::from_secs(30);
const SEND_BATCH_MAX: usize = 32;

pub(crate) enum DialFailure {
    LocalDenied,
    RemoteRejected,
    Transient,
}

pub(crate) fn backoff_delay(step: u32) -> Duration {
    let shift = step.min(8);
    let base = BACKOFF_BASE.as_millis() as u64 * (1u64 << shift);
    let capped = base.min(BACKOFF_CAP.as_millis() as u64);
    let jitter = rand::random::<u64>() % (capped / 2 + 1);
    Duration::from_millis(capped / 2 + jitter)
}

pub(crate) fn remote_retry_delay(elapsed_since_first: Duration) -> Duration {
    let shift =
        (elapsed_since_first.as_secs() / REMOTE_RETRY_BASE_SECS).min(REMOTE_RETRY_MAX_SHIFT as u64);
    let base = REMOTE_RETRY_BASE_SECS * 1000 * (1u64 << shift);
    let capped = base.min(REMOTE_RETRY_CAP.as_millis() as u64);
    let jitter = rand::random::<u64>() % (capped / 2 + 1);
    Duration::from_millis(capped / 2 + jitter)
}

pub(crate) fn classify_connect_error(e: &ConnectError) -> DialFailure {
    match e {
        ConnectError::Connect {
            source: ConnectWithOptsError::LocallyRejected { .. },
            ..
        }
        | ConnectError::Connecting {
            source: ConnectingError::LocallyRejected { .. },
            ..
        } => DialFailure::LocalDenied,
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => match source {
            _ if is_auth_close_error(source) => DialFailure::RemoteRejected,
            _ => DialFailure::Transient,
        },
        _ => DialFailure::Transient,
    }
}

pub(crate) fn is_auth_close_error(e: &ConnectionError) -> bool {
    matches!(
        e,
        ConnectionError::ApplicationClosed(close)
            if is_authorization_close(
                u32::try_from(close.error_code.into_inner()).unwrap_or(u32::MAX),
                close.reason.as_ref(),
            )
    )
}

pub(crate) fn prefer_incoming(
    local: EndpointId,
    peer: EndpointId,
    existing_opened_by_us: bool,
    incoming_opened_by_us: bool,
) -> bool {
    let want_opened_by_us = local < peer;
    let existing_ok = existing_opened_by_us == want_opened_by_us;
    let incoming_ok = incoming_opened_by_us == want_opened_by_us;
    matches!((existing_ok, incoming_ok), (false, true))
}

fn selected_path_kind(conn: Option<&Connection>) -> String {
    let Some(conn) = conn else {
        return "unknown".into();
    };
    let paths = conn.paths();
    let Some(path) = paths.iter().find(|p| p.is_selected()) else {
        return "unknown".into();
    };
    if path.is_relay() {
        "relay".into()
    } else {
        "direct".into()
    }
}

fn selected_path_is_cloud_relay(conn: &Connection, urls: &HashSet<String>) -> bool {
    let paths = conn.paths();
    let Some(path) = paths.iter().find(|p| p.is_selected()) else {
        return false;
    };
    if !path.is_relay() {
        return false;
    }
    match path.remote_addr() {
        TransportAddr::Relay(url) => urls.contains(url.as_str().trim_end_matches('/')),
        _ => false,
    }
}

use crate::forward::snapshot::AuthorizationEpoch;
use crate::forward::{ForwardingStore, unframe};
use crate::transport_auth::{CLOSE_NOT_MEMBER, CLOSE_NOT_MEMBER_REASON};
use tokio_util::task::TaskTracker;
pub type FeedbackHook = Arc<dyn Fn(Bytes) -> bool + Send + Sync>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Admitted,
    QueueFull,
    Denied,
    Closed,
}
pub struct SendBatchOutcome {
    pub admitted: usize,
    pub admitted_bytes: u64,
    pub queue_full: usize,
    pub blocked: bool,
    pub closed: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct PeerConnSnapshot {
    pub state: String,
    pub keep_alive: bool,
    pub last_activity_secs_ago: u64,
    pub live: bool,
    pub path: String,
}
pub use tunnet_common::local_api::PeerTransportStats;
#[derive(Debug, Clone, Serialize)]
pub struct SessionStats {
    pub reconnect_attempts: u64,
    pub reconnect_success: u64,
    pub reconnect_fail: u64,
    pub packets_buffered: u64,
    pub packets_dropped_timeout: u64,
    pub packets_dropped_blocked: u64,
    pub dials_suppressed: u64,
    pub reconnect_latency_avg_us: u64,
    pub reconnect_latency_max_us: u64,
    pub queue_packets: usize,
    pub queue_bytes: usize,
    pub quic_accepted_packets: u64,
    pub quic_accepted_bytes: u64,
    pub transport_drops: u64,
    pub oversize_packets: u64,
    pub pmtu_feedback_drops: u64,
}
#[derive(Default)]
struct SessionMetrics {
    reconnect_attempts: AtomicU64,
    reconnect_success: AtomicU64,
    reconnect_fail: AtomicU64,
    packets_buffered: AtomicU64,
    packets_dropped_timeout: AtomicU64,
    packets_dropped_blocked: AtomicU64,
    packets_dropped_transport: AtomicU64,
    dials_suppressed: AtomicU64,
    reconnect_latency_sum_us: AtomicU64,
    reconnect_latency_max_us: AtomicU64,
    quic_accepted_packets: AtomicU64,
    quic_accepted_bytes: AtomicU64,
    oversize_packets: AtomicU64,
    pmtu_feedback_drops: AtomicU64,
}
pub struct AuthorizedPacket {
    pub packet: Bytes,
    pub epoch: AuthorizationEpoch,
    pub local_posture: Arc<bool>,
    pub proof: Option<crate::forward::PostureAuthorization>,
}

struct QueuedPacket {
    id: u64,
    bytes: Bytes,
    network: uuid::Uuid,
    epoch: AuthorizationEpoch,
    posture: Arc<bool>,
    proof: Option<crate::forward::PostureAuthorization>,
    enqueued_at: Instant,
}
#[derive(Default)]
struct Retry {
    step: u32,
    rejected: Option<(u64, Instant)>,
    until: Option<Instant>,
    blocked: Option<u64>,
}
impl Retry {
    fn failed(&mut self, failure: DialFailure, generation: u64, now: Instant) {
        match failure {
            DialFailure::LocalDenied => self.blocked = Some(generation),
            DialFailure::Transient => {
                self.until = Some(now + backoff_delay(self.step));
                self.step = self.step.saturating_add(1);
            }
            DialFailure::RemoteRejected => {
                let first = self
                    .rejected
                    .filter(|(g, _)| *g == generation)
                    .map_or(now, |(_, first)| first);
                self.rejected = Some((generation, first));
                self.until = Some(now + remote_retry_delay(now.saturating_duration_since(first)));
            }
        }
    }
}
#[derive(Clone)]
struct Installed {
    conn: Connection,
    opened_by_us: bool,
    token: u64,
    cancel: CancellationToken,
}
struct SessionData {
    queue: VecDeque<QueuedPacket>,
    queue_bytes: usize,
    next_packet_id: u64,
    conn: Option<Installed>,
    token: u64,
    retry: Retry,
    connecting: bool,
    worker_running: bool,
    last_activity: Instant,
}
impl SessionData {
    fn clear_queue(&mut self) -> usize {
        let count = self.queue.len();
        self.queue.clear();
        self.queue_bytes = 0;
        count
    }
    fn pop(&mut self) -> Option<QueuedPacket> {
        let packet = self.queue.pop_front()?;
        self.queue_bytes -= packet.bytes.len();
        Some(packet)
    }
    fn close(&mut self, code: u32, reason: &[u8]) {
        self.token = self
            .token
            .checked_add(1)
            .expect("connection identity exhausted");
        if let Some(old) = self.conn.take() {
            old.cancel.cancel();
            old.conn.close(code.into(), reason);
        }
        self.connecting = false;
    }
}
struct PeerSession {
    peer: EndpointId,
    data: Mutex<SessionData>,
    notify: Notify,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}
impl PeerSession {
    fn new(peer: EndpointId) -> Self {
        Self {
            peer,
            data: Mutex::new(SessionData {
                queue: VecDeque::new(),
                queue_bytes: 0,
                next_packet_id: 0,
                conn: None,
                token: 0,
                retry: Retry::default(),
                connecting: false,
                worker_running: false,
                last_activity: Instant::now(),
            }),
            notify: Notify::new(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }
}
pub struct SessionCtl {
    peer: EndpointId,
    generation: u64,
    cancel: CancellationToken,
}
impl SessionCtl {
    pub fn peer(&self) -> EndpointId {
        self.peer
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }
}
pub type RecvHook = Arc<dyn Fn(EndpointId, Connection, SessionCtl) -> JoinHandle<()> + Send + Sync>;
struct ActiveGen {
    generation: u64,
    cancel: CancellationToken,
    hook: RecvHook,
    feedback: FeedbackHook,
    tasks: TaskTracker,
}
#[derive(Default)]
struct Lifecycle {
    active: Option<ActiveGen>,
    stopping: bool,
}
struct PeerManagerInner {
    endpoint: Endpoint,
    alpn: &'static [u8],
    sessions: DashMap<EndpointId, Arc<PeerSession>>,
    gate: RwLock<Option<TransportAuth>>,
    forwarding: RwLock<Option<ForwardingStore>>,
    metrics: Arc<SessionMetrics>,
    cloud_relay_meter: CloudRelayMeter,
    cloud_relay_urls: Arc<RwLock<HashSet<String>>>,
    keep_alive: Arc<AtomicBool>,
    keep_alive_peers: Arc<DashMap<EndpointId, ()>>,
    lifecycle: Mutex<Lifecycle>,
    shutdown: tokio::sync::Mutex<()>,
}
impl Drop for PeerManagerInner {
    fn drop(&mut self) {
        if let Some(active) = self.lifecycle.get_mut().active.take() {
            active.cancel.cancel();
            active.tasks.close();
        }
        for session in self.sessions.iter() {
            session.data.lock().close(0, b"dataplane_down");
        }
    }
}
#[derive(Clone)]
pub struct PeerManager {
    inner: Arc<PeerManagerInner>,
}
#[derive(Clone)]
pub struct WeakPeerManager {
    inner: std::sync::Weak<PeerManagerInner>,
}
impl WeakPeerManager {
    pub fn upgrade(&self) -> Option<PeerManager> {
        self.inner.upgrade().map(|inner| PeerManager { inner })
    }
}
impl PeerManager {
    pub fn downgrade(&self) -> WeakPeerManager {
        WeakPeerManager {
            inner: Arc::downgrade(&self.inner),
        }
    }
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        Self {
            inner: Arc::new(PeerManagerInner {
                endpoint,
                alpn,
                sessions: DashMap::new(),
                gate: RwLock::new(None),
                forwarding: RwLock::new(None),
                metrics: Arc::new(SessionMetrics::default()),
                cloud_relay_meter: CloudRelayMeter::new(),
                cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
                keep_alive: Arc::new(AtomicBool::new(true)),
                keep_alive_peers: Arc::new(DashMap::new()),
                lifecycle: Mutex::new(Lifecycle::default()),
                shutdown: tokio::sync::Mutex::new(()),
            }),
        }
    }
    pub fn set_transport_auth(&self, auth: TransportAuth) {
        let lifecycle = self.inner.lifecycle.lock();
        assert!(
            lifecycle.active.is_none(),
            "configure auth before activation"
        );
        *self.inner.gate.write() = Some(auth);
    }
    pub fn set_forwarding(&self, forwarding: ForwardingStore) {
        let lifecycle = self.inner.lifecycle.lock();
        assert!(
            lifecycle.active.is_none(),
            "configure forwarding before activation"
        );
        *self.inner.forwarding.write() = Some(forwarding);
    }
    pub fn activate(
        &self,
        generation: u64,
        cancel: CancellationToken,
        hook: RecvHook,
        feedback: FeedbackHook,
    ) -> anyhow::Result<()> {
        let mut lifecycle = self.inner.lifecycle.lock();
        anyhow::ensure!(
            lifecycle.active.is_none() && !lifecycle.stopping,
            "dataplane already active or stopping"
        );
        anyhow::ensure!(!cancel.is_cancelled(), "dataplane cancelled");
        anyhow::ensure!(
            self.inner.gate.read().is_some(),
            "transport authorization absent"
        );
        lifecycle.active = Some(ActiveGen {
            generation,
            cancel,
            hook,
            feedback,
            tasks: TaskTracker::new(),
        });
        Ok(())
    }
    pub async fn deactivate(&self) {
        let _shutdown = self.inner.shutdown.lock().await;
        let active = {
            let mut lifecycle = self.inner.lifecycle.lock();
            lifecycle.stopping = true;
            let active = lifecycle.active.take();
            if let Some(active) = &active {
                active.cancel.cancel();
                active.tasks.close();
            }
            for session in self.inner.sessions.iter() {
                let mut data = session.data.lock();
                data.close(0, b"dataplane_down");
                data.clear_queue();
                session.notify.notify_one();
            }
            active
        };
        if let Some(active) = active {
            active.tasks.wait().await;
        }
        let mut lifecycle = self.inner.lifecycle.lock();
        self.inner.sessions.clear();
        lifecycle.stopping = false;
    }
    fn start_worker(&self, session: &Arc<PeerSession>, active: &ActiveGen, auth: TransportAuth) {
        let mut data = session.data.lock();
        if data.worker_running {
            return;
        }
        data.worker_running = true;
        drop(data);
        let deps = WorkerDeps {
            manager: Arc::downgrade(&self.inner),
            endpoint: self.inner.endpoint.clone(),
            alpn: self.inner.alpn,
            auth,
            forwarding: self.inner.forwarding.read().clone(),
            metrics: self.inner.metrics.clone(),
            urls: self.inner.cloud_relay_urls.clone(),
            meter: self.inner.cloud_relay_meter.clone(),
            keep_alive: self.inner.keep_alive.clone(),
            keep_alive_peers: self.inner.keep_alive_peers.clone(),
            generation: active.generation,
            cancel: active.cancel.child_token(),
            hook: active.hook.clone(),
            feedback: active.feedback.clone(),
        };
        active.tasks.spawn(run_session(session.clone(), deps));
    }
    fn retire_idle(&self, session: &Arc<PeerSession>, generation: u64) -> bool {
        let lifecycle = self.inner.lifecycle.lock();
        if lifecycle
            .active
            .as_ref()
            .is_none_or(|active| active.generation != generation || active.cancel.is_cancelled())
        {
            return false;
        }
        let mut data = session.data.lock();
        if data.conn.is_some() || !data.queue.is_empty() || data.last_activity.elapsed() < QUEUE_TTL
        {
            return false;
        }
        data.worker_running = false;
        data.close(0, b"idle");
        drop(data);
        self.inner
            .sessions
            .remove_if(&session.peer, |_, entry| Arc::ptr_eq(entry, session));
        true
    }
    #[cfg(test)]
    fn send(&self, peer: EndpointId, packet: Bytes) -> SendOutcome {
        Self::single(self.send_batch(peer, vec![packet]))
    }
    pub fn send_authorized(&self, peer: EndpointId, packet: AuthorizedPacket) -> SendOutcome {
        Self::single(self.send_batch_authorized(peer, vec![packet]))
    }
    fn single(out: SendBatchOutcome) -> SendOutcome {
        if out.admitted == 1 {
            SendOutcome::Admitted
        } else if out.closed {
            SendOutcome::Closed
        } else if out.blocked {
            SendOutcome::Denied
        } else {
            SendOutcome::QueueFull
        }
    }
    #[cfg(test)]
    fn send_batch(&self, peer: EndpointId, packets: Vec<Bytes>) -> SendBatchOutcome {
        let forwarding = self.inner.forwarding.read().clone();
        let snapshot = forwarding.as_ref().map(|f| f.load());
        let packets = packets
            .into_iter()
            .filter_map(|p| {
                let (net, _) = unframe(&p).ok()?;
                let s = snapshot.as_ref()?;
                Some(AuthorizedPacket {
                    packet: p,
                    epoch: s.auth_epoch(net),
                    local_posture: s.posture_ok.load_full(),
                    proof: None,
                })
            })
            .collect();
        self.send_batch_authorized(peer, packets)
    }
    pub fn send_batch_authorized(
        &self,
        peer: EndpointId,
        packets: Vec<AuthorizedPacket>,
    ) -> SendBatchOutcome {
        let mut out = SendBatchOutcome {
            admitted: 0,
            admitted_bytes: 0,
            queue_full: 0,
            blocked: false,
            closed: false,
        };
        let lifecycle = self.inner.lifecycle.lock();
        let Some(active) = lifecycle
            .active
            .as_ref()
            .filter(|a| !a.cancel.is_cancelled())
        else {
            out.closed = true;
            return out;
        };
        let Some(auth) = self.inner.gate.read().clone() else {
            out.blocked = true;
            return out;
        };
        let gate = auth.authorization_gate();
        let _authorization = gate.read();
        if !auth.allows(&peer.to_string()) {
            out.blocked = true;
            return out;
        }
        let forwarding = self.inner.forwarding.read();
        let snapshot = forwarding.as_ref().map(|f| f.load());
        let session = self
            .inner
            .sessions
            .entry(peer)
            .or_insert_with(|| Arc::new(PeerSession::new(peer)))
            .clone();
        let mut data = session.data.lock();
        if data.retry.blocked == Some(auth.generation()) {
            out.blocked = true;
            return out;
        }
        let was_empty = data.queue.is_empty();
        for AuthorizedPacket {
            packet,
            epoch,
            local_posture: posture,
            proof,
        } in packets
        {
            let Ok((network, _)) = unframe(&packet) else {
                out.blocked = true;
                continue;
            };
            if snapshot.as_ref().is_none_or(|s| {
                s.auth_epoch(network) != epoch
                    || !s.allows_network(network, peer)
                    || !Arc::ptr_eq(&s.posture_ok.load_full(), &posture)
                    || proof.is_some_and(|proof| !proof.allows(s, network, peer))
            }) {
                out.blocked = true;
                continue;
            }
            if data.queue.len() == MAX_QUEUE_PACKETS
                || data.queue_bytes + packet.len() > MAX_QUEUE_BYTES
            {
                out.queue_full += 1;
                continue;
            }
            let bytes = packet.len();
            data.next_packet_id = data
                .next_packet_id
                .checked_add(1)
                .expect("packet identity exhausted");
            let id = data.next_packet_id;
            data.queue.push_back(QueuedPacket {
                id,
                bytes: packet,
                network,
                epoch,
                posture,
                proof,
                enqueued_at: Instant::now(),
            });
            data.queue_bytes += bytes;
            out.admitted += 1;
            out.admitted_bytes += bytes as u64;
        }
        if out.admitted > 0 {
            data.last_activity = Instant::now();
        }
        drop(data);
        drop(forwarding);
        if out.admitted > 0 {
            self.inner
                .metrics
                .packets_buffered
                .fetch_add(out.admitted as u64, Ordering::Relaxed);
            self.start_worker(&session, active, auth);
            if was_empty {
                session.notify.notify_one();
            }
        } else {
            let data = session.data.lock();
            let unused = !data.worker_running && data.conn.is_none() && data.queue.is_empty();
            drop(data);
            if unused {
                self.inner
                    .sessions
                    .remove_if(&peer, |_, entry| Arc::ptr_eq(entry, &session));
            }
        }
        out
    }
    pub fn install(&self, peer: EndpointId, conn: Connection, opened_by_us: bool) -> bool {
        let lifecycle = self.inner.lifecycle.lock();
        let Some(active) = lifecycle
            .active
            .as_ref()
            .filter(|a| !a.cancel.is_cancelled())
        else {
            conn.close(0u32.into(), b"dataplane_down");
            return false;
        };
        let Some(auth) = self.inner.gate.read().clone() else {
            conn.close(CLOSE_NOT_MEMBER.into(), CLOSE_NOT_MEMBER_REASON);
            return false;
        };
        let gate = auth.authorization_gate();
        let _authorization = gate.read();
        if conn.remote_id() != peer || !auth.allows(&peer.to_string()) {
            conn.close(CLOSE_NOT_MEMBER.into(), CLOSE_NOT_MEMBER_REASON);
            return false;
        }
        let session = self
            .inner
            .sessions
            .entry(peer)
            .or_insert_with(|| Arc::new(PeerSession::new(peer)))
            .clone();
        let mut data = session.data.lock();
        if let Some(old) = data
            .conn
            .as_ref()
            .filter(|c| c.conn.close_reason().is_none())
            && !prefer_incoming(
                self.inner.endpoint.id(),
                peer,
                old.opened_by_us,
                opened_by_us,
            )
        {
            conn.close(0u32.into(), b"tie_break");
            return false;
        }
        data.close(0, b"replaced");
        let token = data.token;
        data.conn = Some(Installed {
            conn,
            opened_by_us,
            token,
            cancel: active.cancel.child_token(),
        });
        data.retry = Retry::default();
        data.last_activity = Instant::now();
        drop(data);
        self.start_worker(&session, active, auth);
        session.notify.notify_one();
        true
    }
    pub async fn reconcile(&self) {
        let _lifecycle = self.inner.lifecycle.lock();
        let Some(auth) = self.inner.gate.read().clone() else {
            return;
        };
        let gate = auth.authorization_gate();
        let _authorization = gate.read();
        for session in self.inner.sessions.iter() {
            let mut data = session.data.lock();
            if !auth.allows(&session.peer.to_string()) {
                data.close(CLOSE_NOT_MEMBER, CLOSE_NOT_MEMBER_REASON);
                let dropped = data.clear_queue();
                self.inner
                    .metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                data.retry.blocked = Some(auth.generation());
            } else if data.retry.blocked != Some(auth.generation()) {
                data.retry.blocked = None;
                if data
                    .retry
                    .rejected
                    .is_some_and(|(g, _)| g != auth.generation())
                {
                    data.retry = Retry::default();
                }
            }
            session.notify.notify_one();
        }
    }
    pub async fn revoke_peer(&self, peer: EndpointId) {
        let _lifecycle = self.inner.lifecycle.lock();
        if let Some(session) = self.inner.sessions.get(&peer) {
            let mut data = session.data.lock();
            data.close(CLOSE_NOT_MEMBER, CLOSE_NOT_MEMBER_REASON);
            let dropped = data.clear_queue();
            self.inner
                .metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            data.retry.blocked = self.inner.gate.read().as_ref().map(|a| a.generation());
            session.notify.notify_one();
        }
    }
    pub async fn close_all(&self) {
        let _lifecycle = self.inner.lifecycle.lock();
        for session in self.inner.sessions.iter() {
            let mut data = session.data.lock();
            data.close(0, b"dataplane_down");
            data.clear_queue();
            data.retry = Retry::default();
            session.notify.notify_one();
        }
    }
    pub fn set_keep_alive(&self, enabled: bool) {
        self.inner.keep_alive.store(enabled, Ordering::Relaxed);
    }
    pub fn keep_alive(&self) -> bool {
        self.inner.keep_alive.load(Ordering::Relaxed)
    }
    pub fn set_peer_keep_alive(&self, peer: EndpointId, enabled: bool) {
        if enabled {
            self.inner.keep_alive_peers.insert(peer, ());
        } else {
            self.inner.keep_alive_peers.remove(&peer);
        }
        if let Some(s) = self.inner.sessions.get(&peer) {
            s.notify.notify_one();
        }
    }
    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        *self.inner.cloud_relay_urls.write() = urls
            .into_iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect();
    }
    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.inner.cloud_relay_meter.clone()
    }
    pub fn record_bytes_in(&self, peer: EndpointId, bytes: u64) {
        if let Some(s) = self.inner.sessions.get(&peer) {
            s.bytes_in.fetch_add(bytes, Ordering::Relaxed);
            s.data.lock().last_activity = Instant::now();
        }
    }
    pub fn has_live(&self, peer: EndpointId) -> bool {
        self.inner.sessions.get(&peer).is_some_and(|s| {
            s.data
                .lock()
                .conn
                .as_ref()
                .is_some_and(|c| c.conn.close_reason().is_none())
        })
    }
    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        self.inner.sessions.get(&peer).map_or((0, 0), |s| {
            (
                s.bytes_in.load(Ordering::Relaxed),
                s.bytes_out.load(Ordering::Relaxed),
            )
        })
    }
    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let mut out = (0, 0, 0);
        for s in self.inner.sessions.iter() {
            out.0 += u32::from(
                s.data
                    .lock()
                    .conn
                    .as_ref()
                    .is_some_and(|c| c.conn.close_reason().is_none()),
            );
            out.1 += s.bytes_out.load(Ordering::Relaxed);
            out.2 += s.bytes_in.load(Ordering::Relaxed);
        }
        out
    }
    pub fn peer_snapshot(&self, peer: EndpointId) -> PeerConnSnapshot {
        let keep_alive = self.keep_alive() || self.inner.keep_alive_peers.contains_key(&peer);
        let Some(s) = self.inner.sessions.get(&peer) else {
            return PeerConnSnapshot {
                state: "idle".into(),
                keep_alive,
                last_activity_secs_ago: u64::MAX,
                live: false,
                path: "unknown".into(),
            };
        };
        let data = s.data.lock();
        let live = data
            .conn
            .as_ref()
            .filter(|c| c.conn.close_reason().is_none());
        let state = if live.is_some() {
            "connected"
        } else if data.retry.blocked.is_some() {
            "blocked"
        } else if data.connecting {
            "dialing"
        } else if data.retry.rejected.is_some() {
            "rejected"
        } else if data.retry.until.is_some() {
            "backoff"
        } else {
            "idle"
        };
        PeerConnSnapshot {
            state: state.into(),
            keep_alive,
            last_activity_secs_ago: data.last_activity.elapsed().as_secs(),
            live: live.is_some(),
            path: selected_path_kind(live.map(|c| &c.conn)),
        }
    }
    pub fn session_stats(&self) -> SessionStats {
        let m = &self.inner.metrics;
        let success = m.reconnect_success.load(Ordering::Relaxed);
        let mut queue_packets = 0;
        let mut queue_bytes = 0;
        for session in self.inner.sessions.iter() {
            let data = session.data.lock();
            queue_packets += data.queue.len();
            queue_bytes += data.queue_bytes;
        }
        SessionStats {
            reconnect_attempts: m.reconnect_attempts.load(Ordering::Relaxed),
            reconnect_success: success,
            reconnect_fail: m.reconnect_fail.load(Ordering::Relaxed),
            packets_buffered: m.packets_buffered.load(Ordering::Relaxed),
            packets_dropped_timeout: m.packets_dropped_timeout.load(Ordering::Relaxed),
            packets_dropped_blocked: m.packets_dropped_blocked.load(Ordering::Relaxed),
            dials_suppressed: m.dials_suppressed.load(Ordering::Relaxed),
            reconnect_latency_avg_us: m
                .reconnect_latency_sum_us
                .load(Ordering::Relaxed)
                .checked_div(success)
                .unwrap_or(0),
            reconnect_latency_max_us: m.reconnect_latency_max_us.load(Ordering::Relaxed),
            queue_packets,
            queue_bytes,
            quic_accepted_packets: m.quic_accepted_packets.load(Ordering::Relaxed),
            quic_accepted_bytes: m.quic_accepted_bytes.load(Ordering::Relaxed),
            transport_drops: m.packets_dropped_transport.load(Ordering::Relaxed),
            oversize_packets: m.oversize_packets.load(Ordering::Relaxed),
            pmtu_feedback_drops: m.pmtu_feedback_drops.load(Ordering::Relaxed),
        }
    }
    pub fn transport_stats(&self) -> Vec<PeerTransportStats> {
        let mut peers = Vec::new();
        for session in self.inner.sessions.iter() {
            let data = session.data.lock();
            let Some(installed) = data.conn.as_ref() else {
                continue;
            };
            let paths = installed.conn.paths();
            let selected = paths.iter().find(|p| p.is_selected());
            let stats = installed.conn.stats();
            let path_stats = selected.as_ref().map(|p| p.stats());
            peers.push(PeerTransportStats {
                peer: session.peer.to_string(),
                token: installed.token,
                selected_local_addr: selected.as_ref().map(|p| format!("{:?}", p.local_addr())),
                selected_remote_addr: selected.as_ref().map(|p| format!("{:?}", p.remote_addr())),
                max_datagram_size: installed.conn.max_datagram_size(),
                send_buffer_available_bytes: installed.conn.datagram_send_buffer_space(),
                queue_packets: data.queue.len(),
                queue_bytes: data.queue_bytes,
                udp_tx_packets: stats.udp_tx.datagrams,
                udp_tx_bytes: stats.udp_tx.bytes,
                udp_rx_packets: stats.udp_rx.datagrams,
                udp_rx_bytes: stats.udp_rx.bytes,
                datagram_frames_tx: stats.frame_tx.datagram,
                datagram_frames_rx: stats.frame_rx.datagram,
                lost_packets: stats.lost_packets,
                lost_bytes: stats.lost_bytes,
                selected_rtt_us: path_stats.as_ref().map(|p| p.rtt.as_micros() as u64),
                selected_cwnd_bytes: path_stats.as_ref().map(|p| p.cwnd),
                selected_udp_mtu: path_stats.as_ref().map(|p| p.current_mtu),
            });
        }
        peers.sort_by(|a, b| a.peer.cmp(&b.peer));
        peers
    }
}
struct WorkerDeps {
    manager: std::sync::Weak<PeerManagerInner>,
    endpoint: Endpoint,
    alpn: &'static [u8],
    auth: TransportAuth,
    forwarding: Option<ForwardingStore>,
    metrics: Arc<SessionMetrics>,
    urls: Arc<RwLock<HashSet<String>>>,
    meter: CloudRelayMeter,
    keep_alive: Arc<AtomicBool>,
    keep_alive_peers: Arc<DashMap<EndpointId, ()>>,
    generation: u64,
    cancel: CancellationToken,
    hook: RecvHook,
    feedback: FeedbackHook,
}
impl WorkerDeps {
    fn packet_allowed(&self, peer: EndpointId, peer_hex: &str, p: &QueuedPacket) -> bool {
        self.auth.allows(peer_hex)
            && self.forwarding.as_ref().is_some_and(|f| {
                let s = f.load();
                s.auth_epoch(p.network) == p.epoch
                    && s.allows_network(p.network, peer)
                    && Arc::ptr_eq(&s.posture_ok.load_full(), &p.posture)
                    && p.proof
                        .is_none_or(|proof| proof.allows(&s, p.network, peer))
            })
    }
    fn accepted(&self, session: &PeerSession, conn: &Connection, packets: usize, bytes: u64) {
        self.metrics
            .quic_accepted_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.metrics
            .quic_accepted_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        session.bytes_out.fetch_add(bytes, Ordering::Relaxed);
        if selected_path_is_cloud_relay(conn, &self.urls.read()) {
            self.meter.record(bytes);
        }
    }
}
async fn stop_reader(reader: &mut Option<(u64, JoinHandle<()>)>) {
    if let Some((_, h)) = reader.take() {
        h.abort();
        let _ = h.await;
    }
}
async fn run_session(session: Arc<PeerSession>, deps: WorkerDeps) {
    let peer = session.peer;
    let peer_hex = peer.to_string();
    let gate = deps.auth.authorization_gate();
    let mut reader: Option<(u64, JoinHandle<()>)> = None;
    let mut retired = false;
    loop {
        if deps.cancel.is_cancelled() {
            break;
        }
        let installed = {
            let _authorization = gate.read();
            let mut data = session.data.lock();
            if !deps.auth.allows(&peer_hex) {
                data.close(CLOSE_NOT_MEMBER, CLOSE_NOT_MEMBER_REASON);
                let dropped = data.clear_queue();
                deps.metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                data.retry.blocked = Some(deps.auth.generation());
            }
            while let Some(packet) = data.queue.front() {
                let expired = packet.enqueued_at.elapsed() >= QUEUE_TTL;
                if !expired && deps.packet_allowed(peer, &peer_hex, packet) {
                    break;
                }
                data.pop();
                if expired {
                    deps.metrics
                        .packets_dropped_timeout
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    deps.metrics
                        .packets_dropped_blocked
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            if let Some(conn) = data
                .conn
                .as_ref()
                .filter(|c| c.conn.close_reason().is_some())
            {
                let failure = conn.conn.close_reason().map(|e| {
                    if is_auth_close_error(&e) {
                        DialFailure::RemoteRejected
                    } else {
                        DialFailure::Transient
                    }
                });
                data.close(0, b"closed");
                if let Some(f) = failure {
                    data.retry.failed(f, deps.auth.generation(), Instant::now());
                }
            }
            if data.conn.is_some()
                && !deps.keep_alive.load(Ordering::Relaxed)
                && !deps.keep_alive_peers.contains_key(&peer)
                && data.queue.is_empty()
                && data.last_activity.elapsed()
                    >= Duration::from_secs(crate::iroh_pool::DEFAULT_IDLE_SECS)
            {
                data.close(0, b"idle");
            }
            data.conn.clone()
        };
        if reader.as_ref().map(|(token, _)| *token) != installed.as_ref().map(|c| c.token) {
            stop_reader(&mut reader).await;
            if let Some(conn) = &installed {
                let ctl = SessionCtl {
                    peer,
                    generation: deps.generation,
                    cancel: conn.cancel.clone(),
                };
                reader = Some((conn.token, (deps.hook)(peer, conn.conn.clone(), ctl)));
            }
        }
        if let Some(installed) = installed {
            if reader
                .as_ref()
                .is_some_and(|(_, handle)| handle.is_finished())
            {
                stop_reader(&mut reader).await;
                let mut data = session.data.lock();
                if data
                    .conn
                    .as_ref()
                    .is_some_and(|c| c.token == installed.token)
                {
                    data.close(0, b"receiver_ended");
                    data.retry.failed(
                        DialFailure::Transient,
                        deps.auth.generation(),
                        Instant::now(),
                    );
                }
                continue;
            }
            let progress = {
                let _authorization = gate.read();
                let mut data = session.data.lock();
                let mut accepted = 0;
                let mut bytes = 0;
                if data
                    .conn
                    .as_ref()
                    .is_some_and(|c| c.token == installed.token)
                {
                    for _ in 0..SEND_BATCH_MAX {
                        let Some(front) = data.queue.front() else {
                            break;
                        };
                        if !deps.packet_allowed(peer, &peer_hex, front) {
                            data.pop();
                            deps.metrics
                                .packets_dropped_blocked
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let Some(maximum) = installed.conn.max_datagram_size() else {
                            break;
                        };
                        let mut packet = data.pop().expect("queued packet");
                        if packet.bytes.len() > maximum {
                            deps.metrics
                                .oversize_packets
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        use crate::forward::mtu::{PreparedDatagram, prepare_datagram};
                        match prepare_datagram(packet.bytes, maximum) {
                            PreparedDatagram::Ready(bytes) => packet.bytes = bytes,
                            PreparedDatagram::Fragments(fragments) => {
                                let bytes: usize = fragments.iter().map(Bytes::len).sum();
                                if data.queue.len() + fragments.len() <= MAX_QUEUE_PACKETS
                                    && data.queue_bytes + bytes <= MAX_QUEUE_BYTES
                                {
                                    for bytes in fragments.into_iter().rev() {
                                        data.queue_bytes += bytes.len();
                                        data.next_packet_id = data
                                            .next_packet_id
                                            .checked_add(1)
                                            .expect("packet identity exhausted");
                                        let id = data.next_packet_id;
                                        data.queue.push_front(QueuedPacket {
                                            id,
                                            bytes,
                                            network: packet.network,
                                            epoch: packet.epoch,
                                            posture: packet.posture.clone(),
                                            proof: packet.proof,
                                            enqueued_at: packet.enqueued_at,
                                        });
                                    }
                                } else {
                                    deps.metrics
                                        .packets_dropped_transport
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                continue;
                            }
                            PreparedDatagram::Feedback(reply) => {
                                if !(deps.feedback)(reply) {
                                    deps.metrics
                                        .pmtu_feedback_drops
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                deps.metrics
                                    .packets_dropped_transport
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            PreparedDatagram::Drop => {
                                deps.metrics
                                    .packets_dropped_transport
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }
                        let size = packet.bytes.len();
                        let sent = matches!(
                            installed
                                .conn
                                .send_datagram_wait(packet.bytes.clone())
                                .now_or_never(),
                            Some(Ok(()))
                        );
                        if !sent {
                            data.queue_bytes += size;
                            data.queue.push_front(packet);
                            break;
                        }
                        accepted += 1;
                        bytes += size as u64;
                    }
                    if accepted != 0 {
                        deps.accepted(&session, &installed.conn, accepted, bytes);
                        data.last_activity = Instant::now();
                    }
                }
                accepted
            };
            if progress != 0 {
                tokio::task::yield_now().await;
                continue;
            }
            let pending = session
                .data
                .lock()
                .queue
                .front()
                .map(|p| (p.id, p.bytes.clone()));
            let pending_identity = pending.as_ref().map(|(id, _)| *id);
            enum Submission {
                Accepted,
                Denied,
                Failed,
                Resize,
            }
            enum Event {
                Wake,
                Closed,
                Receiver,
                Submitted(Submission),
                Tick,
                Cancel,
            }
            let event = if let Some((packet_id, packet)) = pending {
                let send = installed.conn.send_datagram_wait(packet.clone());
                tokio::pin!(send);
                tokio::select! {
                    biased;
                    _ = deps.cancel.cancelled() => Event::Cancel,
                    _ = installed.cancel.cancelled() => Event::Wake,
                    _ = installed.conn.closed() => Event::Closed,
                    _ = async { if let Some((_, h)) = reader.as_mut() { let _ = h.await; } else { std::future::pending::<()>().await; } } => Event::Receiver,
                    _ = session.notify.notified() => Event::Wake,
                    result = std::future::poll_fn(|cx| {
                        let _authorization = gate.read(); let data = session.data.lock();
                        let valid = data.conn.as_ref().is_some_and(|c| c.token == installed.token) && data.queue.front().is_some_and(|p| p.id == packet_id && deps.packet_allowed(peer, &peer_hex, p));
                        if !valid || deps.cancel.is_cancelled() { return std::task::Poll::Ready(Submission::Denied); }
                        match std::future::Future::poll(send.as_mut(), cx) {
                            std::task::Poll::Ready(Ok(())) => {
                                deps.accepted(&session, &installed.conn, 1, packet.len() as u64);
                                std::task::Poll::Ready(Submission::Accepted)
                            }
                            std::task::Poll::Ready(Err(iroh::endpoint::SendDatagramError::TooLarge)) => std::task::Poll::Ready(Submission::Resize),
                            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Submission::Failed),
                            std::task::Poll::Pending => std::task::Poll::Pending,
                        }
                    }) => Event::Submitted(result),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => Event::Tick,
                }
            } else {
                tokio::select! {
                    biased;
                    _ = deps.cancel.cancelled() => Event::Cancel,
                    _ = installed.cancel.cancelled() => Event::Wake,
                    _ = installed.conn.closed() => Event::Closed,
                    _ = async { if let Some((_, h)) = reader.as_mut() { let _ = h.await; } else { std::future::pending::<()>().await; } } => Event::Receiver,
                    _ = session.notify.notified() => Event::Wake,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => Event::Tick,
                }
            };
            match event {
                Event::Cancel => break,
                Event::Receiver => {
                    reader.take();
                    let mut data = session.data.lock();
                    if data
                        .conn
                        .as_ref()
                        .is_some_and(|c| c.token == installed.token)
                    {
                        data.close(0, b"receiver_ended");
                        data.retry.failed(
                            DialFailure::Transient,
                            deps.auth.generation(),
                            Instant::now(),
                        );
                    }
                }
                Event::Submitted(Submission::Resize) => {}
                Event::Submitted(submission) => {
                    let mut data = session.data.lock();
                    if data
                        .conn
                        .as_ref()
                        .is_some_and(|c| c.token == installed.token)
                        && data
                            .queue
                            .front()
                            .is_some_and(|p| Some(p.id) == pending_identity)
                        && data.pop().is_some()
                    {
                        match submission {
                            Submission::Accepted => data.last_activity = Instant::now(),
                            Submission::Denied => {
                                deps.metrics
                                    .packets_dropped_blocked
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Submission::Failed => {
                                deps.metrics
                                    .packets_dropped_transport
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Submission::Resize => unreachable!(),
                        }
                    }
                }
                Event::Wake | Event::Closed | Event::Tick => {}
            }
            tokio::task::consume_budget().await;
            continue;
        }
        let decision = {
            let _authorization = gate.read();
            let mut data = session.data.lock();
            if data
                .retry
                .blocked
                .is_some_and(|g| g != deps.auth.generation())
                || data
                    .retry
                    .rejected
                    .is_some_and(|(g, _)| g != deps.auth.generation())
            {
                data.retry = Retry::default();
            }
            let now = Instant::now();
            if data.queue.is_empty() && data.last_activity.elapsed() >= QUEUE_TTL {
                None
            } else if !data.queue.is_empty()
                && data.retry.blocked.is_none()
                && data.retry.until.is_none_or(|until| until <= now)
            {
                data.connecting = true;
                Some((true, data.token, now))
            } else {
                Some((
                    false,
                    data.token,
                    data.retry
                        .until
                        .filter(|until| *until > now)
                        .unwrap_or(now + Duration::from_secs(1)),
                ))
            }
        };
        let Some((dial, token, until)) = decision else {
            let Some(manager) = deps.manager.upgrade() else {
                break;
            };
            if (PeerManager { inner: manager }).retire_idle(&session, deps.generation) {
                retired = true;
                break;
            }
            continue;
        };
        if !dial {
            tokio::select! { _ = deps.cancel.cancelled() => break, _ = session.notify.notified() => {}, _ = tokio::time::sleep_until(tokio::time::Instant::from_std(until)) => {} }
            continue;
        }
        deps.metrics
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let dial = tokio::time::timeout(RECONNECT_TIMEOUT, deps.endpoint.connect(peer, deps.alpn));
        tokio::pin!(dial);
        let result = loop {
            tokio::select! {
                biased;
                _ = deps.cancel.cancelled() => break None,
                _ = session.notify.notified() => {
                    let data = session.data.lock();
                    if data.token != token || data.conn.is_some() {
                        break None;
                    }
                }
                result = &mut dial => break Some(result),
            }
        };
        let Some(result) = result else {
            continue;
        };
        match result {
            Ok(Ok(conn)) => {
                if let Some(manager) = deps.manager.upgrade() {
                    if (PeerManager { inner: manager }).install(peer, conn, true) {
                        let latency = started.elapsed().as_micros() as u64;
                        deps.metrics
                            .reconnect_success
                            .fetch_add(1, Ordering::Relaxed);
                        deps.metrics
                            .reconnect_latency_sum_us
                            .fetch_add(latency, Ordering::Relaxed);
                        deps.metrics
                            .reconnect_latency_max_us
                            .fetch_max(latency, Ordering::Relaxed);
                    }
                } else {
                    conn.close(0u32.into(), b"owner_gone");
                    break;
                }
            }
            failure => {
                let _authorization = gate.read();
                let mut data = session.data.lock();
                if data.token != token || data.conn.is_some() {
                    continue;
                }
                let kind = match failure {
                    Ok(Err(e)) => classify_connect_error(&e),
                    Err(_) => DialFailure::Transient,
                    Ok(Ok(_)) => unreachable!(),
                };
                data.connecting = false;
                data.retry
                    .failed(kind, deps.auth.generation(), Instant::now());
                deps.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    stop_reader(&mut reader).await;
    if retired {
        return;
    }
    if let Some(manager) = deps.manager.upgrade() {
        let lifecycle = manager.lifecycle.lock();
        let mut data = session.data.lock();
        data.worker_running = false;
        data.close(0, b"session_ended");
        let remove = data.queue.is_empty() || deps.cancel.is_cancelled();
        drop(data);
        if remove {
            manager
                .sessions
                .remove_if(&peer, |_, entry| Arc::ptr_eq(entry, &session));
        } else if let Some(active) = lifecycle.active.as_ref() {
            PeerManager {
                inner: manager.clone(),
            }
            .start_worker(&session, active, deps.auth.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::{SelfIdentity, frame};
    use crate::routing::RoutingTable;
    use iroh::address_lookup::memory::MemoryLookup;
    use std::sync::atomic::AtomicUsize;
    use tunnet_common::policy::PolicyBundle;

    const ALPN: &[u8] = b"tunnet/session-test";

    fn configure(manager: &PeerManager, peer: EndpointId) -> (ForwardingStore, RoutingTable) {
        configure_at(manager, peer, "100.64.0.1", "100.64.0.2")
    }

    fn configure_at(
        manager: &PeerManager,
        peer: EndpointId,
        local_ip: &str,
        peer_ip: &str,
    ) -> (ForwardingStore, RoutingTable) {
        let routes = RoutingTable::new();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: peer_ip.parse().unwrap(),
                endpoint_id: peer.to_string(),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "test",
            uuid::Uuid::nil(),
            &manager.inner.endpoint.id().to_string(),
            1,
        );
        let forwarding = ForwardingStore::new();
        forwarding.set_managed_bundle(
            &routes,
            uuid::Uuid::nil(),
            PolicyBundle::default(),
            SelfIdentity {
                endpoint_hex: manager.inner.endpoint.id().to_string(),
                ip: local_ip.parse().unwrap(),
                tags: vec![],
                network: "test".into(),
                posture: tunnet_common::PeerPosture::Unknown,
            },
        );
        manager.set_transport_auth(TransportAuth::managed_with_gate(
            &routes,
            forwarding.authorization_gate(),
        ));
        manager.set_forwarding(forwarding.clone());
        (forwarding, routes)
    }

    async fn endpoints() -> (Endpoint, Endpoint) {
        endpoints_with_config(iroh::endpoint::QuicTransportConfig::default()).await
    }

    async fn endpoints_with_config(
        config: iroh::endpoint::QuicTransportConfig,
    ) -> (Endpoint, Endpoint) {
        let lookup = MemoryLookup::new();
        let a = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .transport_config(config)
            .address_lookup(lookup.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(a.addr());
        lookup.add_endpoint_info(b.addr());
        (a, b)
    }

    async fn connection(a: &Endpoint, b: &Endpoint) -> (Connection, Connection) {
        let (outgoing, incoming) = tokio::join!(a.connect(b.id(), ALPN), async {
            b.accept().await.unwrap().await.unwrap()
        });
        (outgoing.unwrap(), incoming)
    }

    async fn wait_for(check: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !check() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[tokio::test]
    async fn receiver_replacement_recovery_and_shutdown(#[case] shutdown_first: bool) {
        let (a, b) = endpoints().await;
        let manager = PeerManager::new(a.clone(), ALPN);
        configure(&manager, b.id());
        let readers = Arc::new(AtomicUsize::new(0));
        let end_reader = Arc::new(AtomicBool::new(false));
        let hook: RecvHook = Arc::new({
            let readers = readers.clone();
            let end_reader = end_reader.clone();
            move |_, _, ctl| {
                let readers = readers.clone();
                let end_reader = end_reader.clone();
                tokio::spawn(async move {
                    struct Reader(Arc<AtomicUsize>);
                    impl Drop for Reader {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    readers.fetch_add(1, Ordering::SeqCst);
                    let _reader = Reader(readers);
                    loop {
                        if end_reader.load(Ordering::SeqCst) {
                            return;
                        }
                        tokio::select! { _ = ctl.cancel.cancelled() => return, _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
                    }
                })
            }
        });
        manager
            .activate(
                1,
                CancellationToken::new(),
                hook.clone(),
                Arc::new(|_| true),
            )
            .unwrap();
        let preferred = a.id() < b.id();
        let (first, _remote_first) = connection(&a, &b).await;
        assert!(manager.install(b.id(), first.clone(), !preferred));
        wait_for(|| readers.load(Ordering::SeqCst) == 1).await;
        let (second, remote_second) = connection(&a, &b).await;
        assert!(manager.install(b.id(), second.clone(), preferred));
        tokio::time::timeout(Duration::from_secs(5), first.closed())
            .await
            .unwrap();
        wait_for(|| readers.load(Ordering::SeqCst) == 1 && manager.has_live(b.id())).await;
        let packet = frame(uuid::Uuid::nil(), b"replacement-packet");
        assert_eq!(manager.send(b.id(), packet.clone()), SendOutcome::Admitted);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), remote_second.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            packet
        );

        end_reader.store(true, Ordering::SeqCst);
        wait_for(|| !manager.has_live(b.id()) && readers.load(Ordering::SeqCst) == 0).await;
        end_reader.store(false, Ordering::SeqCst);
        let packet = frame(uuid::Uuid::nil(), b"recovered-packet");
        assert_eq!(manager.send(b.id(), packet.clone()), SendOutcome::Admitted);
        let recovered_remote = tokio::time::timeout(Duration::from_secs(5), async {
            b.accept().await.unwrap().await.unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), recovered_remote.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            packet
        );
        assert!(manager.session_stats().reconnect_success > 0);
        let (racing, _remote_racing) = connection(&a, &b).await;
        let install = async {
            if shutdown_first {
                tokio::task::yield_now().await;
            }
            manager.install(b.id(), racing, preferred)
        };
        let shutdown = async {
            if !shutdown_first {
                tokio::task::yield_now().await;
            }
            manager.deactivate().await;
        };
        tokio::join!(install, shutdown);
        assert!(!manager.has_live(b.id()));
        assert!(manager.inner.sessions.is_empty());
        assert_eq!(readers.load(Ordering::SeqCst), 0);
        manager
            .activate(2, CancellationToken::new(), hook, Arc::new(|_| true))
            .unwrap();
        let (restarted, _remote_restarted) = connection(&a, &b).await;
        assert!(manager.install(b.id(), restarted, preferred));
        wait_for(|| readers.load(Ordering::SeqCst) == 1).await;
        manager.deactivate().await;
        a.close().await;
        b.close().await;
    }

    #[tokio::test]
    async fn congested_transport_preserves_admitted_packets() {
        let (a, b) = endpoints_with_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .datagram_send_buffer_size(512)
                .build(),
        )
        .await;
        let manager = PeerManager::new(a.clone(), ALPN);
        configure(&manager, b.id());
        manager
            .activate(
                1,
                CancellationToken::new(),
                Arc::new(|_, _, ctl| tokio::spawn(async move { ctl.cancel.cancelled().await })),
                Arc::new(|_| true),
            )
            .unwrap();
        let (outgoing, incoming) = connection(&a, &b).await;
        assert!(manager.install(b.id(), outgoing, true));
        let expected: Vec<_> = (0..7)
            .map(|id| frame(uuid::Uuid::nil(), &[id; 46]))
            .collect();
        assert_eq!(
            manager.send_batch(b.id(), expected[..3].to_vec()).admitted,
            3
        );
        assert_eq!(
            manager.send_batch(b.id(), expected[3..].to_vec()).admitted,
            4
        );
        let mut received = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            for _ in 0..expected.len() {
                received.push(incoming.read_datagram().await.unwrap());
            }
        })
        .await;
        manager.deactivate().await;
        a.close().await;
        b.close().await;
        assert!(result.is_ok(), "received {} of 7 packets", received.len());
        received.sort();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn bounded_queue_is_cleared_on_authorization_revocation() {
        let (a, b) = endpoints().await;
        let manager = PeerManager::new(a.clone(), ALPN);
        let (forwarding, routes) = configure(&manager, b.id());
        manager
            .activate(
                1,
                CancellationToken::new(),
                Arc::new(|_, _, ctl| tokio::spawn(async move { ctl.cancel.cancelled().await })),
                Arc::new(|_| true),
            )
            .unwrap();
        let packet = frame(uuid::Uuid::nil(), &[1; 100]);
        let outcome = manager.send_batch(b.id(), vec![packet; MAX_QUEUE_PACKETS + 1]);
        assert_eq!(outcome.admitted, MAX_QUEUE_PACKETS);
        assert_eq!(outcome.queue_full, 1);
        assert_eq!(manager.session_stats().queue_packets, MAX_QUEUE_PACKETS);
        forwarding.clear_managed(&routes, uuid::Uuid::nil());
        manager.reconcile().await;
        assert_eq!(manager.session_stats().queue_packets, 0);
        assert_eq!(
            manager.send(b.id(), frame(uuid::Uuid::nil(), b"revoked")),
            SendOutcome::Denied
        );
        manager.deactivate().await;
        assert!(manager.inner.sessions.is_empty());
        a.close().await;
        b.close().await;
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[tokio::test]
    async fn queued_packet_uses_installed_connection_mtu(#[case] df: bool) {
        let (a, b) = endpoints_with_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .initial_mtu(1200)
                .mtu_discovery_config(None)
                .build(),
        )
        .await;
        let manager = PeerManager::new(a.clone(), ALPN);
        configure(&manager, b.id());
        let (outgoing, incoming) = connection(&a, &b).await;
        let maximum = outgoing.max_datagram_size().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        manager
            .activate(
                1,
                CancellationToken::new(),
                Arc::new(|_, _, ctl| tokio::spawn(async move { ctl.cancel.cancelled().await })),
                Arc::new(move |packet| tx.try_send(packet).is_ok()),
            )
            .unwrap();
        let mut ip = etherparse::Ipv4Header::new(
            1260,
            64,
            etherparse::IpNumber::UDP,
            [100, 64, 0, 1],
            [100, 64, 0, 2],
        )
        .unwrap();
        ip.dont_fragment = df;
        let mut raw = Vec::new();
        etherparse::PacketBuilder::ip(etherparse::IpHeaders::Ipv4(ip, Default::default()))
            .udp(1234, 5678)
            .write(&mut raw, &[42; 1252])
            .unwrap();
        assert_eq!(
            manager.send(b.id(), frame(uuid::Uuid::nil(), &raw)),
            SendOutcome::Admitted
        );
        assert!(manager.install(b.id(), outgoing, true));
        tokio::time::timeout(Duration::from_secs(5), async {
            if df {
                let reply = rx.recv().await.unwrap();
                let (_, rest) = etherparse::Ipv4Header::from_slice(&reply).unwrap();
                let (icmp, quoted) = etherparse::Icmpv4Header::from_slice(rest).unwrap();
                assert_eq!(
                    icmp.icmp_type,
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                            next_hop_mtu: (maximum - crate::forward::FRAME_OVERHEAD) as u16
                        }
                    )
                );
                assert_eq!(quoted, &raw[..28]);
            } else {
                let mut payload = vec![0; raw.len() - 20];
                let mut received = 0;
                while received < payload.len() {
                    let datagram = incoming.read_datagram().await.unwrap();
                    assert!(datagram.len() <= maximum);
                    let (network, fragment) = unframe(&datagram).unwrap();
                    assert_eq!(network, uuid::Uuid::nil());
                    let (header, bytes) = etherparse::Ipv4Header::from_slice(fragment).unwrap();
                    let offset = usize::from(header.fragment_offset.value()) * 8;
                    payload[offset..offset + bytes.len()].copy_from_slice(bytes);
                    received += bytes.len();
                }
                assert_eq!(payload, raw[20..]);
            }
        })
        .await
        .unwrap();
        manager.deactivate().await;
        a.close().await;
        b.close().await;
    }

    #[test]
    fn retry_history_survives_attempts_and_rejections() {
        let mut retry = Retry::default();
        let now = Instant::now();
        for step in 0..6 {
            retry.failed(DialFailure::Transient, 7, now);
            let delay = retry.until.unwrap().duration_since(now);
            let max = BACKOFF_BASE * (1 << step);
            assert!(delay >= max / 2 && delay <= max);
            assert_eq!(retry.step, step + 1);
        }
        retry.failed(DialFailure::RemoteRejected, 7, now);
        retry.failed(
            DialFailure::RemoteRejected,
            7,
            now + Duration::from_secs(30),
        );
        assert_eq!(retry.rejected, Some((7, now)));
        assert!(retry.until.unwrap() > now + Duration::from_secs(60));
        retry.failed(
            DialFailure::RemoteRejected,
            8,
            now + Duration::from_secs(31),
        );
        assert_eq!(retry.rejected, Some((8, now + Duration::from_secs(31))));
    }

    #[tokio::test]
    async fn incoming_connection_wins_over_pending_idle_retirement() {
        let (a, b) = endpoints().await;
        let (conn, remote) = connection(&a, &b).await;
        let manager = PeerManager::new(a.clone(), ALPN);
        configure(&manager, b.id());
        manager
            .activate(
                1,
                CancellationToken::new(),
                Arc::new(|_, _, ctl| tokio::spawn(async move { ctl.cancel.cancelled().await })),
                Arc::new(|_| true),
            )
            .unwrap();
        let old = Arc::new(PeerSession::new(b.id()));
        {
            let mut data = old.data.lock();
            data.worker_running = true;
            data.last_activity = Instant::now() - QUEUE_TTL;
        }
        manager.inner.sessions.insert(b.id(), old.clone());
        assert!(manager.install(b.id(), conn, true));
        let token = old.data.lock().token;
        assert!(!manager.retire_idle(&old, 1));
        assert_eq!(old.data.lock().token, token);
        assert!(
            old.data
                .lock()
                .conn
                .as_ref()
                .unwrap()
                .conn
                .close_reason()
                .is_none()
        );
        assert!(Arc::ptr_eq(
            &manager.inner.sessions.get(&b.id()).unwrap(),
            &old
        ));
        manager.deactivate().await;
        remote.close(0u32.into(), b"done");
        a.close().await;
        b.close().await;
    }

    #[cfg(feature = "direct")]
    #[tokio::test]
    async fn firewall_reject_round_trip_uses_authenticated_network_framing() {
        use crate::direct::firewall::{
            FirewallAction, FirewallDirection, FirewallRule, PeerFilter,
        };
        use crate::forward::{
            FirewallRules, InDecision, OutDecision, PolicyEngine, inbound_frame, outbound,
        };
        use tunnet_common::policy::Protocol;
        let (a, b) = endpoints().await;
        let manager_a = PeerManager::new(a.clone(), ALPN);
        let manager_b = PeerManager::new(b.clone(), ALPN);
        let (store_a, routes_a) = configure(&manager_a, b.id());
        let (store_b, routes_b) = configure_at(&manager_b, a.id(), "100.64.0.2", "100.64.0.1");
        for (store, routes, peer, reject) in [
            (&store_a, &routes_a, b.id(), false),
            (&store_b, &routes_b, a.id(), true),
        ] {
            let auth = crate::direct::AuthCache::with_gate(store.authorization_gate());
            auth.insert(peer.to_string(), uuid::Uuid::nil());
            auth.insert(store.load().self_id.endpoint_hex.clone(), uuid::Uuid::nil());
            store.set_direct_auth(auth);
            store.set_firewall(
                routes,
                uuid::Uuid::nil(),
                FirewallRules {
                    enabled: true,
                    local: if reject {
                        vec![FirewallRule {
                            direction: FirewallDirection::In,
                            action: FirewallAction::Reject,
                            protocol: Protocol::Tcp,
                            ports: vec![],
                            peer: PeerFilter::Any,
                        }]
                    } else {
                        vec![]
                    },
                    ..FirewallRules::default()
                },
            );
        }
        let policy_a = PolicyEngine::new();
        let policy_b = PolicyEngine::new();
        let (result_tx, mut result_rx) = tokio::sync::mpsc::channel(1);
        let hook_a: RecvHook = Arc::new({
            let store = store_a.clone();
            let policy = policy_a.clone();
            move |peer, conn, ctl| {
                let store = store.clone();
                let policy = policy.clone();
                let tx = result_tx.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = ctl.cancel.cancelled() => {},
                        received = conn.read_datagram() => {
                            let received = received.unwrap();
                            let snapshot = store.load();
                            let InDecision::ToTun { network, ip, .. } = inbound_frame(&snapshot, &policy, &received, peer) else { panic!("Reject did not pass remote forwarding policy"); };
                            tx.send((network, Bytes::copy_from_slice(ip))).await.unwrap();
                            ctl.cancel.cancelled().await;
                        }
                    }
                })
            }
        });
        let hook_b: RecvHook = Arc::new({
            let store = store_b.clone();
            let policy = policy_b.clone();
            let manager = manager_b.downgrade();
            move |peer, conn, ctl| {
                let store = store.clone();
                let policy = policy.clone();
                let manager = manager.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = ctl.cancel.cancelled() => {},
                        received = conn.read_datagram() => {
                            let received = received.unwrap();
                            let snapshot = store.load();
                            let InDecision::Reject { network, reply } = inbound_frame(&snapshot, &policy, &received, peer) else { panic!("inbound TCP SYN did not reject"); };
                            assert_eq!(manager.upgrade().unwrap().send_authorized(peer, AuthorizedPacket { packet: frame(network, &reply), epoch: snapshot.auth_epoch(network), local_posture: snapshot.posture_ok.load_full(), proof: None }), SendOutcome::Admitted);
                            ctl.cancel.cancelled().await;
                        }
                    }
                })
            }
        });
        manager_a
            .activate(1, CancellationToken::new(), hook_a, Arc::new(|_| true))
            .unwrap();
        manager_b
            .activate(1, CancellationToken::new(), hook_b, Arc::new(|_| true))
            .unwrap();
        let (conn_a, conn_b) = connection(&a, &b).await;
        assert!(manager_a.install(b.id(), conn_a, true));
        assert!(manager_b.install(a.id(), conn_b, false));
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv4([100, 64, 0, 1], [100, 64, 0, 2], 64)
            .tcp(42000, 443, 123, 4096)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        let snapshot = store_a.load();
        assert!(
            matches!(outbound(&snapshot, &policy_a, &syn), OutDecision::Forward { peer, network, .. } if peer == b.id() && network == uuid::Uuid::nil())
        );
        assert_eq!(
            manager_a.send_authorized(
                b.id(),
                AuthorizedPacket {
                    packet: frame(uuid::Uuid::nil(), &syn),
                    epoch: snapshot.auth_epoch(uuid::Uuid::nil()),
                    local_posture: snapshot.posture_ok.load_full(),
                    proof: None
                }
            ),
            SendOutcome::Admitted
        );
        let (network, reply) = tokio::time::timeout(Duration::from_secs(5), result_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(network, uuid::Uuid::nil());
        let packet = tunnet_common::packet::parse(&reply).unwrap();
        assert_eq!(packet.ip.v4_src().unwrap().octets(), [100, 64, 0, 2]);
        assert_eq!(packet.ip.v4_dst().unwrap().octets(), [100, 64, 0, 1]);
        let tcp = etherparse::TcpHeaderSlice::from_slice(&reply[20..]).unwrap();
        assert!(tcp.rst());
        assert!(tcp.ack());
        assert_eq!(tcp.source_port(), 443);
        assert_eq!(tcp.destination_port(), 42000);
        assert_eq!(tcp.acknowledgment_number(), 124);
        assert_eq!(
            tcp.checksum(),
            tunnet_common::packet::tcp_ipv4_checksum_of(&reply).unwrap()
        );
        manager_a.deactivate().await;
        manager_b.deactivate().await;
        a.close().await;
        b.close().await;
    }
}
