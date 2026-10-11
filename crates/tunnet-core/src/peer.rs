use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt;
use iroh::TransportAddr;
use iroh::endpoint::{
    ConnectError, ConnectWithOptsError, ConnectingError, Connection, ConnectionError, PathEvent,
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

pub async fn send_datagram(conn: &Connection, packet: Bytes) -> anyhow::Result<()> {
    if let Some(max) = conn.max_datagram_size()
        && packet.len() > max
    {
        anyhow::bail!(
            "datagram_too_large: packet {} > max_datagram_size {}",
            packet.len(),
            max
        );
    }
    if conn.datagram_send_buffer_space() == 0 {
        conn.send_datagram_wait(packet)
            .await
            .context("send_datagram_wait (datagram buffer full or connection closed)")?;
        return Ok(());
    }
    conn.send_datagram(packet)
        .context("send_datagram (packet too big or unsupported)")?;
    Ok(())
}

const SEND_BATCH_MAX: usize = 32;
const TRANSPORT_LOG_EVERY: Duration = Duration::from_secs(15);

pub struct BatchOutcome {
    pub accepted: usize,
    pub accepted_bytes: u64,
    pub oversize: usize,
    pub transport_drops: usize,
}

pub async fn send_datagram_batch(conn: &Connection, queue: &mut VecDeque<Bytes>) -> BatchOutcome {
    let mut out = BatchOutcome {
        accepted: 0,
        accepted_bytes: 0,
        oversize: 0,
        transport_drops: 0,
    };
    let mut batch: Vec<Bytes> = Vec::with_capacity(SEND_BATCH_MAX);
    while !queue.is_empty() {
        let max = conn.max_datagram_size();
        batch.clear();
        while batch.len() < SEND_BATCH_MAX {
            if queue
                .front()
                .is_some_and(|f| max.is_some_and(|m| f.len() > m))
            {
                queue.pop_front();
                out.oversize += 1;
                continue;
            }
            let Some(packet) = queue.pop_front() else {
                break;
            };
            batch.push(packet);
        }
        if batch.is_empty() {
            continue;
        }
        match conn.send_many_datagrams(&batch) {
            Ok(n) => {
                for b in batch.drain(..n.min(batch.len())) {
                    out.accepted += 1;
                    out.accepted_bytes += b.len() as u64;
                }
                out.transport_drops += batch.len();
                batch.clear();
            }
            Err(_) => {
                out.transport_drops += batch.len();
                batch.clear();
            }
        }
    }
    out
}

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
}

enum SessionState {
    Idle,
    Connecting,
    Connected {
        auth_gen: u64,
    },
    Backoff {
        until: Instant,
        step: u32,
    },
    Blocked {
        generation: u64,
    },
    Rejected {
        generation: u64,
        first: Instant,
        retry_after: Instant,
    },
}

impl SessionState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "dialing",
            Self::Connected { .. } => "connected",
            Self::Backoff { .. } => "backoff",
            Self::Blocked { .. } => "blocked",
            Self::Rejected { .. } => "rejected",
        }
    }
}

struct QueuedPacket {
    bytes: Bytes,
    enqueued_at: Instant,
}

struct SessionQueue {
    packets: VecDeque<QueuedPacket>,
    bytes: usize,
}

impl SessionQueue {
    fn push(&mut self, packet: Bytes) -> bool {
        if self.packets.len() >= MAX_QUEUE_PACKETS || self.bytes + packet.len() > MAX_QUEUE_BYTES {
            return false;
        }
        self.bytes += packet.len();
        self.packets.push_back(QueuedPacket {
            bytes: packet,
            enqueued_at: Instant::now(),
        });
        true
    }

    fn drop_all(&mut self) -> usize {
        let n = self.packets.len();
        self.packets.clear();
        self.bytes = 0;
        n
    }

    fn pop_due(&mut self, now: Instant) -> (VecDeque<Bytes>, usize) {
        let mut expired = 0usize;
        while self
            .packets
            .front()
            .is_some_and(|p| now.saturating_duration_since(p.enqueued_at) > QUEUE_TTL)
        {
            if let Some(p) = self.packets.pop_front() {
                self.bytes = self.bytes.saturating_sub(p.bytes.len());
                expired += 1;
            }
        }
        let mut out = VecDeque::with_capacity(self.packets.len());
        for p in self.packets.drain(..) {
            self.bytes = self.bytes.saturating_sub(p.bytes.len());
            out.push_back(p.bytes);
        }
        debug_assert_eq!(self.bytes, 0);
        (out, expired)
    }
}

struct SessionConn {
    conn: Connection,
    opened_by_us: bool,
}

struct ActiveGen {
    generation: u64,
    cancel: CancellationToken,
}

pub struct SessionCtl {
    manager: PeerManager,
    peer: EndpointId,
    token: u64,
    generation: u64,
}

impl SessionCtl {
    pub fn peer(&self) -> EndpointId {
        self.peer
    }

    pub fn cancel(&self) -> Option<CancellationToken> {
        self.manager.active_cancel(self.generation)
    }

    pub fn finished(&self) {
        self.manager
            .recv_finished(self.peer, self.token, self.generation);
    }
}

pub type RecvHook = Arc<dyn Fn(EndpointId, Connection, SessionCtl) -> JoinHandle<()> + Send + Sync>;

struct PeerSession {
    peer: EndpointId,
    queue: Mutex<SessionQueue>,
    conn: Mutex<Option<SessionConn>>,
    state: Mutex<SessionState>,
    install_lock: Mutex<()>,
    notify: Notify,
    sender_running: AtomicBool,
    sender_handle: Mutex<Option<JoinHandle<()>>>,
    recv_handle: Mutex<Option<JoinHandle<()>>>,
    token: AtomicU64,
    last_activity: Mutex<Instant>,
    last_transport_log: Mutex<Instant>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl PeerSession {
    fn new(peer: EndpointId) -> Self {
        Self {
            peer,
            queue: Mutex::new(SessionQueue {
                packets: VecDeque::new(),
                bytes: 0,
            }),
            conn: Mutex::new(None),
            state: Mutex::new(SessionState::Idle),
            install_lock: Mutex::new(()),
            notify: Notify::new(),
            sender_running: AtomicBool::new(false),
            sender_handle: Mutex::new(None),
            recv_handle: Mutex::new(None),
            token: AtomicU64::new(0),
            last_activity: Mutex::new(Instant::now()),
            last_transport_log: Mutex::new(Instant::now()),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    fn live_conn(&self) -> Option<Connection> {
        self.conn
            .lock()
            .as_ref()
            .filter(|s| s.conn.close_reason().is_none())
            .map(|s| s.conn.clone())
    }
}

struct PeerManagerInner {
    endpoint: Endpoint,
    alpn: &'static [u8],
    sessions: DashMap<EndpointId, Arc<PeerSession>>,
    gate: RwLock<Option<TransportAuth>>,
    metrics: SessionMetrics,
    cloud_relay_meter: CloudRelayMeter,
    cloud_relay_urls: Arc<RwLock<HashSet<String>>>,
    peer_cloud_relay: Arc<DashMap<EndpointId, AtomicBool>>,
    keep_alive: AtomicBool,
    keep_alive_peers: DashMap<EndpointId, ()>,
    active: Mutex<Option<ActiveGen>>,
    recv_hook: Mutex<Option<RecvHook>>,
}

#[derive(Clone)]
pub struct PeerManager {
    inner: Arc<PeerManagerInner>,
}

impl PeerManager {
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        let manager = Self {
            inner: Arc::new(PeerManagerInner {
                endpoint,
                alpn,
                sessions: DashMap::new(),
                gate: RwLock::new(None),
                metrics: SessionMetrics::default(),
                cloud_relay_meter: CloudRelayMeter::new(),
                cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
                peer_cloud_relay: Arc::new(DashMap::new()),
                keep_alive: AtomicBool::new(true),
                keep_alive_peers: DashMap::new(),
                active: Mutex::new(None),
                recv_hook: Mutex::new(None),
            }),
        };
        manager.spawn_idle_sweeper();
        manager
    }

    pub fn set_transport_auth(&self, auth: TransportAuth) {
        *self.inner.gate.write() = Some(auth);
    }

    fn gate_allows(&self, peer_hex: &str) -> bool {
        self.inner
            .gate
            .read()
            .as_ref()
            .is_none_or(|g| g.allows(peer_hex))
    }

    fn gate_generation(&self) -> u64 {
        self.inner
            .gate
            .read()
            .as_ref()
            .map(|g| g.generation())
            .unwrap_or(0)
    }

    pub fn set_recv_hook(&self, hook: RecvHook) {
        *self.inner.recv_hook.lock() = Some(hook);
    }

    pub fn clear_recv_hook(&self) {
        *self.inner.recv_hook.lock() = None;
    }

    pub fn activate(&self, generation: u64, cancel: CancellationToken) {
        *self.inner.active.lock() = Some(ActiveGen { generation, cancel });
    }

    pub fn deactivate(&self) {
        *self.inner.active.lock() = None;
        *self.inner.recv_hook.lock() = None;
        for entry in self.inner.sessions.iter() {
            let session = entry.value().clone();
            session.token.fetch_add(1, Ordering::AcqRel);
            if let Some(h) = session.sender_handle.lock().take() {
                h.abort();
            }
            if let Some(h) = session.recv_handle.lock().take() {
                h.abort();
            }
            session.sender_running.store(false, Ordering::Release);
            if let Some(s) = session.conn.lock().take() {
                s.conn.close(0u32.into(), b"dataplane_down");
            }
            session.queue.lock().drop_all();
            *session.state.lock() = SessionState::Idle;
        }
    }

    fn active_gen(&self) -> Option<u64> {
        self.inner.active.lock().as_ref().map(|a| a.generation)
    }

    fn active_cancel(&self, generation: u64) -> Option<CancellationToken> {
        self.inner
            .active
            .lock()
            .as_ref()
            .filter(|a| a.generation == generation)
            .map(|a| a.cancel.clone())
    }

    fn session(&self, peer: EndpointId) -> Arc<PeerSession> {
        self.inner
            .sessions
            .entry(peer)
            .or_insert_with(|| Arc::new(PeerSession::new(peer)))
            .clone()
    }

    pub fn send(&self, peer: EndpointId, packet: Bytes) -> SendOutcome {
        match self.send_batch(peer, vec![packet]) {
            SendBatchOutcome { admitted: 1, .. } => SendOutcome::Admitted,
            SendBatchOutcome { closed: true, .. } => SendOutcome::Closed,
            SendBatchOutcome { blocked: true, .. } => SendOutcome::Denied,
            _ => SendOutcome::QueueFull,
        }
    }

    pub fn send_batch(&self, peer: EndpointId, packets: Vec<Bytes>) -> SendBatchOutcome {
        if !self.inner.active.lock().is_some() {
            return SendBatchOutcome {
                admitted: 0,
                admitted_bytes: 0,
                queue_full: packets.len(),
                blocked: false,
                closed: true,
            };
        }
        let session = self.session(peer);
        let peer_hex = format!("{peer}");
        let mut out = SendBatchOutcome {
            admitted: 0,
            admitted_bytes: 0,
            queue_full: 0,
            blocked: false,
            closed: false,
        };
        {
            let mut state = session.state.lock();
            if matches!(*state, SessionState::Blocked { generation } if generation == self.gate_generation())
            {
                self.inner
                    .metrics
                    .dials_suppressed
                    .fetch_add(1, Ordering::Relaxed);
                out.blocked = true;
                return out;
            }
            if !self.gate_allows(&peer_hex) {
                let dropped = session.queue.lock().drop_all();
                self.inner
                    .metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64 + packets.len() as u64, Ordering::Relaxed);
                *state = SessionState::Blocked {
                    generation: self.gate_generation(),
                };
                out.blocked = true;
                return out;
            }
            if matches!(*state, SessionState::Blocked { .. }) {
                *state = SessionState::Idle;
            }
            let mut queue = session.queue.lock();
            let mut buffered = 0u64;
            for packet in packets {
                let len = packet.len();
                if !queue.push(packet) {
                    out.queue_full += 1;
                } else {
                    out.admitted += 1;
                    out.admitted_bytes += len as u64;
                    buffered += 1;
                }
            }
            drop(queue);
            if out.queue_full > 0 {
                self.inner
                    .metrics
                    .packets_dropped_timeout
                    .fetch_add(out.queue_full as u64, Ordering::Relaxed);
            }
            if buffered > 0 {
                self.inner
                    .metrics
                    .packets_buffered
                    .fetch_add(buffered, Ordering::Relaxed);
            }
        }
        if out.admitted > 0 {
            session.touch();
            self.ensure_sender(&session);
            session.notify.notify_one();
        }
        out
    }

    pub fn conn_max_datagram_size(&self, peer: EndpointId) -> Option<usize> {
        let session = self.inner.sessions.get(&peer)?;
        session.live_conn()?.max_datagram_size()
    }

    fn ensure_sender(&self, session: &Arc<PeerSession>) {
        if session.sender_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(generation) = self.active_gen() else {
            session.sender_running.store(false, Ordering::Release);
            return;
        };
        let manager = self.clone();
        let sender_session = session.clone();
        let token = session.token.load(Ordering::Acquire);
        let handle = tokio::spawn(async move {
            run_sender(manager, sender_session, token, generation).await;
        });
        *session.sender_handle.lock() = Some(handle);
    }

    pub fn install(&self, peer: EndpointId, conn: Connection, opened_by_us: bool) -> bool {
        let (generation, cancel) = match self.inner.active.lock().as_ref() {
            Some(a) => (a.generation, a.cancel.clone()),
            None => {
                conn.close(0u32.into(), b"dataplane_down");
                return false;
            }
        };
        if cancel.is_cancelled() {
            conn.close(0u32.into(), b"dataplane_down");
            return false;
        }
        let peer_hex = format!("{peer}");
        if !self.gate_allows(&peer_hex) {
            conn.close(1u32.into(), b"not_authorized");
            return false;
        }
        let session = self.session(peer);
        let _guard = session.install_lock.lock();
        let token = session.token.load(Ordering::Acquire);
        {
            let mut slot = session.conn.lock();
            if let Some(existing) = slot.as_ref().filter(|s| s.conn.close_reason().is_none()) {
                if !prefer_incoming(
                    self.inner.endpoint.id(),
                    peer,
                    existing.opened_by_us,
                    opened_by_us,
                ) {
                    conn.close(0u32.into(), b"tie_break");
                    return false;
                }
                existing.conn.close(0u32.into(), b"tie_break");
            }
            *slot = Some(SessionConn {
                conn: conn.clone(),
                opened_by_us,
            });
            *session.state.lock() = SessionState::Connected {
                auth_gen: self.gate_generation(),
            };
        }
        session.touch();
        self.spawn_cloud_relay_path_watch(peer, conn.clone());
        if let Some(hook) = self.inner.recv_hook.lock().clone() {
            let ctl = SessionCtl {
                manager: self.clone(),
                peer,
                token,
                generation,
            };
            let handle = hook(peer, conn.clone(), ctl);
            if let Some(old) = session.recv_handle.lock().replace(handle) {
                old.abort();
            }
        }
        self.ensure_sender(&session);
        session.notify.notify_one();
        true
    }

    fn recv_finished(&self, peer: EndpointId, token: u64, generation: u64) {
        if self.active_gen() != Some(generation) {
            return;
        }
        let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) else {
            return;
        };
        if session.token.load(Ordering::Acquire) != token {
            return;
        }
        let mut guard = session.recv_handle.lock();
        if guard.as_ref().is_some_and(|h| h.is_finished()) {
            guard.take();
        }
    }

    pub async fn reconcile(&self) {
        let generation = self.gate_generation();
        for entry in self.inner.sessions.iter() {
            let session = entry.value().clone();
            let peer_hex = format!("{}", session.peer);
            if self.gate_allows(&peer_hex) {
                let mut state = session.state.lock();
                match *state {
                    SessionState::Blocked { .. } | SessionState::Rejected { .. } => {
                        *state = SessionState::Idle;
                        session.notify.notify_one();
                    }
                    _ => {}
                }
                drop(state);
                let _ = generation;
                continue;
            }
            let dropped = session.queue.lock().drop_all();
            self.inner
                .metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            if let Some(s) = session.conn.lock().take() {
                s.conn.close(1u32.into(), b"not_authorized");
            }
            let mut state = session.state.lock();
            if !matches!(*state, SessionState::Blocked { generation: g } if g == generation) {
                *state = SessionState::Blocked { generation };
                session.notify.notify_one();
            }
        }
    }

    pub async fn revoke_peer(&self, peer: EndpointId) {
        let generation = self.gate_generation();
        if let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) {
            let dropped = session.queue.lock().drop_all();
            self.inner
                .metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            if let Some(s) = session.conn.lock().take() {
                s.conn.close(1u32.into(), b"not_authorized");
            }
            if let Some(h) = session.recv_handle.lock().take() {
                h.abort();
            }
            *session.state.lock() = SessionState::Blocked { generation };
            session.notify.notify_one();
        }
    }

    pub async fn close_all(&self) {
        for entry in self.inner.sessions.iter() {
            let session = entry.value().clone();
            session.queue.lock().drop_all();
            if let Some(s) = session.conn.lock().take() {
                s.conn.close(0u32.into(), b"dataplane_down");
            }
            *session.state.lock() = SessionState::Idle;
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
    }

    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        let normalized: HashSet<String> = urls
            .into_iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect();
        *self.inner.cloud_relay_urls.write() = normalized;
        self.inner.peer_cloud_relay.clear();
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.inner.cloud_relay_meter.clone()
    }

    fn spawn_cloud_relay_path_watch(&self, peer: EndpointId, conn: Connection) {
        let urls = self.inner.cloud_relay_urls.clone();
        let flags = self.inner.peer_cloud_relay.clone();
        tokio::spawn(async move {
            let refresh = |conn: &Connection| {
                let metered = selected_path_is_cloud_relay(conn, &urls.read());
                flags
                    .entry(peer)
                    .or_insert_with(|| AtomicBool::new(false))
                    .store(metered, Ordering::Relaxed);
            };
            refresh(&conn);
            let mut events = conn.path_events();
            while let Some(ev) = events.next().await {
                match ev {
                    PathEvent::Selected { .. }
                    | PathEvent::Lagged { .. }
                    | PathEvent::Opened { .. }
                    | PathEvent::Closed { .. } => {
                        refresh(&conn);
                    }
                    _ => {}
                }
            }
            flags.remove(&peer);
        });
    }

    pub fn record_bytes_in(&self, peer: EndpointId, n: u64) {
        if let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) {
            session.bytes_in.fetch_add(n, Ordering::Relaxed);
            session.touch();
        }
    }

    fn record_bytes_out(&self, session: &PeerSession, n: u64) {
        session.bytes_out.fetch_add(n, Ordering::Relaxed);
        if self
            .inner
            .peer_cloud_relay
            .get(&session.peer)
            .is_some_and(|f| f.load(Ordering::Relaxed))
        {
            self.inner.cloud_relay_meter.record(n);
        }
        session.touch();
    }

    pub fn has_live(&self, peer: EndpointId) -> bool {
        let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) else {
            return false;
        };
        match session.conn.try_lock() {
            Some(g) => g.as_ref().is_some_and(|s| s.conn.close_reason().is_none()),
            None => true,
        }
    }

    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let mut active_conns = 0u32;
        let mut bytes_rx = 0u64;
        let mut bytes_tx = 0u64;
        for entry in self.inner.sessions.iter() {
            let session = entry.value();
            let live = match session.conn.try_lock() {
                Some(g) => g.as_ref().is_some_and(|s| s.conn.close_reason().is_none()),
                None => true,
            };
            if live {
                active_conns += 1;
            }
            bytes_rx += session.bytes_in.load(Ordering::Relaxed);
            bytes_tx += session.bytes_out.load(Ordering::Relaxed);
        }
        (active_conns, bytes_tx, bytes_rx)
    }

    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) else {
            return (0, 0);
        };
        (
            session.bytes_in.load(Ordering::Relaxed),
            session.bytes_out.load(Ordering::Relaxed),
        )
    }

    pub fn peer_snapshot(&self, peer: EndpointId) -> PeerConnSnapshot {
        let keep_alive = self.keep_alive() || self.inner.keep_alive_peers.contains_key(&peer);
        let Some(session) = self.inner.sessions.get(&peer).map(|e| e.value().clone()) else {
            return PeerConnSnapshot {
                state: "idle".into(),
                keep_alive,
                last_activity_secs_ago: u64::MAX,
                live: false,
                path: "unknown".into(),
            };
        };
        let conn_guard = session.conn.try_lock();
        let live = conn_guard
            .as_ref()
            .and_then(|g| g.as_ref())
            .map(|s| s.conn.clone());
        let state = match session.state.try_lock() {
            Some(g) => g.as_str().to_string(),
            None => "connected".to_string(),
        };
        PeerConnSnapshot {
            state,
            keep_alive,
            last_activity_secs_ago: session.last_activity.lock().elapsed().as_secs(),
            live: live.is_some(),
            path: selected_path_kind(live.as_ref()),
        }
    }

    pub fn session_stats(&self) -> SessionStats {
        let success = self.inner.metrics.reconnect_success.load(Ordering::Relaxed);
        let sum = self
            .inner
            .metrics
            .reconnect_latency_sum_us
            .load(Ordering::Relaxed);
        SessionStats {
            reconnect_attempts: self
                .inner
                .metrics
                .reconnect_attempts
                .load(Ordering::Relaxed),
            reconnect_success: success,
            reconnect_fail: self.inner.metrics.reconnect_fail.load(Ordering::Relaxed),
            packets_buffered: self.inner.metrics.packets_buffered.load(Ordering::Relaxed),
            packets_dropped_timeout: self
                .inner
                .metrics
                .packets_dropped_timeout
                .load(Ordering::Relaxed)
                + self
                    .inner
                    .metrics
                    .packets_dropped_transport
                    .load(Ordering::Relaxed),
            packets_dropped_blocked: self
                .inner
                .metrics
                .packets_dropped_blocked
                .load(Ordering::Relaxed),
            dials_suppressed: self.inner.metrics.dials_suppressed.load(Ordering::Relaxed),
            reconnect_latency_avg_us: sum.checked_div(success).unwrap_or(0),
            reconnect_latency_max_us: self
                .inner
                .metrics
                .reconnect_latency_max_us
                .load(Ordering::Relaxed),
        }
    }

    fn spawn_idle_sweeper(&self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if inner.keep_alive.load(Ordering::Relaxed) {
                    continue;
                }
                for entry in inner.sessions.iter() {
                    let session = entry.value().clone();
                    if inner.keep_alive_peers.contains_key(&session.peer) {
                        continue;
                    }
                    let idle = matches!(*session.state.lock(), SessionState::Connected { .. })
                        && session.queue.lock().packets.is_empty()
                        && session.last_activity.lock().elapsed()
                            >= Duration::from_secs(crate::iroh_pool::DEFAULT_IDLE_SECS);
                    if !idle {
                        continue;
                    }
                    if let Some(s) = session.conn.lock().take() {
                        s.conn.close(0u32.into(), b"idle");
                    }
                    *session.state.lock() = SessionState::Idle;
                    session.notify.notify_one();
                }
            }
        });
    }

    async fn dial_once(&self, peer: EndpointId) -> Result<Connection, (DialFailure, Arc<str>)> {
        let start = Instant::now();
        self.inner
            .metrics
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(
            RECONNECT_TIMEOUT,
            self.inner.endpoint.connect(peer, self.inner.alpn),
        )
        .await
        {
            Ok(Ok(conn)) => {
                if let Some(reason) = conn.close_reason() {
                    let msg: Arc<str> =
                        Arc::from(format!("connection to {peer} dead on arrival: {reason:?}"));
                    if is_auth_close_error(&reason) {
                        return Err((DialFailure::RemoteRejected, msg));
                    }
                    return Err((DialFailure::Transient, msg));
                }
                let latency_us = start.elapsed().as_micros() as u64;
                self.inner
                    .metrics
                    .reconnect_success
                    .fetch_add(1, Ordering::Relaxed);
                self.inner
                    .metrics
                    .reconnect_latency_sum_us
                    .fetch_add(latency_us, Ordering::Relaxed);
                let max = self
                    .inner
                    .metrics
                    .reconnect_latency_max_us
                    .load(Ordering::Relaxed);
                if latency_us > max {
                    self.inner
                        .metrics
                        .reconnect_latency_max_us
                        .store(latency_us, Ordering::Relaxed);
                }
                Ok(conn)
            }
            Ok(Err(e)) => {
                let kind = classify_connect_error(&e);
                let msg: Arc<str> = Arc::from(format!("connect to {peer}: {e}"));
                Err((kind, msg))
            }
            Err(_) => Err((
                DialFailure::Transient,
                Arc::from(format!("reconnect to {peer} timed out")),
            )),
        }
    }
}

async fn run_sender(manager: PeerManager, session: Arc<PeerSession>, token: u64, generation: u64) {
    let peer = session.peer;
    loop {
        if manager.active_gen() != Some(generation)
            || session.token.load(Ordering::Acquire) != token
        {
            break;
        }
        let conn = session.live_conn();
        if let Some(conn) = conn {
            let gate_gen = manager.gate_generation();
            let validated = matches!(*session.state.lock(), SessionState::Connected { auth_gen } if auth_gen == gate_gen);
            if !validated {
                if manager.gate_allows(&format!("{peer}")) {
                    *session.state.lock() = SessionState::Connected { auth_gen: gate_gen };
                } else {
                    if let Some(s) = session.conn.lock().take() {
                        s.conn.close(1u32.into(), b"not_authorized");
                    }
                    let dropped = session.queue.lock().drop_all();
                    manager
                        .inner
                        .metrics
                        .packets_dropped_blocked
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                    *session.state.lock() = SessionState::Blocked {
                        generation: gate_gen,
                    };
                    continue;
                }
            }
            let now = Instant::now();
            let (mut due, expired) = session.queue.lock().pop_due(now);
            if expired > 0 {
                manager
                    .inner
                    .metrics
                    .packets_dropped_timeout
                    .fetch_add(expired as u64, Ordering::Relaxed);
            }
            if due.is_empty() {
                session.notify.notified().await;
                continue;
            }
            let total = due.len();
            let out = send_datagram_batch(&conn, &mut due).await;
            debug_assert!(due.is_empty());
            if out.accepted > 0 {
                manager.record_bytes_out(&session, out.accepted_bytes);
            }
            let dropped = total - out.accepted;
            if dropped > 0 {
                manager
                    .inner
                    .metrics
                    .packets_dropped_transport
                    .fetch_add(dropped as u64, Ordering::Relaxed);
            }
            if now.saturating_duration_since(*session.last_transport_log.lock())
                >= TRANSPORT_LOG_EVERY
            {
                *session.last_transport_log.lock() = now;
                let stats = conn.stats();
                tracing::info!(
                    peer = %peer,
                    max_datagram_size = ?conn.max_datagram_size(),
                    udp_tx_datagrams = stats.udp_tx.datagrams,
                    udp_tx_bytes = stats.udp_tx.bytes,
                    lost_packets = stats.lost_packets,
                    lost_bytes = stats.lost_bytes,
                    accepted = out.accepted,
                    oversize = out.oversize,
                    send_dropped = out.transport_drops,
                    "tunnel transport state",
                );
            }
            if conn.close_reason().is_some() {
                if session
                    .conn
                    .lock()
                    .as_ref()
                    .is_some_and(|s| s.conn.close_reason().is_some())
                {
                    session.conn.lock().take();
                }
                classify_dead_conn(&manager, &session, &conn, peer);
                continue;
            }
            continue;
        }

        if session.conn.lock().take().is_some() {
            *session.state.lock() = SessionState::Idle;
        }
        enum Decision {
            Dial,
            Wait(Instant),
            Hold,
        }
        let decision = {
            let mut state = session.state.lock();
            let gate_gen = manager.gate_generation();
            let peer_hex = format!("{peer}");
            if !manager.gate_allows(&peer_hex) {
                let fresh = !matches!(*state, SessionState::Blocked { generation } if generation == gate_gen);
                *state = SessionState::Blocked {
                    generation: gate_gen,
                };
                if fresh {
                    let dropped = session.queue.lock().drop_all();
                    manager
                        .inner
                        .metrics
                        .packets_dropped_blocked
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                } else {
                    manager
                        .inner
                        .metrics
                        .dials_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Decision::Hold
            } else {
                if matches!(*state, SessionState::Blocked { .. }) {
                    *state = SessionState::Idle;
                }
                match *state {
                    SessionState::Rejected {
                        generation,
                        retry_after,
                        ..
                    } => {
                        if generation != gate_gen || Instant::now() >= retry_after {
                            if session.queue.lock().packets.is_empty() {
                                Decision::Hold
                            } else {
                                Decision::Dial
                            }
                        } else {
                            manager
                                .inner
                                .metrics
                                .dials_suppressed
                                .fetch_add(1, Ordering::Relaxed);
                            Decision::Wait(retry_after)
                        }
                    }
                    SessionState::Backoff { until, .. } => {
                        if Instant::now() >= until {
                            if session.queue.lock().packets.is_empty() {
                                Decision::Hold
                            } else {
                                Decision::Dial
                            }
                        } else {
                            manager
                                .inner
                                .metrics
                                .dials_suppressed
                                .fetch_add(1, Ordering::Relaxed);
                            Decision::Wait(until)
                        }
                    }
                    SessionState::Connecting => Decision::Hold,
                    _ => {
                        if session.queue.lock().packets.is_empty() {
                            Decision::Hold
                        } else {
                            Decision::Dial
                        }
                    }
                }
            }
        };
        match decision {
            Decision::Hold => {
                session.notify.notified().await;
            }
            Decision::Wait(until) => {
                tokio::select! {
                    _ = session.notify.notified() => {}
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(until)) => {}
                }
            }
            Decision::Dial => {
                *session.state.lock() = SessionState::Connecting;
                let rejected_ctx = match *session.state.lock() {
                    SessionState::Rejected {
                        generation, first, ..
                    } => Some((generation, first)),
                    _ => None,
                };
                let backoff_step = match *session.state.lock() {
                    SessionState::Backoff { step, .. } => step,
                    _ => 0,
                };
                match manager.dial_once(peer).await {
                    Ok(conn) => {
                        if !manager.gate_allows(&format!("{peer}")) {
                            conn.close(1u32.into(), b"not_authorized");
                            let dropped = session.queue.lock().drop_all();
                            manager
                                .inner
                                .metrics
                                .packets_dropped_blocked
                                .fetch_add(dropped as u64, Ordering::Relaxed);
                            *session.state.lock() = SessionState::Blocked {
                                generation: manager.gate_generation(),
                            };
                            continue;
                        }
                        manager.install(peer, conn, true);
                    }
                    Err((DialFailure::LocalDenied, _)) => {
                        let dropped = session.queue.lock().drop_all();
                        manager
                            .inner
                            .metrics
                            .packets_dropped_blocked
                            .fetch_add(dropped as u64, Ordering::Relaxed);
                        manager
                            .inner
                            .metrics
                            .reconnect_fail
                            .fetch_add(1, Ordering::Relaxed);
                        *session.state.lock() = SessionState::Blocked {
                            generation: manager.gate_generation(),
                        };
                    }
                    Err((DialFailure::RemoteRejected, _)) => {
                        manager
                            .inner
                            .metrics
                            .reconnect_fail
                            .fetch_add(1, Ordering::Relaxed);
                        let now = Instant::now();
                        let generation = manager.gate_generation();
                        let (first, _continuing) = match rejected_ctx {
                            Some((g, first)) if g == generation => (first, true),
                            _ => (now, false),
                        };
                        let delay = remote_retry_delay(now.saturating_duration_since(first));
                        *session.state.lock() = SessionState::Rejected {
                            generation,
                            first,
                            retry_after: now + delay,
                        };
                    }
                    Err((DialFailure::Transient, _)) => {
                        manager
                            .inner
                            .metrics
                            .reconnect_fail
                            .fetch_add(1, Ordering::Relaxed);
                        let wait = backoff_delay(backoff_step);
                        *session.state.lock() = SessionState::Backoff {
                            until: Instant::now() + wait,
                            step: backoff_step.saturating_add(1),
                        };
                    }
                }
            }
        }
    }
    if session.token.load(Ordering::Acquire) == token {
        session.sender_running.store(false, Ordering::Release);
        if manager.active_gen() == Some(generation) && !session.queue.lock().packets.is_empty() {
            manager.ensure_sender(&session);
        }
    }
}

fn classify_dead_conn(
    manager: &PeerManager,
    session: &Arc<PeerSession>,
    dead: &Connection,
    peer: EndpointId,
) {
    let generation = manager.gate_generation();
    if matches!(*session.state.lock(), SessionState::Rejected { generation: g, .. } if g == generation)
    {
        return;
    }
    let Some(reason) = dead.close_reason() else {
        *session.state.lock() = SessionState::Idle;
        return;
    };
    if !is_auth_close_error(&reason) {
        *session.state.lock() = SessionState::Idle;
        return;
    }
    let now = Instant::now();
    *session.state.lock() = SessionState::Rejected {
        generation,
        first: now,
        retry_after: now + remote_retry_delay(Duration::ZERO),
    };
    let _ = peer;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn queue_admission_enforces_packet_and_byte_limits() {
        let mut q = SessionQueue {
            packets: VecDeque::new(),
            bytes: 0,
        };
        for _ in 0..MAX_QUEUE_PACKETS {
            assert!(q.push(Bytes::from_static(b"x")));
        }
        assert!(!q.push(Bytes::from_static(b"overflow")));

        let mut q = SessionQueue {
            packets: VecDeque::new(),
            bytes: 0,
        };
        assert!(q.push(Bytes::from(vec![0u8; MAX_QUEUE_BYTES])));
        assert!(!q.push(Bytes::from_static(b"overflow")));
    }

    #[test]
    fn queue_ttl_expiry_drops_stale_packets() {
        let mut q = SessionQueue {
            packets: VecDeque::new(),
            bytes: 0,
        };
        q.packets.push_back(QueuedPacket {
            bytes: Bytes::from_static(b"stale"),
            enqueued_at: Instant::now() - QUEUE_TTL - Duration::from_secs(1),
        });
        q.bytes = 5;
        q.packets.push_back(QueuedPacket {
            bytes: Bytes::from_static(b"fresh"),
            enqueued_at: Instant::now(),
        });
        q.bytes += 5;
        let (due, expired) = q.pop_due(Instant::now());
        assert_eq!(expired, 1);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], Bytes::from_static(b"fresh"));
        assert_eq!(q.bytes, 0);
    }

    #[rstest]
    #[case(false, true, true)]
    #[case(true, false, false)]
    #[case(true, true, false)]
    #[case(false, false, false)]
    fn tie_break_prefers_canonical_initiator_side(
        #[case] existing_by_us: bool,
        #[case] incoming_by_us: bool,
        #[case] want_switch: bool,
    ) {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        assert_eq!(
            prefer_incoming(low, high, existing_by_us, incoming_by_us),
            want_switch
        );
        assert_eq!(
            prefer_incoming(high, low, incoming_by_us, existing_by_us),
            want_switch
        );
    }

    #[rstest]
    #[case(0)]
    #[case(3)]
    #[case(11)]
    fn backoff_delay_stays_bounded(#[case] step: u32) {
        assert!(backoff_delay(step) <= BACKOFF_CAP);
    }

    #[test]
    fn backoff_delay_grows_with_step() {
        assert!(backoff_delay(8) > backoff_delay(0));
    }

    #[test]
    fn remote_retry_delay_is_bounded_and_grows() {
        let fresh = remote_retry_delay(Duration::ZERO);
        assert!(fresh >= Duration::from_secs(5));
        let aged = remote_retry_delay(Duration::from_secs(3600));
        assert!(aged <= REMOTE_RETRY_CAP);
        assert!(aged > fresh);
    }

    async fn bind_endpoint() -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .expect("bind test endpoint")
    }

    fn active_manager(ep: Endpoint) -> PeerManager {
        let manager = PeerManager::new(ep, b"test/tunnel");
        manager.activate(1, CancellationToken::new());
        manager
    }

    #[tokio::test]
    async fn install_before_activation_is_rejected() {
        const ALPN: &[u8] = b"test/inactive-install";
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind server");
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind client");
        let accept = tokio::spawn({
            let server = server.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    tokio::spawn(async move {
                        let _ = incoming.await;
                    });
                }
            }
        });
        let conn = client.connect(server.addr(), ALPN).await.expect("connect");
        let peer = server.id();
        let ep = bind_endpoint().await;
        let manager = PeerManager::new(ep, ALPN);
        assert_eq!(
            manager.send(peer, Bytes::from_static(b"p")),
            SendOutcome::Closed
        );
        assert!(!manager.install(peer, conn, false));
        accept.abort();
    }

    #[tokio::test]
    async fn blocked_peer_denies_without_dial() {
        use crate::routing::RoutingTable;
        let ep = bind_endpoint().await;
        let manager = active_manager(ep);
        let routes = RoutingTable::new();
        manager.set_transport_auth(TransportAuth::managed(&routes));
        let peer = iroh::SecretKey::generate().public();
        for _ in 0..8 {
            assert_eq!(
                manager.send(peer, Bytes::from_static(b"p")),
                SendOutcome::Denied
            );
        }
        assert_eq!(manager.session_stats().reconnect_attempts, 0);
        assert!(manager.session_stats().dials_suppressed > 0);
    }

    #[tokio::test]
    async fn revoke_peer_drops_queue_and_blocks() {
        let ep = bind_endpoint().await;
        let manager = active_manager(ep);
        let peer = iroh::SecretKey::generate().public();
        assert_eq!(
            manager.send(peer, Bytes::from_static(b"one")),
            SendOutcome::Admitted
        );
        manager.revoke_peer(peer).await;
        assert_eq!(
            manager.send(peer, Bytes::from_static(b"two")),
            SendOutcome::Denied
        );
        let snap = manager.peer_snapshot(peer);
        assert_eq!(snap.state, "blocked");
    }

    #[tokio::test]
    async fn stale_recv_finish_keeps_newer_reader() {
        let ep = bind_endpoint().await;
        let manager = active_manager(ep);
        let peer = iroh::SecretKey::generate().public();
        let session = manager.session(peer);
        let h1 = tokio::spawn(async {});
        let h2 = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(30)).await });
        *session.recv_handle.lock() = Some(h1);
        let token = session.token.load(Ordering::Acquire);
        *session.recv_handle.lock() = Some(h2);
        manager.recv_finished(peer, token, 1);
        assert!(session.recv_handle.lock().is_some());
        if let Some(h) = session.recv_handle.lock().take() {
            h.abort();
        }
    }

    #[tokio::test]
    async fn session_roundtrip_over_real_quic() {
        use iroh::address_lookup::memory::MemoryLookup;
        const ALPN: &[u8] = b"test/tunnel-rt";
        let disco = MemoryLookup::new();
        let endpoint_a = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(disco.clone())
            .bind()
            .await
            .expect("bind A");
        let endpoint_b = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(disco.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind B");
        disco.add_endpoint_info(endpoint_a.addr());
        disco.add_endpoint_info(endpoint_b.addr());
        let id_b = endpoint_b.id();
        let (got_tx, mut got_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let accept = tokio::spawn({
            let endpoint_b = endpoint_b.clone();
            async move {
                while let Some(incoming) = endpoint_b.accept().await {
                    let tx = got_tx.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let mut batch: [Bytes; 8] = std::array::from_fn(|_| Bytes::new());
                            while let Ok(n) = conn.read_many_datagrams(&mut batch).await {
                                for dg in &batch[..n] {
                                    let _ = tx.send(dg.to_vec()).await;
                                }
                                batch[n..].fill(Bytes::new());
                            }
                        }
                    });
                }
            }
        });

        let manager = PeerManager::new(endpoint_a.clone(), ALPN);
        manager.activate(7, CancellationToken::new());
        manager.set_recv_hook(Arc::new(|_, _, _| tokio::spawn(async {})));
        for i in 0..5u8 {
            assert_eq!(
                manager.send(id_b, Bytes::from(vec![i; 64])),
                SendOutcome::Admitted
            );
        }
        let mut received = Vec::new();
        for _ in 0..5 {
            received.push(
                tokio::time::timeout(Duration::from_secs(20), got_rx.recv())
                    .await
                    .expect("datagram arrives")
                    .expect("channel open"),
            );
        }
        received.sort();
        assert_eq!(received, (0..5u8).map(|i| vec![i; 64]).collect::<Vec<_>>());
        assert!(manager.has_live(id_b));
        let (active, tx, rx) = manager.heartbeat_counters();
        assert_eq!(active, 1);
        assert_eq!(tx, 5 * 64);
        let _ = rx;
        manager.deactivate();
        assert!(!manager.has_live(id_b));
        accept.abort();
    }

    #[tokio::test]
    async fn send_datagram_batch_drains_queue() {
        for count in [1, SEND_BATCH_MAX, SEND_BATCH_MAX + 5] {
            assert_batch_roundtrip(count).await;
        }
    }

    async fn assert_batch_roundtrip(count: usize) {
        const ALPN: &[u8] = b"test/batch-rt";
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind server");
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind client");
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(count * 2);
        let accept = tokio::spawn({
            let server = server.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let Ok(conn) = incoming.await else { return };
                        let mut batch: [Bytes; SEND_BATCH_MAX] =
                            std::array::from_fn(|_| Bytes::new());
                        while let Ok(n) = conn.read_many_datagrams(&mut batch).await {
                            for dg in &batch[..n] {
                                if tx.send(dg[0]).await.is_err() {
                                    return;
                                }
                            }
                            batch[n..].fill(Bytes::new());
                        }
                    });
                }
            }
        });
        let conn = client.connect(server.addr(), ALPN).await.expect("connect");
        let mut queue: VecDeque<Bytes> =
            (0..count).map(|i| Bytes::from(vec![i as u8; 64])).collect();
        let out = send_datagram_batch(&conn, &mut queue).await;
        assert_eq!(out.accepted, count);
        assert_eq!(out.accepted_bytes, (count * 64) as u64);
        assert_eq!(out.oversize, 0);
        assert_eq!(out.transport_drops, 0);
        assert!(queue.is_empty());
        let mut received = Vec::with_capacity(count);
        for _ in 0..count {
            received.push(
                tokio::time::timeout(Duration::from_secs(15), rx.recv())
                    .await
                    .expect("datagram arrives")
                    .expect("channel open"),
            );
        }
        assert_eq!(received, (0..count).map(|i| i as u8).collect::<Vec<_>>());
        accept.abort();
    }

    #[tokio::test]
    async fn send_datagram_batch_skips_oversized() {
        const ALPN: &[u8] = b"test/batch-skip";
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind server");
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind client");
        let server_addr = server.addr();
        let accept = tokio::spawn({
            async move {
                while let Some(incoming) = server.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(conn);
                        }
                    });
                }
            }
        });
        let conn = client.connect(server_addr, ALPN).await.expect("connect");
        let max = conn.max_datagram_size().expect("datagrams enabled");
        let mut queue: VecDeque<Bytes> = VecDeque::from([
            Bytes::from(vec![1u8; 64]),
            Bytes::from(vec![0u8; max + 1]),
            Bytes::from(vec![2u8; 64]),
        ]);
        let out = send_datagram_batch(&conn, &mut queue).await;
        assert_eq!(out.accepted, 2);
        assert_eq!(out.oversize, 1);
        assert_eq!(out.transport_drops, 0);
        assert!(queue.is_empty());
        accept.abort();
    }

    #[rstest]
    #[case(1)]
    #[case(33)]
    #[case(96)]
    #[tokio::test]
    async fn send_datagram_batch_chunks_whole_queue(#[case] count: usize) {
        const ALPN: &[u8] = b"test/batch-chunk";
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind server");
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .expect("bind client");
        let server_addr = server.addr();
        let accept = tokio::spawn({
            async move {
                while let Some(incoming) = server.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let mut batch: [Bytes; SEND_BATCH_MAX] =
                                std::array::from_fn(|_| Bytes::new());
                            while conn.read_many_datagrams(&mut batch).await.is_ok() {
                                batch.fill(Bytes::new());
                            }
                        }
                    });
                }
            }
        });
        let conn = client.connect(server_addr, ALPN).await.expect("connect");
        let mut queue: VecDeque<Bytes> = (0..count)
            .map(|i| Bytes::from(vec![(i % 251) as u8; 64]))
            .collect();
        let out = send_datagram_batch(&conn, &mut queue).await;
        assert_eq!(out.accepted, count);
        assert!(queue.is_empty());
        accept.abort();
    }
}
