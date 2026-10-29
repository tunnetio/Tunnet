//! Connection pool with optional on-demand (idle suspend / reconnect) behavior.
//!
//! Direct mode defaults to on-demand (`keep_alive = false`): idle connections are
//! closed after [`DEFAULT_IDLE_SECS`] and reopened when traffic resumes.
//! Managed mode defaults to keep-alive (connections stay open).
//!
//! This pool serves stream-oriented services (streams, blobs, ping, recording).
//! IP-datagram tunnel sessions are owned by [`crate::peer::PeerManager`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::HashMap;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::peer::{
    DialFailure, RECONNECT_TIMEOUT, backoff_delay, classify_connect_error, is_auth_close_error,
    remote_retry_delay,
};
use crate::transport_auth::{CLOSE_NOT_MEMBER, CLOSE_NOT_MEMBER_REASON, TransportAuth};

pub const DEFAULT_IDLE_SECS: u64 = 120;

type DialResult = Result<Connection, Arc<str>>;
type DialWaiters = tokio::sync::broadcast::Sender<DialResult>;

enum Readiness {
    Dial,
    Deny,
    Wait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnState {
    Connected {
        auth_gen: u64,
    },
    Dialing,
    Idle,
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

impl PeerConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected { .. } => "connected",
            Self::Dialing => "dialing",
            Self::Idle => "idle",
            Self::Backoff { .. } => "backoff",
            Self::Blocked { .. } => "blocked",
            Self::Rejected { .. } => "rejected",
        }
    }
}

struct PeerSlot {
    conn: Option<Connection>,
    state: PeerConnState,
    last_activity: Instant,
    dial_waiters: Option<DialWaiters>,
    lifecycle: u64,
    dial_id: u64,
    dial_cancel: Option<CancellationToken>,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            state: PeerConnState::Idle,
            last_activity: Instant::now(),
            dial_waiters: None,
            lifecycle: 0,
            dial_id: 0,
            dial_cancel: None,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn live_conn(&self) -> Option<Connection> {
        self.conn
            .as_ref()
            .filter(|c| c.close_reason().is_none())
            .cloned()
    }
}

#[derive(Default)]
struct PoolMetrics {
    reconnect_attempts: AtomicU64,
    reconnect_success: AtomicU64,
    reconnect_fail: AtomicU64,
    dials_suppressed: AtomicU64,
    reconnect_latency_sum_us: AtomicU64,
    reconnect_latency_max_us: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnDemandStats {
    pub reconnect_attempts: u64,
    pub reconnect_success: u64,
    pub reconnect_fail: u64,
    pub dials_suppressed: u64,
    pub reconnect_latency_avg_us: u64,
    pub reconnect_latency_max_us: u64,
}

enum LiveUse {
    Use(Connection),
    Revoked,
    Absent,
}

fn not_authorized(peer: EndpointId) -> anyhow::Error {
    anyhow::anyhow!("not_authorized: {peer} is not an authorized peer")
}

fn not_authorized_remote(peer: EndpointId) -> anyhow::Error {
    anyhow::anyhow!("not_authorized: {peer} rejected the connection")
}

fn mark_local_blocked(slot: &mut PeerSlot, generation: u64) -> bool {
    if let Some(cancel) = slot.dial_cancel.take() {
        cancel.cancel();
    }
    if let Some(c) = slot.conn.take() {
        c.close(CLOSE_NOT_MEMBER.into(), CLOSE_NOT_MEMBER_REASON);
    }
    let state = &mut slot.state;
    let fresh = !matches!(state, PeerConnState::Blocked { generation: g } if *g == generation);
    *state = PeerConnState::Blocked { generation };
    fresh
}

struct Lifecycle {
    generation: u64,
    cancel: CancellationToken,
    shutdown: bool,
}

type SlotKey = (EndpointId, &'static [u8]);
type SlotHandle = Arc<AsyncMutex<PeerSlot>>;

struct DialContext {
    generation: u64,
    id: u64,
    cancel: CancellationToken,
    rejected: Option<(u64, Instant)>,
    step: u32,
}

struct PoolInner {
    endpoint: Endpoint,
    alpn: &'static [u8],
    entries: Mutex<HashMap<SlotKey, SlotHandle>>,
    keep_alive: AtomicBool,
    metrics: PoolMetrics,
    gate: RwLock<Option<TransportAuth>>,
    lifecycle: RwLock<Lifecycle>,
    tasks: TaskTracker,
    dial_limit: Arc<tokio::sync::Semaphore>,
    sweeper: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for PoolInner {
    fn drop(&mut self) {
        self.lifecycle.get_mut().cancel.cancel();
        if let Some(task) = self.sweeper.get_mut().take() {
            task.abort();
        }
    }
}

#[derive(Clone)]
pub struct ConnPool {
    inner: Arc<PoolInner>,
}

const MAX_SLOTS: usize = 2048;

impl ConnPool {
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        let pool = Self {
            inner: Arc::new(PoolInner {
                endpoint,
                alpn,
                entries: Mutex::new(HashMap::new()),
                keep_alive: AtomicBool::new(true),
                metrics: PoolMetrics::default(),
                gate: RwLock::new(None),
                lifecycle: RwLock::new(Lifecycle {
                    generation: 0,
                    cancel: CancellationToken::new(),
                    shutdown: false,
                }),
                tasks: TaskTracker::new(),
                dial_limit: Arc::new(tokio::sync::Semaphore::new(MAX_SLOTS)),
                sweeper: Mutex::new(None),
            }),
        };
        pool.spawn_idle_sweeper();
        pool
    }

    pub fn set_transport_auth(&self, auth: TransportAuth) {
        let _life = self.inner.lifecycle.write();
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

    fn readiness(
        &self,
        state: &mut PeerConnState,
        peer: EndpointId,
        peer_hex: &str,
        now: Instant,
    ) -> Readiness {
        let (allows, generation) = {
            let gate = self.inner.gate.read();
            match gate.as_ref() {
                None => (true, 0),
                Some(auth) => (auth.allows(peer_hex), auth.generation()),
            }
        };
        if !allows {
            match state {
                PeerConnState::Blocked { generation: g } if *g == generation => {
                    self.inner
                        .metrics
                        .dials_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                    Readiness::Deny
                }
                _ => {
                    *state = PeerConnState::Blocked { generation };
                    tracing::warn!(%peer, "peer blocked: not authorized; retrying only when membership changes");
                    Readiness::Deny
                }
            }
        } else {
            if matches!(state, PeerConnState::Blocked { .. }) {
                *state = PeerConnState::Idle;
                tracing::info!(%peer, "peer authorized again");
            }
            match state {
                PeerConnState::Rejected {
                    generation: rejected_at,
                    retry_after,
                    ..
                } => {
                    if *rejected_at != generation {
                        *state = PeerConnState::Idle;
                        tracing::debug!(%peer, "re-probing rejected peer after membership change");
                        Readiness::Dial
                    } else if now >= *retry_after {
                        tracing::debug!(%peer, "re-probing rejected peer after cooldown");
                        Readiness::Dial
                    } else {
                        self.inner
                            .metrics
                            .dials_suppressed
                            .fetch_add(1, Ordering::Relaxed);
                        Readiness::Wait
                    }
                }
                PeerConnState::Backoff { until, .. } if now < *until => {
                    self.inner
                        .metrics
                        .dials_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                    Readiness::Wait
                }
                _ => Readiness::Dial,
            }
        }
    }

    fn mark_remote_rejected(
        &self,
        slot: &mut PeerSlot,
        peer: EndpointId,
        prev: Option<(u64, Instant)>,
        err: &Arc<str>,
    ) {
        self.inner
            .metrics
            .reconnect_fail
            .fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let generation = self.gate_generation();
        let (first, continuing) = match prev {
            Some((g, first)) if g == generation => (first, true),
            _ => (now, false),
        };
        let delay = remote_retry_delay(now.saturating_duration_since(first));
        slot.state = PeerConnState::Rejected {
            generation,
            first,
            retry_after: now + delay,
        };
        if let Some(tx) = slot.dial_waiters.take() {
            let _ = tx.send(Err(err.clone()));
        }
        if continuing {
            tracing::debug!(%peer, reason = %err, retry_in_ms = delay.as_millis(), "peer rejected again; cooling down");
        } else {
            tracing::warn!(%peer, reason = %err, retry_in_ms = delay.as_millis(), "peer rejected the connection; re-probing on membership change or cooldown");
        }
    }

    fn mark_backoff(&self, slot: &mut PeerSlot, step: u32, peer: EndpointId, err: &Arc<str>) {
        self.inner
            .metrics
            .reconnect_fail
            .fetch_add(1, Ordering::Relaxed);
        let wait = backoff_delay(step);
        let until = Instant::now() + wait;
        slot.state = PeerConnState::Backoff {
            until,
            step: step.saturating_add(1),
        };
        if let Some(tx) = slot.dial_waiters.take() {
            let _ = tx.send(Err(err.clone()));
        }
        tracing::debug!(%peer, wait_ms = wait.as_millis(), reason = %err, "dial failed; backing off");
    }

    fn mark_local_denied(&self, slot: &mut PeerSlot, peer: EndpointId, err: &Arc<str>) {
        self.inner
            .metrics
            .reconnect_fail
            .fetch_add(1, Ordering::Relaxed);
        let fresh = mark_local_blocked(slot, self.gate_generation());
        if let Some(tx) = slot.dial_waiters.take() {
            let _ = tx.send(Err(err.clone()));
        }
        if fresh {
            tracing::warn!(%peer, reason = %err, "peer denied by local membership; retrying only when membership changes");
        }
    }

    fn locked_live(&self, slot: &mut PeerSlot, peer: EndpointId) -> LiveUse {
        let Some(c) = slot.live_conn() else {
            return LiveUse::Absent;
        };
        let generation = self.gate_generation();
        let peer_hex = format!("{peer}");
        if self.gate_allows(&peer_hex) {
            slot.state = PeerConnState::Connected {
                auth_gen: generation,
            };
            slot.touch();
            return LiveUse::Use(c);
        }
        if let Some(conn) = slot.conn.take() {
            conn.close(CLOSE_NOT_MEMBER.into(), CLOSE_NOT_MEMBER_REASON);
        }
        if mark_local_blocked(slot, generation) {
            tracing::warn!(%peer, "revoked peer connection closed at point of use");
        }
        LiveUse::Revoked
    }

    fn note_dead_conn(
        &self,
        state: &mut PeerConnState,
        dead: &Connection,
        peer: EndpointId,
    ) -> bool {
        let generation = self.gate_generation();
        if matches!(state, PeerConnState::Rejected { generation: g, .. } if *g == generation) {
            return true;
        }
        let Some(reason) = dead.close_reason() else {
            return false;
        };
        if !is_auth_close_error(&reason) {
            return false;
        }
        let now = Instant::now();
        *state = PeerConnState::Rejected {
            generation,
            first: now,
            retry_after: now + remote_retry_delay(Duration::ZERO),
        };
        tracing::warn!(%peer, "established connection closed by peer authorization; cooling down");
        true
    }

    pub async fn reconcile(&self) {
        let slots = self.slots();
        for ((peer, _), slot) in slots {
            let mut slot = slot.lock().await;
            let auth = self.inner.gate.read().clone();
            let auth_gate = auth.as_ref().map(TransportAuth::authorization_gate);
            let _validated = auth_gate.as_ref().map(|gate| gate.read());
            let generation = auth.as_ref().map_or(0, TransportAuth::generation);
            if auth
                .as_ref()
                .is_some_and(|auth| !auth.allows(&peer.to_string()))
            {
                mark_local_blocked(&mut slot, generation);
                slot.dial_id = slot.dial_id.checked_add(1).expect("pool dial id exhausted");
                slot.dial_waiters = None;
            } else if matches!(slot.state, PeerConnState::Blocked { .. })
                || matches!(slot.state,
                PeerConnState::Rejected { generation: rejected, .. } if rejected != generation)
            {
                slot.state = PeerConnState::Idle;
            }
        }
        self.reclaim();
    }

    pub async fn revoke_peer(&self, peer: EndpointId) {
        for ((id, _), slot) in self.slots() {
            if id != peer {
                continue;
            }
            let mut slot = slot.lock().await;
            mark_local_blocked(&mut slot, self.gate_generation());
            slot.dial_id = slot.dial_id.checked_add(1).expect("pool dial id exhausted");
            slot.dial_waiters = None;
        }
        self.reclaim();
    }

    pub async fn close_all(&self) {
        self.close(false).await;
    }

    pub async fn shutdown(&self) {
        self.close(true).await;
        let sweeper = self.inner.sweeper.lock().take();
        if let Some(task) = sweeper {
            task.abort();
            let _ = task.await;
        }
        self.inner.tasks.close();
        self.inner.tasks.wait().await;
    }

    async fn close(&self, shutdown: bool) {
        let generation = {
            let mut life = self.inner.lifecycle.write();
            life.cancel.cancel();
            life.cancel = CancellationToken::new();
            life.generation = life
                .generation
                .checked_add(1)
                .expect("pool generation exhausted");
            life.shutdown |= shutdown;
            life.generation
        };
        for (_, slot) in self.slots() {
            let mut slot = slot.lock().await;
            if slot.lifecycle < generation {
                if let Some(conn) = slot.conn.take() {
                    conn.close(0u32.into(), b"pool_closed");
                }
                slot.dial_waiters = None;
                slot.state = PeerConnState::Idle;
            }
        }
        self.reclaim();
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }
    pub fn default_alpn(&self) -> &'static [u8] {
        self.inner.alpn
    }

    pub fn set_keep_alive(&self, enabled: bool) {
        self.inner.keep_alive.store(enabled, Ordering::Relaxed);
    }

    pub fn keep_alive(&self) -> bool {
        self.inner.keep_alive.load(Ordering::Relaxed)
    }

    pub fn on_demand_stats(&self) -> OnDemandStats {
        let success = self.inner.metrics.reconnect_success.load(Ordering::Relaxed);
        let sum = self
            .inner
            .metrics
            .reconnect_latency_sum_us
            .load(Ordering::Relaxed);
        OnDemandStats {
            reconnect_attempts: self
                .inner
                .metrics
                .reconnect_attempts
                .load(Ordering::Relaxed),
            reconnect_success: success,
            reconnect_fail: self.inner.metrics.reconnect_fail.load(Ordering::Relaxed),
            dials_suppressed: self.inner.metrics.dials_suppressed.load(Ordering::Relaxed),
            reconnect_latency_avg_us: sum.checked_div(success).unwrap_or(0),
            reconnect_latency_max_us: self
                .inner
                .metrics
                .reconnect_latency_max_us
                .load(Ordering::Relaxed),
        }
    }

    fn slots(&self) -> Vec<(SlotKey, SlotHandle)> {
        self.inner
            .entries
            .lock()
            .iter()
            .map(|(key, slot)| (*key, slot.clone()))
            .collect()
    }

    fn reclaim(&self) {
        self.inner.entries.lock().retain(|_, slot| {
            if Arc::strong_count(slot) != 1 {
                return true;
            }
            let Ok(slot) = slot.try_lock() else {
                return true;
            };
            slot.live_conn().is_some()
                || slot.dial_waiters.is_some()
                || matches!(slot.state, PeerConnState::Rejected { retry_after, .. } if retry_after > Instant::now())
                || (!matches!(slot.state, PeerConnState::Idle)
                    && slot.last_activity.elapsed() < Duration::from_secs(DEFAULT_IDLE_SECS))
        });
    }

    fn keyed_slot(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
    ) -> anyhow::Result<Arc<AsyncMutex<PeerSlot>>> {
        let key = (peer, alpn);
        let mut slots = self.inner.entries.lock();
        if !slots.contains_key(&key) && slots.len() >= MAX_SLOTS {
            drop(slots);
            self.reclaim();
            slots = self.inner.entries.lock();
        }
        if let Some(slot) = slots.get(&key) {
            return Ok(slot.clone());
        }
        anyhow::ensure!(slots.len() < MAX_SLOTS, "stream connection pool is full");
        let slot = Arc::new(AsyncMutex::new(PeerSlot::new()));
        slots.insert(key, slot.clone());
        Ok(slot)
    }

    #[cfg(test)]
    fn slot(&self, peer: EndpointId) -> Arc<AsyncMutex<PeerSlot>> {
        self.keyed_slot(peer, self.inner.alpn).unwrap()
    }

    fn spawn_idle_sweeper(&self) {
        let weak = Arc::downgrade(&self.inner);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                let pool = ConnPool { inner };
                if !pool.keep_alive() {
                    for (_, slot) in pool.slots() {
                        let mut slot = slot.lock().await;
                        if slot.last_activity.elapsed() >= Duration::from_secs(DEFAULT_IDLE_SECS)
                            && let Some(conn) = slot.conn.take()
                        {
                            conn.close(0u32.into(), b"idle");
                            slot.state = PeerConnState::Idle;
                        }
                    }
                }
                pool.reclaim();
            }
        });
        *self.inner.sweeper.lock() = Some(task);
    }

    pub async fn get(&self, peer: EndpointId) -> anyhow::Result<Connection> {
        self.get_alpn(peer, self.inner.alpn).await
    }

    pub async fn get_alpn(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
    ) -> anyhow::Result<Connection> {
        anyhow::ensure!(
            !self.inner.lifecycle.read().shutdown,
            "stream connection pool is shut down"
        );
        let slot = self.keyed_slot(peer, alpn)?;
        let mut receiver = {
            let mut guard = slot.lock().await;
            let life = self.inner.lifecycle.read();
            anyhow::ensure!(!life.shutdown, "stream connection pool is shut down");
            if guard.lifecycle != life.generation {
                if let Some(conn) = guard.conn.take() {
                    conn.close(0u32.into(), b"pool_closed");
                }
                guard.dial_waiters = None;
                guard.state = PeerConnState::Idle;
                guard.lifecycle = life.generation;
            }
            let auth = self.inner.gate.read().clone();
            let auth_gate = auth.as_ref().map(TransportAuth::authorization_gate);
            let _validated = auth_gate.as_ref().map(|gate| gate.read());
            match self.locked_live(&mut guard, peer) {
                LiveUse::Use(conn) => return Ok(conn),
                LiveUse::Revoked => return Err(not_authorized(peer)),
                LiveUse::Absent => {}
            }
            if let Some(dead) = guard.conn.take()
                && self.note_dead_conn(&mut guard.state, &dead, peer)
            {
                return Err(not_authorized_remote(peer));
            }
            match self.readiness(&mut guard.state, peer, &peer.to_string(), Instant::now()) {
                Readiness::Deny => return Err(not_authorized(peer)),
                Readiness::Wait => anyhow::bail!("dial to {peer} suppressed by backoff"),
                Readiness::Dial => {}
            }
            if let Some(waiters) = &guard.dial_waiters {
                waiters.subscribe()
            } else {
                let rejected = match guard.state {
                    PeerConnState::Rejected {
                        generation, first, ..
                    } => Some((generation, first)),
                    _ => None,
                };
                let step = match guard.state {
                    PeerConnState::Backoff { step, .. } => step,
                    _ => 0,
                };
                let permit = self
                    .inner
                    .dial_limit
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow::anyhow!("stream connection dial limit reached"))?;
                let (tx, receiver) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                guard.dial_id = guard
                    .dial_id
                    .checked_add(1)
                    .expect("pool dial id exhausted");
                let dial_id = guard.dial_id;
                guard.state = PeerConnState::Dialing;
                let pool = self.clone();
                let slot = slot.clone();
                let generation = life.generation;
                let cancel = life.cancel.child_token();
                if let Some(old) = guard.dial_cancel.replace(cancel.clone()) {
                    old.cancel();
                }
                self.inner.tasks.spawn(async move {
                    let _permit = permit;
                    pool.run_dial(
                        peer,
                        alpn,
                        slot,
                        DialContext {
                            generation,
                            id: dial_id,
                            cancel,
                            rejected,
                            step,
                        },
                    )
                    .await;
                });
                receiver
            }
        };
        match receiver.recv().await {
            Ok(Ok(_)) => {
                let mut slot = slot.lock().await;
                let life = self.inner.lifecycle.read();
                anyhow::ensure!(
                    !life.shutdown && life.generation == slot.lifecycle,
                    "stream connection pool closed during dial"
                );
                let auth = self.inner.gate.read().clone();
                let auth_gate = auth.as_ref().map(TransportAuth::authorization_gate);
                let _validated = auth_gate.as_ref().map(|gate| gate.read());
                match self.locked_live(&mut slot, peer) {
                    LiveUse::Use(conn) => Ok(conn),
                    _ => Err(not_authorized(peer)),
                }
            }
            Ok(Err(error)) => anyhow::bail!("{error}"),
            Err(_) => anyhow::bail!("stream connection dial was invalidated"),
        }
    }

    async fn run_dial(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
        slot: SlotHandle,
        context: DialContext,
    ) {
        let DialContext {
            generation,
            id: dial_id,
            cancel,
            rejected,
            step,
        } = context;
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = self.dial_once(peer, alpn) => result,
        };
        let mut slot = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                if let Ok(conn) = result { conn.close(0u32.into(), b"pool_closed"); }
                return;
            }
            slot = slot.lock() => slot,
        };
        let life = self.inner.lifecycle.read();
        if life.shutdown || life.generation != generation || slot.dial_id != dial_id {
            if let Ok(conn) = result {
                conn.close(0u32.into(), b"pool_closed");
            }
            return;
        }
        let auth = self.inner.gate.read().clone();
        let auth_gate = auth.as_ref().map(TransportAuth::authorization_gate);
        let _validated = auth_gate.as_ref().map(|gate| gate.read());
        if auth
            .as_ref()
            .is_some_and(|auth| !auth.allows(&peer.to_string()))
        {
            if let Ok(conn) = result {
                conn.close(CLOSE_NOT_MEMBER.into(), CLOSE_NOT_MEMBER_REASON);
            }
            self.mark_local_denied(&mut slot, peer, &Arc::from("peer revoked while dialing"));
            return;
        }
        match result {
            Ok(conn) => {
                slot.conn = Some(conn.clone());
                slot.state = PeerConnState::Connected {
                    auth_gen: self.gate_generation(),
                };
                slot.touch();
                if let Some(waiters) = slot.dial_waiters.take() {
                    let _ = waiters.send(Ok(conn));
                }
            }
            Err((DialFailure::LocalDenied, error)) => {
                self.mark_local_denied(&mut slot, peer, &error)
            }
            Err((DialFailure::RemoteRejected, error)) => {
                self.mark_remote_rejected(&mut slot, peer, rejected, &error)
            }
            Err((DialFailure::Transient, error)) => {
                self.mark_backoff(&mut slot, step, peer, &error)
            }
        }
    }

    async fn dial_once(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
    ) -> Result<Connection, (DialFailure, Arc<str>)> {
        let start = Instant::now();
        self.inner
            .metrics
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, alpn = %String::from_utf8_lossy(alpn), "dialing peer");
        match tokio::time::timeout(RECONNECT_TIMEOUT, self.inner.endpoint.connect(peer, alpn)).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh::address_lookup::memory::MemoryLookup;

    use crate::routing::RoutingTable;
    use crate::transport_auth::{TransportAuth, TransportHook};

    const TEST_ALPN: &[u8] = b"test/alpn";

    async fn bind_endpoint() -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .expect("bind test endpoint")
    }

    fn denying_pool(ep: Endpoint) -> (ConnPool, RoutingTable) {
        let routes = RoutingTable::new();
        let pool = ConnPool::new(ep, TEST_ALPN);
        pool.set_transport_auth(TransportAuth::managed(&routes));
        (pool, routes)
    }

    fn put_peer(routes: &RoutingTable, id: &EndpointId, ip: &str) {
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: ip.parse().unwrap(),
                endpoint_id: format!("{id}"),
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
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
    }

    struct TestPair {
        pool: ConnPool,
        routes_a: RoutingTable,
        routes_b: RoutingTable,
        _endpoint_b: Endpoint,
        id_b: EndpointId,
    }

    async fn test_pair() -> TestPair {
        let disco = MemoryLookup::new();
        let endpoint_a = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(disco.clone())
            .bind()
            .await
            .expect("bind A");
        let routes_b = RoutingTable::new();
        let endpoint_b = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(disco.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .hooks(TransportHook::managed(&routes_b))
            .bind()
            .await
            .expect("bind B");
        disco.add_endpoint_info(endpoint_a.addr());
        disco.add_endpoint_info(endpoint_b.addr());
        let id_b = endpoint_b.id();
        tokio::spawn({
            let endpoint_b = endpoint_b.clone();
            async move {
                while let Some(incoming) = endpoint_b.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(conn);
                        }
                    });
                }
            }
        });
        let routes_a = RoutingTable::new();
        put_peer(&routes_a, &id_b, "100.64.0.2");
        let pool = ConnPool::new(endpoint_a, TEST_ALPN);
        pool.set_transport_auth(TransportAuth::managed(&routes_a));
        TestPair {
            pool,
            routes_a,
            routes_b,
            _endpoint_b: endpoint_b,
            id_b,
        }
    }

    async fn wait_for_attempts(pool: &ConnPool, n: u64) {
        tokio::time::timeout(Duration::from_secs(15), async {
            while pool.on_demand_stats().reconnect_attempts < n {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("dial did not start in time");
    }

    #[tokio::test]
    async fn concurrent_get_coalesce_failure() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();

        let p1 = pool.clone();
        let p2 = pool.clone();
        let (r1, r2) = tokio::join!(p1.get(peer), p2.get(peer));
        assert!(r1.is_err(), "expected dial failure");
        assert!(r2.is_err(), "expected dial failure");
        assert_eq!(
            pool.on_demand_stats().reconnect_fail,
            1,
            "only one dialer should record the failure"
        );
    }

    #[tokio::test]
    async fn concurrent_success_shares_one_dial() {
        let t = test_pair().await;
        put_peer(&t.routes_b, &t.pool.endpoint().id(), "100.64.0.3");

        let mut handles = Vec::new();
        for _ in 0..4 {
            let p = t.pool.clone();
            let id = t.id_b;
            handles.push(tokio::spawn(async move { p.get(id).await.map(|_| ()) }));
        }
        for h in handles {
            h.await.expect("task").expect("dial succeeds");
        }
        let stats = t.pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 1);
        assert_eq!(stats.reconnect_success, 1);
        t.pool.get(t.id_b).await.expect("live conn reused");
    }

    #[tokio::test]
    async fn blocked_burst_produces_no_dials() {
        let ep = bind_endpoint().await;
        let (pool, _routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        for _ in 0..20 {
            let _ = pool.get(peer).await;
        }
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0, "blocked peer must never dial");
        assert!(stats.dials_suppressed > 0);
    }

    #[tokio::test]
    async fn concurrent_blocked_callers_share_no_dial() {
        let ep = bind_endpoint().await;
        let (pool, _routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move { p.get(peer).await.map(|_| ()) }));
        }
        for h in handles {
            let r = h.await.expect("task");
            assert!(r.is_err());
            assert!(format!("{}", r.unwrap_err()).contains("not_authorized"));
        }
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 0);
    }

    #[tokio::test]
    async fn blocked_retries_only_on_generation_change() {
        let ep = bind_endpoint().await;
        let (pool, routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        let _ = pool.get(peer).await;
        assert_eq!(pool.on_demand_stats().dials_suppressed, 0);
        let _ = pool.get(peer).await;
        assert_eq!(pool.on_demand_stats().dials_suppressed, 1);

        routes.replace(
            &[],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
        let _ = pool.get(peer).await;
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 0);
        assert_eq!(pool.on_demand_stats().dials_suppressed, 1);
        let _ = pool.get(peer).await;
        assert_eq!(pool.on_demand_stats().dials_suppressed, 2);
    }

    #[tokio::test]
    async fn reconcile_unblocks_then_redials() {
        let ep = bind_endpoint().await;
        let (pool, routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();
        let peer_hex = format!("{peer}");

        let _ = pool.get(peer).await;
        assert!(pool.get(peer).await.is_err());

        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: "100.64.0.9".parse().unwrap(),
                endpoint_id: peer_hex,
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
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            2,
        );
        pool.reconcile().await;
        let probe = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get(peer).await }
        });
        wait_for_attempts(&pool, 1).await;
        let _ = probe.await.expect("task");
    }

    #[tokio::test]
    async fn revoke_peer_pins_blocked() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();

        pool.revoke_peer(peer).await;
        pool.set_transport_auth(TransportAuth::managed(&RoutingTable::new()));
        let _ = pool.get(peer).await;
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0);
    }

    #[tokio::test]
    async fn backoff_suppresses_without_dial() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();

        {
            let slot = pool.slot(peer);
            let mut g = slot.lock().await;
            g.state = PeerConnState::Backoff {
                until: Instant::now() + Duration::from_secs(60),
                step: 0,
            };
        }
        assert!(pool.get(peer).await.is_err());
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0);
        assert_eq!(stats.dials_suppressed, 1);
    }

    #[tokio::test]
    async fn expired_backoff_redials() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();

        {
            let slot = pool.slot(peer);
            let mut g = slot.lock().await;
            g.state = PeerConnState::Backoff {
                until: Instant::now() - Duration::from_secs(1),
                step: 0,
            };
        }
        let dial = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get(peer).await }
        });
        wait_for_attempts(&pool, 1).await;
        let _ = dial.await.expect("task");
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 1);
    }

    #[tokio::test]
    async fn remote_rejection_ignores_local_gate_until_state_changes() {
        let ep = bind_endpoint().await;
        let routes = RoutingTable::new();
        let pool = ConnPool::new(ep, TEST_ALPN);
        pool.set_transport_auth(TransportAuth::managed(&routes));
        let peer = SecretKey::generate().public();
        put_peer(&routes, &peer, "100.64.0.9");

        {
            let generation = pool.gate_generation();
            let slot = pool.slot(peer);
            let mut g = slot.lock().await;
            g.state = PeerConnState::Rejected {
                generation,
                first: Instant::now(),
                retry_after: Instant::now() + Duration::from_secs(60),
            };
        }
        for _ in 0..10 {
            assert!(pool.get(peer).await.is_err());
        }
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 0);

        put_peer(&routes, &peer, "100.64.0.9");
        let probe = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get(peer).await }
        });
        wait_for_attempts(&pool, 1).await;
        let _ = probe.await.expect("task");
    }

    #[tokio::test]
    async fn asymmetric_rejection_no_storm_then_recover() {
        let t = test_pair().await;

        let first = tokio::time::timeout(Duration::from_secs(15), t.pool.get(t.id_b))
            .await
            .expect("dial resolves");
        drop(first);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = t.pool.get(t.id_b).await;
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);

        for _ in 0..20 {
            let _ = t.pool.get(t.id_b).await;
        }
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);

        put_peer(&t.routes_b, &t.pool.endpoint().id(), "100.64.0.3");
        assert!(t.pool.get(t.id_b).await.is_err());
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);

        {
            let slot = t.pool.slot(t.id_b);
            let mut g = slot.lock().await;
            if let PeerConnState::Rejected {
                generation, first, ..
            } = g.state
            {
                g.state = PeerConnState::Rejected {
                    generation,
                    first,
                    retry_after: Instant::now() - Duration::from_secs(1),
                };
            } else {
                panic!("expected rejected state, got {:?}", g.state);
            }
        }
        tokio::time::timeout(Duration::from_secs(15), t.pool.get(t.id_b))
            .await
            .expect("dial resolves")
            .expect("recovers after B admits");
        t.pool.get(t.id_b).await.expect("live conn reused");
    }

    #[tokio::test]
    async fn revoked_live_connection_closed_at_point_of_use() {
        let t = test_pair().await;
        put_peer(&t.routes_b, &t.pool.endpoint().id(), "100.64.0.3");
        tokio::time::timeout(Duration::from_secs(15), t.pool.get(t.id_b))
            .await
            .expect("dial resolves")
            .expect("connects");
        t.pool.get(t.id_b).await.expect("live conn reused");

        t.routes_a.replace(
            &[],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            2,
        );
        assert!(t.pool.get(t.id_b).await.is_err());
        assert!(t.pool.get(t.id_b).await.is_err());
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);
    }

    #[tokio::test]
    async fn extra_path_blocked_without_dial() {
        let ep = bind_endpoint().await;
        let (pool, _routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        for _ in 0..5 {
            let _ = pool.get_alpn(peer, b"other/alpn").await;
        }
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 0);
        assert!(pool.on_demand_stats().dials_suppressed > 0);
    }
    struct PausedPair {
        pool: ConnPool,
        routes: RoutingTable,
        peer: EndpointId,
        incoming: Arc<tokio::sync::Notify>,
        proceed: Arc<tokio::sync::Notify>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for PausedPair {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn paused_pair() -> PausedPair {
        let lookup = MemoryLookup::new();
        let a = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        let b = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(a.addr());
        lookup.add_endpoint_info(b.addr());
        let peer = b.id();
        let routes = RoutingTable::new();
        put_peer(&routes, &peer, "100.64.0.2");
        let pool = ConnPool::new(a, TEST_ALPN);
        pool.set_transport_auth(TransportAuth::managed(&routes));
        let incoming = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        let server = tokio::spawn({
            let incoming = incoming.clone();
            let proceed = proceed.clone();
            async move {
                let mut first = true;
                let mut connections = Vec::new();
                while let Some(accept) = b.accept().await {
                    if first {
                        incoming.notify_one();
                        proceed.notified().await;
                        first = false;
                    }
                    if let Ok(conn) = accept.await {
                        connections.push(conn);
                    }
                }
            }
        });
        PausedPair {
            pool,
            routes,
            peer,
            incoming,
            proceed,
            server,
        }
    }

    #[tokio::test]
    async fn revoke_while_install_waits_closes_new_connection() {
        let pair = paused_pair().await;
        let dial = tokio::spawn({
            let pool = pair.pool.clone();
            let peer = pair.peer;
            async move { pool.get(peer).await }
        });
        tokio::time::timeout(Duration::from_secs(5), pair.incoming.notified())
            .await
            .unwrap();
        let slot = pair.pool.slot(pair.peer);
        let held = slot.lock().await;
        pair.proceed.notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            while pair.pool.on_demand_stats().reconnect_success == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pair.routes.replace(
            &[],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            2,
        );
        drop(held);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), dial)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(slot.lock().await.live_conn().is_none());
        pair.pool.shutdown().await;
    }

    #[tokio::test]
    async fn close_cancels_inflight_dial_and_allows_fresh_recovery() {
        let pair = paused_pair().await;
        let dial = tokio::spawn({
            let pool = pair.pool.clone();
            let peer = pair.peer;
            async move { pool.get(peer).await }
        });
        tokio::time::timeout(Duration::from_secs(5), pair.incoming.notified())
            .await
            .unwrap();
        pair.pool.close_all().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), dial)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        pair.proceed.notify_one();
        let conn = tokio::time::timeout(Duration::from_secs(5), pair.pool.get(pair.peer))
            .await
            .unwrap()
            .unwrap();
        assert!(conn.close_reason().is_none());
        pair.pool.shutdown().await;
        assert!(pair.pool.get(pair.peer).await.is_err());
        assert!(conn.close_reason().is_some());
    }

    #[tokio::test]
    async fn canceled_request_does_not_strand_coalesced_dial() {
        let pair = paused_pair().await;
        let request = tokio::spawn({
            let pool = pair.pool.clone();
            let peer = pair.peer;
            async move { pool.get(peer).await }
        });
        tokio::time::timeout(Duration::from_secs(5), pair.incoming.notified())
            .await
            .unwrap();
        request.abort();
        let _ = request.await;
        pair.proceed.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), pair.pool.get(pair.peer))
                .await
                .unwrap()
                .is_ok()
        );
        assert_eq!(pair.pool.on_demand_stats().reconnect_attempts, 1);
        pair.pool.shutdown().await;
    }

    #[tokio::test]
    async fn idle_maintenance_does_not_retain_pool() {
        let pool = ConnPool::new(bind_endpoint().await, TEST_ALPN);
        let weak = Arc::downgrade(&pool.inner);
        drop(pool);
        assert!(weak.upgrade().is_none());
    }
    #[tokio::test]
    async fn obsolete_slots_are_bounded_and_reclaimed() {
        let (pool, _) = denying_pool(bind_endpoint().await);
        {
            let mut entries = pool.inner.entries.lock();
            for i in 0..MAX_SLOTS {
                let mut key = [0; 32];
                key[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let peer = SecretKey::from_bytes(&key).public();
                let mut slot = PeerSlot::new();
                slot.state = PeerConnState::Blocked { generation: 0 };
                entries.insert((peer, TEST_ALPN), Arc::new(AsyncMutex::new(slot)));
            }
        }
        assert!(
            pool.get(SecretKey::generate().public())
                .await
                .unwrap_err()
                .to_string()
                .contains("pool is full")
        );
        assert_eq!(pool.inner.entries.lock().len(), MAX_SLOTS);
        for (_, slot) in pool.slots() {
            slot.lock().await.last_activity =
                Instant::now() - Duration::from_secs(DEFAULT_IDLE_SECS + 1);
        }
        pool.reclaim();
        assert!(pool.inner.entries.lock().is_empty());
        pool.shutdown().await;
    }
    #[tokio::test]
    async fn repeated_transport_failures_preserve_retry_step_per_alpn() {
        let pair = test_pair().await;
        put_peer(&pair.routes_b, &pair.pool.endpoint().id(), "100.64.0.3");
        let alpn = b"unsupported/alpn";
        let slot = pair.pool.keyed_slot(pair.id_b, alpn).unwrap();
        for expected in 1..=3 {
            assert!(
                tokio::time::timeout(Duration::from_secs(5), pair.pool.get_alpn(pair.id_b, alpn))
                    .await
                    .unwrap()
                    .is_err()
            );
            let mut guard = slot.lock().await;
            let PeerConnState::Backoff { until, step } = guard.state else {
                panic!("expected transient backoff, got {:?}", guard.state);
            };
            assert_eq!(step, expected);
            assert!(until > Instant::now());
            guard.state = PeerConnState::Backoff {
                until: Instant::now(),
                step,
            };
        }
        assert!(pair.pool.get(pair.id_b).await.is_ok());
        pair.pool.shutdown().await;
    }
}
