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

use dashmap::DashMap;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use parking_lot::RwLock;
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::peer::{
    DialFailure, RECONNECT_TIMEOUT, backoff_delay, classify_connect_error, is_auth_close_error,
    remote_retry_delay,
};
use crate::transport_auth::TransportAuth;

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
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            state: PeerConnState::Idle,
            last_activity: Instant::now(),
            dial_waiters: None,
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

struct ExtraSlot {
    conn: Option<Connection>,
    dial_waiters: Option<DialWaiters>,
    state: PeerConnState,
}

impl ExtraSlot {
    fn new() -> Self {
        Self {
            conn: None,
            dial_waiters: None,
            state: PeerConnState::Idle,
        }
    }
}

type ExtraConnMap = DashMap<(EndpointId, Vec<u8>), Arc<AsyncMutex<ExtraSlot>>>;

trait ConnSlot {
    fn live_conn(&self) -> Option<Connection>;
    fn conn_ref(&mut self) -> &mut Option<Connection>;
    fn slot_state(&mut self) -> &mut PeerConnState;
    fn slot_waiters(&mut self) -> &mut Option<DialWaiters>;
    fn touch_slot(&mut self);
}

impl ConnSlot for PeerSlot {
    fn live_conn(&self) -> Option<Connection> {
        PeerSlot::live_conn(self)
    }
    fn conn_ref(&mut self) -> &mut Option<Connection> {
        &mut self.conn
    }
    fn slot_state(&mut self) -> &mut PeerConnState {
        &mut self.state
    }
    fn slot_waiters(&mut self) -> &mut Option<DialWaiters> {
        &mut self.dial_waiters
    }
    fn touch_slot(&mut self) {
        self.touch();
    }
}

impl ConnSlot for ExtraSlot {
    fn live_conn(&self) -> Option<Connection> {
        self.conn
            .as_ref()
            .filter(|c| c.close_reason().is_none())
            .cloned()
    }
    fn conn_ref(&mut self) -> &mut Option<Connection> {
        &mut self.conn
    }
    fn slot_state(&mut self) -> &mut PeerConnState {
        &mut self.state
    }
    fn slot_waiters(&mut self) -> &mut Option<DialWaiters> {
        &mut self.dial_waiters
    }
    fn touch_slot(&mut self) {}
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

fn mark_local_blocked(slot: &mut impl ConnSlot, generation: u64) -> bool {
    if let Some(c) = slot.conn_ref().take() {
        c.close(1u32.into(), b"not_authorized");
    }
    let state = slot.slot_state();
    let fresh = !matches!(state, PeerConnState::Blocked { generation: g } if *g == generation);
    *state = PeerConnState::Blocked { generation };
    fresh
}

#[derive(Clone)]
pub struct ConnPool {
    endpoint: Endpoint,
    alpn: &'static [u8],
    entries: Arc<DashMap<EndpointId, Arc<AsyncMutex<PeerSlot>>>>,
    extra: Arc<ExtraConnMap>,
    keep_alive: Arc<AtomicBool>,
    metrics: Arc<PoolMetrics>,
    gate: Arc<RwLock<Option<TransportAuth>>>,
}

impl ConnPool {
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        let pool = Self {
            endpoint,
            alpn,
            entries: Arc::new(DashMap::new()),
            extra: Arc::new(DashMap::new()),
            keep_alive: Arc::new(AtomicBool::new(true)),
            metrics: Arc::new(PoolMetrics::default()),
            gate: Arc::new(RwLock::new(None)),
        };
        pool.spawn_idle_sweeper();
        pool
    }

    pub fn set_transport_auth(&self, auth: TransportAuth) {
        *self.gate.write() = Some(auth);
    }

    fn gate_allows(&self, peer_hex: &str) -> bool {
        self.gate.read().as_ref().is_none_or(|g| g.allows(peer_hex))
    }

    fn gate_generation(&self) -> u64 {
        self.gate
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
            let gate = self.gate.read();
            match gate.as_ref() {
                None => (true, 0),
                Some(auth) => (auth.allows(peer_hex), auth.generation()),
            }
        };
        if !allows {
            match state {
                PeerConnState::Blocked { generation: g } if *g == generation => {
                    self.metrics
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
                        self.metrics
                            .dials_suppressed
                            .fetch_add(1, Ordering::Relaxed);
                        Readiness::Wait
                    }
                }
                PeerConnState::Backoff { until, .. } if now < *until => {
                    self.metrics
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
        slot: &mut impl ConnSlot,
        peer: EndpointId,
        prev: Option<(u64, Instant)>,
        err: &Arc<str>,
    ) {
        self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let generation = self.gate_generation();
        let (first, continuing) = match prev {
            Some((g, first)) if g == generation => (first, true),
            _ => (now, false),
        };
        let delay = remote_retry_delay(now.saturating_duration_since(first));
        *slot.slot_state() = PeerConnState::Rejected {
            generation,
            first,
            retry_after: now + delay,
        };
        if let Some(tx) = slot.slot_waiters().take() {
            let _ = tx.send(Err(err.clone()));
        }
        if continuing {
            tracing::debug!(%peer, reason = %err, retry_in_ms = delay.as_millis(), "peer rejected again; cooling down");
        } else {
            tracing::warn!(%peer, reason = %err, retry_in_ms = delay.as_millis(), "peer rejected the connection; re-probing on membership change or cooldown");
        }
    }

    fn mark_backoff(&self, slot: &mut impl ConnSlot, step: u32, peer: EndpointId, err: &Arc<str>) {
        self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
        let wait = backoff_delay(step);
        let until = Instant::now() + wait;
        *slot.slot_state() = PeerConnState::Backoff {
            until,
            step: step.saturating_add(1),
        };
        if let Some(tx) = slot.slot_waiters().take() {
            let _ = tx.send(Err(err.clone()));
        }
        tracing::debug!(%peer, wait_ms = wait.as_millis(), reason = %err, "dial failed; backing off");
    }

    fn mark_local_denied(&self, slot: &mut impl ConnSlot, peer: EndpointId, err: &Arc<str>) {
        self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
        let fresh = mark_local_blocked(slot, self.gate_generation());
        if let Some(tx) = slot.slot_waiters().take() {
            let _ = tx.send(Err(err.clone()));
        }
        if fresh {
            tracing::warn!(%peer, reason = %err, "peer denied by local membership; retrying only when membership changes");
        }
    }

    fn locked_live(&self, slot: &mut impl ConnSlot, peer: EndpointId) -> LiveUse {
        let Some(c) = slot.live_conn() else {
            return LiveUse::Absent;
        };
        let generation = self.gate_generation();
        let validated = matches!(slot.slot_state(), PeerConnState::Connected { auth_gen } if *auth_gen == generation);
        if validated {
            slot.touch_slot();
            return LiveUse::Use(c);
        }
        let peer_hex = format!("{peer}");
        if self.gate_allows(&peer_hex) {
            *slot.slot_state() = PeerConnState::Connected {
                auth_gen: generation,
            };
            slot.touch_slot();
            return LiveUse::Use(c);
        }
        if let Some(conn) = slot.conn_ref().take() {
            conn.close(1u32.into(), b"not_authorized");
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
        let generation = self.gate_generation();
        let peers: Vec<_> = self
            .entries
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        for (peer, slot) in peers {
            let peer_hex = format!("{peer}");
            let mut g = slot.lock().await;
            if self.gate_allows(&peer_hex) {
                match g.state {
                    PeerConnState::Blocked { .. } => {
                        g.state = if g.live_conn().is_some() {
                            PeerConnState::Connected {
                                auth_gen: generation,
                            }
                        } else {
                            PeerConnState::Idle
                        };
                        tracing::info!(%peer, "peer authorized again");
                    }
                    PeerConnState::Rejected { .. } => {
                        g.state = if g.live_conn().is_some() {
                            PeerConnState::Connected {
                                auth_gen: generation,
                            }
                        } else {
                            PeerConnState::Idle
                        };
                        tracing::debug!(%peer, "re-probing rejected peer after membership change");
                    }
                    _ => {}
                }
                continue;
            }
            if mark_local_blocked(&mut *g, generation) {
                g.dial_waiters = None;
                tracing::warn!(%peer, "peer authorization revoked; connection invalidated");
            }
        }
        let extra: Vec<_> = self
            .extra
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        for ((peer, alpn), slot) in extra {
            let peer_hex = format!("{peer}");
            let mut g = slot.lock().await;
            if self.gate_allows(&peer_hex) {
                if matches!(
                    g.state,
                    PeerConnState::Blocked { .. } | PeerConnState::Rejected { .. }
                ) {
                    g.state = PeerConnState::Idle;
                    tracing::debug!(%peer, alpn = %String::from_utf8_lossy(&alpn), "peer authorized again");
                }
                continue;
            }
            if mark_local_blocked(&mut *g, generation) {
                g.dial_waiters = None;
                tracing::warn!(%peer, alpn = %String::from_utf8_lossy(&alpn), "peer authorization revoked; connection invalidated");
            }
        }
    }

    pub async fn revoke_peer(&self, peer: EndpointId) {
        let generation = self.gate_generation();
        if let Some(slot) = self.entries.get(&peer) {
            let mut g = slot.lock().await;
            mark_local_blocked(&mut *g, generation);
            g.dial_waiters = None;
        }
        self.extra.retain(|(p, _), _| *p != peer);
        tracing::warn!(%peer, "peer revoked; connection state invalidated");
    }

    pub async fn close_all(&self) {
        let peers: Vec<_> = self
            .entries
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        for (peer, slot) in peers {
            let mut g = slot.lock().await;
            if let Some(c) = g.conn.take() {
                c.close(0u32.into(), b"dataplane_down");
            }
            g.state = PeerConnState::Idle;
            tracing::debug!(%peer, "closed pool connection");
        }
        for entry in self.extra.iter() {
            let mut g = entry.value().lock().await;
            if let Some(c) = g.conn.take() {
                c.close(0u32.into(), b"dataplane_down");
            }
            g.state = PeerConnState::Idle;
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn default_alpn(&self) -> &'static [u8] {
        self.alpn
    }

    pub fn set_keep_alive(&self, enabled: bool) {
        self.keep_alive.store(enabled, Ordering::Relaxed);
    }

    pub fn keep_alive(&self) -> bool {
        self.keep_alive.load(Ordering::Relaxed)
    }

    pub fn on_demand_stats(&self) -> OnDemandStats {
        let success = self.metrics.reconnect_success.load(Ordering::Relaxed);
        let sum = self
            .metrics
            .reconnect_latency_sum_us
            .load(Ordering::Relaxed);
        OnDemandStats {
            reconnect_attempts: self.metrics.reconnect_attempts.load(Ordering::Relaxed),
            reconnect_success: success,
            reconnect_fail: self.metrics.reconnect_fail.load(Ordering::Relaxed),
            dials_suppressed: self.metrics.dials_suppressed.load(Ordering::Relaxed),
            reconnect_latency_avg_us: sum.checked_div(success).unwrap_or(0),
            reconnect_latency_max_us: self
                .metrics
                .reconnect_latency_max_us
                .load(Ordering::Relaxed),
        }
    }

    fn slot(&self, peer: EndpointId) -> Arc<AsyncMutex<PeerSlot>> {
        self.entries
            .entry(peer)
            .or_insert_with(|| Arc::new(AsyncMutex::new(PeerSlot::new())))
            .clone()
    }

    fn spawn_idle_sweeper(&self) {
        let entries = self.entries.clone();
        let keep_alive = self.keep_alive.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if keep_alive.load(Ordering::Relaxed) {
                    continue;
                }
                let timeout = Duration::from_secs(DEFAULT_IDLE_SECS);
                let peers: Vec<_> = entries
                    .iter()
                    .map(|e| (*e.key(), e.value().clone()))
                    .collect();
                for (peer, slot) in peers {
                    let mut g = slot.lock().await;
                    if !matches!(g.state, PeerConnState::Connected { .. }) {
                        continue;
                    }
                    if g.last_activity.elapsed() < timeout {
                        continue;
                    }
                    if let Some(c) = g.conn.take() {
                        c.close(0u32.into(), b"idle");
                    }
                    g.state = PeerConnState::Idle;
                    tracing::debug!(%peer, "idled peer connection");
                }
            }
        });
    }

    pub async fn get(&self, peer: EndpointId) -> anyhow::Result<Connection> {
        self.get_alpn(peer, self.alpn).await
    }

    pub async fn get_alpn(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
    ) -> anyhow::Result<Connection> {
        if alpn != self.alpn {
            return self.get_extra(peer, alpn).await;
        }
        let peer_hex = format!("{peer}");

        let slot = self.slot(peer);
        let now = Instant::now();
        let mut rejected_ctx: Option<(u64, Instant)> = None;
        let mut backoff_step = 0u32;
        let mut waiter_rx = None;
        let mut am_dialer = false;
        {
            let mut guard = slot.lock().await;
            match self.locked_live(&mut *guard, peer) {
                LiveUse::Use(c) => return Ok(c),
                LiveUse::Revoked => return Err(not_authorized(peer)),
                LiveUse::Absent => {}
            }
            if let Some(dead) = guard.conn.take() {
                if self.note_dead_conn(&mut guard.state, &dead, peer) {
                    return Err(not_authorized_remote(peer));
                }
                tracing::debug!(%peer, "cached connection dead, dialing again");
            }
            match self.readiness(&mut guard.state, peer, &peer_hex, now) {
                Readiness::Deny => {
                    return Err(not_authorized(peer));
                }
                Readiness::Wait => {
                    anyhow::bail!("dial to {peer} suppressed by backoff");
                }
                Readiness::Dial => {}
            }
            if let Some(tx) = &guard.dial_waiters {
                waiter_rx = Some(tx.subscribe());
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                rejected_ctx = match guard.state {
                    PeerConnState::Rejected {
                        generation, first, ..
                    } => Some((generation, first)),
                    _ => None,
                };
                backoff_step = match guard.state {
                    PeerConnState::Backoff { step, .. } => step,
                    _ => 0,
                };
                guard.state = PeerConnState::Dialing;
                am_dialer = true;
            }
        }

        if let Some(mut rx) = waiter_rx {
            match rx.recv().await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => anyhow::bail!("{e}"),
                Err(_) => {
                    drop(rx);
                    return Box::pin(self.get_alpn(peer, alpn)).await;
                }
            }
        }

        debug_assert!(am_dialer);
        let _ = am_dialer;

        match self.dial_once(peer, alpn).await {
            Ok(conn) => {
                if !self.gate_allows(&peer_hex) {
                    conn.close(1u32.into(), b"not_authorized");
                    let mut guard = slot.lock().await;
                    if mark_local_blocked(&mut *guard, self.gate_generation()) {
                        guard.dial_waiters = None;
                        tracing::warn!(%peer, "peer revoked while dialing; connection dropped");
                    }
                    return Err(not_authorized(peer));
                }
                let generation = self.gate_generation();
                let canonical = {
                    let mut guard = slot.lock().await;
                    if let Some(existing) = guard.live_conn() {
                        let existing = existing.clone();
                        if let Some(tx) = guard.dial_waiters.take() {
                            let _ = tx.send(Ok(existing.clone()));
                        }
                        drop(guard);
                        conn.close(0u32.into(), b"tie_break");
                        existing
                    } else {
                        guard.conn = Some(conn.clone());
                        guard.state = PeerConnState::Connected {
                            auth_gen: generation,
                        };
                        guard.touch();
                        if let Some(tx) = guard.dial_waiters.take() {
                            let _ = tx.send(Ok(conn.clone()));
                        }
                        conn
                    }
                };
                Ok(canonical)
            }
            Err((DialFailure::LocalDenied, err)) => {
                let mut guard = slot.lock().await;
                self.mark_local_denied(&mut *guard, peer, &err);
                anyhow::bail!("{err}")
            }
            Err((DialFailure::RemoteRejected, err)) => {
                let mut guard = slot.lock().await;
                self.mark_remote_rejected(&mut *guard, peer, rejected_ctx, &err);
                anyhow::bail!("{err}")
            }
            Err((DialFailure::Transient, err)) => {
                let mut guard = slot.lock().await;
                self.mark_backoff(&mut *guard, backoff_step, peer, &err);
                anyhow::bail!("{err}")
            }
        }
    }

    async fn dial_once(
        &self,
        peer: EndpointId,
        alpn: &'static [u8],
    ) -> Result<Connection, (DialFailure, Arc<str>)> {
        let start = Instant::now();
        self.metrics
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, alpn = %String::from_utf8_lossy(alpn), "dialing peer");
        match tokio::time::timeout(RECONNECT_TIMEOUT, self.endpoint.connect(peer, alpn)).await {
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
                self.metrics
                    .reconnect_success
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .reconnect_latency_sum_us
                    .fetch_add(latency_us, Ordering::Relaxed);
                let max = self
                    .metrics
                    .reconnect_latency_max_us
                    .load(Ordering::Relaxed);
                if latency_us > max {
                    self.metrics
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

    fn extra_slot(&self, peer: EndpointId, alpn: &'static [u8]) -> Arc<AsyncMutex<ExtraSlot>> {
        self.extra
            .entry((peer, alpn.to_vec()))
            .or_insert_with(|| Arc::new(AsyncMutex::new(ExtraSlot::new())))
            .clone()
    }

    async fn get_extra(&self, peer: EndpointId, alpn: &'static [u8]) -> anyhow::Result<Connection> {
        let peer_hex = format!("{peer}");
        let slot = self.extra_slot(peer, alpn);
        let now = Instant::now();
        let mut rejected_ctx: Option<(u64, Instant)> = None;
        let mut backoff_step = 0u32;
        let mut waiter_rx = None;
        let mut am_dialer = false;
        {
            let mut guard = slot.lock().await;
            match self.locked_live(&mut *guard, peer) {
                LiveUse::Use(c) => return Ok(c),
                LiveUse::Revoked => return Err(not_authorized(peer)),
                LiveUse::Absent => {}
            }
            if let Some(dead) = guard.conn.take()
                && self.note_dead_conn(&mut guard.state, &dead, peer)
            {
                return Err(not_authorized_remote(peer));
            }
            match self.readiness(&mut guard.state, peer, &peer_hex, now) {
                Readiness::Deny => {
                    return Err(not_authorized(peer));
                }
                Readiness::Wait => {
                    anyhow::bail!("dial to {peer} suppressed by backoff");
                }
                Readiness::Dial => {}
            }
            if let Some(tx) = &guard.dial_waiters {
                waiter_rx = Some(tx.subscribe());
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                rejected_ctx = match guard.state {
                    PeerConnState::Rejected {
                        generation, first, ..
                    } => Some((generation, first)),
                    _ => None,
                };
                backoff_step = match guard.state {
                    PeerConnState::Backoff { step, .. } => step,
                    _ => 0,
                };
                guard.state = PeerConnState::Dialing;
                am_dialer = true;
            }
        }

        if let Some(mut rx) = waiter_rx {
            match rx.recv().await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => anyhow::bail!("{e}"),
                Err(_) => {
                    drop(rx);
                    return Box::pin(self.get_extra(peer, alpn)).await;
                }
            }
        }

        debug_assert!(am_dialer);
        let _ = am_dialer;

        match self.dial_once(peer, alpn).await {
            Ok(conn) => {
                if !self.gate_allows(&peer_hex) {
                    conn.close(1u32.into(), b"not_authorized");
                    let mut guard = slot.lock().await;
                    if mark_local_blocked(&mut *guard, self.gate_generation()) {
                        guard.dial_waiters = None;
                        tracing::warn!(%peer, alpn = %String::from_utf8_lossy(alpn), "peer revoked while dialing; connection dropped");
                    }
                    return Err(not_authorized(peer));
                }
                let mut guard = slot.lock().await;
                if let Some(existing) = guard.live_conn() {
                    if let Some(tx) = guard.dial_waiters.take() {
                        let _ = tx.send(Ok(existing.clone()));
                    }
                    drop(guard);
                    conn.close(0u32.into(), b"tie_break");
                    return Ok(existing);
                }
                guard.conn = Some(conn.clone());
                guard.state = PeerConnState::Connected {
                    auth_gen: self.gate_generation(),
                };
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Ok(conn.clone()));
                }
                Ok(conn)
            }
            Err((DialFailure::LocalDenied, err)) => {
                let mut guard = slot.lock().await;
                self.mark_local_denied(&mut *guard, peer, &err);
                anyhow::bail!("{err}")
            }
            Err((DialFailure::RemoteRejected, err)) => {
                let mut guard = slot.lock().await;
                self.mark_remote_rejected(&mut *guard, peer, rejected_ctx, &err);
                anyhow::bail!("{err}")
            }
            Err((DialFailure::Transient, err)) => {
                let mut guard = slot.lock().await;
                self.mark_backoff(&mut *guard, backoff_step, peer, &err);
                anyhow::bail!("{err}")
            }
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
}
