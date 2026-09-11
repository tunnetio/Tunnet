//! Connection pool with optional on-demand (idle suspend / reconnect) behavior.
//!
//! Direct mode defaults to on-demand (`keep_alive = false`): idle connections are
//! closed after [`DEFAULT_IDLE_SECS`] and reopened when traffic resumes.
//! Managed mode defaults to keep-alive (connections stay open).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures_util::StreamExt;
use iroh::TransportAddr;
use iroh::endpoint::{
    ConnectError, ConnectWithOptsError, ConnectingError, Connection, ConnectionError, PathEvent,
};
use iroh::{Endpoint, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::cloud_relay_meter::CloudRelayMeter;
use crate::transport_auth::{TransportAuth, is_authorization_close};

pub const DEFAULT_IDLE_SECS: u64 = 120;
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_BASE: Duration = Duration::from_millis(200);
const BACKOFF_CAP: Duration = Duration::from_secs(30);
const REMOTE_RETRY_BASE_SECS: u64 = 10;
const REMOTE_RETRY_CAP: Duration = Duration::from_secs(300);
const REMOTE_RETRY_MAX_SHIFT: u32 = 5;

type DialResult = Result<Connection, Arc<str>>;
type DialWaiters = tokio::sync::broadcast::Sender<DialResult>;

/// Outcome of the shared dial-readiness decision.
enum Readiness {
    /// Caller may dial (or subscribe to the in-flight dial).
    Dial,
    /// Caller must fail fast: the local gate denies the peer. `shed` is true
    /// exactly once per episode so the caller drops queued load a single time.
    Deny { shed: bool },
    /// Caller must wait: backoff or remote-rejection cooldown is active.
    /// Packets may be absorbed into the bounded buffer; explicit dial
    /// requests fail fast.
    Wait,
}

/// Classified dial outcome. Local denial and remote rejection carry different
/// invalidation: the first clears when local membership changes, the second
/// also re-probes on a bounded cooldown since remote membership is
/// unobservable locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailure {
    LocalDenied,
    RemoteRejected,
    Transient,
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

#[derive(Debug, Clone, Serialize)]
pub struct PeerConnSnapshot {
    pub state: String,
    pub keep_alive: bool,
    pub last_activity_secs_ago: u64,
    pub live: bool,
    pub path: String,
}

struct PeerSlot {
    conn: Option<Connection>,
    /// True if the live connection was opened by our dial (not accepted).
    opened_by_us: bool,
    state: PeerConnState,
    last_activity: Instant,
    peer_keep_alive: bool,
    /// Shared dial in flight: first waiter dials, others subscribe and await the result.
    dial_waiters: Option<DialWaiters>,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            opened_by_us: false,
            state: PeerConnState::Idle,
            last_activity: Instant::now(),
            peer_keep_alive: false,
            dial_waiters: None,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn drop_buf(&mut self) -> usize {
        0
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
    packets_buffered: AtomicU64,
    packets_dropped_timeout: AtomicU64,
    packets_dropped_blocked: AtomicU64,
    dials_suppressed: AtomicU64,
    reconnect_latency_sum_us: AtomicU64,
    reconnect_latency_max_us: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnDemandStats {
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

/// Secondary-ALPN connection with the same retry protections as the default pool.
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

/// Common connection + retry state shared by default and secondary ALPN slots,
/// so both paths enforce the same authorization decisions.
trait ConnSlot {
    fn live_conn(&self) -> Option<Connection>;
    fn conn_ref(&mut self) -> &mut Option<Connection>;
    fn slot_state(&mut self) -> &mut PeerConnState;
    fn slot_waiters(&mut self) -> &mut Option<DialWaiters>;
    fn touch_slot(&mut self);
    fn drop_queued(&mut self) -> usize;
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
    fn drop_queued(&mut self) -> usize {
        self.drop_buf()
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
    fn drop_queued(&mut self) -> usize {
        0
    }
}

/// Locked live-connection use after membership revalidation.
enum LiveUse {
    Use(Connection),
    Revoked,
    Absent,
}

fn normalize_relay_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Bounded exponential backoff with jitter for transient dial failures.
fn backoff_delay(step: u32) -> Duration {
    let shift = step.min(8);
    let base = BACKOFF_BASE.as_millis() as u64 * (1u64 << shift);
    let capped = base.min(BACKOFF_CAP.as_millis() as u64);
    let jitter = rand::random::<u64>() % (capped / 2 + 1);
    Duration::from_millis(capped / 2 + jitter)
}

/// Bounded re-probe schedule for remote rejections. Grows with the time since
/// the consecutive episode started, so a persistently rejecting peer costs one
/// dial per few minutes while a freshly rejected one re-probes within seconds
/// of any local membership change or the first cooldown.
fn remote_retry_delay(elapsed_since_first: Duration) -> Duration {
    let shift =
        (elapsed_since_first.as_secs() / REMOTE_RETRY_BASE_SECS).min(REMOTE_RETRY_MAX_SHIFT as u64);
    let base = REMOTE_RETRY_BASE_SECS * 1000 * (1u64 << shift);
    let capped = base.min(REMOTE_RETRY_CAP.as_millis() as u64);
    let jitter = rand::random::<u64>() % (capped / 2 + 1);
    Duration::from_millis(capped / 2 + jitter)
}

/// Classify a dial error from its type, matching authorization rejections
/// against the hooks' wire contract. Free-form messages never decide.
fn classify_connect_error(e: &ConnectError) -> DialFailure {
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

fn not_authorized(peer: EndpointId) -> anyhow::Error {
    anyhow::anyhow!("not_authorized: {peer} is not an authorized peer")
}

fn not_authorized_remote(peer: EndpointId) -> anyhow::Error {
    anyhow::anyhow!("not_authorized: {peer} rejected the connection")
}

/// True for a remote authorization close under the hooks' wire contract.
fn is_auth_close_error(e: &ConnectionError) -> bool {
    matches!(
        e,
        ConnectionError::ApplicationClosed(close)
            if is_authorization_close(
                u32::try_from(close.error_code.into_inner()).unwrap_or(u32::MAX),
                close.reason.as_ref(),
            )
    )
}

/// Pin locally-blocked at `generation`, closing any connection. Returns true
/// on a new episode (caller logs once).
fn mark_local_blocked(slot: &mut impl ConnSlot, generation: u64) -> bool {
    if let Some(c) = slot.conn_ref().take() {
        c.close(1u32.into(), b"not_authorized");
    }
    let state = slot.slot_state();
    let fresh = !matches!(state, PeerConnState::Blocked { generation: g } if *g == generation);
    *state = PeerConnState::Blocked { generation };
    fresh
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
        TransportAddr::Relay(url) => urls.contains(&normalize_relay_url(url.as_str())),
        _ => false,
    }
}

#[derive(Clone)]
pub struct ConnPool {
    endpoint: Endpoint,
    alpn: &'static [u8],
    /// Keyed by endpoint only for the pool's default ALPN (on-demand state).
    /// Secondary ALPNs use `extra` without idle management.
    entries: Arc<DashMap<EndpointId, Arc<AsyncMutex<PeerSlot>>>>,
    extra: Arc<ExtraConnMap>,
    policy: Arc<PoolPolicy>,
    metrics: Arc<PoolMetrics>,
    bytes_in: Arc<DashMap<EndpointId, AtomicU64>>,
    bytes_out: Arc<DashMap<EndpointId, AtomicU64>>,
    cloud_relay_meter: CloudRelayMeter,
    cloud_relay_urls: Arc<RwLock<HashSet<String>>>,
    peer_cloud_relay: Arc<DashMap<EndpointId, AtomicBool>>,
    /// Membership gate for outbound dials. `None` admits everything
    /// (tests / shells without membership); configured pools fail
    /// deterministically-blocked peers without dialing.
    gate: Arc<RwLock<Option<TransportAuth>>>,
}

struct PoolPolicy {
    keep_alive: AtomicBool,
    idle_timeout: Mutex<Duration>,
    keep_alive_hosts: DashMap<String, ()>,
    keep_alive_peers: DashMap<EndpointId, ()>,
}

impl ConnPool {
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        let pool = Self {
            endpoint,
            alpn,
            entries: Arc::new(DashMap::new()),
            extra: Arc::new(DashMap::new()),
            policy: Arc::new(PoolPolicy {
                keep_alive: AtomicBool::new(true),
                idle_timeout: Mutex::new(Duration::from_secs(DEFAULT_IDLE_SECS)),
                keep_alive_hosts: DashMap::new(),
                keep_alive_peers: DashMap::new(),
            }),
            metrics: Arc::new(PoolMetrics::default()),
            bytes_in: Arc::new(DashMap::new()),
            bytes_out: Arc::new(DashMap::new()),
            cloud_relay_meter: CloudRelayMeter::new(),
            cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
            peer_cloud_relay: Arc::new(DashMap::new()),
            gate: Arc::new(RwLock::new(None)),
        };
        pool.spawn_idle_sweeper();
        pool
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.cloud_relay_meter.clone()
    }

    /// Install the membership gate guarding outbound dials (default + extra ALPNs).
    pub fn set_transport_auth(&self, auth: TransportAuth) {
        *self.gate.write() = Some(auth);
    }

    pub fn transport_auth(&self) -> Option<TransportAuth> {
        self.gate.read().clone()
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

    /// Single dial-readiness decision shared by `get`, `get_extra` and the
    /// packet path. Expired backoffs and due remote re-probes proceed; steady
    /// holds fail fast without dialing. Buffer shedding stays with the caller:
    /// `Deny` carries `shed == true` exactly once per local-block episode.
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
                    Readiness::Deny { shed: false }
                }
                _ => {
                    *state = PeerConnState::Blocked { generation };
                    tracing::warn!(%peer, "peer blocked: not authorized; retrying only when membership changes");
                    Readiness::Deny { shed: true }
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

    /// Record a remote deterministic rejection. `prev` is the (generation,
    /// episode start) snapshotted when the dial began; a moved generation or
    /// an intervening success starts a fresh consecutive episode.
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

    /// Record a transient failure with backoff.
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

    /// Record a deterministic local denial (pool gate or endpoint hook, same
    /// membership source). Fails waiters with the hook's message.
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

    /// Locked live-connection fast path with membership revalidation. The gate
    /// itself is consulted only when the membership generation moved, keeping
    /// steady traffic to a single atomic load; a revoked peer's connection is
    /// closed here even if `reconcile()` has not run yet.
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
        let dropped = slot.drop_queued();
        self.metrics
            .packets_dropped_blocked
            .fetch_add(dropped as u64, Ordering::Relaxed);
        if mark_local_blocked(slot, generation) {
            tracing::warn!(%peer, "revoked peer connection closed at point of use");
        }
        LiveUse::Revoked
    }

    /// Classify an observed-dead connection. A remote authorization close means
    /// the peer rejects us now: enter the rejection cooldown instead of
    /// redialing. Returns true when the caller must fail fast. An already
    /// governing episode is left untouched so trickling observations cannot
    /// postpone its re-probe.
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

    /// Drop connection for peers the gate now rejects; clear stale
    /// blocks the gate now admits. Call on every membership change so
    /// authorization changes propagate by event. The pool additionally
    /// revalidates live connections on generation change at point of use, so
    /// a missed call only delays observability, never enforcement.
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
            let dropped = g.drop_buf();
            self.metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            if mark_local_blocked(&mut *g, generation) {
                g.dial_waiters = None;
                tracing::warn!(%peer, dropped, "peer authorization revoked; connection invalidated");
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

    /// Explicitly revoke a peer: close all its connections and pin it blocked
    /// at the current generation until authorizing state changes.
    pub async fn revoke_peer(&self, peer: EndpointId) {
        let generation = self.gate_generation();
        if let Some(slot) = self.entries.get(&peer) {
            let mut g = slot.lock().await;
            let dropped = g.drop_buf();
            self.metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            mark_local_blocked(&mut *g, generation);
            g.dial_waiters = None;
        }
        self.extra.retain(|(p, _), _| *p != peer);
        tracing::warn!(%peer, "peer revoked; connection state invalidated");
    }

    /// Replace the set of billable Tunnet Cloud deployment relay URLs.
    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        let normalized: HashSet<String> =
            urls.into_iter().map(|u| normalize_relay_url(&u)).collect();
        *self.cloud_relay_urls.write() = normalized;
        // Clear stale peer flags; path watchers will recompute on next event.
        self.peer_cloud_relay.clear();
    }

    fn spawn_cloud_relay_path_watch(&self, peer: EndpointId, conn: Connection) {
        let urls = self.cloud_relay_urls.clone();
        let flags = self.peer_cloud_relay.clone();
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

    fn on_live_conn(&self, peer: EndpointId, conn: Connection) {
        self.spawn_cloud_relay_path_watch(peer, conn);
    }

    /// Local EndpointId is the canonical initiator when `local < peer`.
    /// Prefer the connection opened by that initiator so both ends converge.
    fn prefer_incoming(
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

    /// Install an accepted connection. Returns false if tie-break keeps the existing conn.
    pub async fn adopt(&self, peer: EndpointId, conn: Connection) -> bool {
        if !self.gate_allows(&format!("{peer}")) {
            conn.close(1u32.into(), b"not_authorized");
            return false;
        }
        let local = self.endpoint.id();
        let slot = self.slot(peer);
        let mut guard = slot.lock().await;
        if let Some(existing) = guard.live_conn() {
            if existing.stable_id() == conn.stable_id() {
                guard.touch();
                return true;
            }
            if !Self::prefer_incoming(local, peer, guard.opened_by_us, false) {
                return false;
            }
            if let Some(old) = guard.conn.take() {
                old.close(0u32.into(), b"tie_break");
            }
        }
        guard.conn = Some(conn.clone());
        guard.opened_by_us = false;
        guard.state = PeerConnState::Connected {
            auth_gen: self.gate_generation(),
        };
        guard.touch();
        drop(guard);
        self.on_live_conn(peer, conn);
        true
    }

    /// Close every default-ALPN peer connection (e.g. data plane down).
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
            g.opened_by_us = false;
            g.state = PeerConnState::Idle;
            g.drop_buf();
            tracing::debug!(%peer, "closed tunnel pool connection");
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
        self.policy.keep_alive.store(enabled, Ordering::Relaxed);
    }

    pub fn keep_alive(&self) -> bool {
        self.policy.keep_alive.load(Ordering::Relaxed)
    }

    pub fn set_idle_timeout(&self, d: Duration) {
        *self.policy.idle_timeout.lock() = d;
    }

    pub fn add_keep_alive_host(&self, hostname: &str) {
        self.policy
            .keep_alive_hosts
            .insert(hostname.to_ascii_lowercase(), ());
    }

    pub fn remove_keep_alive_host(&self, hostname: &str) {
        self.policy
            .keep_alive_hosts
            .remove(&hostname.to_ascii_lowercase());
    }

    pub fn set_peer_keep_alive(&self, peer: EndpointId, enabled: bool) {
        if enabled {
            self.policy.keep_alive_peers.insert(peer, ());
        } else {
            self.policy.keep_alive_peers.remove(&peer);
        }
        let slot = self.slot(peer);
        tokio::spawn(async move {
            slot.lock().await.peer_keep_alive = enabled;
        });
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
            packets_buffered: self.metrics.packets_buffered.load(Ordering::Relaxed),
            packets_dropped_timeout: self.metrics.packets_dropped_timeout.load(Ordering::Relaxed),
            packets_dropped_blocked: self.metrics.packets_dropped_blocked.load(Ordering::Relaxed),
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
        let policy = self.policy.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if policy.keep_alive.load(Ordering::Relaxed) {
                    continue;
                }
                let timeout = *policy.idle_timeout.lock();
                let peers: Vec<_> = entries
                    .iter()
                    .map(|e| (*e.key(), e.value().clone()))
                    .collect();
                for (peer, slot) in peers {
                    if policy.keep_alive_peers.contains_key(&peer) {
                        continue;
                    }
                    let mut g = slot.lock().await;
                    if g.peer_keep_alive {
                        continue;
                    }
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
        // Dialer context snapshotted under the electing lock: a consecutive
        // remote rejection lengthens the next cooldown, a fresh state resets it.
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
                Readiness::Deny { shed } => {
                    if shed {
                        let dropped = guard.drop_buf();
                        self.metrics
                            .packets_dropped_blocked
                            .fetch_add(dropped as u64, Ordering::Relaxed);
                    }
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
                    // Abandoned dial or lost wakeup: re-run the full decision.
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
                    let dropped = guard.drop_buf();
                    self.metrics
                        .packets_dropped_blocked
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                    if mark_local_blocked(&mut *guard, self.gate_generation()) {
                        guard.dial_waiters = None;
                        tracing::warn!(%peer, "peer revoked while dialing; connection dropped");
                    }
                    return Err(not_authorized(peer));
                }
                let generation = self.gate_generation();
                let local = self.endpoint.id();
                let canonical = {
                    let mut guard = slot.lock().await;
                    if let Some(existing) = guard.live_conn() {
                        let existing_by_us = guard.opened_by_us;
                        if Self::prefer_incoming(local, peer, existing_by_us, true) {
                            // Our dial wins tie-break over the accepted conn.
                            if let Some(old) = guard.conn.take() {
                                old.close(0u32.into(), b"tie_break");
                            }
                            guard.conn = Some(conn.clone());
                            guard.opened_by_us = true;
                            guard.state = PeerConnState::Connected {
                                auth_gen: generation,
                            };
                            guard.touch();
                            if let Some(tx) = guard.dial_waiters.take() {
                                let _ = tx.send(Ok(conn.clone()));
                            }
                            conn
                        } else {
                            let existing = existing.clone();
                            if let Some(tx) = guard.dial_waiters.take() {
                                let _ = tx.send(Ok(existing.clone()));
                            }
                            drop(guard);
                            conn.close(0u32.into(), b"tie_break");
                            existing
                        }
                    } else {
                        guard.conn = Some(conn.clone());
                        guard.opened_by_us = true;
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
                self.on_live_conn(peer, canonical.clone());
                Ok(canonical)
            }
            Err((DialFailure::LocalDenied, err)) => {
                let mut guard = slot.lock().await;
                let dropped = guard.drop_buf();
                self.metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                self.mark_local_denied(&mut *guard, peer, &err);
                anyhow::bail!("{err}")
            }
            Err((DialFailure::RemoteRejected, err)) => {
                let mut guard = slot.lock().await;
                let dropped = guard.drop_buf();
                self.metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64, Ordering::Relaxed);
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

    /// Single classified dial shared by the default and secondary ALPN paths.
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
                // A remote hook rejection cannot fail the dial itself: TLS
                // ordering completes the client handshake before the server
                // can run its hook and close. The rejection therefore arrives
                // as an already-dead connection and must classify as one.
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
                Readiness::Deny { .. } => {
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

    pub fn touch_peer(&self, peer: EndpointId) {
        if let Some(slot) = self.entries.get(&peer)
            && let Ok(mut g) = slot.try_lock()
        {
            g.touch();
            // Promote idle slots only: the generation stamp on an established
            // connection is the pool's revocation tripwire and must survive
            // inbound traffic.
            if matches!(g.state, PeerConnState::Idle) && g.live_conn().is_some() {
                g.state = PeerConnState::Connected {
                    auth_gen: self.gate_generation(),
                };
            }
        }
    }

    pub async fn drop_peer(&self, peer: EndpointId) {
        self.entries.remove(&peer);
        self.extra.retain(|(p, _), _| *p != peer);
    }

    /// True only if the peer slot has a connection with no close reason.
    /// If the slot mutex is held, returns true tentatively (likely mid-dial/send).
    pub fn has_live(&self, peer: EndpointId) -> bool {
        let Some(slot) = self.entries.get(&peer) else {
            return false;
        };
        match slot.try_lock() {
            Ok(g) => g.live_conn().is_some(),
            Err(_) => true,
        }
    }

    pub fn has_any_live(&self) -> bool {
        self.entries.iter().any(|e| match e.value().try_lock() {
            Ok(g) => g.live_conn().is_some(),
            Err(_) => true,
        })
    }

    /// Counts live on-demand slots plus aggregated byte counters for heartbeats.
    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let active_conns = self
            .entries
            .iter()
            .filter(|e| match e.value().try_lock() {
                Ok(g) => g.live_conn().is_some(),
                Err(_) => true,
            })
            .count() as u32;
        let bytes_rx: u64 = self
            .bytes_in
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum();
        let bytes_tx: u64 = self
            .bytes_out
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum();
        (active_conns, bytes_tx, bytes_rx)
    }

    pub fn keep_alive_global(&self) -> bool {
        self.policy.keep_alive.load(Ordering::Relaxed)
    }

    pub fn record_bytes_out(&self, peer: EndpointId, n: u64) {
        self.bytes_out
            .entry(peer)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
        if self
            .peer_cloud_relay
            .get(&peer)
            .is_some_and(|f| f.load(Ordering::Relaxed))
        {
            self.cloud_relay_meter.record(n);
        }
    }

    pub fn record_bytes_in(&self, peer: EndpointId, n: u64) {
        self.bytes_in
            .entry(peer)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        let inn = self
            .bytes_in
            .get(&peer)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0);
        let out = self
            .bytes_out
            .get(&peer)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0);
        (inn, out)
    }

    /// Best-effort snapshot of a peer's on-demand connection state.
    pub fn peer_snapshot(&self, peer: EndpointId) -> PeerConnSnapshot {
        let keep_alive = self.policy.keep_alive.load(Ordering::Relaxed)
            || self.policy.keep_alive_peers.contains_key(&peer);
        let Some(slot) = self.entries.get(&peer).map(|e| e.value().clone()) else {
            return PeerConnSnapshot {
                state: PeerConnState::Idle.as_str().into(),
                keep_alive,
                last_activity_secs_ago: u64::MAX,
                live: false,
                path: "unknown".into(),
            };
        };
        // Try non-blocking; if locked, return coarse has_live info.
        match slot.try_lock() {
            Ok(g) => PeerConnSnapshot {
                state: g.state.as_str().into(),
                keep_alive: keep_alive || g.peer_keep_alive,
                last_activity_secs_ago: g.last_activity.elapsed().as_secs(),
                live: g.live_conn().is_some(),
                path: "unknown".into(),
            },
            Err(_) => PeerConnSnapshot {
                state: (if keep_alive { "connected" } else { "idle" }).into(),
                keep_alive,
                last_activity_secs_ago: 0,
                live: true,
                path: "unknown".into(),
            },
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

    /// Two endpoints with direct local connectivity: the pool dials B over
    /// real QUIC while B's transport hook answers from `routes_b`.
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
        // Drive B's handshakes: without accept(), incoming connections (and
        // their hooks) never progress.
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

    #[test]
    fn tie_break_prefers_canonical_initiator_side() {
        let a = SecretKey::generate().public();
        let b = SecretKey::generate().public();
        let (low, high) = if a < b { (a, b) } else { (b, a) };

        // Low endpoint is initiator: wants opened_by_us=true.
        assert!(ConnPool::prefer_incoming(low, high, false, true));
        assert!(!ConnPool::prefer_incoming(low, high, true, false));
        assert!(!ConnPool::prefer_incoming(low, high, true, true));

        // High endpoint is not initiator: wants accepted (opened_by_us=false).
        assert!(ConnPool::prefer_incoming(high, low, true, false));
        assert!(!ConnPool::prefer_incoming(high, low, false, true));
    }

    #[tokio::test]
    async fn has_live_false_without_entry() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();
        assert!(!pool.has_live(peer));
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
        // Both should observe the same coalesced failure path (no live conn left).
        assert!(!pool.has_live(peer));
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
        assert!(t.pool.has_live(t.id_b));
    }

    #[test]
    fn backoff_delay_is_bounded_and_grows() {
        for step in 0..12 {
            assert!(backoff_delay(step) <= BACKOFF_CAP);
        }
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

    #[tokio::test]
    async fn blocked_burst_produces_no_dials() {
        let ep = bind_endpoint().await;
        let (pool, _routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        for _ in 0..100 {
            let _ = pool.get(peer).await;
        }
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0, "blocked peer must never dial");
        assert!(stats.dials_suppressed > 0);
        assert_eq!(pool.peer_snapshot(peer).state, "blocked");
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

        // Membership write without adding the peer: a new episode, still no dial.
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
    async fn reconcile_unblocks_on_membership_add() {
        let ep = bind_endpoint().await;
        let (pool, routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();
        let peer_hex = format!("{peer}");

        let _ = pool.get(peer).await;
        assert_eq!(pool.peer_snapshot(peer).state, "blocked");

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
        assert_eq!(pool.peer_snapshot(peer).state, "idle");
    }

    #[tokio::test]
    async fn revoke_peer_pins_blocked() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, TEST_ALPN);
        let peer = SecretKey::generate().public();

        pool.revoke_peer(peer).await;

        // Pin the denial at the same generation so no dial can follow.
        pool.set_transport_auth(TransportAuth::managed(&RoutingTable::new()));
        let _ = pool.get(peer).await;
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0);
        assert_eq!(pool.peer_snapshot(peer).state, "blocked");
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
    async fn expired_backoff_redials_on_get() {
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
        let caller = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get(peer).await.map(|_| ()) }
        });
        wait_for_attempts(&pool, 1).await;
        let _ = caller.await.expect("task");
        assert_eq!(pool.on_demand_stats().reconnect_attempts, 1);
        assert_eq!(pool.peer_snapshot(peer).state, "backoff");
    }

    #[tokio::test]
    async fn remote_rejection_ignores_local_gate_until_state_changes() {
        let ep = bind_endpoint().await;
        let routes = RoutingTable::new();
        let pool = ConnPool::new(ep, TEST_ALPN);
        pool.set_transport_auth(TransportAuth::managed(&routes));
        let peer = SecretKey::generate().public();
        put_peer(&routes, &peer, "100.64.0.9");

        // Asymmetric view: the local gate allows the peer, but the remote
        // side rejected the last dial. Packets must not redial.
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
        assert_eq!(pool.peer_snapshot(peer).state, "rejected");

        // Local membership moves while still allowing: immediate re-probe.
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

        // B's hook rejects over the real wire. The first dial may resolve Ok
        // (client handshake wins the race) or Err (close wins); either way
        // the rejection is observed without a second dial.
        let first = tokio::time::timeout(Duration::from_secs(15), t.pool.get(t.id_b))
            .await
            .expect("dial resolves");
        drop(first);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = t.pool.get(t.id_b).await;
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);
        assert_eq!(t.pool.peer_snapshot(t.id_b).state, "rejected");

        // Burst while the local gate still allows: must stay at one dial.
        for _ in 0..20 {
            let _ = t.pool.get(t.id_b).await;
        }
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);

        // B admits A, but A's view is unchanged: still no redial.
        put_peer(&t.routes_b, &t.pool.endpoint().id(), "100.64.0.3");
        assert!(t.pool.get(t.id_b).await.is_err());
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);

        // Only the cooldown clock is forced; the rejection itself was real.
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
        assert!(t.pool.has_live(t.id_b));
    }

    #[tokio::test]
    async fn revoked_live_connection_closed_at_point_of_use() {
        let t = test_pair().await;
        put_peer(&t.routes_b, &t.pool.endpoint().id(), "100.64.0.3");
        tokio::time::timeout(Duration::from_secs(15), t.pool.get(t.id_b))
            .await
            .expect("dial resolves")
            .expect("connects");
        assert!(t.pool.has_live(t.id_b));

        // Revoke locally without reconcile: the next stream get must still close.
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
        assert!(!t.pool.has_live(t.id_b));
        assert_eq!(t.pool.on_demand_stats().reconnect_attempts, 1);
        assert_eq!(t.pool.peer_snapshot(t.id_b).state, "blocked");
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
