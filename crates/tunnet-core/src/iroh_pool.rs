//! Connection pool with optional on-demand (idle suspend / reconnect) behavior.
//!
//! Direct mode defaults to on-demand (`keep_alive = false`): idle connections are
//! closed after [`DEFAULT_IDLE_SECS`] and reopened when traffic resumes.
//! Managed mode defaults to keep-alive (connections stay open).

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt;
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathEvent};
use iroh::{Endpoint, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::cloud_relay_meter::CloudRelayMeter;
use crate::transport_auth::TransportAuth;

pub const DEFAULT_IDLE_SECS: u64 = 120;
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_BUFFER_PACKETS: usize = 64;
pub const MAX_BUFFER_BYTES: usize = 1024 * 1024;
const BACKOFF_BASE: Duration = Duration::from_millis(200);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

type DialResult = Result<Connection, Arc<str>>;
type DialWaiters = tokio::sync::broadcast::Sender<DialResult>;

/// Classified dial outcome: `Blocked` retries only after authorizing state
/// changes, `Transient` retries with backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialFailure {
    Blocked,
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnState {
    Connected,
    Dialing,
    Idle,
    Backoff,
    Blocked,
}

impl PeerConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Dialing => "dialing",
            Self::Idle => "idle",
            Self::Backoff => "backoff",
            Self::Blocked => "blocked",
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
    buffer: VecDeque<Bytes>,
    buffer_bytes: usize,
    /// Shared dial in flight: first waiter dials, others subscribe and await the result.
    dial_waiters: Option<DialWaiters>,
    /// Transport gate rejected at this membership generation. A blocked peer
    /// stays blocked until the generation moves: at most one dial per episode.
    blocked_generation: Option<u64>,
    backoff_until: Option<Instant>,
    backoff_step: u32,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            opened_by_us: false,
            state: PeerConnState::Idle,
            last_activity: Instant::now(),
            peer_keep_alive: false,
            buffer: VecDeque::new(),
            buffer_bytes: 0,
            dial_waiters: None,
            blocked_generation: None,
            backoff_until: None,
            backoff_step: 0,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn push_buf(&mut self, packet: Bytes) -> bool {
        if self.buffer.len() >= MAX_BUFFER_PACKETS
            || self.buffer_bytes + packet.len() > MAX_BUFFER_BYTES
        {
            return false;
        }
        self.buffer_bytes += packet.len();
        self.buffer.push_back(packet);
        true
    }

    fn take_buf(&mut self) -> Vec<Bytes> {
        self.buffer_bytes = 0;
        self.buffer.drain(..).collect()
    }

    fn drop_buf(&mut self) -> usize {
        let n = self.buffer.len();
        self.buffer.clear();
        self.buffer_bytes = 0;
        n
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
    blocked_generation: Option<u64>,
    backoff_until: Option<Instant>,
    backoff_step: u32,
}

type ExtraConnMap = DashMap<(EndpointId, Vec<u8>), Arc<AsyncMutex<ExtraSlot>>>;

/// Invoked when this pool dials a live tunnel connection.
///
/// The dialer must read datagrams on that connection (the accept path only
/// reads accepted sockets). Without this hook, reverse-path IP traffic on a
/// keep-alive/dialed connection is never delivered to the local TUN.
pub type TunnelConnHook = Arc<dyn Fn(EndpointId, Connection) + Send + Sync>;

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

/// Remote deterministic rejects surface as application closes carrying the
/// hooks' reasons (`not_member`, `auth_required`; `policy_deny` from older
/// peers). Everything else is transient.
fn is_deterministic_reject(msg: &str) -> bool {
    msg.contains("not_member") || msg.contains("policy_deny") || msg.contains("auth_required")
}

fn not_authorized(peer: EndpointId) -> anyhow::Error {
    anyhow::anyhow!("not_authorized: {peer} is not an authorized peer")
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
    tunnel_hook: Arc<Mutex<Option<TunnelConnHook>>>,
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
            tunnel_hook: Arc::new(Mutex::new(None)),
            cloud_relay_meter: CloudRelayMeter::new(),
            cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
            peer_cloud_relay: Arc::new(DashMap::new()),
            gate: Arc::new(RwLock::new(None)),
        };
        pool.spawn_idle_sweeper();
        pool
    }

    /// Create a pool that shares keep-alive / idle policy with `other` (different ALPN).
    ///
    /// Does **not** spawn an idle sweeper - only [`Self::new`] owns the sweeper for a
    /// given policy Arc.
    pub fn with_shared_policy(endpoint: Endpoint, alpn: &'static [u8], other: &ConnPool) -> Self {
        Self {
            endpoint,
            alpn,
            entries: Arc::new(DashMap::new()),
            extra: Arc::new(DashMap::new()),
            policy: other.policy.clone(),
            metrics: other.metrics.clone(),
            bytes_in: other.bytes_in.clone(),
            bytes_out: other.bytes_out.clone(),
            tunnel_hook: Arc::new(Mutex::new(None)),
            cloud_relay_meter: other.cloud_relay_meter.clone(),
            cloud_relay_urls: other.cloud_relay_urls.clone(),
            peer_cloud_relay: other.peer_cloud_relay.clone(),
            gate: other.gate.clone(),
        }
    }

    /// Register a hook invoked whenever this pool dials a tunnel connection.
    pub fn set_tunnel_hook(&self, hook: TunnelConnHook) {
        *self.tunnel_hook.lock() = Some(hook);
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.cloud_relay_meter.clone()
    }

    /// Install the membership gate guarding outbound dials (default + extra ALPNs).
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

    /// Pin a slot blocked at the current generation: drop stale buffer, fail
    /// waiters, warn only on the transition into a new blocked episode.
    fn note_blocked(&self, guard: &mut PeerSlot, peer: EndpointId, dropped: usize) {
        let generation = self.gate_generation();
        self.metrics
            .packets_dropped_blocked
            .fetch_add(dropped as u64, Ordering::Relaxed);
        let fresh = guard.blocked_generation != Some(generation);
        guard.blocked_generation = Some(generation);
        guard.backoff_until = None;
        guard.state = PeerConnState::Blocked;
        if let Some(tx) = guard.dial_waiters.take() {
            let _ = tx.send(Err(Arc::from(format!("not_authorized: {peer}"))));
        }
        if fresh {
            tracing::warn!(%peer, "peer blocked: not authorized; retrying only when membership changes");
        }
    }

    /// Drop connection + buffer for peers the gate now rejects; clear stale
    /// blocks the gate now admits. Call on every membership/policy change so
    /// authorization changes propagate by event, never by retry timer.
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
                if g.blocked_generation.take().is_some() {
                    g.state = if g.live_conn().is_some() {
                        PeerConnState::Connected
                    } else {
                        PeerConnState::Idle
                    };
                    g.backoff_until = None;
                    g.backoff_step = 0;
                    tracing::info!(%peer, "peer authorized again");
                }
                continue;
            }
            let fresh = g.blocked_generation != Some(generation);
            if let Some(c) = g.conn.take() {
                c.close(1u32.into(), b"not_authorized");
            }
            let dropped = g.drop_buf();
            self.metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            g.blocked_generation = Some(generation);
            g.backoff_until = None;
            g.state = PeerConnState::Blocked;
            g.dial_waiters = None;
            if fresh {
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
                if g.blocked_generation.take().is_some() {
                    g.backoff_until = None;
                    g.backoff_step = 0;
                    tracing::info!(%peer, alpn = %String::from_utf8_lossy(&alpn), "peer authorized again");
                }
                continue;
            }
            let fresh = g.blocked_generation != Some(generation);
            if let Some(c) = g.conn.take() {
                c.close(1u32.into(), b"not_authorized");
            }
            g.blocked_generation = Some(generation);
            g.backoff_until = None;
            g.dial_waiters = None;
            if fresh {
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
            if let Some(c) = g.conn.take() {
                c.close(1u32.into(), b"not_authorized");
            }
            let dropped = g.drop_buf();
            self.metrics
                .packets_dropped_blocked
                .fetch_add(dropped as u64, Ordering::Relaxed);
            g.blocked_generation = Some(generation);
            g.backoff_until = None;
            g.state = PeerConnState::Blocked;
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

    fn fire_tunnel_hook(&self, peer: EndpointId, conn: Connection) {
        let hook = self.tunnel_hook.lock().clone();
        if let Some(hook) = hook {
            hook(peer, conn.clone());
        }
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
        guard.state = PeerConnState::Connected;
        guard.touch();
        drop(guard);
        self.fire_tunnel_hook(peer, conn);
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
            g.blocked_generation = None;
            g.backoff_until = None;
            g.backoff_step = 0;
            g.drop_buf();
            tracing::debug!(%peer, "closed tunnel pool connection");
        }
        for entry in self.extra.iter() {
            let mut g = entry.value().lock().await;
            if let Some(c) = g.conn.take() {
                c.close(0u32.into(), b"dataplane_down");
            }
            g.blocked_generation = None;
            g.backoff_until = None;
            g.backoff_step = 0;
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
                    if g.state != PeerConnState::Connected {
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
        let mut waiter_rx = None;
        let mut am_dialer = false;
        {
            let mut guard = slot.lock().await;
            if !self.gate_allows(&peer_hex) {
                let generation = self.gate_generation();
                if guard.blocked_generation == Some(generation) {
                    self.metrics
                        .dials_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                    guard.state = PeerConnState::Blocked;
                    return Err(not_authorized(peer));
                }
                let dropped = guard.drop_buf();
                self.note_blocked(&mut guard, peer, dropped);
                return Err(not_authorized(peer));
            }
            if guard.blocked_generation.take().is_some() {
                guard.backoff_until = None;
                guard.backoff_step = 0;
                tracing::info!(%peer, "peer authorized again");
            }
            if let Some(c) = guard.live_conn() {
                guard.touch();
                guard.state = PeerConnState::Connected;
                return Ok(c);
            }
            if guard.conn.is_some() {
                tracing::debug!(%peer, "cached connection dead, dialing again");
                guard.conn = None;
            }
            if let Some(until) = guard.backoff_until
                && Instant::now() < until
            {
                self.metrics
                    .dials_suppressed
                    .fetch_add(1, Ordering::Relaxed);
                guard.state = PeerConnState::Backoff;
                anyhow::bail!("backoff: retry to {peer} suppressed");
            }
            if let Some(tx) = &guard.dial_waiters {
                waiter_rx = Some(tx.subscribe());
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                guard.state = PeerConnState::Dialing;
                am_dialer = true;
            }
        }

        if let Some(mut rx) = waiter_rx {
            match rx.recv().await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => anyhow::bail!("{e}"),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    let guard = slot.lock().await;
                    if let Some(c) = guard.live_conn() {
                        return Ok(c);
                    }
                    // Dialer vanished without a result - retry as dialer.
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let guard = slot.lock().await;
                    if let Some(c) = guard.live_conn() {
                        return Ok(c);
                    }
                }
            }
            // Fall through: become dialer if nobody else is dialing.
            let mut guard = slot.lock().await;
            if let Some(c) = guard.live_conn() {
                return Ok(c);
            }
            if guard.dial_waiters.is_some() {
                drop(guard);
                return Box::pin(self.get_alpn(peer, alpn)).await;
            }
            let (tx, _) = tokio::sync::broadcast::channel(1);
            guard.dial_waiters = Some(tx);
            guard.state = PeerConnState::Dialing;
            am_dialer = true;
        }

        debug_assert!(am_dialer);
        let _ = am_dialer;

        match self.dial_once(peer, alpn).await {
            Ok(conn) => {
                if !self.gate_allows(&peer_hex) {
                    conn.close(1u32.into(), b"not_authorized");
                    let mut guard = slot.lock().await;
                    let dropped = guard.drop_buf();
                    self.note_blocked(&mut guard, peer, dropped);
                    return Err(not_authorized(peer));
                }
                let local = self.endpoint.id();
                let (canonical, buffered, fire_hook) = {
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
                            guard.state = PeerConnState::Connected;
                            guard.touch();
                            if let Some(tx) = guard.dial_waiters.take() {
                                let _ = tx.send(Ok(conn.clone()));
                            }
                            let buffered = guard.take_buf();
                            (conn, buffered, true)
                        } else {
                            let existing = existing.clone();
                            if let Some(tx) = guard.dial_waiters.take() {
                                let _ = tx.send(Ok(existing.clone()));
                            }
                            let buffered = guard.take_buf();
                            drop(guard);
                            conn.close(0u32.into(), b"tie_break");
                            (existing, buffered, true)
                        }
                    } else {
                        guard.conn = Some(conn.clone());
                        guard.opened_by_us = true;
                        guard.state = PeerConnState::Connected;
                        guard.touch();
                        if let Some(tx) = guard.dial_waiters.take() {
                            let _ = tx.send(Ok(conn.clone()));
                        }
                        let buffered = guard.take_buf();
                        (conn, buffered, true)
                    }
                };

                for pkt in buffered {
                    if let Err(e) = send_datagram(&canonical, pkt).await {
                        tracing::debug!(%peer, ?e, "flush buffered datagram failed");
                    }
                }
                if fire_hook {
                    self.fire_tunnel_hook(peer, canonical.clone());
                }
                Ok(canonical)
            }
            Err((DialFailure::Blocked, err)) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let generation = self.gate_generation();
                let mut guard = slot.lock().await;
                let dropped = guard.drop_buf();
                self.metrics
                    .packets_dropped_blocked
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                let fresh = guard.blocked_generation != Some(generation);
                guard.blocked_generation = Some(generation);
                guard.backoff_until = None;
                guard.state = PeerConnState::Blocked;
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Err(err.clone()));
                }
                if fresh {
                    tracing::warn!(%peer, reason = %err, "peer blocked by authorization; retrying only when membership changes");
                }
                anyhow::bail!("{err}")
            }
            Err((DialFailure::Transient, err)) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let mut guard = slot.lock().await;
                let dropped = guard.drop_buf();
                self.metrics
                    .packets_dropped_timeout
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                let wait = backoff_delay(guard.backoff_step);
                guard.backoff_step = guard.backoff_step.saturating_add(1);
                guard.backoff_until = Some(Instant::now() + wait);
                guard.state = PeerConnState::Backoff;
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Err(err.clone()));
                }
                tracing::debug!(%peer, wait_ms = wait.as_millis(), reason = %err, "dial failed; backing off");
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
                let msg: Arc<str> = Arc::from(format!("connect to {peer}: {e}"));
                if is_deterministic_reject(&msg) {
                    Err((DialFailure::Blocked, msg))
                } else {
                    Err((DialFailure::Transient, msg))
                }
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
            .or_insert_with(|| {
                Arc::new(AsyncMutex::new(ExtraSlot {
                    conn: None,
                    dial_waiters: None,
                    blocked_generation: None,
                    backoff_until: None,
                    backoff_step: 0,
                }))
            })
            .clone()
    }

    async fn get_extra(&self, peer: EndpointId, alpn: &'static [u8]) -> anyhow::Result<Connection> {
        let peer_hex = format!("{peer}");
        let slot = self.extra_slot(peer, alpn);

        let mut waiter_rx = None;
        let mut am_dialer = false;
        {
            let mut guard = slot.lock().await;
            if !self.gate_allows(&peer_hex) {
                let generation = self.gate_generation();
                if guard.blocked_generation == Some(generation) {
                    self.metrics
                        .dials_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(not_authorized(peer));
                }
                guard.blocked_generation = Some(generation);
                guard.backoff_until = None;
                guard.dial_waiters = None;
                tracing::warn!(%peer, alpn = %String::from_utf8_lossy(alpn), "peer blocked: not authorized; retrying only when membership changes");
                return Err(not_authorized(peer));
            }
            if guard.blocked_generation.take().is_some() {
                guard.backoff_until = None;
                guard.backoff_step = 0;
                tracing::info!(%peer, alpn = %String::from_utf8_lossy(alpn), "peer authorized again");
            }
            if let Some(c) = guard.conn.as_ref()
                && c.close_reason().is_none()
            {
                return Ok(c.clone());
            }
            guard.conn = None;
            if let Some(until) = guard.backoff_until
                && Instant::now() < until
            {
                self.metrics
                    .dials_suppressed
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("backoff: retry to {peer} suppressed");
            }
            if let Some(tx) = &guard.dial_waiters {
                waiter_rx = Some(tx.subscribe());
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                am_dialer = true;
            }
        }

        if let Some(mut rx) = waiter_rx {
            match rx.recv().await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => anyhow::bail!("{e}"),
                Err(_) => {
                    let guard = slot.lock().await;
                    if let Some(c) = guard.conn.as_ref()
                        && c.close_reason().is_none()
                    {
                        return Ok(c.clone());
                    }
                }
            }
            let mut guard = slot.lock().await;
            if let Some(c) = guard.conn.as_ref()
                && c.close_reason().is_none()
            {
                return Ok(c.clone());
            }
            if guard.dial_waiters.is_some() {
                drop(guard);
                return Box::pin(self.get_extra(peer, alpn)).await;
            }
            let (tx, _) = tokio::sync::broadcast::channel(1);
            guard.dial_waiters = Some(tx);
            am_dialer = true;
        }

        debug_assert!(am_dialer);
        let _ = am_dialer;

        match self.dial_once(peer, alpn).await {
            Ok(conn) => {
                if !self.gate_allows(&peer_hex) {
                    conn.close(1u32.into(), b"not_authorized");
                    let mut guard = slot.lock().await;
                    let generation = self.gate_generation();
                    let fresh = guard.blocked_generation != Some(generation);
                    guard.blocked_generation = Some(generation);
                    guard.backoff_until = None;
                    if let Some(tx) = guard.dial_waiters.take() {
                        let _ = tx.send(Err(Arc::from(format!("not_authorized: {peer}"))));
                    }
                    if fresh {
                        tracing::warn!(%peer, alpn = %String::from_utf8_lossy(alpn), "peer blocked: not authorized; retrying only when membership changes");
                    }
                    return Err(not_authorized(peer));
                }
                let mut guard = slot.lock().await;
                guard.conn = Some(conn.clone());
                guard.backoff_until = None;
                guard.backoff_step = 0;
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Ok(conn.clone()));
                }
                Ok(conn)
            }
            Err((DialFailure::Blocked, err)) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let generation = self.gate_generation();
                let mut guard = slot.lock().await;
                let fresh = guard.blocked_generation != Some(generation);
                guard.blocked_generation = Some(generation);
                guard.backoff_until = None;
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Err(err.clone()));
                }
                if fresh {
                    tracing::warn!(%peer, alpn = %String::from_utf8_lossy(alpn), reason = %err, "peer blocked by authorization");
                }
                anyhow::bail!("{err}")
            }
            Err((DialFailure::Transient, err)) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let mut guard = slot.lock().await;
                let wait = backoff_delay(guard.backoff_step);
                guard.backoff_step = guard.backoff_step.saturating_add(1);
                guard.backoff_until = Some(Instant::now() + wait);
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Err(err.clone()));
                }
                tracing::debug!(%peer, alpn = %String::from_utf8_lossy(alpn), wait_ms = wait.as_millis(), reason = %err, "dial failed; backing off");
                anyhow::bail!("{err}")
            }
        }
    }

    /// Send a packet, buffering + dialing when the peer is idle.
    /// Deterministically blocked peers fail immediately without buffering:
    /// stale traffic for unauthorized peers is dropped and counted, never queued.
    pub async fn send_or_buffer(&self, peer: EndpointId, packet: Bytes) -> anyhow::Result<()> {
        let slot = self.slot(peer);
        {
            let mut guard = slot.lock().await;
            if let Some(c) = guard.live_conn() {
                guard.touch();
                drop(guard);
                return send_datagram(&c, packet).await;
            }
            if guard.conn.is_some() {
                guard.conn = None;
                guard.state = PeerConnState::Idle;
            }

            let peer_hex = format!("{peer}");
            if !self.gate_allows(&peer_hex) {
                let generation = self.gate_generation();
                if guard.blocked_generation != Some(generation) {
                    let dropped = guard.drop_buf();
                    self.note_blocked(&mut guard, peer, dropped);
                }
                self.metrics
                    .packets_dropped_blocked
                    .fetch_add(1, Ordering::Relaxed);
                guard.state = PeerConnState::Blocked;
                return Err(not_authorized(peer));
            }
            if guard.blocked_generation.take().is_some() {
                guard.backoff_until = None;
                guard.backoff_step = 0;
                tracing::info!(%peer, "peer authorized again");
            }

            if !guard.push_buf(packet) {
                self.metrics
                    .packets_dropped_timeout
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("on-demand buffer full for {peer}");
            }
            self.metrics
                .packets_buffered
                .fetch_add(1, Ordering::Relaxed);
            if guard.state == PeerConnState::Dialing
                || guard.state == PeerConnState::Backoff
                || guard.dial_waiters.is_some()
            {
                return Ok(());
            }
            guard.state = PeerConnState::Dialing;
        }

        let _ = self.get(peer).await?;
        Ok(())
    }

    pub fn touch_peer(&self, peer: EndpointId) {
        if let Some(slot) = self.entries.get(&peer)
            && let Ok(mut g) = slot.try_lock()
        {
            g.touch();
            if g.live_conn().is_some() {
                g.state = PeerConnState::Connected;
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
                state: if keep_alive {
                    PeerConnState::Connected.as_str().into()
                } else {
                    PeerConnState::Idle.as_str().into()
                },
                keep_alive,
                last_activity_secs_ago: 0,
                live: true,
                path: "unknown".into(),
            },
        }
    }
}

/// Send a datagram, waiting for buffer space when congested instead of dropping.
///
/// Drops packets larger than the connection's current `max_datagram_size`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    use crate::routing::RoutingTable;
    use crate::transport_auth::TransportAuth;

    async fn bind_endpoint() -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .expect("bind test endpoint")
    }

    fn denying_pool(ep: Endpoint) -> (ConnPool, RoutingTable) {
        let routes = RoutingTable::new();
        let pool = ConnPool::new(ep, b"test/alpn");
        pool.set_transport_auth(TransportAuth::managed(&routes));
        (pool, routes)
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
        let pool = ConnPool::new(ep, b"test/alpn");
        let peer = SecretKey::generate().public();
        assert!(!pool.has_live(peer));
    }

    #[tokio::test]
    async fn concurrent_get_coalesce_failure() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, b"test/alpn");
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

    #[test]
    fn backoff_delay_is_bounded_and_grows() {
        for step in 0..12 {
            assert!(backoff_delay(step) <= BACKOFF_CAP);
        }
        assert!(backoff_delay(8) > backoff_delay(0));
    }

    #[tokio::test]
    async fn blocked_burst_produces_no_dials() {
        let ep = bind_endpoint().await;
        let (pool, _routes) = denying_pool(ep);
        let peer = SecretKey::generate().public();

        for _ in 0..100 {
            let _ = pool.send_or_buffer(peer, Bytes::from_static(b"pkt")).await;
        }
        for _ in 0..20 {
            let _ = pool.get(peer).await;
        }
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0, "blocked peer must never dial");
        assert!(stats.dials_suppressed > 0);
        assert!(stats.packets_dropped_blocked >= 100);
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
    async fn revoke_peer_drops_buffer_and_pins_blocked() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, b"test/alpn");
        let peer = SecretKey::generate().public();

        pool.slot(peer)
            .lock()
            .await
            .push_buf(Bytes::from_static(b"stale"));
        pool.revoke_peer(peer).await;

        // Pin the denial at the same generation so no dial can follow.
        pool.set_transport_auth(TransportAuth::managed(&RoutingTable::new()));
        let _ = pool.get(peer).await;
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0);
        assert!(stats.packets_dropped_blocked >= 1);
        assert_eq!(pool.peer_snapshot(peer).state, "blocked");
    }

    #[tokio::test]
    async fn backoff_suppresses_without_dial() {
        let ep = bind_endpoint().await;
        let pool = ConnPool::new(ep, b"test/alpn");
        let peer = SecretKey::generate().public();

        {
            let slot = pool.slot(peer);
            let mut g = slot.lock().await;
            g.backoff_until = Some(Instant::now() + Duration::from_secs(60));
            g.state = PeerConnState::Backoff;
        }
        assert!(pool.get(peer).await.is_err());
        let stats = pool.on_demand_stats();
        assert_eq!(stats.reconnect_attempts, 0);
        assert_eq!(stats.dials_suppressed, 1);
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
