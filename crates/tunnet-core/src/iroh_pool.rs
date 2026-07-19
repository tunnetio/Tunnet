//! Connection pool with optional on-demand (idle suspend / reconnect) behavior.
//!
//! Direct mode defaults to on-demand (`keep_alive = false`): idle connections are
//! closed after [`DEFAULT_IDLE_SECS`] and reopened when traffic resumes.
//! Managed mode defaults to keep-alive (connections stay open).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

pub const DEFAULT_IDLE_SECS: u64 = 120;
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_BUFFER_PACKETS: usize = 64;
pub const MAX_BUFFER_BYTES: usize = 1024 * 1024;

type DialResult = Result<Connection, Arc<str>>;
type DialWaiters = tokio::sync::broadcast::Sender<DialResult>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnState {
    Connected,
    Suspended,
    Reconnecting,
}

impl PeerConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Suspended => "suspended",
            Self::Reconnecting => "reconnecting",
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
    state: PeerConnState,
    last_activity: Instant,
    peer_keep_alive: bool,
    buffer: VecDeque<Bytes>,
    buffer_bytes: usize,
    /// Shared dial in flight: first waiter dials, others subscribe and await the result.
    dial_waiters: Option<DialWaiters>,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            state: PeerConnState::Suspended,
            last_activity: Instant::now(),
            peer_keep_alive: false,
            buffer: VecDeque::new(),
            buffer_bytes: 0,
            dial_waiters: None,
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
    pub reconnect_latency_avg_us: u64,
    pub reconnect_latency_max_us: u64,
}

type ExtraConnMap = DashMap<(EndpointId, Vec<u8>), Arc<AsyncMutex<Option<Connection>>>>;

/// Invoked when this pool dials a live tunnel connection.
///
/// The dialer must read datagrams on that connection (the accept path only
/// reads accepted sockets). Without this hook, reverse-path IP traffic on a
/// keep-alive/dialed connection is never delivered to the local TUN.
pub type TunnelConnHook = Arc<dyn Fn(EndpointId, Connection) + Send + Sync>;

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
        }
    }

    /// Register a hook invoked whenever this pool dials a tunnel connection.
    pub fn set_tunnel_hook(&self, hook: TunnelConnHook) {
        *self.tunnel_hook.lock() = Some(hook);
    }

    fn fire_tunnel_hook(&self, peer: EndpointId, conn: Connection) {
        let hook = self.tunnel_hook.lock().clone();
        if let Some(hook) = hook {
            hook(peer, conn);
        }
    }

    /// Install an accepted tunnel connection as the peer's live conn when none exists.
    ///
    /// Returns whether `conn` is (or already was) the canonical live connection.
    /// If a *different* live dial already won the race, returns `false` and leaves
    /// the pool unchanged — caller should close `conn` and not start a reader.
    pub async fn adopt(&self, peer: EndpointId, conn: Connection) -> bool {
        let slot = self.slot(peer);
        let mut guard = slot.lock().await;
        if let Some(existing) = guard.live_conn() {
            if existing.stable_id() == conn.stable_id() {
                guard.touch();
                return true;
            }
            // Dial already installed a live connection — keep it.
            guard.touch();
            return false;
        }
        guard.conn = Some(conn);
        guard.state = PeerConnState::Connected;
        guard.touch();
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
            g.state = PeerConnState::Suspended;
            g.drop_buf();
            tracing::debug!(%peer, "closed tunnel pool connection");
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
                    g.state = PeerConnState::Suspended;
                    tracing::debug!(%peer, "suspended idle peer connection");
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

        let slot = self.slot(peer);
        let mut waiter_rx = None;
        let mut am_dialer = false;
        {
            let mut guard = slot.lock().await;
            if let Some(c) = guard.live_conn() {
                guard.touch();
                guard.state = PeerConnState::Connected;
                return Ok(c);
            }
            if guard.conn.is_some() {
                tracing::info!(%peer, "cached connection dead, reconnecting");
                guard.conn = None;
            }
            if let Some(tx) = &guard.dial_waiters {
                waiter_rx = Some(tx.subscribe());
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                guard.dial_waiters = Some(tx);
                guard.state = PeerConnState::Reconnecting;
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
            guard.state = PeerConnState::Reconnecting;
            am_dialer = true;
        }

        debug_assert!(am_dialer);
        let _ = am_dialer;

        let start = Instant::now();
        self.metrics
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(%peer, alpn = %String::from_utf8_lossy(alpn), "dialing peer");
        let dial_result: Result<Connection, Arc<str>> = match tokio::time::timeout(
            RECONNECT_TIMEOUT,
            self.endpoint.connect(peer, alpn),
        )
        .await
        {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => Err(Arc::from(format!("connect to {peer}: {e}"))),
            Err(_) => Err(Arc::from(format!("reconnect to {peer} timed out"))),
        };

        match dial_result {
            Ok(conn) => {
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

                let (canonical, buffered, fire_hook) = {
                    let mut guard = slot.lock().await;
                    // Accept may have installed a live conn while we dialed.
                    // Prefer that connection so send and ingress stay on one QUIC path.
                    if let Some(existing) = guard.live_conn() {
                        let existing = existing.clone();
                        if let Some(tx) = guard.dial_waiters.take() {
                            let _ = tx.send(Ok(existing.clone()));
                        }
                        let buffered = guard.take_buf();
                        drop(guard);
                        conn.close(0u32.into(), b"superseded");
                        (existing, buffered, false)
                    } else {
                        guard.conn = Some(conn.clone());
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
                        tracing::warn!(%peer, ?e, "flush buffered datagram failed");
                    }
                }
                if fire_hook {
                    self.fire_tunnel_hook(peer, canonical.clone());
                }
                Ok(canonical)
            }
            Err(err) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let mut guard = slot.lock().await;
                let dropped = guard.drop_buf();
                self.metrics
                    .packets_dropped_timeout
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                guard.state = PeerConnState::Suspended;
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Err(err.clone()));
                }
                anyhow::bail!("{err}")
            }
        }
    }

    async fn get_extra(&self, peer: EndpointId, alpn: &'static [u8]) -> anyhow::Result<Connection> {
        let key = (peer, alpn.to_vec());
        let slot = self
            .extra
            .entry(key)
            .or_insert_with(|| Arc::new(AsyncMutex::new(None)))
            .clone();
        let mut guard = slot.lock().await;
        if let Some(c) = guard.as_ref()
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let conn = self
            .endpoint
            .connect(peer, alpn)
            .await
            .with_context(|| format!("connect to {peer}"))?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Send a packet, buffering + reconnecting when the peer is suspended (on-demand).
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
                guard.state = PeerConnState::Suspended;
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
            if guard.state == PeerConnState::Reconnecting || guard.dial_waiters.is_some() {
                return Ok(());
            }
            guard.state = PeerConnState::Reconnecting;
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
                state: PeerConnState::Suspended.as_str().into(),
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
                    PeerConnState::Suspended.as_str().into()
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
pub async fn send_datagram(conn: &Connection, packet: Bytes) -> anyhow::Result<()> {
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

    async fn bind_endpoint() -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .expect("bind test endpoint")
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
}
