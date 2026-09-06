//! Stream connection pool and shared connection preferences. Tunnel connections are owned by the agent.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::cloud_relay_meter::CloudRelayMeter;

pub const DEFAULT_IDLE_SECS: u64 = 120;
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    dial_waiters: Option<DialWaiters>,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            conn: None,
            state: PeerConnState::Suspended,
            last_activity: Instant::now(),
            peer_keep_alive: false,
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
    reconnect_latency_sum_us: AtomicU64,
    reconnect_latency_max_us: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnDemandStats {
    pub reconnect_attempts: u64,
    pub reconnect_success: u64,
    pub reconnect_fail: u64,
    pub reconnect_latency_avg_us: u64,
    pub reconnect_latency_max_us: u64,
}

type ExtraConnMap = DashMap<(EndpointId, Vec<u8>), Arc<AsyncMutex<Option<Connection>>>>;

fn normalize_relay_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

#[derive(Clone)]
pub struct ConnPool {
    endpoint: Endpoint,
    alpn: &'static [u8],
    entries: Arc<DashMap<EndpointId, Arc<AsyncMutex<PeerSlot>>>>,
    peer_registry: Arc<Mutex<Option<Arc<crate::peers::PeerRegistry>>>>,
    extra: Arc<ExtraConnMap>,
    policy: Arc<PoolPolicy>,
    metrics: Arc<PoolMetrics>,
    cloud_relay_meter: CloudRelayMeter,
    cloud_relay_urls: Arc<RwLock<HashSet<String>>>,
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
            peer_registry: Arc::new(Mutex::new(None)),
            extra: Arc::new(DashMap::new()),
            policy: Arc::new(PoolPolicy {
                keep_alive: AtomicBool::new(true),
                idle_timeout: Mutex::new(Duration::from_secs(DEFAULT_IDLE_SECS)),
                keep_alive_hosts: DashMap::new(),
                keep_alive_peers: DashMap::new(),
            }),
            metrics: Arc::new(PoolMetrics::default()),
            cloud_relay_meter: CloudRelayMeter::new(),
            cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
        };
        pool.spawn_idle_sweeper();
        pool
    }
    pub fn set_peer_registry(&self, registry: Arc<crate::peers::PeerRegistry>) {
        *self.peer_registry.lock() = Some(registry);
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.cloud_relay_meter.clone()
    }
    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        let normalized: HashSet<String> =
            urls.into_iter().map(|u| normalize_relay_url(&u)).collect();
        *self.cloud_relay_urls.write() = normalized;
    }

    pub fn peer_keep_alive(&self, peer: EndpointId) -> bool {
        self.policy.keep_alive.load(Ordering::Relaxed)
            || self.policy.keep_alive_peers.contains_key(&peer)
    }
    pub fn idle_timeout(&self) -> Duration {
        *self.policy.idle_timeout.lock()
    }
    pub fn uses_cloud_relay(&self, conn: &Connection) -> bool {
        conn.paths()
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|path| match path.remote_addr() {
                iroh::TransportAddr::Relay(url) => self
                    .cloud_relay_urls
                    .read()
                    .contains(&normalize_relay_url(url.as_str())),
                _ => false,
            })
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
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let guard = slot.lock().await;
                    if let Some(c) = guard.live_conn() {
                        return Ok(c);
                    }
                }
            }
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

                let mut guard = slot.lock().await;
                guard.conn = Some(conn.clone());
                guard.state = PeerConnState::Connected;
                guard.touch();
                if let Some(tx) = guard.dial_waiters.take() {
                    let _ = tx.send(Ok(conn.clone()));
                }
                Ok(conn)
            }
            Err(err) => {
                self.metrics.reconnect_fail.fetch_add(1, Ordering::Relaxed);
                let mut guard = slot.lock().await;
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
        if let Some((_, slot)) = self.entries.remove(&peer) {
            let mut g = slot.lock().await;
            if let Some(c) = g.conn.take() {
                c.close(0u32.into(), b"membership_removed");
            }
        }
        if let Some(reg) = self.peer_registry.lock().clone() {
            reg.remove_transport(peer);
        }
        self.extra.retain(|(p, _), _| *p != peer);
    }
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
    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let active_conns = self
            .entries
            .iter()
            .filter(|e| match e.value().try_lock() {
                Ok(g) => g.live_conn().is_some(),
                Err(_) => true,
            })
            .count() as u32;
        let (extra_conns, bytes_tx, bytes_rx) = self
            .peer_registry
            .lock()
            .clone()
            .map(|r| r.heartbeat_counters())
            .unwrap_or((0, 0, 0));
        (active_conns.max(extra_conns), bytes_tx, bytes_rx)
    }

    pub fn keep_alive_global(&self) -> bool {
        self.policy.keep_alive.load(Ordering::Relaxed)
    }

    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        self.peer_registry
            .lock()
            .clone()
            .map(|r| r.peer_bytes(peer))
            .unwrap_or((0, 0))
    }
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
        assert!(!pool.has_live(peer));
        assert_eq!(
            pool.on_demand_stats().reconnect_fail,
            1,
            "only one dialer should record the failure"
        );
    }
}
