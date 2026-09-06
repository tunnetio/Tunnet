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
    /// True if the live connection was opened by our dial (not accepted).
    opened_by_us: bool,
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
            opened_by_us: false,
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

fn normalize_relay_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
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
    /// Established fast states (owned by routing; slow paths only: adopt,
    /// dial, close, drop, heartbeats). The established packet path never
    /// touches this — it uses the `Arc<PeerMembershipState>` from routing.
    peer_registry: Arc<Mutex<Option<Arc<crate::peers::PeerRegistry>>>>,
    extra: Arc<ExtraConnMap>,
    policy: Arc<PoolPolicy>,
    metrics: Arc<PoolMetrics>,
    tunnel_hook: Arc<Mutex<Option<TunnelConnHook>>>,
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
            tunnel_hook: Arc::new(Mutex::new(None)),
            cloud_relay_meter: CloudRelayMeter::new(),
            cloud_relay_urls: Arc::new(RwLock::new(HashSet::new())),
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
            peer_registry: other.peer_registry.clone(),
            extra: Arc::new(DashMap::new()),
            policy: other.policy.clone(),
            metrics: other.metrics.clone(),
            tunnel_hook: Arc::new(Mutex::new(None)),
            cloud_relay_meter: other.cloud_relay_meter.clone(),
            cloud_relay_urls: other.cloud_relay_urls.clone(),
        }
    }

    /// Register a hook invoked whenever this pool dials a tunnel connection.
    /// Dialed connections are read ONLY by this hook (single ownership);
    /// accepted connections are read ONLY by the accept path (`adopt`
    /// never fires the hook).
    pub fn set_tunnel_hook(&self, hook: TunnelConnHook) {
        *self.tunnel_hook.lock() = Some(hook);
    }

    /// Attach the shared established-peer registry (slow-path mirror for
    /// adopt/dial/close/drop; the packet path never touches it).
    pub fn set_peer_registry(&self, registry: Arc<crate::peers::PeerRegistry>) {
        *self.peer_registry.lock() = Some(registry);
    }

    /// Mirror a live connection into its endpoint transport (slow paths only).
    fn sync_fast_conn(&self, peer: EndpointId, conn: Option<Connection>) {
        if let Some(reg) = self.peer_registry.lock().clone() {
            reg.set_transport_conn(peer, conn);
        }
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.cloud_relay_meter.clone()
    }

    /// Replace the set of billable Tunnet Cloud deployment relay URLs.
    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        let normalized: HashSet<String> =
            urls.into_iter().map(|u| normalize_relay_url(&u)).collect();
        *self.cloud_relay_urls.write() = normalized;
    }

    fn spawn_cloud_relay_path_watch(&self, peer: EndpointId, conn: Connection) {
        let urls = self.cloud_relay_urls.clone();
        let registry = self.peer_registry.lock().clone();
        tokio::spawn(async move {
            let refresh = |conn: &Connection| {
                let metered = selected_path_is_cloud_relay(conn, &urls.read());
                if let Some(reg) = &registry {
                    reg.refresh_transport_path(peer, Some(metered));
                }
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
    ///
    /// Ownership rule: whoever calls `adopt` owns reading this connection
    /// (accept path) or takes over an existing reader explicitly. `adopt`
    /// deliberately does NOT fire the dialer tunnel hook — that hook belongs
    /// to connections this pool dialed itself (`get`), so each connection
    /// has exactly one reader and datagrams are never split across two
    /// tasks (the loser would silently eat packets before being aborted).
    pub async fn adopt(&self, peer: EndpointId, conn: Connection) -> bool {
        let local = self.endpoint.id();
        let slot = self.slot(peer);
        let mut guard = slot.lock().await;
        if let Some(existing) = guard.live_conn() {
            if existing.stable_id() == conn.stable_id() {
                guard.touch();
                drop(guard);
                self.sync_fast_conn(peer, Some(conn));
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
        self.sync_fast_conn(peer, Some(conn));
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
            g.state = PeerConnState::Suspended;
            g.drop_buf();
            tracing::debug!(%peer, "closed tunnel pool connection");
            self.sync_fast_conn(peer, None);
        }
        for entry in self.extra.iter() {
            let mut g = entry.value().lock().await;
            if let Some(c) = g.take() {
                c.close(0u32.into(), b"dataplane_down");
            }
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
                            // Tie-break loss: keep the existing connection
                            // (already owned+read by whoever installed it)
                            // and close ours. Do NOT fire the hook: firing
                            // would spawn a second reader on a connection
                            // that already has one, splitting datagrams.
                            let existing = existing.clone();
                            if let Some(tx) = guard.dial_waiters.take() {
                                let _ = tx.send(Ok(existing.clone()));
                            }
                            let buffered = guard.take_buf();
                            drop(guard);
                            conn.close(0u32.into(), b"tie_break");
                            (existing, buffered, false)
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
                        tracing::debug!(%peer, ?e, "flush buffered datagram dropped");
                    }
                }
                self.sync_fast_conn(peer, Some(canonical.clone()));
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
    ///
    /// Slow path only: connection setup, reconnect buffering, tie-breaking.
    /// Established forwarding goes through `PeerMembershipState::try_send_frame`.
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

    /// Hard-drop a peer (§2.1-9, §2.2-1): close the live tunnel connection,
    /// deactivate ALL of its memberships (epoch bumps close readers/pumps
    /// holding Arcs), and forget the slot. Idempotent.
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
    /// Byte totals come from the shared fast-state registry (slow path only).
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

/// Non-blocking DATAGRAM error. The scheduler owns drop/retry decisions;
/// the transport is never awaited while holding a stale packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySendError {
    Full,
    TooLarge,
    Closed,
}

impl std::fmt::Display for TrySendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "transport buffer full"),
            Self::TooLarge => write!(f, "datagram_too_large"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for TrySendError {}

/// Non-blocking DATAGRAM submit with Model A ownership (§0.6): never awaits
/// transport capacity, and never submits unless the reported free space fits
/// the ENTIRE frame.
///
/// Iroh guarantees no older buffered datagram is displaced only when the new
/// datagram is `<= datagram_send_buffer_space()`; plain `send_datagram`
/// otherwise discards oldest-first to make room. Tunnet therefore treats
/// insufficient space as [`TrySendError::Full`] and lets its flow-aware
/// scheduler own the drop/retry decision (QUIC has no flow information).
pub fn try_send_datagram(conn: &Connection, packet: Bytes) -> Result<(), TrySendError> {
    if conn.close_reason().is_some() {
        return Err(TrySendError::Closed);
    }
    if let Some(max) = conn.max_datagram_size()
        && packet.len() > max
    {
        return Err(TrySendError::TooLarge);
    }
    if conn.datagram_send_buffer_space() < packet.len() {
        return Err(TrySendError::Full);
    }
    conn.send_datagram(packet).map_err(|_| TrySendError::Closed)
}

/// Send a datagram without ever awaiting transport capacity.
///
/// Replaces the old `send_datagram_wait` semantics: when the QUIC DATAGRAM
/// buffer is full the packet is dropped (caller records `transport_full`)
/// instead of converting one stale packet into an arbitrarily long awaited
/// future that blocks the whole peer scheduler.
pub async fn send_datagram(conn: &Connection, packet: Bytes) -> anyhow::Result<()> {
    try_send_datagram(conn, packet).map_err(|e| anyhow::anyhow!("{e}"))
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
}
