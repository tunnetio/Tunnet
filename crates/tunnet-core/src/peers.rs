//! Established-peer state (§0.5, §2.2-1).
//!
//! Transport identity and network membership are SEPARATE objects because
//! one endpoint may belong to many networks (Direct mode):
//!
//! ```text
//! PeerTransportState (key: EndpointId)
//!   live QUIC connection, MPS/RTT/path state, transport counters,
//!   frame-ID counter (unique across the endpoint's memberships)
//!
//! PeerMembershipState (key: (EndpointId, NetworkId))
//!   network_id, mesh IP, hostname/tags, network firewall slot,
//!   per-membership scheduler + reassembly, pump task + epoch
//! ```
//!
//! There is no mutable network identity inside endpoint-global transport
//! state, and no endpoint-global scheduler shared across networks. Routing
//! hands out `Arc<PeerMembershipState>` clones embedded in peer handles;
//! inbound readers resolve (endpoint, frame network) per connection and
//! switch membership when the frame network changes.
//!
//! The registries (transport + membership DashMaps) are touched only on
//! slow paths: creation, reconnect, teardown, policy relink, heartbeats.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::policy_runtime::{FwSlot, PolicyRuntime};
use crate::reassembly::ReassemblyTable;
use crate::scheduler::PeerScheduler;

/// Per-network peer identity: who this endpoint IS in one network.
/// The same endpoint has one of these per network it belongs to — never a
/// single mutable network context shared across networks.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub endpoint: EndpointId,
    pub endpoint_hex: String,
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network_id: Uuid,
    pub network_name: String,
}

/// Default DRR quantum: one logical MTU-ish chunk (retuned with MPS).
pub const DEFAULT_QUANTUM: usize = 1536;
/// Default effective DATAGRAM payload before the first measurement.
pub const DEFAULT_MPS: usize = 1280;

/// Endpoint-global transport state: the live QUIC connection and path
/// measurements shared by all of the endpoint's network memberships.
/// Carries NO network identity, NO firewall state, NO scheduler.
pub struct PeerTransportState {
    pub endpoint: EndpointId,
    pub conn: ArcSwapOption<Connection>,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub last_activity_ms: AtomicU64,
    pub relay: AtomicBool,
    /// Effective DATAGRAM payload size (frame bytes), adapted to path MTU.
    pub mps: AtomicUsize,
    /// Cached RTT millis for adaptive backoff (updated by path watcher).
    pub rtt_ms: AtomicU64,
    /// Frame-ID counter shared across memberships (unique per endpoint).
    pub next_frame_id: AtomicU32,
    /// Sends since the last MPS refresh (periodic re-measurement).
    pub sends_since_mps_check: AtomicU64,
}

impl PeerTransportState {
    fn new(endpoint: EndpointId) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            conn: ArcSwapOption::empty(),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(now_millis()),
            relay: AtomicBool::new(false),
            mps: AtomicUsize::new(DEFAULT_MPS),
            rtt_ms: AtomicU64::new(90),
            next_frame_id: AtomicU32::new(rand::random()),
            sends_since_mps_check: AtomicU64::new(0),
        })
    }

    /// Non-blocking DATAGRAM submit with Model A ownership (§0.6): submit
    /// only when the reported free space fits the ENTIRE frame, so QUIC never
    /// silently displaces an older buffered datagram behind our back.
    ///
    /// The frame is returned on EVERY error path (§2.1-8) — including a
    /// failed `send_datagram` after the prechecks passed (via a cheap
    /// refcount clone handed to QUIC) — so the pump can requeue or resume
    /// losslessly. A stall never consumes bytes.
    pub fn try_send_frame(&self, frame: bytes::Bytes) -> Result<(), (FastSendError, bytes::Bytes)> {
        let frame_len = frame.len();
        let Some(conn) = self.conn.load_full() else {
            return Err((FastSendError::NoConnection, frame));
        };
        if conn.close_reason().is_some() {
            self.conn.store(None);
            return Err((FastSendError::NoConnection, frame));
        }
        if let Some(max) = conn.max_datagram_size()
            && frame_len > max
        {
            return Err((FastSendError::TooLarge, frame));
        }
        if conn.datagram_send_buffer_space() < frame_len {
            return Err((FastSendError::TransportFull, frame));
        }
        // Clone before handing to QUIC: `send_datagram` consumes its
        // argument without returning it on error, so without this clone a
        // late failure would silently eat the frame and break the
        // ownership/requeue invariant. `Bytes::clone` is a refcount bump.
        match conn.send_datagram(frame.clone()) {
            Ok(()) => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(frame_len as u64, Ordering::Relaxed);
                self.touch();
                Ok(())
            }
            Err(_) => Err((FastSendError::Closed, frame)),
        }
    }

    /// Refresh the cached MPS from the live connection (slow-ish: locks the
    /// QUIC connection state; called periodically, not per packet).
    pub fn refresh_mps(&self) -> Option<usize> {
        let conn = self.conn.load_full()?;
        let mps = conn.max_datagram_size()?;
        self.mps.store(mps, Ordering::Relaxed);
        // Sample RTT from the selected path for adaptive backoff.
        if let Some(rtt) = conn
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .map(|p| p.stats().rtt)
        {
            self.rtt_ms.store(
                rtt.as_millis().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
        }
        Some(mps)
    }

    pub fn live_conn(&self) -> Option<Connection> {
        let conn = self.conn.load_full()?;
        if conn.close_reason().is_some() {
            return None;
        }
        Some(conn.as_ref().clone())
    }

    pub fn touch(&self) {
        let now = now_millis();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        if now.wrapping_sub(last) >= 1000 {
            self.last_activity_ms.store(now, Ordering::Relaxed);
        }
    }

    pub fn record_rx(&self, n: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }
}

/// Per-(endpoint, network) membership state: everything the established
/// packet path needs for ONE network, so after routing there are no map
/// lookups, no async mutexes, and no string conversions.
pub struct PeerMembershipState {
    /// Shared endpoint transport (connection, MPS, counters).
    pub transport: Arc<PeerTransportState>,
    pub identity: RwLock<Arc<PeerIdentity>>,
    /// Stable network firewall slot (§2.1-3): assigned once per network
    /// (re)resolution, swapped in place by firewall publication. The hot
    /// path loads set + counters with two atomic loads — no map lookup,
    /// no relink.
    pub policy: ArcSwap<FwSlot>,
    pub scheduler: Mutex<PeerScheduler>,
    pub reassembly: Mutex<ReassemblyTable>,
    pub notify: Notify,
    pub pump_running: AtomicBool,
    /// Membership epoch: bumped when THIS membership is revoked. Its pump
    /// drains and exits; readers holding this Arc observe the change. Other
    /// memberships of the same endpoint are unaffected.
    pub epoch: AtomicU64,
}

impl PeerMembershipState {
    pub fn new(
        transport: Arc<PeerTransportState>,
        identity: Arc<PeerIdentity>,
        reassembly_budget: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport,
            identity: RwLock::new(identity),
            policy: ArcSwap::from_pointee(FwSlot::default()),
            scheduler: Mutex::new(PeerScheduler::new(DEFAULT_QUANTUM)),
            reassembly: Mutex::new(ReassemblyTable::new(reassembly_budget)),
            notify: Notify::new(),
            pump_running: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
        })
    }

    /// Hard-deactivate THIS membership (§2.1-9, §2.2-1): epoch bump (its
    /// pump drains and exits; readers holding this Arc observe it) plus a
    /// pump wakeup for prompt exit. Never touches the shared transport
    /// connection — sibling memberships keep working. Idempotent.
    pub fn deactivate(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_one();
    }

    /// Refresh path measurements from the shared transport and retune this
    /// membership's DRR quantum to the effective payload.
    pub fn refresh_mps(&self) -> Option<usize> {
        let mps = self.transport.refresh_mps()?;
        // Scale the DRR quantum with the effective payload: one logical
        // MTU-ish chunk keeps DRR fair as paths change.
        self.scheduler.lock().set_quantum(mps.max(512));
        Some(mps)
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastSendError {
    /// No live connection: caller must take the slow reconnect path.
    NoConnection,
    /// QUIC DATAGRAM buffer full: scheduler owns the drop/retry decision.
    TransportFull,
    TooLarge,
    Closed,
}

impl std::fmt::Display for FastSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConnection => write!(f, "no live connection"),
            Self::TransportFull => write!(f, "transport buffer full"),
            Self::TooLarge => write!(f, "datagram_too_large"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for FastSendError {}

/// Slow-path-only registries. Packet paths never touch these maps: routing
/// embeds `Arc<PeerMembershipState>` in peer handles and inbound readers
/// cache one `Arc` per (endpoint, network).
#[derive(Clone, Default)]
pub struct PeerRegistry {
    transports: Arc<DashMap<EndpointId, Arc<PeerTransportState>>>,
    memberships: Arc<DashMap<(EndpointId, Uuid), Arc<PeerMembershipState>>>,
    reassembly_budget: Arc<AtomicU64>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            transports: Arc::new(DashMap::new()),
            memberships: Arc::new(DashMap::new()),
            reassembly_budget: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared reassembly byte counter (global cap denominator).
    pub fn reassembly_budget(&self) -> &Arc<AtomicU64> {
        &self.reassembly_budget
    }

    /// Get-or-create the endpoint transport (slow path).
    pub fn ensure_transport(&self, endpoint: EndpointId) -> Arc<PeerTransportState> {
        self.transports
            .entry(endpoint)
            .or_insert_with(|| PeerTransportState::new(endpoint))
            .clone()
    }

    /// Get-or-create the (endpoint, network) membership (slow path:
    /// routing rebuild, adopt, dial). The transport is shared across the
    /// endpoint's memberships; identity refreshes in place. Refreshing with
    /// a DIFFERENT network id is a caller bug — memberships are keyed by
    /// network, so assert instead of silently mutating (no last-writer-wins).
    pub fn ensure_membership(&self, identity: Arc<PeerIdentity>) -> Arc<PeerMembershipState> {
        let key = (identity.endpoint, identity.network_id);
        if let Some(existing) = self.memberships.get(&key) {
            let current = existing.identity.read().clone();
            debug_assert_eq!(
                current.network_id, identity.network_id,
                "membership key/network mismatch"
            );
            // Refresh mutable context in place; the object stays stable.
            *existing.identity.write() = identity;
            return existing.value().clone();
        }
        let transport = self.ensure_transport(identity.endpoint);
        let state =
            PeerMembershipState::new(transport, identity.clone(), self.reassembly_budget.clone());
        self.memberships.entry(key).or_insert(state).clone()
    }

    /// Backwards-compatible single-network ensure (tests, legacy callers):
    /// exactly `ensure_membership`.
    pub fn ensure(&self, identity: Arc<PeerIdentity>) -> Arc<PeerMembershipState> {
        self.ensure_membership(identity)
    }

    pub fn get_transport(&self, peer: EndpointId) -> Option<Arc<PeerTransportState>> {
        self.transports.get(&peer).map(|e| e.value().clone())
    }

    /// True when the endpoint holds any network membership (reader-exit
    /// check: a connection with zero memberships left is dead).
    pub fn has_any_membership(&self, peer: EndpointId) -> bool {
        self.memberships.iter().any(|e| e.key().0 == peer)
    }

    pub fn get_membership(
        &self,
        peer: EndpointId,
        network: Uuid,
    ) -> Option<Arc<PeerMembershipState>> {
        self.memberships
            .get(&(peer, network))
            .map(|e| e.value().clone())
    }

    /// Backwards-compatible get (legacy callers that only know the
    /// endpoint): returns a membership only when the endpoint has EXACTLY
    /// ONE — ambiguous endpoints must resolve with a network. Never guesses.
    pub fn get(&self, peer: EndpointId) -> Option<Arc<PeerMembershipState>> {
        let mut found = None;
        for entry in self.memberships.iter() {
            if entry.key().0 == peer {
                if found.is_some() {
                    return None;
                }
                found = Some(entry.value().clone());
            }
        }
        found
    }

    /// Mirror a live connection into the endpoint transport (slow paths
    /// only). `Some` stores + re-measures + resets frame pacing + retunes
    /// member schedulers; `None` clears the connection and deactivates all
    /// of the endpoint's memberships (teardown without replacement).
    pub fn set_transport_conn(&self, peer: EndpointId, conn: Option<Connection>) {
        let transport = self.ensure_transport(peer);
        match conn {
            Some(c) => {
                transport.conn.store(Some(Arc::new(c.clone())));
                // Fresh connection: reset pacing state to measured values.
                transport
                    .next_frame_id
                    .store(rand::random(), Ordering::Relaxed);
                transport.sends_since_mps_check.store(0, Ordering::Relaxed);
                drop(transport);
                self.refresh_transport_path(peer, None);
            }
            None => {
                transport.conn.store(None);
                drop(transport);
                for entry in self.memberships.iter() {
                    if entry.key().0 == peer {
                        entry.value().deactivate();
                    }
                }
            }
        }
    }

    /// Path-event refresh (slow path): re-measure transport MPS/RTT,
    /// optionally update the relay flag, and retune member schedulers.
    pub fn refresh_transport_path(&self, peer: EndpointId, metered: Option<bool>) {
        let Some(t) = self.transports.get(&peer).map(|e| e.value().clone()) else {
            return;
        };
        if let Some(m) = metered {
            t.relay.store(m, Ordering::Relaxed);
        }
        if let Some(mps) = t.refresh_mps() {
            for entry in self.memberships.iter() {
                if entry.key().0 == peer {
                    entry.value().scheduler.lock().set_quantum(mps.max(512));
                }
            }
        }
    }

    /// Legacy single-peer set_conn (pool slow path): delegates to
    /// `set_transport_conn`.
    pub fn set_conn(&self, peer: EndpointId, conn: Option<Connection>) {
        self.set_transport_conn(peer, conn);
    }

    /// Remove ONE membership (network revoked, endpoint stays for others):
    /// deactivate it, forget it. The shared transport connection is
    /// untouched — sibling memberships keep working.
    pub fn remove_membership(&self, peer: EndpointId, network: Uuid) {
        if let Some((_, state)) = self.memberships.remove(&(peer, network)) {
            // Hard revoke (§2.2-1): readers holding the Arc observe the
            // epoch bump and exit; its pump drains and stops.
            state.deactivate();
        }
        self.prune_empty_transport(peer);
    }

    /// Remove the endpoint entirely (all memberships + transport):
    /// deactivate every membership, close the live tunnel connection,
    /// forget everything.
    pub fn remove_transport(&self, peer: EndpointId) {
        let mut members = Vec::new();
        self.memberships.retain(|k, v| {
            if k.0 == peer {
                members.push(v.clone());
                false
            } else {
                true
            }
        });
        for m in members {
            m.deactivate();
        }
        if let Some((_, t)) = self.transports.remove(&peer)
            && let Some(conn) = t.conn.swap(None)
        {
            conn.close(0u32.into(), b"membership_removed");
        }
    }

    /// Legacy remove: full endpoint removal.
    pub fn remove(&self, peer: EndpointId) {
        self.remove_transport(peer);
    }

    /// Retain only live (endpoint, network) memberships (slow path: routing
    /// rebuild prunes departed memberships). Removed memberships are
    /// hard-deactivated first, so no stale Arc keeps forwarding through
    /// dead identity/policy state. Transports left with no memberships are
    /// closed and forgotten.
    pub fn retain(&self, live: &std::collections::HashSet<(EndpointId, Uuid)>) {
        let mut departed = Vec::new();
        self.memberships.retain(|k, v| {
            let keep = live.contains(k);
            if !keep {
                departed.push(v.clone());
            }
            keep
        });
        for state in departed {
            state.deactivate();
        }
        let live_eps: std::collections::HashSet<EndpointId> =
            live.iter().map(|(ep, _)| *ep).collect();
        let mut closed = Vec::new();
        self.transports.retain(|ep, t| {
            let keep = live_eps.contains(ep);
            if !keep {
                closed.push(t.clone());
            }
            keep
        });
        for t in closed {
            if let Some(conn) = t.conn.swap(None) {
                conn.close(0u32.into(), b"membership_removed");
            }
        }
    }

    /// Legacy retain by endpoint set (pool-era callers): keeps every
    /// membership of a live endpoint. Prefer the (endpoint, network) form.
    pub fn retain_endpoints(&self, live: &std::collections::HashSet<EndpointId>) {
        let mut departed = Vec::new();
        self.memberships.retain(|k, v| {
            let keep = live.contains(&k.0);
            if !keep {
                departed.push(v.clone());
            }
            keep
        });
        for state in departed {
            state.deactivate();
        }
        let mut closed = Vec::new();
        self.transports.retain(|ep, t| {
            let keep = live.contains(ep);
            if !keep {
                closed.push(t.clone());
            }
            keep
        });
        for t in closed {
            if let Some(conn) = t.conn.swap(None) {
                conn.close(0u32.into(), b"membership_removed");
            }
        }
    }

    /// Drop a transport left with no memberships (after single-membership
    /// removal): close its connection so no orphan conn lingers.
    fn prune_empty_transport(&self, peer: EndpointId) {
        if self.memberships.iter().any(|e| e.key().0 == peer) {
            return;
        }
        if let Some((_, t)) = self.transports.remove(&peer)
            && let Some(conn) = t.conn.swap(None)
        {
            conn.close(0u32.into(), b"membership_removed");
        }
    }

    pub fn clear(&self) {
        let all: Vec<_> = self.memberships.iter().map(|e| e.value().clone()).collect();
        self.memberships.clear();
        for state in all {
            state.deactivate();
        }
        let conns: Vec<_> = self.transports.iter().map(|e| e.value().clone()).collect();
        self.transports.clear();
        for t in conns {
            if let Some(conn) = t.conn.swap(None) {
                conn.close(0u32.into(), b"membership_removed");
            }
        }
    }

    /// Install-time policy slot assignment (slow/control path): every
    /// membership points at its network's stable slot. Firewall publication
    /// NEVER needs this — slots swap in place (§2.1-3).
    pub fn relink_policy(&self, runtime: &PolicyRuntime) {
        for entry in self.memberships.iter() {
            let state = entry.value();
            let network = state.identity.read().network_id;
            state.policy.store(runtime.slot_for_network(network));
        }
    }

    /// Heartbeat aggregates (slow path only).
    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let mut conns = 0u32;
        let mut tx = 0u64;
        let mut rx = 0u64;
        for entry in self.transports.iter() {
            let s = entry.value();
            if s.live_conn().is_some() {
                conns += 1;
            }
            tx += s.tx_bytes.load(Ordering::Relaxed);
            rx += s.rx_bytes.load(Ordering::Relaxed);
        }
        (conns, tx, rx)
    }

    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        match self.transports.get(&peer) {
            Some(s) => (
                s.rx_bytes.load(Ordering::Relaxed),
                s.tx_bytes.load(Ordering::Relaxed),
            ),
            None => (0, 0),
        }
    }

    /// Adaptive transport-full backoff (§0.7): RTT/4 clamped to
    /// [100µs, max]. The ceiling defaults to 2 ms and can be raised for
    /// A/B runs via `TUNNET_PUMP_BACKOFF_MAX_US` (diagnostic only). No
    /// fixed 5 ms stall, no spin, no send_datagram_wait. New enqueues
    /// notify immediately, so this timeout is only the no-new-work
    /// fallback. (A public `datagrams_unblocked` waiter in Iroh/noq would
    /// be the cleaner upstream primitive; investigated, not available —
    /// the internal Notify stays private.)
    pub fn backoff_for(transport: &PeerTransportState) -> Duration {
        static MAX_MICROS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        let max = *MAX_MICROS.get_or_init(|| {
            std::env::var("TUNNET_PUMP_BACKOFF_MAX_US")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v >= 100)
                .unwrap_or(2000)
        });
        let rtt_ms = transport.rtt_ms.load(Ordering::Relaxed);
        let micros = rtt_ms.saturating_mul(250).clamp(100, max);
        Duration::from_micros(micros)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn test_endpoint() -> EndpointId {
        SecretKey::generate().public()
    }

    fn identity(endpoint: EndpointId) -> Arc<PeerIdentity> {
        identity_in(endpoint, Uuid::nil(), [10, 0, 0, 2])
    }

    fn identity_in(endpoint: EndpointId, network: Uuid, ip: [u8; 4]) -> Arc<PeerIdentity> {
        Arc::new(PeerIdentity {
            endpoint,
            endpoint_hex: format!("{endpoint}"),
            hostname: "peer".into(),
            ip: std::net::Ipv4Addr::from(ip),
            tags: vec![],
            network_id: network,
            network_name: "net".into(),
        })
    }

    const NET_A: Uuid = Uuid::from_u128(0x0a0a);
    const NET_B: Uuid = Uuid::from_u128(0x0b0b);

    #[test]
    fn registry_reuses_stable_state() {
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let a = reg.ensure(identity(ep));
        let b = reg.ensure(identity(ep));
        assert!(Arc::ptr_eq(&a, &b), "same stable object");
        // Identity refresh keeps the object.
        let mut id = identity(ep);
        let idm = Arc::get_mut(&mut id).unwrap();
        idm.hostname = "renamed".into();
        let c = reg.ensure(id);
        assert!(Arc::ptr_eq(&a, &c));
        assert_eq!(c.identity.read().hostname, "renamed");
    }

    #[test]
    fn try_send_without_conn_returns_frame() {
        // §2.1-8: every error path returns the frame for lossless requeue.
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let s = reg.ensure(identity(ep));
        let frame = bytes::Bytes::from_static(b"frame-bytes");
        let (err, back) = s.transport.try_send_frame(frame.clone()).unwrap_err();
        assert_eq!(err, FastSendError::NoConnection);
        assert_eq!(back, frame, "frame must come back byte-identical");
    }

    #[test]
    fn removal_deactivates_fast_state() {
        // §2.1-9: removing a peer hard-revokes its fast state — epoch
        // bumped (pumps/readers holding the Arc observe it and exit),
        // connection cleared. A subsequent resolve finds nothing.
        use std::collections::HashSet;
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let s = reg.ensure(identity(ep));
        let epoch0 = s.epoch.load(Ordering::Relaxed);
        // Simulate a live peer: epoch + scheduler contents (pump-owned).
        s.epoch.fetch_add(0, Ordering::Relaxed);
        assert!(reg.get(ep).is_some());
        reg.remove(ep);
        assert!(reg.get(ep).is_none(), "removed peer must not resolve");
        assert!(reg.get_transport(ep).is_none(), "transport forgotten too");
        assert_eq!(
            s.epoch.load(Ordering::Relaxed),
            epoch0 + 1,
            "reader/pump exit signal"
        );
        assert!(s.transport.conn.load_full().is_none());
        // Retain with an empty live set deactivates too.
        let ep2 = test_endpoint();
        let s2 = reg.ensure(identity(ep2));
        let epoch2 = s2.epoch.load(Ordering::Relaxed);
        reg.retain(&HashSet::new());
        assert!(reg.get(ep2).is_none());
        assert_eq!(s2.epoch.load(Ordering::Relaxed), epoch2 + 1);
    }

    #[test]
    fn same_endpoint_two_networks_isolated() {
        // §2.2-1 (tests 1, 2, 10): one EndpointId in networks A and B gets
        // two independent membership states sharing one transport. Ensuring
        // B never mutates A's identity (no last-writer-wins), in either
        // insertion order (reverse order covered by the next test).
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let id_a = identity_in(ep, NET_A, [10, 0, 0, 2]);
        let id_b = identity_in(ep, NET_B, [10, 0, 1, 2]);
        let a = reg.ensure_membership(id_a);
        let b = reg.ensure_membership(id_b);
        assert!(!Arc::ptr_eq(&a, &b), "distinct membership objects");
        // Shared transport, distinct memberships.
        assert!(Arc::ptr_eq(&a.transport, &b.transport));
        assert_eq!(a.identity.read().network_id, NET_A);
        assert_eq!(b.identity.read().network_id, NET_B);
        assert_eq!(a.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(b.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 1, 2));
        // Exact resolution per (endpoint, network).
        assert!(
            reg.get_membership(ep, NET_A)
                .is_some_and(|m| Arc::ptr_eq(&m, &a))
        );
        assert!(
            reg.get_membership(ep, NET_B)
                .is_some_and(|m| Arc::ptr_eq(&m, &b))
        );
        // Bare endpoint resolve refuses to guess across networks.
        assert!(reg.get(ep).is_none(), "ambiguous endpoint must not resolve");
    }

    #[test]
    fn same_endpoint_two_networks_reverse_order() {
        // Insert B before A: A must still resolve exactly, with its own IP.
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let b = reg.ensure_membership(identity_in(ep, NET_B, [10, 0, 1, 2]));
        let a = reg.ensure_membership(identity_in(ep, NET_A, [10, 0, 0, 2]));
        assert_eq!(a.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(b.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 1, 2));
        assert!(
            reg.get_membership(ep, NET_A)
                .is_some_and(|m| Arc::ptr_eq(&m, &a))
        );
    }

    #[test]
    fn removing_one_membership_leaves_sibling() {
        // §2.2-1 (tests 8, 9): revoking A deactivates only A; B keeps its
        // epoch, transport, and resolvability.
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let a = reg.ensure_membership(identity_in(ep, NET_A, [10, 0, 0, 2]));
        let b = reg.ensure_membership(identity_in(ep, NET_B, [10, 0, 1, 2]));
        let epoch_b = b.epoch.load(Ordering::Relaxed);
        reg.remove_membership(ep, NET_A);
        assert!(reg.get_membership(ep, NET_A).is_none());
        assert_eq!(a.epoch.load(Ordering::Relaxed), 1);
        // Sibling untouched: same epoch, still resolvable, transport alive.
        assert_eq!(b.epoch.load(Ordering::Relaxed), epoch_b);
        assert!(
            reg.get_membership(ep, NET_B)
                .is_some_and(|m| Arc::ptr_eq(&m, &b))
        );
        assert!(reg.get_transport(ep).is_some());
        // Endpoint-wide get() now unambiguous again.
        assert!(reg.get(ep).is_some_and(|m| Arc::ptr_eq(&m, &b)));
    }

    #[test]
    fn backoff_bounds() {
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let s = reg.ensure(identity(ep));
        s.transport.rtt_ms.store(0, Ordering::Relaxed);
        assert_eq!(
            PeerRegistry::backoff_for(&s.transport),
            Duration::from_micros(100)
        );
        s.transport.rtt_ms.store(10_000, Ordering::Relaxed);
        assert_eq!(
            PeerRegistry::backoff_for(&s.transport),
            Duration::from_micros(2000)
        );
        s.transport.rtt_ms.store(90, Ordering::Relaxed);
        // 90 ms → 22.5 ms raw, clamped to the 2 ms ceiling.
        assert_eq!(
            PeerRegistry::backoff_for(&s.transport),
            Duration::from_micros(2000)
        );
        s.transport.rtt_ms.store(4, Ordering::Relaxed);
        // 4 ms → 1 ms raw, inside the band.
        assert_eq!(
            PeerRegistry::backoff_for(&s.transport),
            Duration::from_micros(1000)
        );
    }
}
