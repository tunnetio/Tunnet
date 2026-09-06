//! Network-scoped membership, revocation, and endpoint traffic observations. No connection ownership.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use iroh::EndpointId;
use parking_lot::RwLock;
use uuid::Uuid;

use crate::policy_runtime::{FwSlot, PolicyRuntime};
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
pub struct PeerTransportState {
    pub endpoint: EndpointId,
    pub connected: AtomicBool,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub last_activity_ms: AtomicU64,
    pub relay: AtomicBool,
}

impl PeerTransportState {
    fn new(endpoint: EndpointId) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            connected: AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(now_millis()),
            relay: AtomicBool::new(false),
        })
    }

    pub fn touch(&self) {
        let now = now_millis();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        if now.wrapping_sub(last) >= 1000 {
            self.last_activity_ms.store(now, Ordering::Relaxed);
        }
    }

    pub fn record_tx(&self, n: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }
    pub fn record_rx(&self, n: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }
}
pub struct PeerMembershipState {
    pub transport: Arc<PeerTransportState>,
    pub identity: RwLock<Arc<PeerIdentity>>,
    pub policy: ArcSwap<FwSlot>,
    pub epoch: AtomicU64,
}

impl PeerMembershipState {
    pub fn new(transport: Arc<PeerTransportState>, identity: Arc<PeerIdentity>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            identity: RwLock::new(identity),
            policy: ArcSwap::from_pointee(FwSlot::default()),
            epoch: AtomicU64::new(0),
        })
    }
    pub fn deactivate(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
#[derive(Clone, Default)]
pub struct PeerRegistry {
    transports: Arc<DashMap<EndpointId, Arc<PeerTransportState>>>,
    memberships: Arc<DashMap<(EndpointId, Uuid), Arc<PeerMembershipState>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            transports: Arc::new(DashMap::new()),
            memberships: Arc::new(DashMap::new()),
        }
    }
    pub fn ensure_transport(&self, endpoint: EndpointId) -> Arc<PeerTransportState> {
        self.transports
            .entry(endpoint)
            .or_insert_with(|| PeerTransportState::new(endpoint))
            .clone()
    }
    pub fn ensure_membership(&self, identity: Arc<PeerIdentity>) -> Arc<PeerMembershipState> {
        let key = (identity.endpoint, identity.network_id);
        if let Some(existing) = self.memberships.get(&key) {
            let current = existing.identity.read().clone();
            debug_assert_eq!(
                current.network_id, identity.network_id,
                "membership key/network mismatch"
            );
            *existing.identity.write() = identity;
            return existing.value().clone();
        }
        let transport = self.ensure_transport(identity.endpoint);
        let state = PeerMembershipState::new(transport, identity.clone());
        self.memberships.entry(key).or_insert(state).clone()
    }

    pub fn get_transport(&self, peer: EndpointId) -> Option<Arc<PeerTransportState>> {
        self.transports.get(&peer).map(|e| e.value().clone())
    }
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
    pub fn remove_membership(&self, peer: EndpointId, network: Uuid) {
        if let Some((_, state)) = self.memberships.remove(&(peer, network)) {
            state.deactivate();
        }
        self.prune_empty_transport(peer);
    }
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
        self.transports.remove(&peer);
    }
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

        self.transports.retain(|ep, _| live_eps.contains(ep));
    }
    fn prune_empty_transport(&self, peer: EndpointId) {
        if self.memberships.iter().any(|e| e.key().0 == peer) {
            return;
        }
        self.transports.remove(&peer);
    }

    pub fn clear(&self) {
        let all: Vec<_> = self.memberships.iter().map(|e| e.value().clone()).collect();
        self.memberships.clear();
        for state in all {
            state.deactivate();
        }
        self.transports.clear();
    }
    pub fn relink_policy(&self, runtime: &PolicyRuntime) {
        for entry in self.memberships.iter() {
            let state = entry.value();
            let network = state.identity.read().network_id;
            state.policy.store(runtime.slot_for_network(network));
        }
    }
    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        let mut conns = 0u32;
        let mut tx = 0u64;
        let mut rx = 0u64;
        for entry in self.transports.iter() {
            let s = entry.value();
            if s.connected.load(Ordering::Relaxed) {
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
        let a = reg.ensure_membership(identity(ep));
        let b = reg.ensure_membership(identity(ep));
        assert!(Arc::ptr_eq(&a, &b), "same stable object");
        let mut id = identity(ep);
        let idm = Arc::get_mut(&mut id).unwrap();
        idm.hostname = "renamed".into();
        let c = reg.ensure_membership(id);
        assert!(Arc::ptr_eq(&a, &c));
        assert_eq!(c.identity.read().hostname, "renamed");
    }

    #[test]
    fn removal_deactivates_fast_state() {
        use std::collections::HashSet;
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let s = reg.ensure_membership(identity(ep));
        let epoch0 = s.epoch.load(Ordering::Relaxed);
        s.epoch.fetch_add(0, Ordering::Relaxed);
        assert!(reg.get_membership(ep, Uuid::nil()).is_some());
        reg.remove_transport(ep);
        assert!(
            reg.get_membership(ep, Uuid::nil()).is_none(),
            "removed peer must not resolve"
        );
        assert!(reg.get_transport(ep).is_none(), "transport forgotten too");
        assert_eq!(
            s.epoch.load(Ordering::Relaxed),
            epoch0 + 1,
            "reader/pump exit signal"
        );
        let ep2 = test_endpoint();
        let s2 = reg.ensure_membership(identity(ep2));
        let epoch2 = s2.epoch.load(Ordering::Relaxed);
        reg.retain(&HashSet::new());
        assert!(reg.get_membership(ep2, Uuid::nil()).is_none());
        assert_eq!(s2.epoch.load(Ordering::Relaxed), epoch2 + 1);
    }

    #[test]
    fn same_endpoint_two_networks_isolated() {
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let id_a = identity_in(ep, NET_A, [10, 0, 0, 2]);
        let id_b = identity_in(ep, NET_B, [10, 0, 1, 2]);
        let a = reg.ensure_membership(id_a);
        let b = reg.ensure_membership(id_b);
        assert!(!Arc::ptr_eq(&a, &b), "distinct membership objects");
        assert!(Arc::ptr_eq(&a.transport, &b.transport));
        assert_eq!(a.identity.read().network_id, NET_A);
        assert_eq!(b.identity.read().network_id, NET_B);
        assert_eq!(a.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(b.identity.read().ip, std::net::Ipv4Addr::new(10, 0, 1, 2));
        assert!(
            reg.get_membership(ep, NET_A)
                .is_some_and(|m| Arc::ptr_eq(&m, &a))
        );
        assert!(
            reg.get_membership(ep, NET_B)
                .is_some_and(|m| Arc::ptr_eq(&m, &b))
        );
        assert!(
            reg.get_membership(ep, Uuid::nil()).is_none(),
            "ambiguous endpoint must not resolve"
        );
    }

    #[test]
    fn same_endpoint_two_networks_reverse_order() {
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
        let reg = PeerRegistry::new();
        let ep = test_endpoint();
        let a = reg.ensure_membership(identity_in(ep, NET_A, [10, 0, 0, 2]));
        let b = reg.ensure_membership(identity_in(ep, NET_B, [10, 0, 1, 2]));
        let epoch_b = b.epoch.load(Ordering::Relaxed);
        reg.remove_membership(ep, NET_A);
        assert!(reg.get_membership(ep, NET_A).is_none());
        assert_eq!(a.epoch.load(Ordering::Relaxed), 1);
        assert_eq!(b.epoch.load(Ordering::Relaxed), epoch_b);
        assert!(
            reg.get_membership(ep, NET_B)
                .is_some_and(|m| Arc::ptr_eq(&m, &b))
        );
        assert!(reg.get_transport(ep).is_some());
    }
}
