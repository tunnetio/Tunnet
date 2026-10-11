use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use iroh::EndpointId;
use parking_lot::Mutex;
use tunnet_common::policy::{FlowEndpoint, PolicyBundle, SshPolicyRule};
use uuid::Uuid;

use crate::direct::firewall::FirewallRule;
use crate::routing::{PeerInfo, RoutingTable, Tables};

#[derive(Debug, Clone)]
pub struct SelfIdentity {
    pub endpoint_hex: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network: String,
}

#[derive(Debug, Clone)]
pub struct PeerBinding {
    pub endpoint: EndpointId,
    pub endpoint_hex: String,
    pub ip: Ipv4Addr,
    pub hostname: String,
    pub tags: Vec<String>,
    pub network: Uuid,
    pub network_name: String,
}

impl PeerBinding {
    fn from_info(info: &PeerInfo) -> Self {
        Self {
            endpoint: info.endpoint,
            endpoint_hex: info.endpoint_hex.clone(),
            ip: info.ip,
            hostname: info.hostname.clone(),
            tags: info.tags.clone(),
            network: info.network_id,
            network_name: info.network_name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    Managed {
        bundle: PolicyBundle,
    },
    Direct {
        enabled: bool,
        version: u64,
        local: Vec<FirewallRule>,
        suggested: Vec<FirewallRule>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct FirewallRules {
    pub enabled: bool,
    pub version: u64,
    pub local: Vec<FirewallRule>,
    pub suggested: Vec<FirewallRule>,
}

impl FirewallRules {
    pub fn from_config(cfg: &crate::direct::FirewallConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            version: cfg.version,
            local: cfg.rules.clone(),
            suggested: Vec::new(),
        }
    }
}

pub struct ForwardingSnapshot {
    pub generation: u64,
    pub tables: Arc<Tables>,
    pub self_id: SelfIdentity,
    pub bindings: HashMap<(Uuid, EndpointId), PeerBinding>,
    pub networks_of: HashMap<EndpointId, Vec<Uuid>>,
    pub policies: HashMap<Uuid, NetworkPolicy>,
    pub managed: Option<Uuid>,
    pub auth: HashMap<Uuid, u64>,
    pub conflicts: HashSet<Ipv4Addr>,
    pub conflict_cidrs: Vec<Ipv4Net>,
    pub ssh_addrs: HashSet<Ipv4Addr>,
    pub tun_mtu: u16,
    pub stale: Arc<ArcSwap<bool>>,
    pub posture_ok: Arc<ArcSwap<bool>>,
}

impl ForwardingSnapshot {
    fn empty() -> Self {
        Self {
            generation: 0,
            tables: RoutingTable::new().tables(),
            self_id: SelfIdentity {
                endpoint_hex: String::new(),
                ip: Ipv4Addr::UNSPECIFIED,
                tags: Vec::new(),
                network: String::new(),
            },
            bindings: HashMap::new(),
            networks_of: HashMap::new(),
            policies: HashMap::new(),
            managed: None,
            auth: HashMap::new(),
            conflicts: HashSet::new(),
            conflict_cidrs: Vec::new(),
            ssh_addrs: HashSet::new(),
            tun_mtu: 1280,
            stale: Arc::new(ArcSwap::from_pointee(false)),
            posture_ok: Arc::new(ArcSwap::from_pointee(true)),
        }
    }

    pub fn binding(&self, network: Uuid, peer: EndpointId) -> Option<&PeerBinding> {
        self.bindings.get(&(network, peer))
    }

    pub fn route(&self, ip: &Ipv4Addr) -> Option<Arc<PeerInfo>> {
        crate::routing::RoutingTable::route_in(&self.tables, ip)
    }

    pub fn policy_for(&self, network: Uuid) -> Option<&NetworkPolicy> {
        self.policies.get(&network)
    }

    pub fn auth_epoch(&self, network: Uuid) -> u64 {
        self.auth.get(&network).copied().unwrap_or(0)
    }

    pub fn self_endpoint(&self) -> FlowEndpoint {
        FlowEndpoint::member(
            self.self_id.endpoint_hex.clone(),
            self.self_id.tags.clone(),
            self.self_id.network.clone(),
            Some(self.self_id.ip),
        )
    }

    pub fn peer_endpoint(&self, peer: EndpointId) -> FlowEndpoint {
        let network = self.self_id.network.clone();
        match self.networks_of.get(&peer).and_then(|nets| {
            nets.iter()
                .filter_map(|n| self.bindings.get(&(*n, peer)))
                .next()
        }) {
            Some(b) => {
                FlowEndpoint::member(b.endpoint_hex.clone(), b.tags.clone(), network, Some(b.ip))
            }
            None => FlowEndpoint::member(peer.to_string(), Vec::new(), network, None),
        }
    }

    pub fn ssh_rules(&self) -> Vec<SshPolicyRule> {
        match self.managed.and_then(|n| self.policies.get(&n)) {
            Some(NetworkPolicy::Managed { bundle }) => bundle.ssh_rules.clone(),
            _ => Vec::new(),
        }
    }
}

#[derive(Default)]
struct ForwardConfig {
    bundle: Option<(Uuid, PolicyBundle)>,
    firewalls: HashMap<Uuid, FirewallRules>,
    self_id: Option<SelfIdentity>,
    ssh_addrs: HashSet<Ipv4Addr>,
    tun_mtu: u16,
    auth_epochs: HashMap<Uuid, u64>,
    binding_hash: HashMap<Uuid, u64>,
}

#[derive(Clone)]
pub struct ForwardingStore {
    current: Arc<ArcSwap<Arc<ForwardingSnapshot>>>,
    generation: Arc<AtomicU64>,
    cfg: Arc<Mutex<ForwardConfig>>,
    stale: Arc<ArcSwap<bool>>,
    posture_ok: Arc<ArcSwap<bool>>,
}

impl Default for ForwardingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardingStore {
    pub fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(Arc::new(ForwardingSnapshot::empty()))),
            generation: Arc::new(AtomicU64::new(0)),
            cfg: Arc::new(Mutex::new(ForwardConfig {
                tun_mtu: 1280,
                ..ForwardConfig::default()
            })),
            stale: Arc::new(ArcSwap::from_pointee(false)),
            posture_ok: Arc::new(ArcSwap::from_pointee(true)),
        }
    }

    pub fn load(&self) -> Arc<ForwardingSnapshot> {
        Arc::clone(&self.current.load())
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn posture_source(&self) -> Arc<ArcSwap<bool>> {
        self.posture_ok.clone()
    }

    pub fn adopt_posture(&self, source: Arc<ArcSwap<bool>>) {
        self.posture_ok.store(source.load_full());
    }

    pub fn set_stale(&self, stale: bool) {
        self.stale.store(Arc::new(stale));
    }

    pub fn set_managed_bundle(
        &self,
        routes: &crate::routing::RoutingTable,
        network: Uuid,
        bundle: PolicyBundle,
        self_id: SelfIdentity,
    ) {
        {
            let mut cfg = self.cfg.lock();
            cfg.bundle = Some((network, bundle));
            cfg.self_id = Some(self_id);
            bump_auth(&mut cfg, network);
        }
        self.publish(routes);
    }

    pub fn clear_managed(&self, routes: &crate::routing::RoutingTable, network: Uuid) {
        {
            let mut cfg = self.cfg.lock();
            if cfg.bundle.as_ref().is_some_and(|(n, _)| *n == network) {
                cfg.bundle = None;
            }
            bump_auth(&mut cfg, network);
        }
        self.publish(routes);
    }

    pub fn set_firewall(
        &self,
        routes: &crate::routing::RoutingTable,
        network: Uuid,
        rules: FirewallRules,
    ) {
        {
            let mut cfg = self.cfg.lock();
            cfg.firewalls.insert(network, rules);
            bump_auth(&mut cfg, network);
        }
        self.publish(routes);
    }

    pub fn set_suggested(
        &self,
        routes: &crate::routing::RoutingTable,
        network: Uuid,
        suggested: Vec<FirewallRule>,
    ) {
        {
            let mut cfg = self.cfg.lock();
            cfg.firewalls
                .entry(network)
                .or_insert_with(|| FirewallRules {
                    enabled: true,
                    ..FirewallRules::default()
                })
                .suggested = suggested;
            bump_auth(&mut cfg, network);
        }
        self.publish(routes);
    }

    pub fn set_self(&self, routes: &crate::routing::RoutingTable, self_id: SelfIdentity) {
        {
            let mut cfg = self.cfg.lock();
            cfg.self_id = Some(self_id);
            for epoch in cfg.auth_epochs.values_mut() {
                *epoch = epoch.wrapping_add(1);
            }
        }
        self.publish(routes);
    }

    pub fn set_mtu(&self, routes: &crate::routing::RoutingTable, mtu: u16) {
        {
            self.cfg.lock().tun_mtu = mtu.max(576);
        }
        self.publish(routes);
    }

    pub fn set_ssh_addrs(&self, routes: &crate::routing::RoutingTable, addrs: HashSet<Ipv4Addr>) {
        {
            self.cfg.lock().ssh_addrs = addrs;
        }
        self.publish(routes);
    }

    pub fn republish(&self, routes: &crate::routing::RoutingTable) {
        self.publish(routes);
    }

    fn publish(&self, routes: &crate::routing::RoutingTable) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let tables = routes.tables();
        let mut cfg = self.cfg.lock();
        let mut bindings = HashMap::new();
        let mut networks_of: HashMap<EndpointId, Vec<Uuid>> = HashMap::new();
        let mut by_ip: HashMap<Ipv4Addr, usize> = HashMap::new();
        let mut members: HashMap<Uuid, Vec<&PeerInfo>> = HashMap::new();
        for ((network, _), info) in tables.by_network_ip.iter() {
            *by_ip.entry(info.ip).or_insert(0) += 1;
            members.entry(*network).or_default().push(info);
            bindings.insert((*network, info.endpoint), PeerBinding::from_info(info));
            networks_of.entry(info.endpoint).or_default().push(*network);
        }
        for peers in members.values_mut() {
            peers.sort_by(|a, b| a.endpoint_hex.cmp(&b.endpoint_hex));
        }
        for (network, peers) in members.iter() {
            let fingerprint = binding_fingerprint(peers);
            if cfg.binding_hash.get(network) != Some(&fingerprint) {
                cfg.binding_hash.insert(*network, fingerprint);
                bump_auth(&mut cfg, *network);
            }
        }
        cfg.binding_hash.retain(|n, _| members.contains_key(n));
        let mut live: HashSet<Uuid> = members.keys().copied().collect();
        live.extend(cfg.firewalls.keys().copied());
        if let Some((n, _)) = &cfg.bundle {
            live.insert(*n);
        }
        cfg.auth_epochs.retain(|n, _| live.contains(n));
        for nets in networks_of.values_mut() {
            nets.sort();
            nets.dedup();
        }
        let conflicts: HashSet<Ipv4Addr> = by_ip
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(ip, _)| ip)
            .collect();
        let conflict_cidrs = identical_cidrs(routes.slice_subnets());
        let mut policies = HashMap::new();
        let mut managed = None;
        if let Some((network, bundle)) = &cfg.bundle {
            policies.insert(
                *network,
                NetworkPolicy::Managed {
                    bundle: bundle.clone(),
                },
            );
            managed = Some(*network);
        }
        for (network, rules) in cfg.firewalls.iter() {
            policies.insert(
                *network,
                NetworkPolicy::Direct {
                    enabled: rules.enabled,
                    version: rules.version,
                    local: rules.local.clone(),
                    suggested: rules.suggested.clone(),
                },
            );
        }
        let snapshot = ForwardingSnapshot {
            generation,
            tables,
            self_id: cfg.self_id.clone().unwrap_or_else(|| SelfIdentity {
                endpoint_hex: String::new(),
                ip: Ipv4Addr::UNSPECIFIED,
                tags: Vec::new(),
                network: String::new(),
            }),
            bindings,
            networks_of,
            policies,
            managed,
            auth: cfg.auth_epochs.clone(),
            conflicts,
            conflict_cidrs,
            ssh_addrs: cfg.ssh_addrs.clone(),
            tun_mtu: cfg.tun_mtu,
            stale: self.stale.clone(),
            posture_ok: self.posture_ok.clone(),
        };
        self.current.store(Arc::new(Arc::new(snapshot)));
    }
}

fn bump_auth(cfg: &mut ForwardConfig, network: Uuid) {
    let epoch = cfg.auth_epochs.entry(network).or_insert(0);
    *epoch = epoch.wrapping_add(1);
}

fn binding_fingerprint(peers: &[&PeerInfo]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    for peer in peers {
        peer.endpoint_hex.hash(&mut hasher);
        peer.ip.hash(&mut hasher);
        peer.hostname.hash(&mut hasher);
        let mut tags = peer.tags.clone();
        tags.sort();
        tags.hash(&mut hasher);
    }
    hasher.finish()
}

fn identical_cidrs(slices: Vec<(Uuid, Vec<Ipv4Net>)>) -> Vec<Ipv4Net> {
    let mut seen: HashMap<Ipv4Net, Uuid> = HashMap::new();
    let mut out = Vec::new();
    for (network, cidrs) in slices {
        for cidr in cidrs {
            if let Some(first) = seen.get(&cidr) {
                if *first != network && !out.contains(&cidr) {
                    out.push(cidr);
                }
            } else {
                seen.insert(cidr, network);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingTable;
    use rstest::rstest;
    use tunnet_common::policy::PolicyBundle;

    fn bundle() -> PolicyBundle {
        PolicyBundle::default()
    }

    fn self_id() -> SelfIdentity {
        SelfIdentity {
            endpoint_hex: "aa".repeat(32),
            ip: "10.7.0.1".parse().unwrap(),
            tags: vec![],
            network: "office".into(),
        }
    }

    fn peer_entry(ip: &str, hex: &str) -> tunnet_common::PeerEntry {
        tunnet_common::PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: hex.to_string(),
            hostname: "peer".into(),
            tags: vec![],
            ssh_host_key: None,
        }
    }

    fn managed_routes() -> RoutingTable {
        let routes = RoutingTable::new();
        routes.replace(
            &[peer_entry("10.7.0.2", &"bb".repeat(32))],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "office",
            Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
        routes
    }

    #[test]
    fn publish_binds_peer_and_policy_coherently() {
        let routes = managed_routes();
        let store = ForwardingStore::new();
        store.set_managed_bundle(&routes, Uuid::nil(), bundle(), self_id());
        let snap = store.load();
        assert_eq!(snap.generation, 1);
        let b = snap
            .binding(Uuid::nil(), "bb".repeat(32).parse().unwrap())
            .expect("binding");
        assert_eq!(b.ip.to_string(), "10.7.0.2");
        assert!(matches!(
            snap.policy_for(Uuid::nil()),
            Some(NetworkPolicy::Managed { .. })
        ));
        assert_eq!(snap.managed, Some(Uuid::nil()));
        assert!(snap.conflicts.is_empty());
    }

    #[test]
    fn duplicate_peer_ip_across_networks_conflicts() {
        let routes = RoutingTable::new();
        routes.replace(
            &[peer_entry("10.7.0.2", &"bb".repeat(32))],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "one",
            Uuid::from_u128(1),
            &"aa".repeat(32),
            1,
        );
        routes.replace_network(
            Uuid::from_u128(2),
            &[peer_entry("10.7.0.2", &"cc".repeat(32))],
            &tunnet_common::DnsConfig::default(),
            "two",
            &"aa".repeat(32),
            1,
        );
        let store = ForwardingStore::new();
        store.republish(&routes);
        let snap = store.load();
        assert!(snap.conflicts.contains(&"10.7.0.2".parse().unwrap()));
    }

    #[rstest]
    #[case(vec![(Uuid::from_u128(1), vec!["10.0.0.0/24".parse().unwrap()]),
               (Uuid::from_u128(2), vec!["10.0.0.0/24".parse().unwrap()])], 1)]
    #[case(vec![(Uuid::from_u128(1), vec!["10.0.0.0/24".parse().unwrap()]),
               (Uuid::from_u128(2), vec!["10.0.1.0/24".parse().unwrap()])], 0)]
    #[case(vec![(Uuid::from_u128(1), vec!["10.0.0.0/24".parse().unwrap()])], 0)]
    fn identical_cidr_detection(#[case] slices: Vec<(Uuid, Vec<Ipv4Net>)>, #[case] n: usize) {
        assert_eq!(identical_cidrs(slices).len(), n);
    }

    #[test]
    fn generations_increase_monotonically() {
        let routes = managed_routes();
        let store = ForwardingStore::new();
        store.republish(&routes);
        store.republish(&routes);
        assert_eq!(store.load().generation, 2);
        assert_eq!(store.generation(), 2);
    }
}
