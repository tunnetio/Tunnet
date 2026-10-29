use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use iroh::EndpointId;
use parking_lot::{Mutex, RwLock};
use tunnet_common::PeerPosture;
use tunnet_common::policy::{Direction, FlowEndpoint, PolicyBundle, SshPolicyRule};
use uuid::Uuid;

use crate::direct::firewall::FirewallRule;
use crate::routing::{PeerInfo, RoutingTable, Tables};

#[derive(Debug, Clone)]
pub struct SelfIdentity {
    pub endpoint_hex: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network: String,
    /// This device's named claim for the managed membership. Not the kill switch.
    pub posture: PeerPosture,
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
    pub posture: PeerPosture,
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
            posture: info.posture.clone(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthorizationEpoch {
    pub configuration: u64,
    pub transport: u64,
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
    #[cfg(feature = "direct")]
    pub direct_auth: Option<crate::direct::AuthCache>,
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
                posture: PeerPosture::Unknown,
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
            #[cfg(feature = "direct")]
            direct_auth: None,
        }
    }

    pub fn binding(&self, network: Uuid, peer: EndpointId) -> Option<&PeerBinding> {
        self.bindings.get(&(network, peer))
    }

    pub fn route(&self, ip: &Ipv4Addr) -> Option<Arc<PeerInfo>> {
        let peer = crate::routing::RoutingTable::route_in(&self.tables, ip)?;
        self.address_isolated(peer.network_id, *ip).then_some(peer)
    }

    pub fn policy_for(&self, network: Uuid) -> Option<&NetworkPolicy> {
        self.policies.get(&network)
    }

    pub fn auth_epoch(&self, network: Uuid) -> AuthorizationEpoch {
        let transport = {
            #[cfg(feature = "direct")]
            {
                self.direct_auth.as_ref().map_or(0, |auth| auth.version())
            }
            #[cfg(not(feature = "direct"))]
            {
                0
            }
        };
        AuthorizationEpoch {
            configuration: self.auth.get(&network).copied().unwrap_or(0),
            transport,
        }
    }

    pub fn self_endpoint(&self) -> FlowEndpoint {
        FlowEndpoint::member(
            self.self_id.endpoint_hex.clone(),
            self.self_id.tags.clone(),
            self.self_id.network.clone(),
            Some(self.self_id.ip),
            self.self_id.posture.clone(),
        )
    }

    pub fn peer_endpoint(&self, network: Uuid, peer: EndpointId) -> Option<FlowEndpoint> {
        let b = self.binding(network, peer)?;
        Some(FlowEndpoint::member(
            b.endpoint_hex.clone(),
            b.tags.clone(),
            b.network_name.clone(),
            Some(b.ip),
            b.posture.clone(),
        ))
    }

    /// Named source claim. The local enforcement flag is not applied here.
    pub fn source_posture(
        &self,
        network: Uuid,
        peer: EndpointId,
        direction: Direction,
    ) -> PeerPosture {
        match direction {
            Direction::Outbound if self.managed == Some(network) => self.self_id.posture.clone(),
            Direction::Outbound => PeerPosture::Unknown,
            Direction::Inbound => self
                .binding(network, peer)
                .map(|binding| binding.posture.clone())
                .unwrap_or(PeerPosture::Unknown),
        }
    }

    pub fn allows_network(&self, network: Uuid, peer: EndpointId) -> bool {
        let Some(binding) = self.binding(network, peer) else {
            return false;
        };
        #[cfg(not(feature = "direct"))]
        let _ = binding;
        match self.policy_for(network) {
            Some(NetworkPolicy::Managed { .. }) => true,
            Some(NetworkPolicy::Direct { .. }) => {
                #[cfg(feature = "direct")]
                {
                    self.direct_auth.as_ref().is_some_and(|auth| {
                        auth.contains_network(&self.self_id.endpoint_hex, network)
                            && auth.contains_network(&binding.endpoint_hex, network)
                    })
                }
                #[cfg(not(feature = "direct"))]
                {
                    false
                }
            }
            None => false,
        }
    }

    pub fn local_ip(&self, network: Uuid) -> Option<Ipv4Addr> {
        self.tables
            .local_ips
            .get(&network)
            .copied()
            .or_else(|| (self.managed == Some(network)).then_some(self.self_id.ip))
    }

    pub fn address_isolated(&self, network: Uuid, ip: Ipv4Addr) -> bool {
        !self
            .tables
            .mesh_ranges
            .iter()
            .any(|(owner, range)| *owner != network && range.contains(&ip))
            && !self.tables.claims.iter().any(|claim| {
                claim.network != network && claim.cidr.prefix_len() > 0 && claim.cidr.contains(&ip)
            })
            && !self.conflict_cidrs.iter().any(|range| range.contains(&ip))
    }

    pub fn local_source_allowed(&self, network: Uuid, source: Ipv4Addr) -> bool {
        if !self.address_isolated(network, source) {
            return false;
        }
        if self.local_ip(network) == Some(source) {
            return true;
        }
        if self
            .tables
            .mesh_ranges
            .values()
            .any(|range| range.contains(&source))
            || self
                .tables
                .by_network_ip
                .keys()
                .any(|(_, ip)| *ip == source)
        {
            return false;
        }
        self.tables.claims.iter().any(|claim| {
            claim.network == network
                && claim.local
                && claim.cidr.prefix_len() < 32
                && claim.cidr.contains(&source)
        })
    }

    pub fn source_allowed(&self, network: Uuid, peer: EndpointId, source: Ipv4Addr) -> bool {
        if source.is_multicast()
            || source.is_broadcast()
            || source.is_loopback()
            || source.is_link_local()
            || source.is_unspecified()
        {
            return false;
        }
        if self
            .conflict_cidrs
            .iter()
            .any(|prefix| prefix.contains(&source))
        {
            return false;
        }
        if !self.address_isolated(network, source) {
            return false;
        }
        if self.binding(network, peer).is_some_and(|b| b.ip == source) {
            return true;
        }
        if self
            .tables
            .mesh_ranges
            .values()
            .any(|range| range.contains(&source))
            || self
                .tables
                .by_network_ip
                .keys()
                .any(|(_, ip)| *ip == source)
            || self.tables.local_ips.values().any(|ip| *ip == source)
        {
            return false;
        }
        self.tables
            .claims
            .iter()
            .filter(|c| c.network == network && !c.local && c.cidr.contains(&source))
            .max_by_key(|c| c.cidr.prefix_len())
            .is_some_and(|c| c.endpoint == peer)
    }

    pub fn destination_allowed(&self, network: Uuid, destination: Ipv4Addr) -> bool {
        if destination.is_multicast()
            || destination.is_broadcast()
            || destination.is_loopback()
            || destination.is_link_local()
            || destination.is_unspecified()
        {
            return false;
        }
        if self
            .conflict_cidrs
            .iter()
            .any(|prefix| prefix.contains(&destination))
        {
            return false;
        }
        if !self.address_isolated(network, destination) {
            return false;
        }
        if self.local_ip(network) == Some(destination) {
            return true;
        }
        if self
            .tables
            .mesh_ranges
            .values()
            .any(|range| range.contains(&destination))
            || self
                .tables
                .by_network_ip
                .keys()
                .any(|(_, ip)| *ip == destination)
            || self.tables.local_ips.values().any(|ip| *ip == destination)
        {
            return false;
        }
        self.tables.claims.iter().any(|c| {
            c.network == network
                && c.local
                && c.cidr.prefix_len() < 32
                && c.cidr.contains(&destination)
        })
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
    next_auth: u64,
    binding_hash: HashMap<Uuid, u64>,
    posture: Option<Arc<ArcSwap<bool>>>,
    #[cfg(feature = "direct")]
    direct_auth: Option<crate::direct::AuthCache>,
}

#[derive(Clone)]
pub struct ForwardingStore {
    changes: tokio::sync::watch::Sender<u64>,
    current: Arc<ArcSwap<ForwardingSnapshot>>,
    generation: Arc<AtomicU64>,
    cfg: Arc<Mutex<ForwardConfig>>,
    stale: Arc<ArcSwap<bool>>,
    posture_ok: Arc<ArcSwap<bool>>,
    gate: Arc<RwLock<()>>,
}

impl Default for ForwardingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardingStore {
    pub fn new() -> Self {
        Self {
            changes: tokio::sync::watch::channel(0).0,
            current: Arc::new(ArcSwap::from_pointee(ForwardingSnapshot::empty())),
            generation: Arc::new(AtomicU64::new(0)),
            cfg: Arc::new(Mutex::new(ForwardConfig {
                tun_mtu: 1280,
                ..ForwardConfig::default()
            })),
            stale: Arc::new(ArcSwap::from_pointee(false)),
            posture_ok: Arc::new(ArcSwap::from_pointee(true)),
            gate: Arc::new(RwLock::new(())),
        }
    }

    pub fn load(&self) -> Arc<ForwardingSnapshot> {
        self.current.load_full()
    }

    pub fn subscribe_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn notify_authorization_changed(&self) {
        self.changes
            .send_modify(|value| *value = value.wrapping_add(1));
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn posture_source(&self) -> Arc<ArcSwap<bool>> {
        self.cfg
            .lock()
            .posture
            .clone()
            .unwrap_or_else(|| self.posture_ok.clone())
    }

    pub fn adopt_posture(&self, source: Arc<ArcSwap<bool>>) {
        self.cfg.lock().posture = Some(source);
    }

    pub fn authorization_gate(&self) -> Arc<RwLock<()>> {
        self.gate.clone()
    }

    #[cfg(feature = "direct")]
    pub fn set_direct_auth(&self, auth: crate::direct::AuthCache) {
        self.cfg.lock().direct_auth = Some(auth);
    }

    pub fn update_routes(&self, routes: &RoutingTable, update: impl FnOnce()) {
        let _gate = self.gate.write();
        let mut cfg = self.cfg.lock();
        update();
        self.publish_locked(routes, &mut cfg);
    }

    pub fn update_managed(
        &self,
        routes: &RoutingTable,
        network: Uuid,
        bundle: PolicyBundle,
        self_id: SelfIdentity,
        update: impl FnOnce(),
    ) {
        let _gate = self.gate.write();
        let mut cfg = self.cfg.lock();
        update();
        if managed_policy_changed(cfg.bundle.as_ref(), network, &bundle) {
            bump_auth(&mut cfg, network);
        }
        cfg.bundle = Some((network, bundle));
        cfg.self_id = Some(self_id);
        self.stale.store(Arc::new(false));
        self.publish_locked(routes, &mut cfg);
    }

    pub fn set_stale(&self, stale: bool) {
        self.stale.store(Arc::new(stale));
        self.notify_authorization_changed();
    }

    pub fn set_managed_bundle(
        &self,
        routes: &crate::routing::RoutingTable,
        network: Uuid,
        bundle: PolicyBundle,
        self_id: SelfIdentity,
    ) {
        let _gate = self.gate.write();
        {
            let mut cfg = self.cfg.lock();
            if managed_policy_changed(cfg.bundle.as_ref(), network, &bundle) {
                bump_auth(&mut cfg, network);
            }
            cfg.bundle = Some((network, bundle));
            cfg.self_id = Some(self_id);
        }
        self.publish(routes);
    }

    pub fn clear_managed(&self, routes: &crate::routing::RoutingTable, network: Uuid) {
        let _gate = self.gate.write();
        routes.clear_managed(
            network,
            &self
                .cfg
                .lock()
                .self_id
                .as_ref()
                .map(|id| id.endpoint_hex.clone())
                .unwrap_or_default(),
        );
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
        let _gate = self.gate.write();
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
        let _gate = self.gate.write();
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
        let _gate = self.gate.write();
        {
            let mut cfg = self.cfg.lock();
            cfg.self_id = Some(self_id);
            let networks: Vec<_> = cfg.auth_epochs.keys().copied().collect();
            for network in networks {
                bump_auth(&mut cfg, network);
            }
        }
        self.publish(routes);
    }

    pub fn set_mtu(&self, routes: &crate::routing::RoutingTable, mtu: u16) {
        let _gate = self.gate.write();
        {
            self.cfg.lock().tun_mtu = mtu.max(576);
        }
        self.publish(routes);
    }

    pub fn set_ssh_addrs(&self, routes: &crate::routing::RoutingTable, addrs: HashSet<Ipv4Addr>) {
        let _gate = self.gate.write();
        {
            self.cfg.lock().ssh_addrs = addrs;
        }
        self.publish(routes);
    }

    pub fn republish(&self, routes: &crate::routing::RoutingTable) {
        let _gate = self.gate.write();
        self.publish(routes);
    }

    fn publish(&self, routes: &crate::routing::RoutingTable) {
        let mut cfg = self.cfg.lock();
        self.publish_locked(routes, &mut cfg);
    }

    fn publish_locked(&self, routes: &RoutingTable, cfg: &mut ForwardConfig) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let previous = self.current.load_full();
        let tables = routes.tables();
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
            let mut fingerprint = binding_fingerprint(peers) ^ route_fingerprint(&tables, *network);
            if cfg.bundle.as_ref().is_some_and(|(id, _)| id == network)
                && let Some(self_id) = &cfg.self_id
            {
                use std::hash::{Hash, Hasher};
                let mut identity = std::collections::hash_map::DefaultHasher::new();
                self_id.endpoint_hex.hash(&mut identity);
                self_id.ip.hash(&mut identity);
                self_id.network.hash(&mut identity);
                let mut tags = self_id.tags.clone();
                tags.sort();
                tags.hash(&mut identity);
                fingerprint ^= identity.finish() ^ self_id.posture.fingerprint();
            }
            let now = jiff::Timestamp::now();
            let proof_gap = peers.iter().any(|peer| {
                previous
                    .binding(*network, peer.endpoint)
                    .is_some_and(|old| {
                        old.posture.expired(now)
                            && peer.posture.valid_until().is_some_and(|until| now < until)
                    })
            }) || (previous.managed == Some(*network)
                && previous.self_id.posture.expired(now)
                && cfg.self_id.as_ref().is_some_and(|identity| {
                    identity
                        .posture
                        .valid_until()
                        .is_some_and(|until| now < until)
                }));
            if cfg.binding_hash.get(network) != Some(&fingerprint) || proof_gap {
                cfg.binding_hash.insert(*network, fingerprint);
                bump_auth(cfg, *network);
            }
        }
        cfg.binding_hash.retain(|n, _| members.contains_key(n));
        let mut live: HashSet<Uuid> = members.keys().copied().collect();
        live.extend(cfg.firewalls.keys().copied());
        if let Some((n, _)) = &cfg.bundle {
            live.insert(*n);
        }
        cfg.auth_epochs.retain(|network, _| live.contains(network));
        for nets in networks_of.values_mut() {
            nets.sort();
            nets.dedup();
        }
        let conflicts: HashSet<Ipv4Addr> = by_ip
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(ip, _)| ip)
            .collect();
        let conflict_cidrs = route_conflicts(&tables);
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
                posture: PeerPosture::Unknown,
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
            posture_ok: cfg
                .posture
                .clone()
                .unwrap_or_else(|| self.posture_ok.clone()),
            #[cfg(feature = "direct")]
            direct_auth: cfg.direct_auth.clone(),
        };
        self.current.store(Arc::new(snapshot));
        self.notify_authorization_changed();
    }
}

fn managed_policy_changed(
    previous: Option<&(Uuid, PolicyBundle)>,
    network: Uuid,
    bundle: &PolicyBundle,
) -> bool {
    let Some((old_network, old)) = previous else {
        return true;
    };
    if *old_network != network {
        return true;
    }
    fn semantics(bundle: &PolicyBundle) -> serde_json::Value {
        let mut value = serde_json::to_value(bundle).expect("policy serialization");
        value
            .as_object_mut()
            .expect("policy object")
            .remove("version");
        value
            .as_object_mut()
            .expect("policy object")
            .remove("signature");
        value
    }
    semantics(old) != semantics(bundle)
}

fn bump_auth(cfg: &mut ForwardConfig, network: Uuid) {
    cfg.next_auth = cfg
        .next_auth
        .checked_add(1)
        .expect("authorization epoch exhausted");
    cfg.auth_epochs.insert(network, cfg.next_auth);
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
        peer.posture.fingerprint().hash(&mut hasher);
    }
    hasher.finish()
}

fn route_fingerprint(tables: &Tables, network: Uuid) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut claims: Vec<_> = tables
        .claims
        .iter()
        .filter(|c| c.network == network)
        .map(|c| (c.cidr, c.endpoint, c.local))
        .collect();
    claims.sort();
    claims.hash(&mut hasher);
    tables.mesh_ranges.hash(&mut hasher);
    route_conflicts(tables).hash(&mut hasher);
    tables.default_ambiguous.hash(&mut hasher);
    if let Some(profile) = tables.profiles.get(&network) {
        serde_json::to_vec(profile)
            .expect("device profile serialization")
            .hash(&mut hasher);
    }
    hasher.finish()
}

fn route_conflicts(tables: &Tables) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    for (i, a) in tables.claims.iter().enumerate() {
        for b in &tables.claims[i + 1..] {
            if a.network != b.network
                && a.cidr.prefix_len() > 0
                && b.cidr.prefix_len() > 0
                && (a.cidr.contains(&b.cidr.network()) || b.cidr.contains(&a.cidr.network()))
            {
                let overlap = if a.cidr.prefix_len() >= b.cidr.prefix_len() {
                    a.cidr
                } else {
                    b.cidr
                };
                if !out.contains(&overlap) {
                    out.push(overlap);
                }
            }
        }
    }
    for (network, range) in &tables.mesh_ranges {
        for (other, other_range) in &tables.mesh_ranges {
            if network != other
                && (range.contains(&other_range.network())
                    || other_range.contains(&range.network()))
            {
                let overlap = if range.prefix_len() >= other_range.prefix_len() {
                    *range
                } else {
                    *other_range
                };
                if !out.contains(&overlap) {
                    out.push(overlap);
                }
            }
        }
        for claim in &tables.claims {
            if claim.network != *network
                && claim.cidr.prefix_len() > 0
                && (range.contains(&claim.cidr.network()) || claim.cidr.contains(&range.network()))
            {
                let overlap = if range.prefix_len() >= claim.cidr.prefix_len() {
                    *range
                } else {
                    claim.cidr
                };
                if !out.contains(&overlap) {
                    out.push(overlap);
                }
            }
        }
    }
    out.sort();
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
            posture: tunnet_common::PeerPosture::Unknown,
        }
    }

    fn peer_entry(ip: &str, hex: &str) -> tunnet_common::PeerEntry {
        tunnet_common::PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: hex.to_string(),
            hostname: "peer".into(),
            tags: vec![],
            ssh_host_key: None,
            posture: tunnet_common::PeerPosture::Unknown,
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

    #[test]
    fn allocator_reservations_block_unassigned_cross_network_addresses() {
        let one = Uuid::from_u128(1);
        let two = Uuid::from_u128(2);
        let routes = managed_routes();
        routes.replace_network_with_plan(
            two,
            &[peer_entry("10.42.0.2", &"cc".repeat(32))],
            &Default::default(),
            "other",
            &"aa".repeat(32),
            1,
            Some("10.42.0.0/16".parse().unwrap()),
        );
        let mut tables = (*routes.tables()).clone();
        tables.claims.push(crate::routing::RouteClaim {
            network: one,
            cidr: "0.0.0.0/0".parse().unwrap(),
            endpoint: "bb".repeat(32).parse().unwrap(),
            local: false,
        });
        tables.claims.push(crate::routing::RouteClaim {
            network: one,
            cidr: "0.0.0.0/0".parse().unwrap(),
            endpoint: "aa".repeat(32).parse().unwrap(),
            local: true,
        });
        let mut snapshot = ForwardingSnapshot::empty();
        snapshot.tables = Arc::new(tables);
        let unknown = "10.42.9.9".parse().unwrap();
        assert!(!snapshot.address_isolated(one, unknown));
        assert!(!snapshot.source_allowed(one, "bb".repeat(32).parse().unwrap(), unknown));
        assert!(!snapshot.local_source_allowed(one, unknown));
        assert!(!snapshot.destination_allowed(one, unknown));
        assert!(snapshot.address_isolated(one, "8.8.8.8".parse().unwrap()));
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
    #[test]
    fn removal_rejoin_never_recycles_authorization_and_posture_is_live() {
        let routes = managed_routes();
        let store = ForwardingStore::new();
        let posture = Arc::new(ArcSwap::from_pointee(true));
        store.adopt_posture(posture.clone());
        store.set_managed_bundle(&routes, Uuid::nil(), bundle(), self_id());
        let before = store.load();
        let epoch = before.auth_epoch(Uuid::nil());
        let old_posture = before.posture_ok.load_full();
        posture.store(Arc::new(false));
        assert!(!**before.posture_ok.load());
        posture.store(Arc::new(true));
        assert!(!Arc::ptr_eq(&old_posture, &before.posture_ok.load_full()));
        store.clear_managed(&routes, Uuid::nil());
        assert!(
            store
                .load()
                .binding(Uuid::nil(), "bb".repeat(32).parse().unwrap())
                .is_none()
        );
        store.update_managed(&routes, Uuid::nil(), bundle(), self_id(), || {
            routes.replace(
                &[peer_entry("10.7.0.2", &"bb".repeat(32))],
                &[],
                &[],
                &[],
                &Default::default(),
                &Default::default(),
                "office",
                Uuid::nil(),
                &"aa".repeat(32),
                2,
            )
        });
        assert_ne!(epoch, store.load().auth_epoch(Uuid::nil()));
    }

    #[rstest]
    #[case("10.0.0.0/16", "10.0.1.0/24", true)]
    #[case("10.0.0.0/16", "10.0.1.2/32", true)]
    #[case("0.0.0.0/0", "10.0.1.2/32", false)]
    #[case("10.0.0.0/24", "10.0.1.0/24", false)]
    fn overlaps_include_mesh_subnet_and_exit_routes(
        #[case] first: &str,
        #[case] second: &str,
        #[case] conflict: bool,
    ) {
        let mut tables = (*RoutingTable::new().tables()).clone();
        tables.claims = vec![
            crate::routing::RouteClaim {
                network: Uuid::from_u128(1),
                cidr: first.parse().unwrap(),
                endpoint: "bb".repeat(32).parse().unwrap(),
                local: false,
            },
            crate::routing::RouteClaim {
                network: Uuid::from_u128(2),
                cidr: second.parse().unwrap(),
                endpoint: "cc".repeat(32).parse().unwrap(),
                local: true,
            },
        ];
        assert_eq!(!route_conflicts(&tables).is_empty(), conflict);
        tables.claims[1].network = tables.claims[0].network;
        assert!(route_conflicts(&tables).is_empty());
    }
    #[test]
    fn concurrent_configuration_writers_publish_matching_identity_routes_and_policy() {
        let routes = RoutingTable::new();
        let store = ForwardingStore::new();
        std::thread::scope(|scope| {
            for worker in 0..8u128 {
                let routes = &routes;
                let store = &store;
                scope.spawn(move || {
                    let network = Uuid::from_u128(worker + 1);
                    let name = format!("network{worker}");
                    for version in 1..=20 {
                        store.update_managed(
                            routes,
                            network,
                            PolicyBundle {
                                version,
                                ..Default::default()
                            },
                            SelfIdentity {
                                network: name.clone(),
                                posture: tunnet_common::PeerPosture::Unknown,
                                ..self_id()
                            },
                            || {
                                routes.replace(
                                    &[peer_entry("10.7.0.2", &"bb".repeat(32))],
                                    &[],
                                    &[],
                                    &[],
                                    &Default::default(),
                                    &Default::default(),
                                    &name,
                                    network,
                                    &"aa".repeat(32),
                                    version,
                                )
                            },
                        );
                        let snapshot = store.load();
                        let current = snapshot.managed.unwrap();
                        let NetworkPolicy::Managed { bundle } =
                            snapshot.policy_for(current).unwrap()
                        else {
                            panic!("managed policy missing")
                        };
                        assert_eq!(snapshot.tables.version, bundle.version);
                        assert!(
                            snapshot
                                .bindings
                                .values()
                                .all(|binding| binding.network == current
                                    && binding.network_name == snapshot.self_id.network)
                        );
                    }
                });
            }
        });
        assert_eq!(store.load().generation, 160);
    }
}
