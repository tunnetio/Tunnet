use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnet::Ipv4Net;
use iroh::EndpointId;
use parking_lot::Mutex;
use tunnet_common::{
    DeviceProfile, DnsConfig, ExitNodeInfo, HostnameRoute, PeerEntry, SubnetRoute,
};
use uuid::Uuid;

pub struct PeerInfo {
    pub endpoint: EndpointId,
    pub endpoint_hex: String,
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network_id: Uuid,
    pub network_name: String,
    pub ssh_host_key: Option<String>,
}

/// Resolved hostname route (exact or wildcard).
pub struct HostnameRouteInfo {
    pub peer: Arc<PeerInfo>,
    pub is_wildcard: bool,
    pub target_ip: Option<Ipv4Addr>,
    /// Stored hostname / suffix (without `*.`).
    pub hostname: String,
}

#[derive(Clone)]
struct NetworkSlice {
    peers: Vec<PeerEntry>,
    subnet_routes: Vec<SubnetRoute>,
    hostname_routes: Vec<HostnameRoute>,
    exit_nodes: Vec<ExitNodeInfo>,
    profile: DeviceProfile,
    dns: DnsConfig,
    network_name: String,
    self_endpoint_id: String,
    /// Join index: lower = first-joined = outbound winner on IP clash.
    join_index: u64,
}

pub struct Tables {
    pub by_ip: std::collections::HashMap<Ipv4Addr, Arc<PeerInfo>>,
    /// All memberships including same IP across networks.
    pub by_network_ip: std::collections::HashMap<(Uuid, Ipv4Addr), Arc<PeerInfo>>,
    pub by_endpoint: std::collections::HashMap<String, Arc<PeerInfo>>,
    pub by_hostname: std::collections::HashMap<String, Arc<PeerInfo>>,
    /// Longest-prefix-match candidates, sorted by prefix length descending.
    pub subnets: Vec<(Ipv4Net, Arc<PeerInfo>)>,
    /// CIDRs this node itself advertises (local LAN forwarding).
    pub advertised: Vec<Ipv4Net>,
    /// Exact hostname → gateway.
    pub hostname_exact: std::collections::HashMap<String, Arc<HostnameRouteInfo>>,
    /// Wildcard suffixes, longest first.
    pub hostname_wildcards: Vec<Arc<HostnameRouteInfo>>,
    /// Hostname routes this node itself advertises (local resolve + proxy).
    pub advertised_hostnames: Vec<Arc<HostnameRouteInfo>>,
    /// Synthetic IP → hostname (PeerDNS hostname-route answers).
    pub synthetic_hosts: std::collections::HashMap<Ipv4Addr, String>,
    pub dns_suffix: String,
    pub network_name: String,
    /// PeerDNS magic listener IP (local, not mesh-forwarded).
    pub magic_ip: Ipv4Addr,
    /// Selected exit node peer (when device_profile chooses one).
    pub exit_node: Option<Arc<PeerInfo>>,
    pub version: u64,
}

#[derive(Clone)]
pub struct RoutingTable {
    inner: Arc<ArcSwap<Tables>>,
    /// Synthetic IPs created at DNS resolve time (esp. wildcard hostname routes).
    dynamic_synth: Arc<DashMap<Ipv4Addr, Arc<PeerInfo>>>,
    slices: Arc<Mutex<BTreeMap<Uuid, NetworkSlice>>>,
    /// Manual IP overrides: (network_id, peer_key) → ip. peer_key is hostname or endpoint hex.
    overrides: Arc<DashMap<(Uuid, String), Ipv4Addr>>,
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(Tables {
                by_ip: Default::default(),
                by_network_ip: Default::default(),
                by_endpoint: Default::default(),
                by_hostname: Default::default(),
                subnets: Default::default(),
                advertised: Default::default(),
                hostname_exact: Default::default(),
                hostname_wildcards: Default::default(),
                advertised_hostnames: Default::default(),
                synthetic_hosts: Default::default(),
                dns_suffix: "tunnet".into(),
                network_name: String::new(),
                magic_ip: Ipv4Addr::new(100, 100, 100, 53),
                exit_node: None,
                version: 0,
            })),
            dynamic_synth: Arc::new(DashMap::new()),
            slices: Arc::new(Mutex::new(BTreeMap::new())),
            overrides: Arc::new(DashMap::new()),
        }
    }

    /// Look up peer by (network, ip) for inbound / firewall context.
    pub fn lookup_network_ip(&self, network_id: Uuid, ip: &Ipv4Addr) -> Option<Arc<PeerInfo>> {
        self.inner
            .load()
            .by_network_ip
            .get(&(network_id, *ip))
            .cloned()
    }

    /// Set a manual outbound IP override for a peer in a network.
    pub fn set_ip_override(&self, network_id: Uuid, peer_key: &str, ip: Ipv4Addr) {
        self.overrides
            .insert((network_id, peer_key.to_ascii_lowercase()), ip);
        self.rebuild(None);
    }

    pub fn clear_ip_override(&self, network_id: Uuid, peer_key: &str) {
        self.overrides
            .remove(&(network_id, peer_key.to_ascii_lowercase()));
        self.rebuild(None);
    }

    /// Direct peer IP, subnet LPM, then selected exit node for internet.
    /// On birthday collisions across networks, first-joined network wins.
    pub fn lookup_ip(&self, ip: &Ipv4Addr) -> Option<Arc<PeerInfo>> {
        let tables = self.inner.load();
        if let Some(peer) = tables.by_ip.get(ip).cloned() {
            return Some(peer);
        }
        if let Some(peer) = self.dynamic_synth.get(ip) {
            return Some(peer.clone());
        }
        for (net, peer) in &tables.subnets {
            if net.contains(ip) {
                return Some(peer.clone());
            }
        }
        // Exit node catches remaining (non-mesh) destinations when configured.
        if !is_mesh_or_link_local(ip)
            && let Some(exit) = &tables.exit_node
        {
            return Some(exit.clone());
        }
        None
    }

    pub fn exit_node(&self) -> Option<Arc<PeerInfo>> {
        self.inner.load().exit_node.clone()
    }

    pub fn is_exit_node(&self) -> bool {
        // Advertised default route means we are an exit.
        self.inner
            .load()
            .advertised
            .iter()
            .any(|n| n.prefix_len() == 0)
    }

    pub fn lookup_endpoint(&self, hex: &str) -> Option<Arc<PeerInfo>> {
        self.inner.load().by_endpoint.get(hex).cloned()
    }

    /// Peer hostname (mesh member), then hostname-route exact/wildcard.
    pub fn lookup_hostname(&self, host: &str) -> Option<Arc<PeerInfo>> {
        let host = host.to_ascii_lowercase();
        let tables = self.inner.load();
        if let Some(peer) = tables.by_hostname.get(&host).cloned() {
            return Some(peer);
        }
        self.lookup_hostname_route(&host)
            .map(|info| info.peer.clone())
    }

    pub fn lookup_hostname_route(&self, host: &str) -> Option<Arc<HostnameRouteInfo>> {
        let host = host.to_ascii_lowercase();
        let tables = self.inner.load();
        if let Some(info) = tables.hostname_exact.get(&host).cloned() {
            return Some(info);
        }
        for info in &tables.hostname_wildcards {
            if hostname_matches_wildcard(&host, &info.hostname) {
                return Some(info.clone());
            }
        }
        None
    }

    /// True when this node advertises a subnet containing `ip`.
    pub fn is_advertised_destination(&self, ip: &Ipv4Addr) -> bool {
        self.inner
            .load()
            .advertised
            .iter()
            .any(|net| net.contains(ip))
    }

    /// True when this node is the gateway for a hostname route matching `host`.
    pub fn is_advertised_hostname(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let tables = self.inner.load();
        tables.advertised_hostnames.iter().any(|info| {
            if info.is_wildcard {
                hostname_matches_wildcard(&host, &info.hostname)
            } else {
                info.hostname == host
            }
        })
    }

    pub fn advertised_subnets(&self) -> Vec<Ipv4Net> {
        self.inner.load().advertised.clone()
    }

    pub fn peers(&self) -> Vec<Arc<PeerInfo>> {
        self.inner.load().by_network_ip.values().cloned().collect()
    }

    pub fn version(&self) -> u64 {
        self.inner.load().version
    }

    pub fn dns_suffix(&self) -> String {
        self.inner.load().dns_suffix.clone()
    }

    pub fn magic_ip(&self) -> Ipv4Addr {
        self.inner.load().magic_ip
    }

    pub fn is_magic_dns_destination(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.inner.load().magic_ip
    }

    pub fn network_name(&self) -> String {
        self.inner.load().network_name.clone()
    }

    /// Approximate PeerDNS / route cache size for `tunnet dns status`.
    pub fn cached_entry_count(&self) -> usize {
        let tables = self.inner.load();
        tables.by_hostname.len()
            + tables.hostname_exact.len()
            + tables.hostname_wildcards.len()
            + tables.synthetic_hosts.len()
            + self.dynamic_synth.len()
    }

    /// Resolve a PeerDNS name to an advertised SSH host pubkey (TXT).
    pub fn resolve_dns_txt(&self, name: &str) -> Option<String> {
        let tables = self.inner.load();
        let suffix = format!(".{}", tables.dns_suffix);
        let lower = name.trim_end_matches('.').to_ascii_lowercase();
        let bare = lower
            .strip_suffix(&suffix)
            .unwrap_or(lower.as_str())
            .trim_end_matches('.');

        for peer in tables.by_network_ip.values() {
            if peer.hostname.is_empty() {
                continue;
            }
            let host = peer.hostname.to_ascii_lowercase();
            let fqdn = if peer.network_name.is_empty() {
                host.clone()
            } else {
                format!("{host}.{}", peer.network_name)
            };
            if bare == host || bare == fqdn {
                return peer.ssh_host_key.clone();
            }
        }

        let network_suffix = if tables.network_name.is_empty() {
            None
        } else {
            Some(format!(".{}", tables.network_name))
        };
        let peer_name = network_suffix
            .as_ref()
            .and_then(|s| bare.strip_suffix(s.as_str()))
            .unwrap_or(bare);

        tables
            .by_hostname
            .get(peer_name)
            .and_then(|p| p.ssh_host_key.clone())
            .or_else(|| {
                tables
                    .by_hostname
                    .get(bare)
                    .and_then(|p| p.ssh_host_key.clone())
            })
    }

    /// Resolve a PeerDNS name to an IPv4 address (peer mesh IP or synthetic).
    /// Pure: does not mutate `dynamic_synth`. For wildcard hostname routes the
    /// caller should [`Self::remember_dns_synth`] so dataplane lookup works.
    pub fn resolve_dns_a(&self, name: &str) -> Option<Ipv4Addr> {
        let tables = self.inner.load();
        let suffix = format!(".{}", tables.dns_suffix);
        let lower = name.trim_end_matches('.').to_ascii_lowercase();

        let bare = lower
            .strip_suffix(&suffix)
            .unwrap_or(lower.as_str())
            .trim_end_matches('.');

        // Try hostname.network.suffix for every known network name in peer set.
        for peer in tables.by_network_ip.values() {
            if peer.hostname.is_empty() {
                continue;
            }
            let host = peer.hostname.to_ascii_lowercase();
            let fqdn = if peer.network_name.is_empty() {
                host.clone()
            } else {
                format!("{host}.{}", peer.network_name)
            };
            if bare == host || bare == fqdn {
                return Some(peer.ip);
            }
        }

        let network_suffix = if tables.network_name.is_empty() {
            None
        } else {
            Some(format!(".{}", tables.network_name))
        };
        let peer_name = network_suffix
            .as_ref()
            .and_then(|s| bare.strip_suffix(s.as_str()))
            .unwrap_or(bare);

        if let Some(peer) = tables.by_hostname.get(peer_name) {
            return Some(peer.ip);
        }

        for host in [bare, peer_name] {
            if self.lookup_hostname_route(host).is_some() {
                return Some(synthetic_ip_for(host));
            }
        }

        None
    }

    /// Cache a synthetic IP → peer mapping for a hostname (wildcard routes).
    /// Survives [`Self::rebuild`] because `dynamic_synth` lives outside the tables Arc.
    pub fn remember_dns_synth(&self, name: &str, ip: Ipv4Addr) {
        let tables = self.inner.load();
        let suffix = format!(".{}", tables.dns_suffix);
        let lower = name.trim_end_matches('.').to_ascii_lowercase();
        let bare = lower
            .strip_suffix(&suffix)
            .unwrap_or(lower.as_str())
            .trim_end_matches('.');
        let network_suffix = if tables.network_name.is_empty() {
            None
        } else {
            Some(format!(".{}", tables.network_name))
        };
        let peer_name = network_suffix
            .as_ref()
            .and_then(|s| bare.strip_suffix(s.as_str()))
            .unwrap_or(bare);

        for host in [bare, peer_name] {
            if let Some(info) = self.lookup_hostname_route(host)
                && synthetic_ip_for(host) == ip
            {
                self.dynamic_synth.insert(ip, info.peer.clone());
                return;
            }
        }
    }

    /// Reverse lookup: mesh IP → `hostname[.network].suffix`.
    pub fn resolve_dns_ptr(&self, ip: Ipv4Addr) -> Option<String> {
        let tables = self.inner.load();
        let peer = tables.by_ip.get(&ip)?;
        let host = if peer.hostname.is_empty() {
            return None;
        } else {
            peer.hostname.to_ascii_lowercase()
        };
        let fqdn = if peer.network_name.is_empty() {
            format!("{host}.{}", tables.dns_suffix)
        } else {
            format!("{host}.{}.{}", peer.network_name, tables.dns_suffix)
        };
        Some(fqdn)
    }

    /// Full table replace (Managed / single-network). Clears other network slices.
    #[allow(clippy::too_many_arguments)]
    pub fn replace(
        &self,
        peers: &[PeerEntry],
        subnet_routes: &[SubnetRoute],
        hostname_routes: &[HostnameRoute],
        exit_nodes: &[ExitNodeInfo],
        profile: &DeviceProfile,
        dns: &DnsConfig,
        network_name: &str,
        network_id: Uuid,
        self_endpoint_id: &str,
        version: u64,
    ) {
        {
            let mut slices = self.slices.lock();
            slices.clear();
            slices.insert(
                network_id,
                NetworkSlice {
                    peers: peers.to_vec(),
                    subnet_routes: subnet_routes.to_vec(),
                    hostname_routes: hostname_routes.to_vec(),
                    exit_nodes: exit_nodes.to_vec(),
                    profile: profile.clone(),
                    dns: dns.clone(),
                    network_name: network_name.to_ascii_lowercase(),
                    self_endpoint_id: self_endpoint_id.to_string(),
                    join_index: 0,
                },
            );
        }
        self.rebuild(Some(version));
    }

    /// Replace peers for one Direct network; other networks kept. First-joined wins outbound.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_network(
        &self,
        network_id: Uuid,
        join_index: u64,
        peers: &[PeerEntry],
        dns: &DnsConfig,
        network_name: &str,
        self_endpoint_id: &str,
        version: u64,
    ) {
        {
            let mut slices = self.slices.lock();
            slices.insert(
                network_id,
                NetworkSlice {
                    peers: peers.to_vec(),
                    subnet_routes: vec![],
                    hostname_routes: vec![],
                    exit_nodes: vec![],
                    profile: DeviceProfile::default(),
                    dns: dns.clone(),
                    network_name: network_name.to_ascii_lowercase(),
                    self_endpoint_id: self_endpoint_id.to_string(),
                    join_index,
                },
            );
        }
        self.rebuild(Some(version));
    }

    pub fn remove_network(&self, network_id: Uuid) {
        self.slices.lock().remove(&network_id);
        self.rebuild(None);
    }

    /// Apply a peer membership delta for one network without replacing routes/policy.
    pub fn apply_peer_delta(
        &self,
        network_id: Uuid,
        added: &[PeerEntry],
        removed: &[String],
        version: u64,
        self_endpoint_id: &str,
        network_name: &str,
    ) {
        {
            let mut slices = self.slices.lock();
            let Some(slice) = slices.get_mut(&network_id) else {
                tracing::debug!(
                    %network_id,
                    "apply_peer_delta skipped: no network slice (await full snapshot)"
                );
                return;
            };

            if !network_name.is_empty() {
                slice.network_name = network_name.to_ascii_lowercase();
            }

            let removed_set: std::collections::HashSet<&str> =
                removed.iter().map(String::as_str).collect();
            slice.peers.retain(|p| {
                p.endpoint_id != self_endpoint_id && !removed_set.contains(p.endpoint_id.as_str())
            });

            for peer in added {
                if peer.endpoint_id == self_endpoint_id {
                    continue;
                }
                if let Some(existing) = slice
                    .peers
                    .iter_mut()
                    .find(|p| p.endpoint_id == peer.endpoint_id)
                {
                    *existing = peer.clone();
                } else {
                    slice.peers.push(peer.clone());
                }
            }
        }
        self.rebuild(Some(version));
    }

    fn rebuild(&self, version: Option<u64>) {
        let slices: Vec<(Uuid, NetworkSlice)> = {
            let g = self.slices.lock();
            let mut v: Vec<_> = g.iter().map(|(k, s)| (*k, s.clone())).collect();
            v.sort_by_key(|(_, s)| s.join_index);
            v
        };

        let version = version.unwrap_or_else(|| self.inner.load().version.saturating_add(1));
        let mut by_ip: std::collections::HashMap<Ipv4Addr, Arc<PeerInfo>> =
            std::collections::HashMap::new();
        let mut by_network_ip: std::collections::HashMap<(Uuid, Ipv4Addr), Arc<PeerInfo>> =
            std::collections::HashMap::new();
        let mut by_endpoint: std::collections::HashMap<String, Arc<PeerInfo>> =
            std::collections::HashMap::new();
        let mut by_hostname: std::collections::HashMap<String, Arc<PeerInfo>> =
            std::collections::HashMap::new();
        let mut subnets = Vec::new();
        let mut advertised = Vec::new();
        let mut hostname_exact: std::collections::HashMap<String, Arc<HostnameRouteInfo>> =
            std::collections::HashMap::new();
        let mut hostname_wildcards = Vec::new();
        let mut advertised_hostnames = Vec::new();
        let mut synthetic_hosts: std::collections::HashMap<Ipv4Addr, String> =
            std::collections::HashMap::new();
        let mut exit_node = None;
        let mut dns_suffix = "tunnet".to_string();
        let mut magic_ip = Ipv4Addr::new(100, 100, 100, 53);
        let mut primary_network_name = String::new();

        for (network_id, slice) in &slices {
            if primary_network_name.is_empty() {
                primary_network_name = slice.network_name.clone();
            }
            dns_suffix = slice.dns.suffix.clone();
            magic_ip = slice.dns.magic_ip;

            let mut local_by_endpoint: std::collections::HashMap<String, Arc<PeerInfo>> =
                std::collections::HashMap::new();
            for p in &slice.peers {
                let Ok(ep) = p.endpoint_id.parse::<EndpointId>() else {
                    tracing::warn!(id = %p.endpoint_id, "skip peer with bad endpoint id");
                    continue;
                };
                let mut ip = p.ip;
                // Apply override by hostname or endpoint hex.
                for key in [
                    p.hostname.to_ascii_lowercase(),
                    p.endpoint_id.to_ascii_lowercase(),
                ] {
                    if key.is_empty() {
                        continue;
                    }
                    if let Some(ov) = self.overrides.get(&(*network_id, key)) {
                        ip = *ov;
                        break;
                    }
                }
                let info = Arc::new(PeerInfo {
                    endpoint: ep,
                    endpoint_hex: p.endpoint_id.clone(),
                    hostname: p.hostname.clone(),
                    ip,
                    tags: p.tags.clone(),
                    network_id: *network_id,
                    network_name: slice.network_name.clone(),
                    ssh_host_key: p.ssh_host_key.clone(),
                });
                by_network_ip.insert((*network_id, ip), info.clone());
                // First-joined wins on outbound by_ip.
                if let Some(existing) = by_ip.get(&ip) {
                    if existing.endpoint_hex != info.endpoint_hex {
                        tracing::warn!(
                            %ip,
                            winner_network = %existing.network_name,
                            winner_peer = %existing.hostname,
                            loser_network = %info.network_name,
                            loser_peer = %info.hostname,
                            "IP collision across Direct networks; first-joined wins outbound \
                             (use `tunnet direct override-ip` to resolve)"
                        );
                    }
                } else {
                    by_ip.insert(ip, info.clone());
                }
                by_endpoint
                    .entry(p.endpoint_id.clone())
                    .or_insert_with(|| info.clone());
                local_by_endpoint.insert(p.endpoint_id.clone(), info.clone());
                if !p.hostname.is_empty() {
                    let key = if slice.network_name.is_empty() {
                        p.hostname.to_ascii_lowercase()
                    } else {
                        format!("{}.{}", p.hostname.to_ascii_lowercase(), slice.network_name)
                    };
                    by_hostname
                        .entry(p.hostname.to_ascii_lowercase())
                        .or_insert_with(|| info.clone());
                    by_hostname.insert(key, info);
                }
            }

            for route in &slice.subnet_routes {
                if route.via_endpoint_id == slice.self_endpoint_id {
                    advertised.push(route.cidr);
                    continue;
                }
                let peer = peer_for_via(
                    &local_by_endpoint,
                    &route.via_endpoint_id,
                    route.via_ip,
                    *network_id,
                    &slice.network_name,
                );
                let Some(peer) = peer else { continue };
                subnets.push((route.cidr, peer));
            }

            for exit in &slice.exit_nodes {
                if exit.endpoint_id == slice.self_endpoint_id {
                    for cidr in &exit.allowed_cidrs {
                        advertised.push(*cidr);
                    }
                }
            }

            if let Some(exit_id) = &slice.profile.exit_node_endpoint_id
                && let Some(exit) = slice.exit_nodes.iter().find(|e| &e.endpoint_id == exit_id)
            {
                let peer = peer_for_via(
                    &local_by_endpoint,
                    &exit.endpoint_id,
                    exit.via_ip,
                    *network_id,
                    &slice.network_name,
                );
                if let Some(peer) = peer {
                    for cidr in &exit.allowed_cidrs {
                        if !subnets.iter().any(|(n, _)| n == cidr) {
                            subnets.push((*cidr, peer.clone()));
                        }
                    }
                    if exit_node.is_none() {
                        exit_node = Some(peer);
                    }
                }
            }

            for route in &slice.hostname_routes {
                let hostname = route.hostname.to_ascii_lowercase();
                let peer = peer_for_via(
                    &local_by_endpoint,
                    &route.via_endpoint_id,
                    route.via_ip,
                    *network_id,
                    &slice.network_name,
                );
                let Some(peer) = peer else { continue };
                let info = Arc::new(HostnameRouteInfo {
                    peer: peer.clone(),
                    is_wildcard: route.is_wildcard,
                    target_ip: route.target_ip,
                    hostname: hostname.clone(),
                });
                if route.via_endpoint_id == slice.self_endpoint_id {
                    advertised_hostnames.push(info.clone());
                    continue;
                }
                if !route.is_wildcard {
                    let synth = synthetic_ip_for(&hostname);
                    by_ip.entry(synth).or_insert_with(|| peer.clone());
                    synthetic_hosts.insert(synth, hostname.clone());
                    hostname_exact.insert(hostname, info);
                } else {
                    hostname_wildcards.push(info);
                }
            }
        }

        subnets.sort_by_key(|subnet| std::cmp::Reverse(subnet.0.prefix_len()));
        hostname_wildcards.sort_by_key(|route| std::cmp::Reverse(route.hostname.len()));

        // Keep dynamic_synth across rebuild - it lives outside the tables Arc so
        // wildcard DNS answers survive membership/policy refreshes.
        self.inner.store(Arc::new(Tables {
            by_ip,
            by_network_ip,
            by_endpoint,
            by_hostname,
            subnets,
            advertised,
            hostname_exact,
            hostname_wildcards,
            advertised_hostnames,
            synthetic_hosts,
            dns_suffix,
            network_name: primary_network_name,
            magic_ip,
            exit_node,
            version,
        }));
    }
}

fn is_mesh_or_link_local(ip: &Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
}

/// Stable synthetic IP in 100.100.0.0/16 derived from hostname.
fn synthetic_ip_for(host: &str) -> Ipv4Addr {
    let mut hash: u32 = 2166136261;
    for b in host.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(16777619);
    }
    let offset = (hash % 65_534) + 1;
    let hi = ((offset >> 8) & 0xff) as u8;
    let low = (offset & 0xff) as u8;
    Ipv4Addr::new(100, 100, hi, low)
}

fn peer_for_via(
    by_endpoint: &std::collections::HashMap<String, Arc<PeerInfo>>,
    via_endpoint_id: &str,
    via_ip: Ipv4Addr,
    network_id: Uuid,
    network_name: &str,
) -> Option<Arc<PeerInfo>> {
    if let Some(existing) = by_endpoint.get(via_endpoint_id) {
        return Some(existing.clone());
    }
    let Ok(ep) = via_endpoint_id.parse::<EndpointId>() else {
        tracing::warn!(id = %via_endpoint_id, "skip route with bad via endpoint id");
        return None;
    };
    Some(Arc::new(PeerInfo {
        endpoint: ep,
        endpoint_hex: via_endpoint_id.to_string(),
        hostname: String::new(),
        ip: via_ip,
        tags: Vec::new(),
        network_id,
        network_name: network_name.to_string(),
        ssh_host_key: None,
    }))
}

fn hostname_matches_wildcard(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tunnet_common::SplitTunnelMode;

    fn peer(endpoint: &str, ip: &str, hostname: &str) -> PeerEntry {
        PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: endpoint.to_string(),
            hostname: hostname.to_string(),
            tags: vec![],
            ssh_host_key: None,
        }
    }

    fn dns() -> DnsConfig {
        DnsConfig::default()
    }

    fn profile() -> DeviceProfile {
        DeviceProfile::default()
    }

    #[test]
    fn lookup_prefers_direct_peer_over_subnet() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let gateway = "b".repeat(64);
        table.replace(
            &[peer(&gateway, "10.7.0.5", "gw")],
            &[SubnetRoute {
                cidr: Ipv4Net::from_str("10.0.0.0/24").unwrap(),
                via_endpoint_id: gateway.clone(),
                via_ip: "10.7.0.5".parse().unwrap(),
            }],
            &[],
            &[],
            &profile(),
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        let found = table.lookup_ip(&"10.0.0.100".parse().unwrap()).unwrap();
        assert_eq!(found.endpoint_hex, gateway);
    }

    #[test]
    fn longest_prefix_match() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let gw_wide = "b".repeat(64);
        let gw_narrow = "c".repeat(64);
        table.replace(
            &[
                peer(&gw_wide, "10.7.0.5", "wide"),
                peer(&gw_narrow, "10.7.0.6", "narrow"),
            ],
            &[
                SubnetRoute {
                    cidr: Ipv4Net::from_str("10.0.0.0/16").unwrap(),
                    via_endpoint_id: gw_wide.clone(),
                    via_ip: "10.7.0.5".parse().unwrap(),
                },
                SubnetRoute {
                    cidr: Ipv4Net::from_str("10.0.1.0/24").unwrap(),
                    via_endpoint_id: gw_narrow.clone(),
                    via_ip: "10.7.0.6".parse().unwrap(),
                },
            ],
            &[],
            &[],
            &profile(),
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        let found = table.lookup_ip(&"10.0.1.50".parse().unwrap()).unwrap();
        assert_eq!(found.endpoint_hex, gw_narrow);
        let found = table.lookup_ip(&"10.0.2.50".parse().unwrap()).unwrap();
        assert_eq!(found.endpoint_hex, gw_wide);
    }

    #[test]
    fn advertised_subnets_excluded_from_remote_lookup() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        table.replace(
            &[],
            &[SubnetRoute {
                cidr: Ipv4Net::from_str("10.0.0.0/24").unwrap(),
                via_endpoint_id: self_id.clone(),
                via_ip: "10.7.0.1".parse().unwrap(),
            }],
            &[],
            &[],
            &profile(),
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        assert!(table.lookup_ip(&"10.0.0.100".parse().unwrap()).is_none());
        assert!(table.is_advertised_destination(&"10.0.0.100".parse().unwrap()));
    }

    #[test]
    fn hostname_route_exact_and_wildcard() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let gw = "b".repeat(64);
        table.replace(
            &[peer(&gw, "10.7.0.5", "gw")],
            &[],
            &[
                HostnameRoute {
                    hostname: "wiki.internal".into(),
                    via_endpoint_id: gw.clone(),
                    via_ip: "10.7.0.5".parse().unwrap(),
                    is_wildcard: false,
                    target_ip: Some("10.0.0.50".parse().unwrap()),
                },
                HostnameRoute {
                    hostname: "internal".into(),
                    via_endpoint_id: gw.clone(),
                    via_ip: "10.7.0.5".parse().unwrap(),
                    is_wildcard: true,
                    target_ip: None,
                },
            ],
            &[],
            &profile(),
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        let exact = table.lookup_hostname_route("wiki.internal").unwrap();
        assert!(!exact.is_wildcard);
        assert_eq!(exact.target_ip, Some("10.0.0.50".parse().unwrap()));
        let wild = table.lookup_hostname("api.internal").unwrap();
        assert_eq!(wild.endpoint_hex, gw);
        assert!(table.lookup_hostname_route("other.com").is_none());
    }

    #[test]
    fn peer_dns_resolves_self() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let self_ip: Ipv4Addr = "10.7.0.3".parse().unwrap();
        // Managed snapshots exclude self from peers; inject like apply_membership.
        table.replace(
            &[peer(&self_id, "10.7.0.3", "desktop-t85djls")],
            &[],
            &[],
            &[],
            &profile(),
            &dns(),
            "default",
            Uuid::nil(),
            &self_id,
            1,
        );
        assert_eq!(table.resolve_dns_a("desktop-t85djls.tunnet"), Some(self_ip));
        assert_eq!(
            table.resolve_dns_a("desktop-t85djls.default.tunnet"),
            Some(self_ip)
        );
        assert_eq!(
            table.resolve_dns_ptr(self_ip).as_deref(),
            Some("desktop-t85djls.default.tunnet")
        );
    }

    #[test]
    fn peer_dns_resolves_peer_and_hostname_route() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let gw = "b".repeat(64);
        table.replace(
            &[peer(&gw, "10.7.0.5", "db-server")],
            &[],
            &[HostnameRoute {
                hostname: "wiki.internal".into(),
                via_endpoint_id: gw.clone(),
                via_ip: "10.7.0.5".parse().unwrap(),
                is_wildcard: false,
                target_ip: None,
            }],
            &[],
            &profile(),
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        assert_eq!(
            table.resolve_dns_a("db-server.tunnet"),
            Some("10.7.0.5".parse().unwrap())
        );
        assert_eq!(
            table.resolve_dns_a("db-server.office.tunnet"),
            Some("10.7.0.5".parse().unwrap())
        );
        let synth = table.resolve_dns_a("wiki.internal.tunnet").unwrap();
        table.remember_dns_synth("wiki.internal.tunnet", synth);
        assert_eq!(synth.octets()[0], 100);
        assert_eq!(synth.octets()[1], 100);
        assert_eq!(table.lookup_ip(&synth).unwrap().endpoint_hex, gw);
    }

    #[test]
    fn apply_peer_delta_add_and_remove() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let peer_a = "b".repeat(64);
        let peer_b = "c".repeat(64);
        let nid = Uuid::nil();
        table.replace(
            &[peer(&peer_a, "10.7.0.5", "alice")],
            &[],
            &[],
            &[],
            &profile(),
            &dns(),
            "office",
            nid,
            &self_id,
            1,
        );
        assert!(table.lookup_endpoint(&peer_a).is_some());
        assert!(table.lookup_endpoint(&peer_b).is_none());

        table.apply_peer_delta(
            nid,
            &[peer(&peer_b, "10.7.0.6", "bob")],
            &[],
            2,
            &self_id,
            "office",
        );
        assert_eq!(table.version(), 2);
        assert!(table.lookup_endpoint(&peer_b).is_some());

        table.apply_peer_delta(
            nid,
            &[],
            std::slice::from_ref(&peer_a),
            3,
            &self_id,
            "office",
        );
        assert_eq!(table.version(), 3);
        assert!(table.lookup_endpoint(&peer_a).is_none());
        assert!(table.lookup_endpoint(&peer_b).is_some());
    }

    #[test]
    fn dynamic_synth_survives_rebuild() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let gw = "b".repeat(64);
        let nid = Uuid::nil();
        table.replace(
            &[peer(&gw, "10.7.0.5", "gw")],
            &[],
            &[HostnameRoute {
                hostname: "internal".into(),
                via_endpoint_id: gw.clone(),
                via_ip: "10.7.0.5".parse().unwrap(),
                is_wildcard: true,
                target_ip: None,
            }],
            &[],
            &profile(),
            &dns(),
            "office",
            nid,
            &self_id,
            1,
        );
        let synth = table.resolve_dns_a("api.internal.tunnet").unwrap();
        table.remember_dns_synth("api.internal.tunnet", synth);
        assert_eq!(table.lookup_ip(&synth).unwrap().endpoint_hex, gw);

        // Rebuild via peer delta must keep dynamic_synth.
        table.apply_peer_delta(
            nid,
            &[peer(&"d".repeat(64), "10.7.0.7", "dave")],
            &[],
            2,
            &self_id,
            "office",
        );
        assert_eq!(table.lookup_ip(&synth).unwrap().endpoint_hex, gw);
    }

    #[test]
    fn exit_node_catches_internet_traffic() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let exit = "b".repeat(64);
        let mut profile = profile();
        profile.exit_node_endpoint_id = Some(exit.clone());
        profile.split_tunnel_mode = SplitTunnelMode::Exclude;
        table.replace(
            &[peer(&exit, "10.7.0.5", "exit")],
            &[],
            &[],
            &[ExitNodeInfo {
                endpoint_id: exit.clone(),
                via_ip: "10.7.0.5".parse().unwrap(),
                allowed_cidrs: vec![Ipv4Net::from_str("0.0.0.0/0").unwrap()],
            }],
            &profile,
            &dns(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        let found = table.lookup_ip(&"8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(found.endpoint_hex, exit);
    }
}
