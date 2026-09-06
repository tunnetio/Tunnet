use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use iroh::EndpointId;
use parking_lot::Mutex;
use prefix_trie::PrefixMap;
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
    peer_cidr: Option<Ipv4Net>,
}

pub struct Tables {
    pub by_ip: std::collections::HashMap<Ipv4Addr, Arc<PeerInfo>>,
    /// All memberships including same IP across networks.
    pub by_network_ip: std::collections::HashMap<(Uuid, Ipv4Addr), Arc<PeerInfo>>,
    pub by_endpoint: std::collections::HashMap<String, Arc<PeerInfo>>,
    pub by_hostname: std::collections::HashMap<String, Arc<PeerInfo>>,
    /// Longest-prefix-match subnet routes (via PrefixMap).
    pub subnets: PrefixMap<Ipv4Net, Arc<PeerInfo>>,
    /// CIDRs this node itself advertises (local LAN forwarding).
    pub advertised: Vec<Ipv4Net>,
    /// Exact hostname → gateway.
    pub hostname_exact: std::collections::HashMap<String, Arc<HostnameRouteInfo>>,
    /// Wildcard suffixes, longest first.
    pub hostname_wildcards: Vec<Arc<HostnameRouteInfo>>,
    /// Hostname routes this node itself advertises (local resolve + proxy).
    pub advertised_hostnames: Vec<Arc<HostnameRouteInfo>>,
    pub dns_suffix: String,
    pub network_name: String,
    /// Selected exit node peer (when device_profile chooses one).
    pub exit_node: Option<Arc<PeerInfo>>,
    /// When true, RFC1918 destinations are not sent via the exit node.
    pub allow_local_lan: bool,
    pub version: u64,
}

#[derive(Clone)]
pub struct RoutingTable {
    inner: Arc<ArcSwap<Tables>>,
    slices: Arc<Mutex<BTreeMap<Uuid, NetworkSlice>>>,
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
                subnets: PrefixMap::new(),
                advertised: Default::default(),
                hostname_exact: Default::default(),
                hostname_wildcards: Default::default(),
                advertised_hostnames: Default::default(),
                dns_suffix: "tunnet".into(),
                network_name: String::new(),
                exit_node: None,
                allow_local_lan: true,
                version: 0,
            })),
            slices: Arc::new(Mutex::new(BTreeMap::new())),
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

    pub fn lookup_endpoint_in(&self, network_id: Uuid, hex: &str) -> Option<Arc<PeerInfo>> {
        let tables = self.inner.load();
        tables
            .by_network_ip
            .iter()
            .find(|((nid, _), p)| *nid == network_id && p.endpoint_hex == hex)
            .map(|(_, p)| p.clone())
    }

    /// Direct peer IP, subnet LPM, then selected exit node for internet.
    pub fn lookup_ip(&self, ip: &Ipv4Addr) -> Option<Arc<PeerInfo>> {
        let tables = self.inner.load();
        if let Some(peer) = tables.by_ip.get(ip).cloned() {
            return Some(peer);
        }
        if let Some((prefix, peer)) = tables.subnets.get_lpm(&Ipv4Net::from(*ip)) {
            // Full-tunnel exit CIDR must not steal LAN when allow_local_lan is on.
            if !(tables.allow_local_lan && is_rfc1918(ip) && prefix.prefix_len() == 0) {
                return Some(peer.clone());
            }
        }
        // Exit node catches remaining (non-mesh, non-LAN when allowed) destinations.
        if !is_mesh_or_link_local(ip)
            && !(tables.allow_local_lan && is_rfc1918(ip))
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

    pub fn network_name(&self) -> String {
        self.inner.load().network_name.clone()
    }

    /// Approximate PeerDNS / route cache size for `tunnet dns status`.
    pub fn cached_entry_count(&self) -> usize {
        let tables = self.inner.load();
        tables.by_hostname.len() + tables.hostname_exact.len() + tables.hostname_wildcards.len()
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

    /// Resolve a PeerDNS name to an IPv4 address.
    /// Hostname routes resolve to the gateway peer IP; the gateway
    /// proxies to the real target via explicit hostname/stream routing.
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
            if let Some(info) = self.lookup_hostname_route(host) {
                return Some(info.peer.ip);
            }
        }

        None
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
                    peer_cidr: None,
                },
            );
        }
        self.rebuild(Some(version));
    }

    /// Replace peers for one Direct network; other networks kept.
    /// Overlapping peer CIDRs are rejected by invariant; duplicate IPs fail closed.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_network(
        &self,
        network_id: Uuid,
        peers: &[PeerEntry],
        dns: &DnsConfig,
        network_name: &str,
        self_endpoint_id: &str,
        version: u64,
    ) {
        self.replace_network_with_plan(
            network_id,
            peers,
            dns,
            network_name,
            self_endpoint_id,
            version,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replace_network_with_plan(
        &self,
        network_id: Uuid,
        peers: &[PeerEntry],
        dns: &DnsConfig,
        network_name: &str,
        self_endpoint_id: &str,
        version: u64,
        peer_cidr: Option<Ipv4Net>,
    ) {
        {
            let mut slices = self.slices.lock();
            if let Some(plan) = peer_cidr {
                for (other_id, other) in slices.iter() {
                    if *other_id == network_id {
                        continue;
                    }
                    if let Some(other_plan) = other.peer_cidr
                        && cidr_overlaps(&plan, &other_plan)
                    {
                        tracing::error!(
                            %network_id,
                            %other_id,
                            %plan,
                            %other_plan,
                            "overlapping Direct peer CIDRs rejected"
                        );
                        return;
                    }
                }
            }
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
                    peer_cidr,
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
            v.sort_by_key(|(id, _)| *id);
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
        let mut subnets: PrefixMap<Ipv4Net, Arc<PeerInfo>> = PrefixMap::new();
        let mut advertised = Vec::new();
        let mut hostname_exact: std::collections::HashMap<String, Arc<HostnameRouteInfo>> =
            std::collections::HashMap::new();
        let mut hostname_wildcards = Vec::new();
        let mut advertised_hostnames = Vec::new();
        let mut exit_node = None;
        let mut allow_local_lan = true;
        let mut dns_suffix = "tunnet".to_string();
        let mut primary_network_name = String::new();

        for (network_id, slice) in &slices {
            if primary_network_name.is_empty() {
                primary_network_name = slice.network_name.clone();
            }
            dns_suffix = slice.dns.suffix.clone();

            let mut local_by_endpoint: std::collections::HashMap<String, Arc<PeerInfo>> =
                std::collections::HashMap::new();
            for p in &slice.peers {
                let Ok(ep) = p.endpoint_id.parse::<EndpointId>() else {
                    tracing::warn!(id = %p.endpoint_id, "skip peer with bad endpoint id");
                    continue;
                };
                let ip = p.ip;
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
                if let Some(existing) = by_ip.get(&ip) {
                    if existing.endpoint_hex != info.endpoint_hex {
                        tracing::error!(
                            %ip,
                            existing_network = %existing.network_name,
                            network = %info.network_name,
                            "duplicate IP across Direct networks; overlapping plans must be rejected"
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
                if !subnets.contains_key(&route.cidr) {
                    subnets.insert(route.cidr, peer);
                }
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
                        if !subnets.contains_key(cidr) {
                            subnets.insert(*cidr, peer.clone());
                        }
                    }
                    if exit_node.is_none() {
                        exit_node = Some(peer);
                        allow_local_lan = slice.profile.allow_local_lan;
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
                    hostname_exact.insert(hostname, info);
                } else {
                    hostname_wildcards.push(info);
                }
            }
        }

        hostname_wildcards.sort_by_key(|route| std::cmp::Reverse(route.hostname.len()));

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
            dns_suffix,
            network_name: primary_network_name,
            exit_node,
            allow_local_lan,
            version,
        }));
    }
}

fn is_mesh_or_link_local(ip: &Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
}

fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    matches!(ip.octets(), [10, ..] | [172, 16..=31, ..] | [192, 168, ..])
}

fn cidr_overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network())
        || a.contains(&b.broadcast())
        || b.contains(&a.network())
        || b.contains(&a.broadcast())
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
        let gw_ip = table.resolve_dns_a("wiki.internal.tunnet").unwrap();
        assert_eq!(gw_ip, Ipv4Addr::new(10, 7, 0, 5));
        assert_eq!(table.lookup_ip(&gw_ip).unwrap().endpoint_hex, gw);
        assert!(table.lookup_hostname_route("wiki.internal").is_some());
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
    fn hostname_route_resolves_to_gateway_without_fake_ip() {
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
        let gw_ip = table.resolve_dns_a("api.internal.tunnet").unwrap();
        assert_eq!(gw_ip, Ipv4Addr::new(10, 7, 0, 5));
        assert_eq!(table.lookup_ip(&gw_ip).unwrap().endpoint_hex, gw);

        table.apply_peer_delta(
            nid,
            &[peer(&"d".repeat(64), "10.7.0.7", "dave")],
            &[],
            2,
            &self_id,
            "office",
        );
        assert_eq!(
            table.resolve_dns_a("api.internal.tunnet").unwrap(),
            Ipv4Addr::new(10, 7, 0, 5)
        );
    }

    #[test]
    fn overlapping_plans_rejected_without_precedence() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let a = "b".repeat(64);
        let b = "c".repeat(64);
        let net_a = Uuid::new_v4();
        let net_b = Uuid::new_v4();
        let plan: Ipv4Net = "10.90.0.0/24".parse().unwrap();
        table.replace_network_with_plan(
            net_a,
            &[peer(&a, "10.90.0.1", "a")],
            &dns(),
            "a",
            &self_id,
            1,
            Some(plan),
        );
        table.replace_network_with_plan(
            net_b,
            &[peer(&b, "10.90.0.2", "b")],
            &dns(),
            "b",
            &self_id,
            1,
            Some(plan),
        );
        assert!(table.lookup_endpoint(&b).is_none());
        assert!(table.lookup_endpoint(&a).is_some());
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

    #[test]
    fn exit_node_skips_rfc1918_when_allow_local_lan() {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        let exit = "b".repeat(64);
        let mut profile = profile();
        profile.exit_node_endpoint_id = Some(exit.clone());
        profile.allow_local_lan = true;
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
        assert!(table.lookup_ip(&"192.168.1.50".parse().unwrap()).is_none());
        assert_eq!(
            table
                .lookup_ip(&"1.1.1.1".parse().unwrap())
                .unwrap()
                .endpoint_hex,
            exit
        );
    }
}
