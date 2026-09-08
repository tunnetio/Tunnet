//! Startup reporting of overlaps between a Direct network's peer CIDR and
//! prefixes already present on the host.
//!
//! `select_peer_cidr` picks a range that avoids the host's networks at
//! creation time, so a fresh network does not collide. That is not sufficient
//! on its own: the host changes afterwards. A user installs another VPN, joins
//! a different LAN, or a DHCP lease moves, and a plan that was safe when it
//! was signed becomes unsafe later. Genesis is signed and the peer CIDR cannot
//! be renegotiated on the fly, so the overlap has to be reported rather than
//! avoided.
//!
//! Reporting matters because the resulting failure is silent in both
//! directions and produces no error on either side. A measured example, and
//! the reason `ConflictCategory::VpnRoute` exists: Tailscale claims
//! `100.64.0.0/10` and installs
//!
//! ```text
//! -A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
//! ```
//!
//! The match is on **source**, not destination, so it also drops the host's
//! own traffic to any address in that range, including over loopback. On an
//! affected host, 50 of 50 packets to the mesh address and 50 of 50 to a
//! resolver inside the range were dropped, while a `127.0.0.1` control was
//! untouched. A DNS resolver in an overlapping range therefore stays listening
//! and simply never receives a query: no error, no log line, and both products
//! reporting "connected" while nothing works.
//!
//! Note when diagnosing a suspected overlap by hand: ICMP is not a valid
//! probe. Hosts that drop ICMP machine-wide make a working path look broken,
//! and the reverse is easy to misread too. Use a TCP connection to a real
//! listener instead.

use std::collections::HashMap;

use tunnet_core::direct::{ConflictCategory, NetworkConflict, detect_conflicts};

use crate::cmds_direct::collect_host_nets;
use crate::metrics::AgentMetrics;

fn category_label(category: ConflictCategory) -> &'static str {
    match category {
        ConflictCategory::ActiveDirectPlan => "active_direct_plan",
        ConflictCategory::LanPrefix => "lan_prefix",
        ConflictCategory::VpnRoute => "vpn_route",
        ConflictCategory::SpecialUse => "special_use",
    }
}

pub fn check_direct_conflicts_with_routes(
    node: &tunnet_core::CoreNode,
    metrics: &AgentMetrics,
    kernel_routes: &[crate::system_routes::RouteSpec],
    owned_routes: &[crate::system_routes::RouteSpec],
) -> Vec<NetworkConflict> {
    let networks: Vec<_> = node.direct.values().map(|runtime| &runtime.state).collect();
    if networks.is_empty() {
        return Vec::new();
    }
    let mut host: Vec<_> = collect_host_nets()
        .into_iter()
        .map(|network| (network, None, ConflictCategory::LanPrefix))
        .collect();
    host.extend(kernel_routes.iter().map(|route| {
        (
            route.dest,
            Some(route.if_name.clone()),
            ConflictCategory::VpnRoute,
        )
    }));
    host.retain(|(network, _, _)| network.prefix_len() != 0);
    let owned: Vec<ipnet::Ipv4Net> = owned_routes
        .iter()
        .map(|route| route.dest)
        .chain(
            node.direct
                .values()
                .map(|runtime| ipnet::Ipv4Net::from(runtime.state.self_record.ipv4)),
        )
        .collect();
    let plans: Vec<(uuid::Uuid, String, ipnet::Ipv4Net)> = networks
        .iter()
        .map(|d| {
            (
                d.network_id,
                d.network_name.clone(),
                d.genesis.address_plan.peer_cidr,
            )
        })
        .collect();
    let mut all = Vec::new();
    let mut by_category: HashMap<&'static str, usize> = HashMap::new();
    for d in &networks {
        let conflicts = detect_conflicts(
            d.network_id,
            &d.network_name,
            &d.genesis.address_plan,
            &plans,
            &host,
            &owned,
        );
        for c in &conflicts {
            *by_category.entry(category_label(c.category)).or_insert(0) += 1;
            tracing::warn!(
                network = %c.network_name,
                network_id = %c.network_id,
                peer_cidr = %c.peer_cidr,
                conflicting = %c.conflicting_prefix,
                interface = ?c.interface,
                category = ?c.category,
                "Direct address conflict; network degraded"
            );
        }
        all.extend(conflicts);
    }
    for category in [
        "active_direct_plan",
        "lan_prefix",
        "vpn_route",
        "special_use",
    ] {
        metrics.direct_conflict(
            category,
            by_category.get(category).copied().unwrap_or(0) as f64,
        );
    }
    metrics.direct_health(all.is_empty());
    all
}
