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
