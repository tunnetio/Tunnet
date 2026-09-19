//! Dataplane helpers (hot-path task spawns).
//!
//! Lifecycle ownership lives in `actors::dataplane::DataPlaneActor`. This
//! module keeps only high-throughput task constructors that must stay plain
//! Tokio: the outbound TUN loop and underlay helpers.

use std::sync::Arc;

use tun_rs::AsyncDevice;
use tunnet_core::{AclEngine, ConnPool, RoutingTable};

use crate::metrics::AgentMetrics;

pub struct OutboundSpawn {
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub pool: ConnPool,
    pub acl: AclEngine,
    pub firewalls: std::collections::HashMap<uuid::Uuid, tunnet_core::direct::FirewallEngine>,
    pub metrics: AgentMetrics,
    pub mtu: u16,
    pub in_tun_dns: Option<std::sync::Arc<tunnet_core::dns::InTun>>,
    /// Called when the loop ends without shutdown (abnormal service death).
    pub on_unexpected_end: Box<dyn FnOnce() + Send + 'static>,
}

pub fn spawn_outbound(spawn: OutboundSpawn) -> tokio::task::JoinHandle<()> {
    let OutboundSpawn {
        tun,
        routes,
        pool,
        acl,
        firewalls,
        metrics,
        mtu,
        in_tun_dns,
        on_unexpected_end,
    } = spawn;
    tokio::spawn(async move {
        if let Err(e) = crate::tun_io::run_outbound(crate::tun_io::OutboundDeps {
            tun,
            routes,
            pool,
            acl,
            firewalls,
            metrics,
            mtu,
            in_tun_dns,
        })
        .await
        {
            tracing::error!(?e, "outbound TUN loop exited");
            on_unexpected_end();
        }
    })
}

/// Resolve IPv4 underlay pins from a control-plane URL (host literal or hostname skip).
#[cfg(not(target_os = "android"))]
pub fn underlay_hosts_from_url(control_url: &str) -> Vec<std::net::Ipv4Addr> {
    let host = control_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>()
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        out.push(ip);
    }
    out
}
