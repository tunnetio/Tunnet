//! Dataplane helpers (hot-path task spawns).
//!
//! Lifecycle ownership lives in `actors::dataplane::DataPlaneActor`. This
//! module keeps only high-throughput task constructors that must stay plain
//! Tokio: the outbound TUN loop and underlay helpers.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tun_rs::AsyncDevice;
use tunnet_common::packet::PacketPool;
use tunnet_core::{PolicyRuntime, RoutingTable};

use crate::endpoint_tx::EndpointTxRegistry;
use crate::metrics::AgentMetrics;
use crate::tun_writer::TunWriterHandle;

pub struct OutboundSpawn {
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub metrics: AgentMetrics,
    pub bufs: Arc<PacketPool>,
    pub mtu: u16,
    pub tx_registry: EndpointTxRegistry,
    pub tun_writer: TunWriterHandle,
    /// Called when the loop ends without shutdown (abnormal service death).
    pub on_unexpected_end: Box<dyn FnOnce() + Send + 'static>,
}

pub fn spawn_outbound(spawn: OutboundSpawn) -> tokio::task::JoinHandle<()> {
    let OutboundSpawn {
        tun,
        routes,
        runtime,
        metrics,
        bufs,
        mtu,
        tx_registry,
        tun_writer,
        on_unexpected_end,
    } = spawn;
    tokio::spawn(async move {
        if let Err(e) = crate::tun_io::run_outbound(crate::tun_io::OutboundDeps {
            tun,
            routes,
            runtime,
            metrics,
            bufs,
            mtu,
            tx_registry,
            tun_writer,
        })
        .await
        {
            tracing::error!(?e, "outbound TUN loop exited");
            on_unexpected_end();
        }
    })
}

/// Resolve IPv4 underlay pins from a control-plane URL (host literal or hostname skip).
pub fn underlay_hosts_from_url(control_url: &str) -> Vec<Ipv4Addr> {
    let host = control_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<Ipv4Addr>()
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        out.push(ip);
    }
    out
}
