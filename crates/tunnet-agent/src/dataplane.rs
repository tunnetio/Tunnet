//! Dataplane helpers (hot-path task spawns).
//!
//! Lifecycle ownership lives in `actors::dataplane::DataPlaneActor`. This
//! module keeps only high-throughput task constructors that must stay plain
//! Tokio: the outbound TUN loop and underlay helpers.

use futures_util::FutureExt;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tun_rs::AsyncDevice;
use tunnet_common::packet::PacketPool;
use tunnet_core::{PolicyRuntime, RoutingTable};

use crate::metrics::AgentMetrics;
use crate::peer_transport::PeerTransports;
use crate::tun_writer::TunWriterHandle;

pub struct OutboundSpawn {
    pub cancel: tokio_util::sync::CancellationToken,
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub runtime: PolicyRuntime,
    pub metrics: AgentMetrics,
    pub bufs: Arc<PacketPool>,
    pub mtu: u16,
    pub transports: PeerTransports,
    pub tun_writer: TunWriterHandle,
    /// Called when the loop ends without shutdown (abnormal service death).
    pub on_unexpected_end: Box<dyn FnOnce() + Send + 'static>,
}

pub fn spawn_outbound(spawn: OutboundSpawn) -> tokio::task::JoinHandle<()> {
    let OutboundSpawn {
        cancel,
        tun,
        routes,
        runtime,
        metrics,
        bufs,
        mtu,
        transports,
        tun_writer,
        on_unexpected_end,
    } = spawn;
    tokio::spawn(async move {
        let run = std::panic::AssertUnwindSafe(crate::tun_io::run_outbound(
            crate::tun_io::OutboundDeps {
                tun,
                routes,
                runtime,
                metrics,
                bufs,
                mtu,
                transports,
                tun_writer,
            },
        ))
        .catch_unwind();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {},
            result = run => {
                tracing::error!(?result, "outbound TUN loop exited unexpectedly");
                on_unexpected_end();
            }
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
