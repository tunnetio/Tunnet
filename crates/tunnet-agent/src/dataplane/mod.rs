//! Mesh DATAGRAM dataplane: TUN I/O, one peer worker, `tunnet/tunnel/2`.

mod frame;
mod peer;
mod tun;

pub use peer::{PeerDeps, TunnelHub};
pub use tun::{TUN_WRITE_QUEUE, build_tun_multi, run_reader, run_writer};

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tun_rs::AsyncDevice;
use tunnet_core::direct::{FirewallEngine, SpoofTracker};
use tunnet_core::{AclEngine, RoutingTable, TransportAuth, TunnelMesh};
use uuid::Uuid;

use crate::metrics::AgentMetrics;

pub struct GenerationSpawn {
    pub tun: Arc<AsyncDevice>,
    pub cancel: CancellationToken,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub direct_auth: Option<tunnet_core::direct::AuthCache>,
    pub transport_auth: Option<TransportAuth>,
    pub metrics: AgentMetrics,
    pub mesh: TunnelMesh,
    pub mtu: u16,
    pub endpoint: iroh::Endpoint,
    pub local_id: iroh::EndpointId,
    pub on_unexpected_end: Box<dyn FnOnce() + Send + 'static>,
}

pub struct GenerationTasks {
    pub hub: TunnelHub,
    pub reader: tokio::task::JoinHandle<()>,
    pub writer: tokio::task::JoinHandle<()>,
}

pub fn spawn_generation(spawn: GenerationSpawn) -> GenerationTasks {
    let GenerationSpawn {
        tun,
        cancel,
        routes,
        acl,
        firewalls,
        spoofs,
        direct_auth,
        transport_auth,
        metrics,
        mesh,
        mtu,
        endpoint,
        local_id,
        on_unexpected_end,
    } = spawn;

    let (tun_tx, tun_rx) = mpsc::channel(TUN_WRITE_QUEUE);
    let hub = TunnelHub::new(
        PeerDeps {
            local_id,
            endpoint,
            routes: routes.clone(),
            acl: acl.clone(),
            firewalls: firewalls.clone(),
            spoofs,
            direct_auth,
            transport_auth,
            metrics: metrics.clone(),
            mesh: mesh.clone(),
            tun_tx: tun_tx.clone(),
            mtu,
        },
        cancel.clone(),
    );
    hub.reconcile();

    let reader_cancel = cancel.clone();
    let reader_hub = hub.clone();
    let reader_tun = tun.clone();
    let reader_metrics = metrics.clone();
    let reader_mesh = mesh.clone();
    let unexpected = on_unexpected_end;
    let unexpected_cancel = cancel.clone();
    let reader = tokio::spawn(async move {
        let result = run_reader(tun::ReaderDeps {
            tun: reader_tun,
            hub: reader_hub,
            routes,
            acl,
            firewalls,
            metrics: reader_metrics,
            mesh: reader_mesh,
            tun_tx,
            mtu,
            cancel: reader_cancel.clone(),
        })
        .await;
        if let Err(e) = result {
            tracing::error!(?e, "TUN reader exited");
            if !unexpected_cancel.is_cancelled() {
                unexpected();
            }
        }
    });

    let writer_cancel = cancel;
    let writer = tokio::spawn(async move {
        if let Err(e) = run_writer(tun, tun_rx, mesh, metrics, writer_cancel).await {
            tracing::error!(?e, "TUN writer exited");
        }
    });

    GenerationTasks {
        hub,
        reader,
        writer,
    }
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
