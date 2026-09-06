//! Dialer-side QUIC datagram pump for the mesh TUN path.

use std::collections::HashMap;
use std::sync::Arc;

use tunnet_common::packet::PacketPool;
use tunnet_core::ConnPool;
use tunnet_core::direct::SpoofTracker;
use tunnet_core::{AclEngine, PolicyRuntime, RoutingTable};
use uuid::Uuid;

use crate::actors::dataplane::PublishedPlane;
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::tun_io::{InboundDeps, serve_tunnel_connection};

/// When we dial a peer, also read datagrams on that connection.
///
/// The accept path only pumps accepted sockets. With keep-alive, reverse traffic
/// often arrives on the dialed connection - without this, ICMP/TCP replies never
/// reach the local TUN even though `tunnet ping` (streams) works.
#[allow(clippy::too_many_arguments)]
pub fn install_dialer_datagram_pump(
    pool: &ConnPool,
    tun_slot: PublishedPlane,
    routes: RoutingTable,
    acl: AclEngine,
    runtime: PolicyRuntime,
    spoofs: HashMap<Uuid, SpoofTracker>,
    metrics: AgentMetrics,
    bufs: Arc<PacketPool>,
    ingress: IngressRegistry,
) {
    let pool_for_hook = pool.clone();
    pool.set_tunnel_hook(Arc::new(move |peer, conn| {
        let tun_slot = tun_slot.clone();
        let routes = routes.clone();
        let acl = acl.clone();
        let runtime = runtime.clone();
        let spoofs = spoofs.clone();
        let metrics = metrics.clone();
        let bufs = bufs.clone();
        let pool = pool_for_hook.clone();
        let ingress = ingress.clone();
        ingress.force_spawn(peer, async move {
            if tun_slot.load_full().is_none() {
                return;
            }
            serve_tunnel_connection(InboundDeps {
                conn,
                tun: tun_slot,
                routes,
                runtime,
                acl,
                spoofs,
                pool: Some(pool),
                bufs,
                metrics,
                // Dialer-side readers have no AuthCache handle; membership
                // existence still gates every frame network.
                auth: None,
            })
            .await;
        });
    }));
}
