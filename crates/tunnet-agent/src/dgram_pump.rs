//! Dialer-side QUIC datagram pump for the mesh TUN path.

use std::collections::HashMap;
use std::sync::Arc;

use tunnet_core::ConnPool;
use tunnet_core::direct::{AuthCache, FirewallEngine, SpoofTracker};
use tunnet_core::{AclEngine, RoutingTable};
use uuid::Uuid;

use crate::dataplane::TunSlot;
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::tun_io::{InboundDeps, serve_tunnel_connection};

/// When we dial a peer, also read datagrams on that connection.
///
/// The accept path only pumps accepted sockets. With keep-alive, reverse traffic
/// often arrives on the dialed connection - without this, ICMP/TCP replies never
/// reach the local TUN even though `tunnet ping` (streams) works.
///
/// The pool never replaces a live accepted conn with a dialed one (see
/// [`ConnPool::get_alpn`]), so when this hook runs the dialed conn is canonical
/// and we must own the ingress reader for it.
#[allow(clippy::too_many_arguments)]
pub fn install_dialer_datagram_pump(
    pool: &ConnPool,
    tun_slot: TunSlot,
    routes: RoutingTable,
    acl: AclEngine,
    firewalls: HashMap<Uuid, FirewallEngine>,
    spoofs: HashMap<Uuid, SpoofTracker>,
    metrics: AgentMetrics,
    direct_auth: Option<AuthCache>,
    ingress: IngressRegistry,
) {
    {
        let pool_for_hook = pool.clone();
        let tun_slot = tun_slot.clone();
        let routes = routes.clone();
        let acl = acl.clone();
        let firewalls = firewalls.clone();
        let spoofs = spoofs.clone();
        let metrics = metrics.clone();
        let direct_auth = direct_auth.clone();
        let ingress = ingress.clone();
        pool.set_tunnel_hook(Arc::new(move |peer, conn| {
            let tun_slot = tun_slot.clone();
            let routes = routes.clone();
            let acl = acl.clone();
            let firewalls = firewalls.clone();
            let spoofs = spoofs.clone();
            let metrics = metrics.clone();
            let direct_auth = direct_auth.clone();
            let pool = pool_for_hook.clone();
            let ingress = ingress.clone();
            ingress.force_spawn(peer, async move {
                if tun_slot.read().await.device.is_none() {
                    return;
                }
                serve_tunnel_connection(InboundDeps {
                    conn,
                    tun: tun_slot,
                    routes,
                    acl,
                    firewalls,
                    spoofs,
                    pool: Some(pool),
                    metrics,
                    direct_auth,
                    install_as_canonical: true,
                })
                .await;
            });
        }));
    }

    {
        let pool_for_hook = pool.clone();
        pool.set_latency_hook(Arc::new(move |peer, conn| {
            let tun_slot = tun_slot.clone();
            let routes = routes.clone();
            let acl = acl.clone();
            let firewalls = firewalls.clone();
            let spoofs = spoofs.clone();
            let metrics = metrics.clone();
            let direct_auth = direct_auth.clone();
            let pool = pool_for_hook.clone();
            let ingress = ingress.clone();
            ingress.force_spawn_latency(peer, async move {
                if tun_slot.read().await.device.is_none() {
                    return;
                }
                serve_tunnel_connection(InboundDeps {
                    conn,
                    tun: tun_slot,
                    routes,
                    acl,
                    firewalls,
                    spoofs,
                    pool: Some(pool),
                    metrics,
                    direct_auth,
                    install_as_canonical: false,
                })
                .await;
            });
        }));
    }
}
