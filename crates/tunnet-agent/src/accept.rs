//! Inbound ALPN demux via iroh [`Router`] + [`ProtocolHandler`].
//!
//! The Router owns `endpoint.accept()` so the agent must not run a parallel accept loop.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tunnet_common::ws::ClientMsg;
use tunnet_common::{RECORDING_ALPN, SEND_ALPN, TUNNEL_ALPN};
use tunnet_core::direct::{
    AUTH_ALPN, AuthCache, DOCS_ALPN, DocsMembership, FirewallEngine, GOSSIP_ALPN, SecretResolver,
    SpoofTracker, run_psk_handshake_server,
};
use tunnet_core::stream::{StreamHandler, StreamProtocolHandler, TUNNEL_STREAM_ALPN};
use tunnet_core::{AclEngine, ConnPool, RoutingTable, SendManager, SignedClient};
use uuid::Uuid;

use crate::dataplane::TunSlot;
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, serve_recording_connection};
use crate::tun_io::{InboundDeps, serve_tunnel_connection};

pub struct AcceptDeps {
    pub endpoint: iroh::Endpoint,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub metrics: AgentMetrics,
    pub tun: TunSlot,
    pub stream_handler: StreamHandler,
    pub cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    pub recording_store: Option<Arc<RecordingStore>>,
    pub signed: Option<SignedClient>,
    pub self_endpoint_id: String,
    pub recorder_enabled: bool,
    pub send: SendManager,
    pub direct_auth: Option<AuthCache>,
    pub secret_resolver: Option<SecretResolver>,
    pub state_dir: PathBuf,
    pub docs: HashMap<Uuid, DocsMembership>,
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub dgram_pool: ConnPool,
    pub agent_gossip: Option<iroh_gossip::net::Gossip>,
    pub ingress: IngressRegistry,
}

/// Spawn the unified ALPN router. Keep the returned [`Router`] alive for the process lifetime.
pub fn spawn(deps: AcceptDeps) -> Router {
    let tunnel = TunnelHandler {
        tun: deps.tun,
        routes: deps.routes,
        acl: deps.acl,
        firewalls: deps.firewalls,
        spoofs: deps.spoofs,
        dgram_pool: deps.dgram_pool,
        metrics: deps.metrics,
        direct_auth: deps.direct_auth.clone(),
        ingress: deps.ingress,
    };
    let stream = StreamProtocolHandler::new(deps.stream_handler);
    let auth = AuthHandler {
        direct_auth: deps.direct_auth.clone(),
        secret_resolver: deps.secret_resolver,
        self_endpoint_id: deps.self_endpoint_id.clone(),
        state_dir: deps.state_dir,
        docs: deps.docs.clone(),
    };
    let docs = DocsHandler {
        direct_auth: deps.direct_auth.clone(),
        docs: deps.docs.clone(),
    };
    let gossip = GossipHandler {
        direct_auth: deps.direct_auth.clone(),
        docs: deps.docs,
        agent_gossip: deps.agent_gossip,
    };
    let recording = RecordingHandler {
        enabled: deps.recorder_enabled,
        store: deps.recording_store,
        cp_tx: deps.cp_tx,
        signed: deps.signed,
        self_endpoint_id: deps.self_endpoint_id,
    };
    let send = SendOfferHandler {
        send: deps.send.clone(),
    };
    let blobs = BlobsHandler {
        send: deps.send,
        direct_auth: deps.direct_auth,
    };

    let mut builder = Router::builder(deps.endpoint);
    builder = builder.accept(TUNNEL_ALPN, tunnel);
    builder = builder.accept(TUNNEL_STREAM_ALPN, stream);
    builder = builder.accept(AUTH_ALPN, auth);
    builder = builder.accept(DOCS_ALPN, docs);
    builder = builder.accept(GOSSIP_ALPN, gossip);
    builder = builder.accept(RECORDING_ALPN, recording);
    builder = builder.accept(SEND_ALPN, send);
    builder = builder.accept(iroh_blobs::ALPN, blobs);

    tracing::info!("unified ALPN accept router started");
    builder.spawn()
}

fn preferred_network(auth: &Option<AuthCache>, peer: &str) -> Option<Uuid> {
    auth.as_ref()
        .and_then(|a| a.networks_for(peer).into_iter().next())
}

#[derive(Clone)]
struct TunnelHandler {
    tun: TunSlot,
    routes: RoutingTable,
    acl: AclEngine,
    firewalls: HashMap<Uuid, FirewallEngine>,
    spoofs: HashMap<Uuid, SpoofTracker>,
    dgram_pool: ConnPool,
    metrics: AgentMetrics,
    direct_auth: Option<AuthCache>,
    ingress: IngressRegistry,
}

impl fmt::Debug for TunnelHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for TunnelHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if self.tun.read().await.device.is_none() {
            tracing::debug!("TUNNEL_ALPN ignored (data plane down)");
            conn.close(1u32.into(), b"dataplane_down");
            return Ok(());
        }
        let peer = conn.remote_id();
        // Install into pool first so outbound send and ingress share one QUIC conn.
        if !self.dgram_pool.adopt(peer, conn.clone()).await {
            tracing::debug!(%peer, "accept superseded by live dial; closing");
            conn.close(0u32.into(), b"superseded");
            return Ok(());
        }
        if !self.ingress.try_spawn(peer, {
            let conn = conn.clone();
            let tun = self.tun.clone();
            let routes = self.routes.clone();
            let acl = self.acl.clone();
            let firewalls = self.firewalls.clone();
            let spoofs = self.spoofs.clone();
            let dgram_pool = self.dgram_pool.clone();
            let metrics = self.metrics.clone();
            let direct_auth = self.direct_auth.clone();
            async move {
                serve_tunnel_connection(InboundDeps {
                    conn,
                    tun,
                    routes,
                    acl,
                    firewalls,
                    spoofs,
                    pool: Some(dgram_pool),
                    metrics,
                    direct_auth,
                })
                .await;
            }
        }) {
            tracing::debug!(%peer, "accept ingress skipped (reader already active)");
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AuthHandler {
    direct_auth: Option<AuthCache>,
    secret_resolver: Option<SecretResolver>,
    self_endpoint_id: String,
    state_dir: PathBuf,
    docs: HashMap<Uuid, DocsMembership>,
}

impl fmt::Debug for AuthHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for AuthHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (Some(auth), Some(resolver)) = (self.direct_auth.clone(), self.secret_resolver.clone())
        else {
            tracing::debug!("AUTH_ALPN ignored (not in Direct mode)");
            conn.close(0u32.into(), b"not_direct");
            return Ok(());
        };
        match run_psk_handshake_server(&conn, resolver, &self.self_endpoint_id, &auth).await {
            Ok((_peer, network_id)) => {
                let docs_ref = self.docs.get(&network_id);
                if let Err(e) = crate::cmds_direct::try_handle_post_auth(
                    &conn,
                    &self.state_dir,
                    docs_ref,
                    &self.self_endpoint_id,
                    network_id,
                )
                .await
                {
                    tracing::warn!(?e, %network_id, "post-auth handle failed");
                }
                conn.close(0u32.into(), b"done");
            }
            Err(e) => {
                tracing::debug!(?e, "direct auth handshake failed");
                conn.close(401u32.into(), b"auth_failed");
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct DocsHandler {
    direct_auth: Option<AuthCache>,
    docs: HashMap<Uuid, DocsMembership>,
}

impl fmt::Debug for DocsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DocsHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for DocsHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = format!("{}", conn.remote_id());
        let preferred = preferred_network(&self.direct_auth, &peer);
        if let Some(nid) = preferred
            && let Some(d) = self.docs.get(&nid)
        {
            d.accept_docs(conn).await;
        } else {
            tracing::debug!(
                %peer,
                preferred = ?preferred,
                "DOCS_ALPN skipped (no preferred network docs)"
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct GossipHandler {
    direct_auth: Option<AuthCache>,
    docs: HashMap<Uuid, DocsMembership>,
    agent_gossip: Option<iroh_gossip::net::Gossip>,
}

impl fmt::Debug for GossipHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GossipHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for GossipHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = format!("{}", conn.remote_id());
        let preferred = preferred_network(&self.direct_auth, &peer);
        if let Some(nid) = preferred
            && let Some(d) = self.docs.get(&nid)
        {
            d.accept_gossip(conn).await;
        } else if let Some(g) = &self.agent_gossip {
            if let Err(e) = g.handle_connection(conn).await {
                tracing::debug!(?e, "agent gossip accept ended");
            }
        } else {
            tracing::debug!(
                %peer,
                preferred = ?preferred,
                "GOSSIP_ALPN skipped (no preferred network / agent gossip)"
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RecordingHandler {
    enabled: bool,
    store: Option<Arc<RecordingStore>>,
    cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    signed: Option<SignedClient>,
    self_endpoint_id: String,
}

impl fmt::Debug for RecordingHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingHandler")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for RecordingHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if !self.enabled {
            tracing::debug!("ignoring recording ALPN (recorder not enabled)");
            return Ok(());
        }
        if let Some(store) = &self.store {
            serve_recording_connection(
                conn,
                store.clone(),
                self.cp_tx.clone(),
                self.signed.clone(),
                self.self_endpoint_id.clone(),
            )
            .await;
        } else {
            tracing::warn!("recording ALPN accepted but store is missing");
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SendOfferHandler {
    send: SendManager,
}

impl fmt::Debug for SendOfferHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendOfferHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for SendOfferHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.send.handle_offer_connection(conn).await;
        Ok(())
    }
}

#[derive(Clone)]
struct BlobsHandler {
    send: SendManager,
    direct_auth: Option<AuthCache>,
}

impl fmt::Debug for BlobsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobsHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for BlobsHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if let Some(auth) = self.direct_auth.as_ref() {
            let peer = format!("{}", conn.remote_id());
            if auth.contains(&peer) {
                self.send.handle_blobs_connection_trusted(conn).await;
                return Ok(());
            }
        }
        self.send.handle_blobs_connection(conn).await;
        Ok(())
    }
}
