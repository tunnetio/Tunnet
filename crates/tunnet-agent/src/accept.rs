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
use tunnet_core::Docs;
use tunnet_core::direct::{
    AUTH_ALPN, AuthCache, DOCS_ALPN, DocsMembership, GOSSIP_ALPN, SharedAuthServerContext,
    SpoofTracker, run_auth_server,
};
use tunnet_core::stream::{StreamHandler, StreamProtocolHandler, TUNNEL_STREAM_ALPN};
use tunnet_core::{AclEngine, ConnPool, PolicyRuntime, RoutingTable, SendManager, SignedClient};
use uuid::Uuid;

use crate::actors::dataplane::PublishedPlane;
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, serve_recording_connection};
use crate::tun_io::{InboundDeps, serve_tunnel_connection};

pub struct AcceptDeps {
    pub endpoint: iroh::Endpoint,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub runtime: PolicyRuntime,
    pub metrics: AgentMetrics,
    pub tun: PublishedPlane,
    pub stream_handler: StreamHandler,
    pub cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    pub recording_store: Option<Arc<RecordingStore>>,
    pub signed: Option<SignedClient>,
    pub self_endpoint_id: String,
    pub recorder_enabled: bool,
    pub send: SendManager,
    pub direct_auth: Option<AuthCache>,
    pub auth_server_ctx: Option<SharedAuthServerContext>,
    pub state_dir: PathBuf,
    pub docs: HashMap<Uuid, DocsMembership>,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub dgram_pool: ConnPool,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub agent_gossip: Option<iroh_gossip::net::Gossip>,
    pub shared_docs: Option<Docs>,
    pub ingress: IngressRegistry,
}

/// Spawn the unified ALPN router. Keep the returned [`Router`] alive for the process lifetime.
pub fn spawn(deps: AcceptDeps) -> Router {
    let tunnel = TunnelHandler {
        tun: deps.tun,
        routes: deps.routes.clone(),
        acl: deps.acl.clone(),
        runtime: deps.runtime.clone(),
        spoofs: deps.spoofs,
        dgram_pool: deps.dgram_pool,
        bufs: deps.bufs,
        metrics: deps.metrics,
        ingress: deps.ingress,
        direct_auth: deps.direct_auth.clone(),
    };
    let stream = StreamProtocolHandler::new(deps.stream_handler);
    let auth = AuthHandler {
        direct_auth: deps.direct_auth.clone(),
        auth_server_ctx: deps.auth_server_ctx,
        self_endpoint_id: deps.self_endpoint_id.clone(),
        state_dir: deps.state_dir,
        docs: deps.docs.clone(),
        routes: deps.routes,
        acl: deps.acl,
    };
    let docs = DocsHandler {
        shared_docs: deps.shared_docs,
    };
    let gossip = GossipHandler {
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
    // Direct membership sync needs blobs before ACL/AuthCache exist.
    let blobs = BlobsHandler {
        send: deps.send,
        direct_bootstrap: deps.direct_auth.is_some(),
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

#[derive(Clone)]
struct TunnelHandler {
    tun: PublishedPlane,
    routes: RoutingTable,
    acl: AclEngine,
    runtime: PolicyRuntime,
    spoofs: HashMap<Uuid, SpoofTracker>,
    dgram_pool: ConnPool,
    bufs: Arc<tunnet_common::packet::PacketPool>,
    metrics: AgentMetrics,
    ingress: IngressRegistry,
    direct_auth: Option<AuthCache>,
}

impl fmt::Debug for TunnelHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for TunnelHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if self.tun.load_full().is_none() {
            tracing::debug!("tunnel ALPN ignored (data plane down)");
            conn.close(1u32.into(), b"dataplane_down");
            return Ok(());
        }
        let peer = conn.remote_id();

        if !self.dgram_pool.adopt(peer, conn.clone()).await {
            tracing::debug!(%peer, "accept lost tie-break; closing");
            conn.close(0u32.into(), b"tie_break");
            return Ok(());
        }
        self.ingress.force_spawn(peer, {
            let conn = conn.clone();
            let tun = self.tun.clone();
            let routes = self.routes.clone();
            let acl = self.acl.clone();
            let runtime = self.runtime.clone();
            let spoofs = self.spoofs.clone();
            let dgram_pool = self.dgram_pool.clone();
            let bufs = self.bufs.clone();
            let metrics = self.metrics.clone();
            let auth = self.direct_auth.clone();
            async move {
                serve_tunnel_connection(InboundDeps {
                    conn,
                    tun,
                    routes,
                    runtime,
                    acl,
                    spoofs,
                    pool: Some(dgram_pool),
                    bufs,
                    metrics,
                    auth,
                })
                .await;
            }
        });
        Ok(())
    }
}

#[derive(Clone)]
struct AuthHandler {
    direct_auth: Option<AuthCache>,
    auth_server_ctx: Option<SharedAuthServerContext>,
    self_endpoint_id: String,
    state_dir: PathBuf,
    docs: HashMap<Uuid, DocsMembership>,
    routes: RoutingTable,
    acl: AclEngine,
}

impl fmt::Debug for AuthHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for AuthHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (Some(auth), Some(ctx)) = (self.direct_auth.clone(), self.auth_server_ctx.clone())
        else {
            tracing::debug!("AUTH_ALPN ignored (not in Direct mode)");
            conn.close(0u32.into(), b"not_direct");
            return Ok(());
        };
        match run_auth_server(&conn, &ctx, &self.self_endpoint_id, &auth).await {
            Ok((_peer, network_id)) => {
                let docs_ref = self.docs.get(&network_id);
                if let Err(e) = crate::cmds_direct::try_handle_post_auth(
                    &conn,
                    &self.state_dir,
                    docs_ref,
                    &self.self_endpoint_id,
                    network_id,
                    &auth,
                    &self.routes,
                    &self.acl,
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
    shared_docs: Option<Docs>,
}

impl fmt::Debug for DocsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DocsHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for DocsHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = format!("{}", conn.remote_id());
        // Membership sync must work before Grant AUTH (bootstrap plane).
        // Record trust is cryptographic; AuthCache gates the data plane only.
        if let Some(docs) = &self.shared_docs {
            if let Err(e) = docs.accept(conn).await {
                tracing::debug!(%peer, ?e, "docs accept ended");
            }
            return Ok(());
        }
        tracing::debug!(%peer, "DOCS_ALPN skipped (no shared Docs)");
        Ok(())
    }
}

#[derive(Clone)]
struct GossipHandler {
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
        // Gossip carries docs live updates + presence; allow before Grant AUTH.
        if let Some(g) = &self.agent_gossip {
            if let Err(e) = g.handle_connection(conn).await {
                tracing::debug!(%peer, ?e, "gossip accept ended");
            }
            return Ok(());
        }
        tracing::debug!(%peer, "GOSSIP_ALPN skipped (no shared Gossip)");
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
    /// When true, skip ACL so iroh-docs content can sync before membership/AuthCache.
    direct_bootstrap: bool,
}

impl fmt::Debug for BlobsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobsHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for BlobsHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if self.direct_bootstrap {
            self.send.handle_blobs_connection_bootstrap(conn).await;
        } else {
            self.send.handle_blobs_connection(conn).await;
        }
        Ok(())
    }
}
