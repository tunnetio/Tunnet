//! Inbound ALPN demux via iroh [`Router`] + [`ProtocolHandler`].
//!
//! The Router owns `endpoint.accept()` so the agent must not run a parallel accept loop.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tunnet_common::local_api::LocalEvent;
use tunnet_common::ws::ClientMsg;
use tunnet_common::{RECORDING_ALPN, SEND_ALPN, TUNNEL_ALPN};
use tunnet_core::Docs;
use tunnet_core::direct::{
    AUTH_ALPN, AuthCache, CONNECT_ALPN, DOCS_ALPN, DirectAuthority, DocsMembership, GOSSIP_ALPN,
    JOIN_ALPN, SharedAuthServerContext, run_auth_server,
};
use tunnet_core::stream::{StreamHandler, StreamProtocolHandler, TUNNEL_STREAM_ALPN};
use tunnet_core::{AclEngine, RoutingTable, SendManager, SignedClient, StatePaths};
use uuid::Uuid;

use crate::actors::dataplane::PublishedPlane;
use crate::recorder::{RecordingStore, serve_recording_connection};

pub struct AcceptDeps {
    pub endpoint: iroh::Endpoint,
    pub routes: RoutingTable,
    pub acl: AclEngine,
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
    pub paths: StatePaths,
    pub join_authorities: HashMap<Uuid, (Arc<DirectAuthority>, DocsMembership)>,
    pub agent_gossip: Option<iroh_gossip::net::Gossip>,
    pub shared_docs: Option<Docs>,
    pub events: tokio::sync::broadcast::Sender<LocalEvent>,
}

/// Spawn the unified ALPN router. Keep the returned [`Router`] alive for the process lifetime.
pub fn spawn(deps: AcceptDeps) -> Router {
    let tunnel = TunnelHandler { tun: deps.tun };
    let stream = StreamProtocolHandler::new(deps.stream_handler);
    let auth_server_ctx = deps.auth_server_ctx.clone();
    let auth = AuthHandler {
        direct_auth: deps.direct_auth.clone(),
        auth_server_ctx: auth_server_ctx.clone(),
        self_endpoint_id: deps.self_endpoint_id.clone(),
    };
    let join = JoinHandler {
        authorities: deps.join_authorities,
        auth: deps.direct_auth.clone(),
        routes: deps.routes.clone(),
        acl: deps.acl.clone(),
        events: deps.events,
    };
    let connect = ConnectHandler {
        auth_server_ctx,
        paths: deps.paths.clone(),
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
    builder = builder.accept(JOIN_ALPN, join);
    builder = builder.accept(CONNECT_ALPN, connect);
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
}

impl fmt::Debug for TunnelHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for TunnelHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let Some(plane) = self.tun.load_full() else {
            tracing::debug!("tunnel ALPN ignored (data plane down)");
            conn.close(1u32.into(), b"dataplane_down");
            return Ok(());
        };
        if plane.cancel.is_cancelled() {
            conn.close(1u32.into(), b"dataplane_down");
            return Ok(());
        }
        plane.hub.accept(conn);
        Ok(())
    }
}

#[derive(Clone)]
struct AuthHandler {
    direct_auth: Option<AuthCache>,
    auth_server_ctx: Option<SharedAuthServerContext>,
    self_endpoint_id: String,
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
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(?e, "direct auth handshake failed");
                conn.close(401u32.into(), b"auth_failed");
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct JoinHandler {
    authorities: HashMap<Uuid, (Arc<DirectAuthority>, DocsMembership)>,
    auth: Option<AuthCache>,
    routes: RoutingTable,
    acl: AclEngine,
    events: tokio::sync::broadcast::Sender<LocalEvent>,
}

impl fmt::Debug for JoinHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for JoinHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if self.authorities.is_empty() {
            conn.close(0u32.into(), b"not_coordinator");
            return Ok(());
        }
        let nets: Vec<(DirectAuthority, DocsMembership)> = self
            .authorities
            .values()
            .map(|(a, d)| ((**a).clone(), d.clone()))
            .collect();
        match tunnet_core::direct::run_join_server_dispatch(&conn, &nets).await {
            Ok(resp) => {
                if let (Some(auth), tunnet_core::direct::JoinStatus::Admitted, Some(adm)) =
                    (&self.auth, resp.status, resp.admission.as_ref())
                    && let Some((_, docs)) = self.authorities.get(&adm.genesis.network_id)
                {
                    let policy = (**self.acl.bundle.load()).clone();
                    docs.project_runtime(auth, &self.routes, &self.acl, &policy);
                }
                if resp.status == tunnet_core::direct::JoinStatus::Pending
                    && let Some(network_id) = resp.network_id
                {
                    let _ = self.events.send(LocalEvent::DirectJoinRequested {
                        network_id: network_id.to_string(),
                        peer_id: format!("{}", conn.remote_id()),
                    });
                }
                conn.close(0u32.into(), b"join_done");
            }
            Err(e) => {
                tracing::debug!(?e, "direct join failed");
                conn.close(401u32.into(), b"join_failed");
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ConnectHandler {
    auth_server_ctx: Option<SharedAuthServerContext>,
    paths: StatePaths,
}

impl fmt::Debug for ConnectHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for ConnectHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let Some(ctx) = &self.auth_server_ctx else {
            conn.close(0u32.into(), b"not_direct");
            return Ok(());
        };
        let remote_id = format!("{}", conn.remote_id());
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(?e, "connect accept_bi failed");
                conn.close(1u32.into(), b"connect_failed");
                return Ok(());
            }
        };
        let mut len_buf = [0u8; 4];
        if recv.read_exact(&mut len_buf).await.is_err() {
            conn.close(1u32.into(), b"bad_request");
            return Ok(());
        }
        let n = u32::from_be_bytes(len_buf) as usize;
        if n > 64 * 1024 {
            conn.close(1u32.into(), b"too_large");
            return Ok(());
        }
        let mut body = vec![0u8; n];
        if recv.read_exact(&mut body).await.is_err() {
            conn.close(1u32.into(), b"bad_request");
            return Ok(());
        }
        let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let grant: tunnet_core::direct::NetworkGrant = match serde_json::from_value(
            req.get("grant").cloned().unwrap_or(serde_json::Value::Null),
        ) {
            Ok(g) => g,
            Err(_) => {
                conn.close(401u32.into(), b"missing_grant");
                return Ok(());
            }
        };
        if grant.endpoint_id != remote_id || (ctx.is_revoked)(grant.network_id, &grant.endpoint_id)
        {
            conn.close(401u32.into(), b"grant_denied");
            return Ok(());
        }
        let Some(vk) = (ctx.resolve_coord_vk)(grant.network_id) else {
            conn.close(401u32.into(), b"unknown_network");
            return Ok(());
        };
        let min_epoch = (ctx.resolve_min_epoch)(grant.network_id);
        if tunnet_core::direct::verify_grant(&vk, &grant, min_epoch).is_err() {
            conn.close(401u32.into(), b"grant_denied");
            return Ok(());
        }
        let allowlist = tunnet_core::agent_config::load_connect_allowlist(&self.paths);
        let (hostname, self_ipv4) = {
            match tunnet_core::PersistedState::try_load(&self.paths)
                .ok()
                .flatten()
                .as_ref()
                .and_then(|s| s.direct_by_id(grant.network_id))
            {
                Some(d) => (d.hostname.clone(), d.self_record.ipv4),
                None => {
                    conn.close(401u32.into(), b"unknown_network");
                    return Ok(());
                }
            }
        };
        let msg_type = req.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if msg_type == "connect_accepted" {
            conn.close(0u32.into(), b"ok");
            return Ok(());
        }
        match tunnet_core::direct::connect::handle_inbound_connect(
            &self.paths,
            &remote_id,
            &body,
            &allowlist,
            &hostname,
            self_ipv4,
        )
        .await
        {
            Ok((_, resp_bytes)) => {
                let _ = send
                    .write_all(&(resp_bytes.len() as u32).to_be_bytes())
                    .await;
                let _ = send.write_all(&resp_bytes).await;
                let _ = send.finish();
                conn.close(0u32.into(), b"ok");
            }
            Err(e) => {
                tracing::debug!(?e, "connect handle failed");
                conn.close(1u32.into(), b"connect_failed");
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
