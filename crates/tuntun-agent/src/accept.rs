//! Single inbound accept loop that demuxes connections by ALPN.
//!
//! Multiple concurrent `endpoint.accept()` loops race and drop wrong-ALPN
//! connections. The agent must use exactly one acceptor.

use std::sync::Arc;

use iroh::Endpoint;
use tuntun_common::ws::ClientMsg;
use tuntun_common::{RECORDING_ALPN, SEND_ALPN, SSH_ALPN, TUNNEL_ALPN};
use tuntun_core::direct::{
    AUTH_ALPN, AuthCache, DOCS_ALPN, DocsMembership, GOSSIP_ALPN, run_psk_handshake_server,
};
use tuntun_core::stream::{StreamHandler, TUNNEL_STREAM_ALPN, serve_stream_connection};
use tuntun_core::{AclEngine, ConnPool, RoutingTable, SendManager, SignedClient};

use crate::dataplane::TunSlot;
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, serve_recording_connection};
use crate::ssh::{SshServeDeps, SshSessionRegistry, serve_ssh_connection};
use crate::tun_io::serve_tunnel_connection;

pub struct AcceptDeps {
    pub endpoint: Endpoint,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub metrics: AgentMetrics,
    pub tun: TunSlot,
    pub stream_handler: StreamHandler,
    pub ssh_sessions: SshSessionRegistry,
    pub cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    pub pool: ConnPool,
    pub recording_store: Option<Arc<RecordingStore>>,
    pub signed: Option<SignedClient>,
    pub hostname: String,
    pub network_name: String,
    pub self_endpoint_id: String,
    pub recorder_enabled: bool,
    pub send: SendManager,
    pub direct_auth: Option<AuthCache>,
    pub network_secret: Option<String>,
    pub state_dir: std::path::PathBuf,
    pub docs: Option<DocsMembership>,
}

pub fn spawn(deps: AcceptDeps) {
    tokio::spawn(async move {
        tracing::info!("unified ALPN accept router started");
        while let Some(incoming) = deps.endpoint.accept().await {
            let routes = deps.routes.clone();
            let acl = deps.acl.clone();
            let metrics = deps.metrics.clone();
            let tun = deps.tun.clone();
            let stream_handler = deps.stream_handler.clone();
            let ssh_sessions = deps.ssh_sessions.clone();
            let cp_tx = deps.cp_tx.clone();
            let pool = deps.pool.clone();
            let recording_store = deps.recording_store.clone();
            let signed = deps.signed.clone();
            let hostname = deps.hostname.clone();
            let network_name = deps.network_name.clone();
            let self_endpoint_id = deps.self_endpoint_id.clone();
            let recorder_enabled = deps.recorder_enabled;
            let send = deps.send.clone();
            let direct_auth = deps.direct_auth.clone();
            let network_secret = deps.network_secret.clone();
            let state_dir = deps.state_dir.clone();
            let docs = deps.docs.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(?e, "incoming handshake failed");
                        return;
                    }
                };
                let alpn = conn.alpn();
                if alpn == AUTH_ALPN {
                    if let (Some(auth), Some(secret)) =
                        (direct_auth.clone(), network_secret.clone())
                    {
                        match run_psk_handshake_server(&conn, &secret, &self_endpoint_id, &auth)
                            .await
                        {
                            Ok(_peer) => {
                                if let Err(e) = crate::cmds_direct::try_handle_join_on_auth_conn(
                                    &conn,
                                    &state_dir,
                                    docs.as_ref(),
                                )
                                .await
                                {
                                    tracing::debug!(?e, "post-auth join handle");
                                }
                            }
                            Err(e) => {
                                tracing::debug!(?e, "direct auth handshake failed");
                            }
                        }
                    } else {
                        tracing::debug!("AUTH_ALPN ignored (not in Direct mode)");
                    }
                } else if alpn == DOCS_ALPN {
                    if let Some(docs) = docs {
                        docs.accept_docs(conn).await;
                    } else {
                        tracing::debug!("DOCS_ALPN ignored (not in Direct mode)");
                    }
                } else if alpn == GOSSIP_ALPN {
                    if let Some(docs) = docs {
                        docs.accept_gossip(conn).await;
                    } else {
                        tracing::debug!("GOSSIP_ALPN ignored (Direct docs not ready)");
                    }
                } else if alpn == TUNNEL_STREAM_ALPN {
                    serve_stream_connection(conn, stream_handler).await;
                } else if alpn == TUNNEL_ALPN {
                    let Some(tun_dev) = tun.read().await.clone() else {
                        tracing::debug!("TUNNEL_ALPN ignored (data plane down)");
                        conn.close(1u32.into(), b"dataplane_down");
                        return;
                    };
                    serve_tunnel_connection(conn, tun_dev, routes, acl, metrics).await;
                } else if alpn == SSH_ALPN {
                    serve_ssh_connection(
                        conn,
                        SshServeDeps {
                            routes,
                            acl,
                            sessions: ssh_sessions,
                            cp_tx,
                            pool,
                            store: recording_store,
                            signed,
                            hostname,
                            network_name,
                            self_endpoint_id,
                        },
                    )
                    .await;
                } else if alpn == RECORDING_ALPN {
                    if recorder_enabled {
                        if let Some(store) = recording_store {
                            serve_recording_connection(
                                conn,
                                store,
                                cp_tx,
                                signed,
                                self_endpoint_id,
                            )
                            .await;
                        } else {
                            tracing::warn!("recording ALPN accepted but store is missing");
                        }
                    } else {
                        tracing::debug!("ignoring recording ALPN (recorder not enabled)");
                    }
                } else if alpn == SEND_ALPN {
                    send.handle_offer_connection(conn).await;
                } else if alpn == iroh_blobs::ALPN {
                    if let Some(auth) = direct_auth.as_ref() {
                        let peer = format!("{}", conn.remote_id());
                        if auth.contains(&peer) {
                            send.handle_blobs_connection_trusted(conn).await;
                            return;
                        }
                    }
                    send.handle_blobs_connection(conn).await;
                } else {
                    tracing::debug!(
                        alpn = %String::from_utf8_lossy(alpn),
                        "ignoring unknown ALPN"
                    );
                }
            });
        }
        tracing::error!("unified ALPN accept router exited");
    });
}
