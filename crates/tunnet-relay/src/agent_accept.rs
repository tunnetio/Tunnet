//! Accept agent QUIC connections (RELAY_ALPN) and register reverse tunnels.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use iroh::Endpoint;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tokio::io::{AsyncBufReadExt, BufReader};
use tunnet_common::RELAY_ALPN;
use tunnet_common::relay::RelayCtrl;
use tunnet_common::{PortMapping, RedirectRule};

use crate::registry::{TunnelRegistry, TunnelSlot};

/// Spawn the relay ALPN router. Keep the returned [`Router`] alive.
pub fn spawn_acceptor(
    endpoint: Endpoint,
    registry: TunnelRegistry,
    auth_tokens: AuthStore,
) -> Router {
    let handler = RelayHandler {
        registry,
        auth: auth_tokens,
    };
    tracing::info!("relay QUIC acceptor started");
    Router::builder(endpoint)
        .accept(RELAY_ALPN, handler)
        .spawn()
}

#[derive(Clone)]
struct RelayHandler {
    registry: TunnelRegistry,
    auth: AuthStore,
}

impl fmt::Debug for RelayHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for RelayHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if let Err(e) = handle_agent(conn, self.registry.clone(), self.auth.clone()).await {
            tracing::debug!(?e, "agent session ended");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TunnelAuth {
    pub tunnel_id: String,
    pub auth_token: String,
    pub local_port: u16,
    pub protocol: String,
    pub basic_auth_user: Option<String>,
    pub basic_auth_password_hash: Option<String>,
    pub redirect_rules: Vec<RedirectRule>,
    pub port_mappings: Vec<PortMapping>,
}

/// Expected auth tokens + tunnel metadata keyed by subdomain (from CP heartbeat).
#[derive(Clone, Default)]
pub struct AuthStore {
    inner: Arc<dashmap::DashMap<String, TunnelAuth>>,
}

impl AuthStore {
    pub fn insert(&self, subdomain: &str, auth: TunnelAuth) {
        self.inner.insert(subdomain.to_ascii_lowercase(), auth);
    }

    pub fn get(&self, subdomain: &str) -> Option<TunnelAuth> {
        self.inner
            .get(&subdomain.to_ascii_lowercase())
            .map(|e| e.clone())
    }

    pub fn verify(&self, subdomain: &str, token: &str) -> bool {
        match self.inner.get(&subdomain.to_ascii_lowercase()) {
            Some(expected) => expected.auth_token.as_str() == token,
            // Open mode when empty: accept reasonably long tokens (dev / pre-seeded).
            None => self.inner.is_empty() && token.len() >= 16,
        }
    }

    pub fn retain_subdomains(&self, keep: &[String]) {
        let keep_lower: Vec<String> = keep.iter().map(|s| s.to_ascii_lowercase()).collect();
        self.inner.retain(|k, _| keep_lower.iter().any(|x| x == k));
    }
}

async fn handle_agent(
    conn: Connection,
    registry: TunnelRegistry,
    auth: AuthStore,
) -> anyhow::Result<()> {
    let (mut send, recv) = conn.accept_bi().await.context("accept control bi")?;
    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line))
        .await
        .context("auth timeout")??;

    let ctrl = RelayCtrl::from_line(&line)?;
    let RelayCtrl::Register {
        tunnel_id,
        subdomain,
        auth_token,
        local_port,
        protocol,
    } = ctrl
    else {
        write_ctrl(
            &mut send,
            &RelayCtrl::Error {
                message: "expected register".into(),
            },
        )
        .await?;
        bail!("expected register on control stream");
    };

    if !auth.verify(&subdomain, &auth_token) {
        write_ctrl(
            &mut send,
            &RelayCtrl::Error {
                message: "invalid auth token".into(),
            },
        )
        .await?;
        bail!("auth failed for subdomain {subdomain}");
    }

    // Pre-seed / refresh token so reconnects work when CP pushed auth already.
    let meta = auth.get(&subdomain);
    auth.insert(
        &subdomain,
        TunnelAuth {
            tunnel_id: tunnel_id.clone(),
            auth_token: auth_token.clone(),
            local_port,
            protocol: protocol.clone(),
            basic_auth_user: meta.as_ref().and_then(|m| m.basic_auth_user.clone()),
            basic_auth_password_hash: meta
                .as_ref()
                .and_then(|m| m.basic_auth_password_hash.clone()),
            redirect_rules: meta
                .as_ref()
                .map(|m| m.redirect_rules.clone())
                .unwrap_or_default(),
            port_mappings: meta
                .as_ref()
                .map(|m| m.port_mappings.clone())
                .unwrap_or_default(),
        },
    );

    write_ctrl(&mut send, &RelayCtrl::Ok).await?;

    let slot = Arc::new(TunnelSlot {
        tunnel_id: tunnel_id.clone(),
        subdomain: subdomain.clone(),
        local_port,
        protocol,
        conn: parking_lot::Mutex::new(Some(conn.clone())),
    });
    registry.insert(slot.clone());
    tracing::info!(%subdomain, %tunnel_id, local_port, "agent tunnel registered");

    let mut ping = tokio::time::interval(Duration::from_secs(25));
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if write_ctrl(&mut send, &RelayCtrl::Ping).await.is_err() {
                    break;
                }
            }
            result = read_ctrl(&mut reader) => {
                match result {
                    Ok(Some(RelayCtrl::Ping)) => {
                        let _ = write_ctrl(&mut send, &RelayCtrl::Pong).await;
                    }
                    Ok(Some(RelayCtrl::Pong)) => {}
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }

    registry.remove_tunnel(&tunnel_id);
    *slot.conn.lock() = None;
    tracing::info!(%subdomain, %tunnel_id, "agent tunnel disconnected");
    Ok(())
}

async fn write_ctrl(send: &mut SendStream, msg: &RelayCtrl) -> anyhow::Result<()> {
    send.write_all(&msg.to_line()?).await?;
    Ok(())
}

async fn read_ctrl(reader: &mut BufReader<RecvStream>) -> anyhow::Result<Option<RelayCtrl>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(RelayCtrl::from_line(&line)?))
}
