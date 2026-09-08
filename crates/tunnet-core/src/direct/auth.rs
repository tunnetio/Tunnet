//! Grant transport authentication for Direct mode.
//!
//! Existing members authenticate over [`AUTH_ALPN`] with a signed [`NetworkGrant`].
//! Join and connect use dedicated ALPNs; this protocol is not an RPC channel.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, RecvStream, SendStream,
    Side,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{CONNECT_ALPN, DOCS_ALPN, GOSSIP_ALPN, JOIN_ALPN};
use crate::direct::grants::{NetworkGrant, verify_grant, verifying_key_from_hex};

/// Wire version: grant-only transport auth.
pub const AUTH_ALPN: &[u8] = b"tunnet/direct-auth/4";

/// ALPNs that must work before Grant AUTH so membership can join/sync.
fn is_bootstrap_alpn(alpn: &[u8]) -> bool {
    alpn == AUTH_ALPN
        || alpn == JOIN_ALPN
        || alpn == CONNECT_ALPN
        || alpn == DOCS_ALPN
        || alpn == GOSSIP_ALPN
        || alpn == iroh_blobs::ALPN
}

/// Peers that completed auth, keyed per network.
#[derive(Clone, Default)]
pub struct AuthCache {
    /// endpoint_hex → set of network_ids
    inner: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    /// Bumped on every insert/remove so connection state can retry on change, not on timers.
    version: Arc<AtomicU64>,
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, endpoint_hex: impl Into<String>, network_id: Uuid) {
        let mut g = self.inner.lock();
        let changed = g.entry(endpoint_hex.into()).or_default().insert(network_id);
        drop(g);
        if changed {
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Authenticated for any joined network.
    pub fn contains(&self, endpoint_hex: &str) -> bool {
        self.inner
            .lock()
            .get(endpoint_hex)
            .is_some_and(|s| !s.is_empty())
    }

    pub fn contains_network(&self, endpoint_hex: &str, network_id: Uuid) -> bool {
        self.inner
            .lock()
            .get(endpoint_hex)
            .is_some_and(|s| s.contains(&network_id))
    }

    pub fn networks_for(&self, endpoint_hex: &str) -> Vec<Uuid> {
        self.inner
            .lock()
            .get(endpoint_hex)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn remove(&self, endpoint_hex: &str) {
        if self.inner.lock().remove(endpoint_hex).is_some() {
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn remove_network(&self, endpoint_hex: &str, network_id: Uuid) {
        let mut g = self.inner.lock();
        let mut changed = false;
        if let Some(set) = g.get_mut(endpoint_hex) {
            changed = set.remove(&network_id);
            if set.is_empty() {
                g.remove(endpoint_hex);
            }
        }
        drop(g);
        if changed {
            self.version.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }
}

/// Direct transport gate: Grant AUTH membership only, never L3/L4 policy.
/// Docs / Gossip / Blobs / Join / Connect are the membership bootstrap plane.
#[derive(Clone)]
pub struct DirectAuthHook {
    auth: AuthCache,
}

impl DirectAuthHook {
    pub fn new(auth: AuthCache) -> Self {
        Self { auth }
    }
}

impl std::fmt::Debug for DirectAuthHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectAuthHook").finish_non_exhaustive()
    }
}

impl EndpointHooks for DirectAuthHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let peer_hex = format!("{}", remote_addr.id);
        if is_bootstrap_alpn(alpn) {
            return BeforeConnectOutcome::Accept;
        }
        if self.auth.contains(&peer_hex) {
            BeforeConnectOutcome::Accept
        } else {
            tracing::debug!(%peer_hex, "outbound connect blocked (not authenticated)");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }
        let peer_hex = format!("{}", conn.remote_id());
        let alpn = conn.alpn();
        if is_bootstrap_alpn(alpn) {
            return AfterHandshakeOutcome::Accept;
        }
        if self.auth.contains(&peer_hex) {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::debug!(%peer_hex, "inbound connection blocked (not authenticated)");
            AfterHandshakeOutcome::Reject {
                error_code: crate::transport_auth::CLOSE_AUTH_REQUIRED.into(),
                reason: crate::transport_auth::CLOSE_AUTH_REQUIRED_REASON.to_vec(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClientHello {
    pub grant: NetworkGrant,
}

type ResolveCoordVkFn = dyn Fn(Uuid) -> Option<VerifyingKey> + Send + Sync;
type ResolveMinEpochFn = dyn Fn(Uuid) -> u64 + Send + Sync;
type IsRevokedFn = dyn Fn(Uuid, &str) -> bool + Send + Sync;

pub struct AuthServerContext {
    pub resolve_coord_vk: Arc<ResolveCoordVkFn>,
    pub resolve_min_epoch: Arc<ResolveMinEpochFn>,
    pub is_revoked: Arc<IsRevokedFn>,
}

pub type SharedAuthServerContext = Arc<AuthServerContext>;

async fn write_frame(send: &mut SendStream, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(data).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        anyhow::bail!("auth frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        recv.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn write_response(send: &mut SendStream, ok: bool) -> anyhow::Result<()> {
    write_frame(send, if ok { b"ok" } else { b"no" }).await
}

/// Client side: authenticate with a network grant, then close.
pub async fn run_auth_client(
    conn: &Connection,
    grant: NetworkGrant,
    _local_endpoint_hex: &str,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    let payload = serde_json::to_vec(&AuthClientHello { grant })?;
    write_frame(&mut send, &payload).await?;
    send.finish()?;
    let resp = read_frame(&mut recv, 64).await?;
    if resp.as_slice() != b"ok" {
        anyhow::bail!("auth rejected by peer");
    }
    Ok(())
}

/// Server handshake: verify signed grant for claimed network, then close.
pub async fn run_auth_server(
    conn: &Connection,
    ctx: &AuthServerContext,
    _self_endpoint_hex: &str,
    auth: &AuthCache,
) -> anyhow::Result<(String, Uuid)> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let remote_hex = format!("{}", conn.remote_id());
    let frame = read_frame(&mut recv, 64 * 1024).await?;
    let hello: AuthClientHello = serde_json::from_slice(&frame).context("auth hello json")?;
    let grant = hello.grant;
    let network_id = grant.network_id;

    let ok = if grant.endpoint_id != remote_hex || (ctx.is_revoked)(network_id, &grant.endpoint_id)
    {
        false
    } else if let Some(vk) = (ctx.resolve_coord_vk)(network_id) {
        let min_epoch = (ctx.resolve_min_epoch)(network_id);
        verify_grant(&vk, &grant, min_epoch).is_ok()
    } else {
        false
    };

    if !ok {
        write_response(&mut send, false).await.ok();
        anyhow::bail!("auth verification failed");
    }

    write_response(&mut send, true).await?;
    send.finish()?;
    let _ = send.stopped().await;
    auth.insert(remote_hex.clone(), network_id);
    Ok((remote_hex, network_id))
}

/// Build server auth context from live docs membership.
pub fn build_auth_server_context(
    docs: &std::collections::HashMap<Uuid, crate::direct::membership::DocsMembership>,
) -> SharedAuthServerContext {
    let docs = Arc::new(docs.clone());
    Arc::new(AuthServerContext {
        resolve_coord_vk: Arc::new({
            let docs = docs.clone();
            move |nid| {
                docs.get(&nid)
                    .and_then(|d| verifying_key_from_hex(d.coordinator_verifying_key()).ok())
            }
        }),
        resolve_min_epoch: Arc::new({
            let docs = docs.clone();
            move |nid| docs.get(&nid).map(|d| d.network_epoch()).unwrap_or(0)
        }),
        is_revoked: Arc::new({
            let docs = docs.clone();
            move |nid, eid| {
                docs.get(&nid)
                    .map(|d| d.revoked_snapshot().contains(eid))
                    .unwrap_or(false)
            }
        }),
    })
}
