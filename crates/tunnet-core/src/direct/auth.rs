//! Grant and invite transport authentication for Direct mode.
//!
//! Peers authenticate over [`AUTH_ALPN`] using either a signed [`NetworkGrant`]
//! or an invite bootstrap proof (HMAC over join secret). The claimed `network_id`
//! is bound into the proof so the server verifies against that network only.
//!
//! [`DirectAuthHook`] blocks data-plane ALPNs until the peer holds a verified grant.
//! Docs / Gossip / Blobs are the membership bootstrap plane and are
//! allowed without AuthCache - trust for those is signed records + content keys.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, KeyInit, Mac};
use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, RecvStream, SendStream,
    Side,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use super::{DOCS_ALPN, GOSSIP_ALPN};
use crate::direct::grants::{NetworkGrant, verify_grant, verifying_key_from_hex};

/// Wire version: grant-based auth with invite bootstrap.
pub const AUTH_ALPN: &[u8] = b"tunnet/direct-auth/3";

/// ALPNs that must work before Grant AUTH so membership can sync.
fn is_bootstrap_alpn(alpn: &[u8]) -> bool {
    alpn == AUTH_ALPN || alpn == DOCS_ALPN || alpn == GOSSIP_ALPN || alpn == iroh_blobs::ALPN
}

type HmacSha256 = Hmac<Sha256>;

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
/// Docs / Gossip / Blobs are the membership bootstrap plane and are
/// allowed without AuthCache - trust for those is signed records + content keys.
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthClientMode {
    Invite {
        network_id: Uuid,
        invite_id: String,
        join_secret_hex: String,
    },
    Grant {
        grant: NetworkGrant,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClientHello {
    pub mode: AuthClientMode,
    /// Present for invite bootstrap only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Present for invite bootstrap only (hex HMAC proof).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_proof: Option<String>,
}

type ResolveJoinSecretFn = dyn Fn(Uuid) -> Option<String> + Send + Sync;
type ResolveCoordVkFn = dyn Fn(Uuid) -> Option<VerifyingKey> + Send + Sync;
type ResolveMinEpochFn = dyn Fn(Uuid) -> u64 + Send + Sync;
type IsRevokedFn = dyn Fn(Uuid, &str) -> bool + Send + Sync;

pub struct AuthServerContext {
    pub resolve_join_secret: Arc<ResolveJoinSecretFn>,
    pub resolve_coord_vk: Arc<ResolveCoordVkFn>,
    pub resolve_min_epoch: Arc<ResolveMinEpochFn>,
    pub is_revoked: Arc<IsRevokedFn>,
}

pub type SharedAuthServerContext = Arc<AuthServerContext>;

fn compute_invite_proof(
    join_secret_hex: &str,
    local_hex: &str,
    remote_hex: &str,
    network_id: Uuid,
    nonce: &[u8],
) -> Vec<u8> {
    let secret =
        hex::decode(join_secret_hex).unwrap_or_else(|_| join_secret_hex.as_bytes().to_vec());
    let mut mac = HmacSha256::new_from_slice(&secret).expect("hmac accepts any key length");
    mac.update(local_hex.as_bytes());
    mac.update(b"|");
    mac.update(remote_hex.as_bytes());
    mac.update(b"|");
    mac.update(network_id.as_bytes());
    mac.update(b"|");
    mac.update(nonce);
    mac.finalize().into_bytes().to_vec()
}

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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn write_response(send: &mut SendStream, ok: bool) -> anyhow::Result<()> {
    write_frame(send, if ok { b"ok" } else { b"no" }).await
}

/// Client side: authenticate with invite bootstrap or network grant.
pub async fn run_auth_client(
    conn: &Connection,
    mode: AuthClientMode,
    local_endpoint_hex: &str,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    let remote_hex = format!("{}", conn.remote_id());

    let hello = match mode {
        AuthClientMode::Invite {
            network_id,
            invite_id,
            join_secret_hex,
        } => {
            let nonce: [u8; 32] = rand::random();
            let proof = compute_invite_proof(
                &join_secret_hex,
                local_endpoint_hex,
                &remote_hex,
                network_id,
                &nonce,
            );
            AuthClientHello {
                mode: AuthClientMode::Invite {
                    network_id,
                    invite_id,
                    join_secret_hex,
                },
                nonce: Some(hex::encode(nonce)),
                invite_proof: Some(hex::encode(proof)),
            }
        }
        AuthClientMode::Grant { grant } => AuthClientHello {
            mode: AuthClientMode::Grant { grant },
            nonce: None,
            invite_proof: None,
        },
    };

    let payload = serde_json::to_vec(&hello)?;
    write_frame(&mut send, &payload).await?;
    let resp = read_frame(&mut recv, 64).await?;
    if resp.as_slice() != b"ok" {
        anyhow::bail!("auth rejected by peer");
    }
    Ok(())
}

/// Server handshake: verify invite proof or signed grant for claimed network.
pub async fn run_auth_server(
    conn: &Connection,
    ctx: &AuthServerContext,
    self_endpoint_hex: &str,
    auth: &AuthCache,
) -> anyhow::Result<(String, Uuid)> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let remote_hex = format!("{}", conn.remote_id());
    let frame = read_frame(&mut recv, 64 * 1024).await?;
    let hello: AuthClientHello = serde_json::from_slice(&frame).context("auth hello json")?;

    let network_id = match &hello.mode {
        AuthClientMode::Invite { network_id, .. } => *network_id,
        AuthClientMode::Grant { grant } => grant.network_id,
    };

    let (ok, insert_auth) = match hello.mode {
        AuthClientMode::Invite {
            network_id,
            invite_id: _,
            join_secret_hex,
        } => {
            if (ctx.is_revoked)(network_id, &remote_hex) {
                (false, false)
            } else {
                match (hello.nonce, hello.invite_proof) {
                    (Some(nonce_hex), Some(proof_hex)) => match (
                        hex::decode(nonce_hex),
                        hex::decode(proof_hex),
                        (ctx.resolve_join_secret)(network_id),
                    ) {
                        (Ok(nonce), Ok(proof), Some(join_secret))
                            if join_secret == join_secret_hex =>
                        {
                            let expected = compute_invite_proof(
                                &join_secret,
                                &remote_hex,
                                self_endpoint_hex,
                                network_id,
                                &nonce,
                            );
                            (constant_time_eq(&expected, &proof), false)
                        }
                        _ => (false, false),
                    },
                    _ => (false, false),
                }
            }
        }
        AuthClientMode::Grant { grant } => {
            let ok = if grant.endpoint_id != remote_hex
                || (ctx.is_revoked)(network_id, &grant.endpoint_id)
            {
                false
            } else if let Some(vk) = (ctx.resolve_coord_vk)(network_id) {
                let min_epoch = (ctx.resolve_min_epoch)(network_id);
                verify_grant(&vk, &grant, min_epoch).is_ok()
            } else {
                false
            };
            (ok, ok)
        }
    };

    if !ok {
        write_response(&mut send, false).await.ok();
        anyhow::bail!("auth verification failed");
    }

    write_response(&mut send, true).await?;
    if insert_auth {
        auth.insert(remote_hex.clone(), network_id);
    }
    Ok((remote_hex, network_id))
}

/// Build server auth context from live docs membership + persisted join secrets.
pub fn build_auth_server_context(
    networks: &[crate::state::DirectState],
    docs: &std::collections::HashMap<Uuid, crate::direct::membership::DocsMembership>,
) -> SharedAuthServerContext {
    let join_secrets: std::collections::HashMap<Uuid, String> = networks
        .iter()
        .map(|d| (d.network_id, d.join_secret.clone()))
        .collect();
    let secrets = Arc::new(join_secrets);
    let docs = Arc::new(docs.clone());
    Arc::new(AuthServerContext {
        resolve_join_secret: Arc::new({
            let secrets = secrets.clone();
            move |nid| secrets.get(&nid).cloned()
        }),
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
