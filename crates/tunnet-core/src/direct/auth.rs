//! Grant transport authentication for Direct mode.
//!
//! Existing members authenticate over [`AUTH_ALPN`] with a signed [`NetworkGrant`].
//! Join and connect use dedicated ALPNs; this protocol is not an RPC channel.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, RecvStream, SendStream,
    Side,
};
use parking_lot::{Mutex, RwLock};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Authentication {
    Local,
    Grant {
        epoch: u64,
        expires_at: jiff::Timestamp,
    },
}
impl Authentication {
    fn valid(self) -> bool {
        match self {
            Self::Local => true,
            Self::Grant { expires_at, .. } => expires_at > jiff::Timestamp::now(),
        }
    }
}
#[derive(Clone)]
pub struct AuthCache {
    inner: Arc<Mutex<HashMap<String, HashMap<Uuid, Authentication>>>>,
    version: Arc<AtomicU64>,
    gate: Arc<RwLock<()>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Default for AuthCache {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            version: Arc::default(),
            gate: Arc::default(),
            changes: tokio::sync::watch::channel(0).0,
        }
    }
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_gate(gate: Arc<RwLock<()>>) -> Self {
        Self {
            gate,
            ..Self::default()
        }
    }

    pub fn authorization_gate(&self) -> Arc<RwLock<()>> {
        self.gate.clone()
    }

    pub fn subscribe_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn changed(&self) {
        let previous = self
            .version
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("transport authorization epoch exhausted");
        let version = previous + 1;
        self.changes.send_replace(version);
    }

    pub fn network_expiry(&self, peer: &str, network: Uuid) -> Option<jiff::Timestamp> {
        match self.inner.lock().get(peer)?.get(&network)? {
            Authentication::Grant { expires_at, .. } => Some(*expires_at),
            Authentication::Local => None,
        }
    }

    pub fn insert(&self, endpoint_hex: impl Into<String>, network_id: Uuid) {
        let _authorization = self.gate.write();
        let mut g = self.inner.lock();
        let changed = g
            .entry(endpoint_hex.into())
            .or_default()
            .insert(network_id, Authentication::Local)
            != Some(Authentication::Local);
        if changed {
            self.changed();
        }
    }

    /// Authenticated for any joined network.
    pub fn contains(&self, endpoint_hex: &str) -> bool {
        self.inner
            .lock()
            .get(endpoint_hex)
            .is_some_and(|s| s.values().any(|permission| permission.valid()))
    }

    pub fn contains_network(&self, endpoint_hex: &str, network_id: Uuid) -> bool {
        self.inner.lock().get(endpoint_hex).is_some_and(|s| {
            s.get(&network_id)
                .is_some_and(|permission| permission.valid())
        })
    }

    pub fn networks_for(&self, endpoint_hex: &str) -> Vec<Uuid> {
        self.inner
            .lock()
            .get(endpoint_hex)
            .map(|s| {
                s.iter()
                    .filter(|(_, permission)| permission.valid())
                    .map(|(network, _)| *network)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn peers_for(&self, network_id: Uuid) -> Vec<String> {
        self.inner
            .lock()
            .iter()
            .filter(|(_, networks)| networks.contains_key(&network_id))
            .map(|(peer, _)| peer.clone())
            .collect()
    }

    pub fn remove(&self, endpoint_hex: &str) {
        let _authorization = self.gate.write();
        if self.inner.lock().remove(endpoint_hex).is_some() {
            self.changed();
        }
    }

    pub fn remove_network(&self, endpoint_hex: &str, network_id: Uuid) {
        let _authorization = self.gate.write();
        let mut g = self.inner.lock();
        let mut changed = false;
        if let Some(set) = g.get_mut(endpoint_hex) {
            changed = set.remove(&network_id).is_some();
            if set.is_empty() {
                g.remove(endpoint_hex);
            }
        }
        if changed {
            self.changed();
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn invalidate_network<T>(&self, network: Uuid, update: impl FnOnce() -> T) -> T {
        let _authorization = self.gate.write();
        let result = update();
        let mut members = self.inner.lock();
        members.retain(|_, permissions| {
            permissions.remove(&network);
            !permissions.is_empty()
        });
        self.changed();
        result
    }

    pub fn revoke_network_peer<T>(
        &self,
        network: Uuid,
        peer: &str,
        update: impl FnOnce() -> T,
    ) -> T {
        let _authorization = self.gate.write();
        let result = update();
        let mut members = self.inner.lock();
        if let Some(permissions) = members.get_mut(peer) {
            permissions.remove(&network);
            if permissions.is_empty() {
                members.remove(peer);
            }
        }
        self.changed();
        result
    }

    pub(crate) fn authenticate(
        &self,
        ctx: &AuthServerContext,
        grant: &NetworkGrant,
        peer: &str,
    ) -> anyhow::Result<()> {
        let _authorization = self.gate.write();
        anyhow::ensure!(
            grant.endpoint_id == peer && !(ctx.is_revoked)(grant.network_id, peer),
            "AUTH identity revoked or mismatched"
        );
        let key = (ctx.resolve_coord_vk)(grant.network_id).context("AUTH network unknown")?;
        verify_grant(&key, grant, (ctx.resolve_min_epoch)(grant.network_id))?;
        let permission = Authentication::Grant {
            epoch: grant.network_epoch,
            expires_at: grant.expires_at,
        };
        let previous = self
            .inner
            .lock()
            .entry(peer.to_owned())
            .or_default()
            .insert(grant.network_id, permission);
        let continuous = matches!(previous,
            Some(Authentication::Grant { epoch, expires_at })
                if epoch == grant.network_epoch && expires_at > jiff::Timestamp::now());
        if previous != Some(permission) && !continuous {
            self.changed();
        } else if previous != Some(permission) {
            self.changes.send_modify(|_| {});
        }
        Ok(())
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
            tracing::warn!(
                %peer_hex,
                alpn = %String::from_utf8_lossy(alpn),
                "inbound connection blocked (not authenticated)"
            );
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
    pub resolve_self_grant: Arc<dyn Fn(Uuid) -> Option<NetworkGrant> + Send + Sync>,
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

pub async fn run_auth_client(
    conn: &Connection,
    grant: NetworkGrant,
    local_endpoint_hex: &str,
    ctx: &AuthServerContext,
    auth: &AuthCache,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        grant.endpoint_id == local_endpoint_hex,
        "local AUTH grant identity mismatch"
    );
    auth.authenticate(ctx, &grant, local_endpoint_hex)?;
    let network = grant.network_id;
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    let payload = serde_json::to_vec(&AuthClientHello { grant })?;
    write_frame(&mut send, &payload).await?;
    send.finish()?;
    let resp = read_frame(&mut recv, 64 * 1024).await?;
    let remote: AuthClientHello = serde_json::from_slice(&resp).context("peer AUTH grant")?;
    anyhow::ensure!(
        remote.grant.network_id == network,
        "peer AUTH network mismatch"
    );
    auth.authenticate(ctx, &remote.grant, &conn.remote_id().to_string())?;
    Ok(())
}

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
    let grant = hello.grant;
    let network_id = grant.network_id;

    let own_grant = (ctx.resolve_self_grant)(network_id).context("local AUTH grant absent")?;
    anyhow::ensure!(
        own_grant.endpoint_id == self_endpoint_hex && own_grant.network_id == network_id,
        "local AUTH identity mismatch"
    );
    auth.authenticate(ctx, &own_grant, self_endpoint_hex)?;
    auth.authenticate(ctx, &grant, &remote_hex)?;
    let response = serde_json::to_vec(&AuthClientHello { grant: own_grant })?;
    write_frame(&mut send, &response).await?;
    send.finish()?;
    send.stopped().await?;
    Ok((remote_hex, network_id))
}

/// Build server auth context from live docs membership.
pub fn build_auth_server_context(
    docs: &std::collections::HashMap<Uuid, crate::direct::membership::DocsMembership>,
) -> SharedAuthServerContext {
    let docs = Arc::new(docs.clone());
    Arc::new(AuthServerContext {
        resolve_self_grant: Arc::new({
            let docs = docs.clone();
            move |nid| docs.get(&nid).and_then(|d| d.self_grant())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct::grants::{MemberRole, sign_grant};

    #[test]
    fn continuous_grant_renewal_preserves_epoch_but_expired_recovery_does_not() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let verifying = key.verifying_key();
        let network = Uuid::nil();
        let peer = "ab".repeat(32);
        let ctx = AuthServerContext {
            resolve_coord_vk: Arc::new(move |_| Some(verifying)),
            resolve_min_epoch: Arc::new(|_| 1),
            is_revoked: Arc::new(|_, _| false),
            resolve_self_grant: Arc::new(|_| None),
        };
        let cache = AuthCache::new();
        let now = jiff::Timestamp::now();
        let mut grant = NetworkGrant {
            network_id: network,
            endpoint_id: peer.clone(),
            role: MemberRole::Member,
            network_epoch: 1,
            issued_at: now,
            expires_at: now + jiff::SignedDuration::from_secs(60),
            content_key: hex::encode([9; 32]),
            sig: String::new(),
        };
        grant = sign_grant(&key, grant).unwrap();
        cache.authenticate(&ctx, &grant, &peer).unwrap();
        let version = cache.version();
        let mut changes = cache.subscribe_changes();
        grant.expires_at += jiff::SignedDuration::from_secs(60);
        grant = sign_grant(&key, grant).unwrap();
        cache.authenticate(&ctx, &grant, &peer).unwrap();
        assert_eq!(cache.version(), version);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        assert_eq!(cache.network_expiry(&peer, network), Some(grant.expires_at));
        cache.inner.lock().get_mut(&peer).unwrap().insert(
            network,
            Authentication::Grant {
                epoch: 1,
                expires_at: now - jiff::SignedDuration::from_secs(1),
            },
        );
        cache.authenticate(&ctx, &grant, &peer).unwrap();
        assert!(cache.version() > version);
        assert!(changes.has_changed().unwrap());
        assert!(cache.contains_network(&peer, network));
    }
}
