//! PSK transport authentication for Direct mode.
//!
//! Peers prove knowledge of the network secret over [`AUTH_ALPN`] using an
//! HMAC challenge-response (patterned after iroh-auth). [`DirectAuthHook`]
//! blocks non-auth ALPNs until the peer is authenticated or already a member.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use hmac::{Hmac, KeyInit, Mac};
use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, RecvStream, SendStream,
    Side,
};
use parking_lot::Mutex;
use sha2::Sha256;

use crate::acl::AclEngine;

pub const AUTH_ALPN: &[u8] = b"tuntun/direct-auth/1";

type HmacSha256 = Hmac<Sha256>;

/// Set of peers that completed PSK auth (or are known members).
#[derive(Clone, Default)]
pub struct AuthCache {
    inner: Arc<Mutex<HashSet<String>>>,
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, endpoint_hex: impl Into<String>) {
        self.inner.lock().insert(endpoint_hex.into());
    }

    pub fn contains(&self, endpoint_hex: &str) -> bool {
        self.inner.lock().contains(endpoint_hex)
    }

    pub fn remove(&self, endpoint_hex: &str) {
        self.inner.lock().remove(endpoint_hex);
    }
}

/// Compose ACL + Direct PSK gate.
#[derive(Clone)]
pub struct DirectAuthHook {
    acl: AclEngine,
    auth: AuthCache,
}

impl DirectAuthHook {
    pub fn new(acl: AclEngine, auth: AuthCache) -> Self {
        Self { acl, auth }
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
        if alpn == AUTH_ALPN {
            return BeforeConnectOutcome::Accept;
        }
        if self.auth.contains(&peer_hex) || self.acl.allow_outbound_peer(&peer_hex) {
            BeforeConnectOutcome::Accept
        } else {
            tracing::warn!(%peer_hex, "outbound connect blocked (not authenticated)");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }
        let peer_hex = format!("{}", conn.remote_id());
        let alpn = conn.alpn();
        if alpn == AUTH_ALPN {
            return AfterHandshakeOutcome::Accept;
        }
        if self.auth.contains(&peer_hex) || self.acl.allow_inbound_peer(&peer_hex) {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::warn!(%peer_hex, "inbound connection blocked (not authenticated)");
            AfterHandshakeOutcome::Reject {
                error_code: 401u32.into(),
                reason: b"auth_required".to_vec(),
            }
        }
    }
}

fn compute_proof(secret_hex: &str, local_hex: &str, remote_hex: &str, nonce: &[u8]) -> Vec<u8> {
    let secret = hex::decode(secret_hex).unwrap_or_else(|_| secret_hex.as_bytes().to_vec());
    let mut mac = HmacSha256::new_from_slice(&secret).expect("hmac accepts any key length");
    mac.update(local_hex.as_bytes());
    mac.update(b"|");
    mac.update(remote_hex.as_bytes());
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

/// Client side: prove PSK to a peer (typically the coordinator).
pub async fn run_psk_handshake_client(
    conn: &Connection,
    network_secret_hex: &str,
    local_endpoint_hex: &str,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;
    let remote_hex = format!("{}", conn.remote_id());
    let nonce: [u8; 32] = rand::random();
    write_frame(&mut send, local_endpoint_hex.as_bytes()).await?;
    write_frame(&mut send, &nonce).await?;
    let proof = compute_proof(network_secret_hex, local_endpoint_hex, &remote_hex, &nonce);
    write_frame(&mut send, &proof).await?;
    let resp = read_frame(&mut recv, 64).await?;
    if resp.as_slice() != b"ok" {
        anyhow::bail!("PSK auth rejected by peer");
    }
    Ok(())
}

/// Server handshake with known local endpoint hex.
pub async fn run_psk_handshake_server(
    conn: &Connection,
    network_secret_hex: &str,
    self_endpoint_hex: &str,
    auth: &AuthCache,
) -> anyhow::Result<String> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let peer_claimed =
        String::from_utf8(read_frame(&mut recv, 128).await?).context("peer id utf8")?;
    let nonce = read_frame(&mut recv, 64).await?;
    let proof = read_frame(&mut recv, 64).await?;
    let remote_hex = format!("{}", conn.remote_id());
    if peer_claimed != remote_hex {
        anyhow::bail!("peer id mismatch in auth handshake");
    }
    let expected = compute_proof(network_secret_hex, &peer_claimed, self_endpoint_hex, &nonce);
    if !constant_time_eq(&expected, &proof) {
        write_frame(&mut send, b"no").await.ok();
        anyhow::bail!("invalid PSK proof");
    }
    write_frame(&mut send, b"ok").await?;
    auth.insert(peer_claimed.clone());
    Ok(peer_claimed)
}
