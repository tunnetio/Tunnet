//! Peer discovery for Direct mode.
//!
//! Topic = blake3(network_name || secret). Peers are primarily discovered via
//! invite coordinator dial + membership gossip. Seed peers are tracked locally;
//! endpoint address lookup uses iroh connectivity (DHT / mDNS / relay).

use std::collections::HashSet;
use std::sync::Arc;

use iroh::Endpoint;
use parking_lot::Mutex;
use tokio::sync::watch;
use uuid::Uuid;

use super::auth::{AUTH_ALPN, AuthCache, run_auth_client};

/// Compute topic hash hex from network name + secret hex.
pub fn topic_from_name_secret(network_name: &str, secret_hex: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(network_name.as_bytes());
    h.update(b"|");
    h.update(secret_hex.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

#[derive(Clone)]
pub struct DiscoveryHandle {
    peers: Arc<Mutex<HashSet<String>>>,
    shutdown: watch::Sender<bool>,
}

impl DiscoveryHandle {
    pub fn known_peers(&self) -> Vec<String> {
        self.peers.lock().iter().cloned().collect()
    }

    pub fn add_peer(&self, endpoint_hex: impl Into<String>) {
        self.peers.lock().insert(endpoint_hex.into());
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

impl Drop for DiscoveryHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Seed known peers for invite/membership follow-up. No background DHT task.
pub fn spawn_discovery(
    _topic_hash_hex: String,
    self_endpoint_hex: String,
    seed_peers: Vec<String>,
) -> DiscoveryHandle {
    let peers = Arc::new(Mutex::new(HashSet::new()));
    for p in seed_peers {
        if p != self_endpoint_hex {
            peers.lock().insert(p);
        }
    }
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    DiscoveryHandle {
        peers,
        shutdown: shutdown_tx,
    }
}

pub fn spawn_seed_auth(
    endpoint: Endpoint,
    auth: AuthCache,
    network_id: Uuid,
    network_grant: Option<super::grants::NetworkGrant>,
    self_endpoint_hex: String,
    seed_peers: Arc<Mutex<Vec<String>>>,
) {
    let Some(grant) = network_grant else {
        tracing::warn!(%network_id, "seed AUTH skipped (no network_grant)");
        return;
    };

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Dial immediately, then retry on the interval.
        loop {
            let seeds: Vec<String> = seed_peers
                .lock()
                .iter()
                .filter(|p| *p != &self_endpoint_hex)
                .cloned()
                .collect();
            for seed in &seeds {
                if auth.contains_network(seed, network_id) {
                    continue;
                }
                let Ok(peer) = seed.parse::<iroh::EndpointId>() else {
                    tracing::warn!(%seed, "invalid seed endpoint id");
                    continue;
                };
                match endpoint.connect(peer, AUTH_ALPN).await {
                    Ok(conn) => {
                        match run_auth_client(
                            &conn,
                            grant.clone(),
                            &self_endpoint_hex,
                        )
                        .await
                        {
                            Ok(()) => {
                                auth.insert(seed.clone(), network_id);
                                tracing::info!(%seed, "seed AUTH ok");
                                conn.close(0u32.into(), b"auth_ok");
                            }
                            Err(e) => {
                                tracing::debug!(?e, %seed, "seed AUTH handshake failed");
                                conn.close(401u32.into(), b"auth_failed");
                            }
                        }
                    }
                    Err(e) => tracing::debug!(?e, %seed, "seed AUTH dial failed"),
                }
            }
            tick.tick().await;
        }
    });
}
