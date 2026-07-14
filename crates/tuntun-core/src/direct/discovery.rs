//! Peer discovery for Direct mode.
//!
//! Topic = blake3(network_name || secret). Peers are primarily discovered via
//! invite coordinator dial + membership gossip. An optional Mainline DHT
//! announce marks topic liveness (endpoint ids still travel via membership).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use mainline::{Dht, Id};
use parking_lot::Mutex;
use tokio::sync::watch;

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
    _shutdown: watch::Sender<bool>,
}

impl DiscoveryHandle {
    pub fn known_peers(&self) -> Vec<String> {
        self.peers.lock().iter().cloned().collect()
    }

    pub fn add_peer(&self, endpoint_hex: impl Into<String>) {
        self.peers.lock().insert(endpoint_hex.into());
    }
}

/// Start discovery: seed peers + best-effort DHT announce loop.
pub fn spawn_discovery(
    topic_hash_hex: String,
    self_endpoint_hex: String,
    seed_peers: Vec<String>,
) -> DiscoveryHandle {
    let peers = Arc::new(Mutex::new(HashSet::new()));
    for p in seed_peers {
        if p != self_endpoint_hex {
            peers.lock().insert(p);
        }
    }
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let dht = match Dht::client() {
            Ok(d) => Some(d.as_async()),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "mainline DHT unavailable; invite/membership discovery only"
                );
                None
            }
        };

        let info_hash = topic_to_info_hash(&topic_hash_hex);
        let mut tick = tokio::time::interval(Duration::from_secs(90));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Some(ref dht) = dht {
                        if let Err(e) = dht.announce_peer(info_hash, None).await {
                            tracing::debug!(?e, "dht announce failed");
                        }
                        // Drain peers for topic liveness; endpoint ids come from membership.
                        let mut stream = dht.get_peers(info_hash);
                        while let Some(_batch) = futures_util::StreamExt::next(&mut stream).await {}
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    DiscoveryHandle {
        peers,
        _shutdown: shutdown_tx,
    }
}

fn topic_to_info_hash(topic_hash_hex: &str) -> Id {
    let bytes = hex::decode(topic_hash_hex)
        .unwrap_or_else(|_| blake3::hash(topic_hash_hex.as_bytes()).as_bytes().to_vec());
    let mut arr = [0u8; 20];
    let n = bytes.len().min(20);
    arr[..n].copy_from_slice(&bytes[..n]);
    Id::from(arr)
}
