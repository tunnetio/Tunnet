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

use super::auth::{AUTH_ALPN, AuthCache, SharedAuthServerContext, run_auth_client};

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
    inner: Arc<DiscoveryInner>,
}

struct DiscoveryInner {
    peers: Arc<Mutex<HashSet<String>>>,
    shutdown: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DiscoveryHandle {
    pub fn known_peers(&self) -> Vec<String> {
        self.inner.peers.lock().iter().cloned().collect()
    }

    pub fn add_peer(&self, endpoint_hex: impl Into<String>) {
        self.inner.peers.lock().insert(endpoint_hex.into());
    }

    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    pub fn set_task(&self, task: tokio::task::JoinHandle<()>) {
        assert!(
            self.inner.task.lock().replace(task).is_none(),
            "seed AUTH already started"
        );
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.send_replace(true);
        let task = self.inner.task.lock().take();
        if let Some(mut task) = task
            && tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for DiscoveryInner {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
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
        inner: Arc::new(DiscoveryInner {
            peers,
            shutdown: shutdown_tx,
            task: Mutex::new(None),
        }),
    }
}

pub fn spawn_seed_auth(
    endpoint: Endpoint,
    auth: AuthCache,
    network_id: Uuid,
    context: SharedAuthServerContext,
    mut shutdown: watch::Receiver<bool>,
    self_endpoint_hex: String,
    seed_peers: Arc<Mutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Dial immediately, then retry on the interval.
        loop {
            if *shutdown.borrow() {
                return;
            }
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
                let Some(grant) = (context.resolve_self_grant)(network_id) else {
                    break;
                };
                let Ok(peer) = seed.parse::<iroh::EndpointId>() else {
                    continue;
                };
                let attempt = async {
                    let conn = endpoint.connect(peer, AUTH_ALPN).await?;
                    let result =
                        run_auth_client(&conn, grant, &self_endpoint_hex, &context, &auth).await;
                    conn.close(
                        if result.is_ok() { 0u32 } else { 401u32 }.into(),
                        b"auth_done",
                    );
                    result
                };
                tokio::select! {
                    _ = shutdown.changed() => return,
                    result = tokio::time::timeout(std::time::Duration::from_secs(10), attempt) => {
                        if !matches!(result, Ok(Ok(()))) { tracing::debug!(%seed, "seed AUTH failed"); }
                    }
                }
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tick.tick() => {},
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_clone_drop_preserves_worker_and_shutdown_joins_it() {
        let discovery = spawn_discovery(String::new(), "self".into(), vec![]);
        let mut shutdown = discovery.shutdown_receiver();
        drop(discovery.clone());
        assert!(!*shutdown.borrow());
        let (done, completed) = tokio::sync::oneshot::channel();
        discovery.set_task(tokio::spawn(async move {
            if !*shutdown.borrow() {
                let _ = shutdown.changed().await;
            }
            let _ = done.send(());
        }));
        discovery.shutdown().await;
        completed.await.unwrap();
        assert!(discovery.inner.task.lock().is_none());
    }
}
