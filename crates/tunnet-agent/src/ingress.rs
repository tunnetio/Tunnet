//! At most one datagram ingress reader per peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use iroh::EndpointId;
use tokio::task::JoinHandle;

/// Tracks the single active TUN ingress task per remote endpoint.
#[derive(Clone, Default)]
pub struct IngressRegistry {
    readers: Arc<DashMap<EndpointId, JoinHandle<()>>>,
    generation: Arc<AtomicU64>,
}

impl IngressRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Bump generation (e.g. data-plane down) so in-flight readers can exit.
    pub fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Try to claim ingress for `peer`. Returns `false` if a live reader already exists.
    /// On success, spawns `fut` and clears the registry entry when it finishes.
    pub fn try_spawn<F>(&self, peer: EndpointId, fut: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        use dashmap::mapref::entry::Entry;
        match self.readers.entry(peer) {
            Entry::Occupied(occ) => {
                if !occ.get().is_finished() {
                    return false;
                }
                drop(occ);
            }
            Entry::Vacant(v) => {
                drop(v);
            }
        }
        self.spawn_inner(peer, fut);
        true
    }

    fn spawn_inner<F>(&self, peer: EndpointId, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let readers = self.readers.clone();
        let handle = tokio::spawn(async move {
            fut.await;
            readers.remove(&peer);
        });
        self.readers.insert(peer, handle);
    }

    pub fn abort_all(&self) {
        self.bump_generation();
        let keys: Vec<_> = self.readers.iter().map(|e| *e.key()).collect();
        for k in keys {
            if let Some((_, h)) = self.readers.remove(&k) {
                h.abort();
            }
        }
    }

    #[allow(dead_code)]
    pub fn has_reader(&self, peer: EndpointId) -> bool {
        self.readers.get(&peer).is_some_and(|h| !h.is_finished())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_has_no_readers() {
        let reg = IngressRegistry::new();
        let mut bytes = [7u8; 32];
        bytes[0] = 1;
        let p = iroh::SecretKey::from(bytes).public();
        assert!(!reg.has_reader(p));
        reg.abort_all();
        assert!(!reg.has_reader(p));
    }

    #[test]
    fn try_spawn_second_time_returns_false() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let mut bytes = [3u8; 32];
            bytes[0] = 2;
            let p = iroh::SecretKey::from(bytes).public();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.try_spawn(p, async move {
                let _ = rx.await;
            }));
            // Drive the runtime so the reader task parks on the oneshot.
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p));
            assert!(!reg.try_spawn(p, async {}));
            reg.abort_all();
            assert!(!reg.has_reader(p));
            drop(tx);
            // Give the aborted task a chance to unwind before runtime drop.
            tokio::task::yield_now().await;
        });
    }

    #[test]
    fn abort_all_clears_readers() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let mut bytes = [5u8; 32];
            bytes[0] = 3;
            let p = iroh::SecretKey::from(bytes).public();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.try_spawn(p, async move {
                let _ = rx.await;
            }));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p));
            reg.abort_all();
            assert!(!reg.has_reader(p));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }
}
