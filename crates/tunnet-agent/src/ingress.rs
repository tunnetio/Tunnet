//! Datagram ingress readers: exactly one reader per peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use iroh::EndpointId;
use tokio::task::JoinHandle;

/// Tracks active TUN ingress tasks per remote endpoint.
///
/// Each registration carries a generation: a finishing old reader removes
/// its entry ONLY if no newer reader replaced it (otherwise a slow
/// shutdown could unregister a live replacement and leave the peer
/// readerless — or resurrect routing for a dead one).
#[derive(Clone, Default)]
pub struct IngressRegistry {
    readers: Arc<DashMap<EndpointId, (u64, JoinHandle<()>)>>,
    generation: Arc<AtomicU64>,
}

impl IngressRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump generation (e.g. data-plane down) so in-flight readers can exit.
    pub fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Abort any existing reader and start a new one. The old task's exit
    /// cleanup cannot remove the new registration (generation-guarded).
    pub fn force_spawn<F>(&self, peer: EndpointId, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let reader_gen = self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some((_, (_, h))) = self.readers.remove(&peer) {
            h.abort();
        }
        let readers = self.readers.clone();
        let handle = tokio::spawn(async move {
            fut.await;
            readers.remove_if(&peer, |_, (g, _)| *g == reader_gen);
        });
        self.readers.insert(peer, (reader_gen, handle));
    }

    pub fn abort_all(&self) {
        self.bump_generation();
        let keys: Vec<_> = self.readers.iter().map(|e| *e.key()).collect();
        for k in keys {
            if let Some((_, (_, h))) = self.readers.remove(&k) {
                h.abort();
            }
        }
    }

    #[cfg(test)]
    pub fn has_reader(&self, peer: EndpointId) -> bool {
        self.readers.get(&peer).is_some_and(|h| !h.1.is_finished())
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
    fn force_spawn_replaces_reader() {
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
            reg.force_spawn(p, async move {
                let _ = rx.await;
            });
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p));
            reg.force_spawn(p, async {});
            tokio::task::yield_now().await;
            assert!(!reg.has_reader(p));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }

    #[test]
    fn stale_reader_exit_keeps_new_registration() {
        // An old reader that exits NORMALLY after being replaced (e.g.
        // tie-break swap: the old connection closes on its own while the
        // new reader runs) must not unregister the live replacement.
        // (Aborted tasks never run wrapper cleanup — the future is
        // dropped — so only normal exits exercise this path.)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let mut bytes = [9u8; 32];
            bytes[0] = 4;
            let p = iroh::SecretKey::from(bytes).public();
            let (tx_old, rx_old) = tokio::sync::oneshot::channel::<()>();
            let (tx_new, rx_new) = tokio::sync::oneshot::channel::<()>();
            reg.force_spawn(p, async move {
                let _ = rx_old.await;
            });
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p));
            // Concurrent replacement with a newer generation (same
            // discipline force_spawn itself uses).
            let new_gen = reg.generation.fetch_add(1, Ordering::SeqCst);
            let readers = reg.readers.clone();
            let new_handle = tokio::spawn(async move {
                let _ = rx_new.await;
                readers.remove_if(&p, |_, (g, _)| *g == new_gen);
            });
            reg.readers.insert(p, (new_gen, new_handle));
            tokio::task::yield_now().await;
            // Old reader now exits normally (its connection closed).
            drop(tx_old);
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                reg.has_reader(p),
                "old exit cleanup must not remove the new reader"
            );
            drop(tx_new);
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
            reg.force_spawn(p, async move {
                let _ = rx.await;
            });
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p));
            reg.abort_all();
            assert!(!reg.has_reader(p));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }
}
