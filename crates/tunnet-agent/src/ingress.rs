//! QUIC ingress lifecycle: exactly one reader per canonical connection.
//!
//! Readers are keyed by `(endpoint, connection stable id)`:
//! - installing the SAME connection is a no-op (idempotent — never a
//!   second reader on one connection);
//! - installing a NEW canonical connection aborts the old reader and
//!   replaces it;
//! - an old reader's normal exit cannot unregister its replacement
//!   (generation-guarded cleanup).
//!
//! A reader that dies unexpectedly (QUIC failure) while its connection is
//! still the pool's canonical one invalidates exactly that connection, so
//! reconnect starts clean — a canonical live connection with no reader can
//! never linger. TUN writer errors never touch readers; they belong to
//! `DataPlaneActor` health/restart.
//!
//! [`IngressManager`] owns installation for both accepted and dialed
//! connections with ONE [`IngressContext`] (same auth cache both sides).
//! The pool hook captures a [`Weak`] pool reference — no
//! `ConnPool -> callback -> ConnPool` ownership cycle.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tunnet_core::direct::{AuthCache, SpoofTracker};
use tunnet_core::{AclEngine, ConnPool, InstallOutcome, PolicyRuntime, RoutingTable};
use uuid::Uuid;

use crate::endpoint_tx::EndpointTxRegistry;
use crate::metrics::AgentMetrics;
use crate::tun_io::{InboundDeps, ReaderExit, serve_tunnel_connection};
use crate::tun_writer::TunWriterHandle;

/// Reader key: (endpoint, canonical connection stable id).
type ReaderKey = (EndpointId, usize);
/// Reader value: (registry generation, task handle).
type ReaderValue = (u64, JoinHandle<()>);

/// Tracks active ingress readers per (endpoint, canonical connection).
#[derive(Clone, Default)]
pub struct IngressRegistry {
    readers: Arc<DashMap<ReaderKey, ReaderValue>>,
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

    /// Install a reader for a canonical connection.
    ///
    /// - Same `(peer, stable_id)` already registered → no-op, returns false.
    /// - New stable id → abort the old reader, spawn the replacement,
    ///   returns true.
    ///
    /// The spawned wrapper supervises the reader: unexpected QUIC failure
    /// while still canonical invalidates that exact connection via the
    /// (weak) pool; anything else just unregisters.
    pub fn install<F>(&self, peer: EndpointId, stable_id: usize, fut: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.readers.contains_key(&(peer, stable_id)) {
            return false;
        }
        let reader_gen = self.generation.fetch_add(1, Ordering::SeqCst);
        // Abort any reader for a DIFFERENT connection of this peer.
        let stale: Vec<_> = self
            .readers
            .iter()
            .filter(|e| e.key().0 == peer && e.key().1 != stable_id)
            .map(|e| *e.key())
            .collect();
        for key in stale {
            if let Some((_, (_, h))) = self.readers.remove(&key) {
                h.abort();
            }
        }
        if self.readers.contains_key(&(peer, stable_id)) {
            return false;
        }
        let readers = self.readers.clone();
        let handle = tokio::spawn(async move {
            fut.await;
            readers.remove_if(&(peer, stable_id), |_, (g, _)| *g == reader_gen);
        });
        self.readers.insert((peer, stable_id), (reader_gen, handle));
        true
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
    pub fn has_reader(&self, peer: EndpointId, stable_id: usize) -> bool {
        self.readers
            .get(&(peer, stable_id))
            .is_some_and(|h| !h.1.is_finished())
    }
}

/// Shared reader construction context: identical for accepted and dialed
/// connections — in particular the SAME Direct [`AuthCache`]. A dialer-side
/// reader with no auth handle would evaluate frames without network
/// bindings; that bypass is gone by construction.
#[derive(Clone)]
pub struct IngressContext {
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub runtime: PolicyRuntime,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub bufs: Arc<tunnet_common::packet::PacketPool>,
    pub metrics: AgentMetrics,
    pub auth: Option<AuthCache>,
}

impl IngressContext {
    /// Build the reader deps for one canonical connection against the
    /// CURRENT generation's writer/registry/cancel (loaded from the
    /// published plane at install time).
    pub fn reader_deps(
        &self,
        conn: Connection,
        tun_writer: TunWriterHandle,
        tx_registry: EndpointTxRegistry,
        cancel: CancellationToken,
    ) -> InboundDeps {
        InboundDeps {
            conn,
            tun_writer,
            tx_registry,
            cancel,
            routes: self.routes.clone(),
            runtime: self.runtime.clone(),
            acl: self.acl.clone(),
            spoofs: self.spoofs.clone(),
            bufs: self.bufs.clone(),
            metrics: self.metrics.clone(),
            auth: self.auth.clone(),
        }
    }
}

/// Installs canonical connections + readers for one pool. Holds only a
/// [`std::sync::Weak`] pool reference: the pool's stored hook captures this
/// manager (strong), the manager never strongly owns the pool back.
#[derive(Clone)]
pub struct IngressManager {
    pool: std::sync::Weak<ConnPool>,
    ingress: IngressRegistry,
    ctx: IngressContext,
    published: crate::actors::dataplane::PublishedPlane,
}

impl IngressManager {
    pub fn new(
        pool: &Arc<ConnPool>,
        ingress: IngressRegistry,
        ctx: IngressContext,
        published: crate::actors::dataplane::PublishedPlane,
    ) -> Self {
        Self {
            pool: Arc::downgrade(pool),
            ingress,
            ctx,
            published,
        }
    }

    /// Canonical install for an ACCEPTED connection: tie-break through the
    /// pool, then install exactly one reader for the winner.
    pub async fn install_accepted(&self, conn: Connection) {
        let peer = conn.remote_id();
        let Some(pool) = self.pool.upgrade() else {
            conn.close(0u32.into(), b"pool_gone");
            return;
        };
        match pool.install_canonical(peer, conn.clone(), false).await {
            InstallOutcome::Canonical(canonical) => {
                self.spawn_reader(peer, canonical);
            }
            InstallOutcome::KeepExisting(_) => {
                conn.close(0u32.into(), b"tie_break");
            }
        }
    }

    /// Reader install for a DIALED canonical connection (pool hook path:
    /// the pool already installed it canonically and fired the hook).
    pub fn install_dialed(&self, peer: EndpointId, conn: Connection) {
        self.spawn_reader(peer, conn);
    }

    fn spawn_reader(&self, peer: EndpointId, conn: Connection) {
        let stable_id = conn.stable_id();
        // Current generation's writer/registry/cancel, pinned at install.
        let Some(plane) = self.published.load_full() else {
            tracing::debug!(%peer, "no dataplane generation; reader not installed");
            return;
        };
        let deps = self.ctx.reader_deps(
            conn,
            plane.tun_writer.clone(),
            plane.tx_registry.clone(),
            plane.cancel.clone(),
        );
        let pool = self.pool.clone();
        let metrics = self.ctx.metrics.clone();
        self.ingress.install(peer, stable_id, async move {
            match serve_tunnel_connection(deps).await {
                ReaderExit::ConnFailed { stable_id } => {
                    // Unexpected death while possibly canonical: invalidate
                    // exactly this connection (no-op when replaced already).
                    if let Some(pool) = pool.upgrade() {
                        let current = pool.canonical_stable_id(peer).await;
                        if current == Some(stable_id) {
                            tracing::warn!(
                                %peer,
                                "ingress reader died on canonical connection; invalidating"
                            );
                            pool.invalidate_canonical(peer, stable_id).await;
                            metrics.dropped_inc("reader_conn_failed");
                        }
                    }
                }
                ReaderExit::GenerationDone | ReaderExit::MembershipGone => {}
            }
        });
    }

    /// The pool hook closure: captures this manager (strong) + a WEAK pool.
    /// Register once, before the ALPN router and before any preconnect.
    pub fn dial_hook(&self) -> Arc<dyn Fn(EndpointId, Connection) + Send + Sync> {
        let manager = self.clone();
        Arc::new(move |peer, conn| {
            manager.install_dialed(peer, conn);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> EndpointId {
        let mut bytes = [7u8; 32];
        bytes[0] = 1;
        iroh::SecretKey::from(bytes).public()
    }

    #[test]
    fn empty_registry_has_no_readers() {
        let reg = IngressRegistry::new();
        let p = test_peer();
        assert!(!reg.has_reader(p, 1));
        reg.abort_all();
        assert!(!reg.has_reader(p, 1));
    }

    #[test]
    fn same_connection_install_is_noop() {
        // Installing the same canonical connection twice must not spawn a
        // second reader (datagrams would split across two tasks).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let p = test_peer();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(p, 42, async move {
                let _ = rx.await;
            }));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 42));
            // Same connection again: no-op.
            assert!(!reg.install(p, 42, async {}));
            assert!(reg.has_reader(p, 42));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }

    #[test]
    fn new_connection_replaces_old_reader() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let p = test_peer();
            let (tx_old, rx_old) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(p, 1, async move {
                let _ = rx_old.await;
            }));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 1));
            // New canonical connection: replaces, old aborted.
            assert!(reg.install(p, 2, async {}));
            tokio::task::yield_now().await;
            assert!(!reg.has_reader(p, 1));
            drop(tx_old);
            tokio::task::yield_now().await;
        });
    }

    #[test]
    fn stale_reader_exit_keeps_new_registration() {
        // An old reader that exits NORMALLY after being replaced must not
        // unregister the live replacement.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let p = test_peer();
            let (tx_old, rx_old) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(p, 1, async move {
                let _ = rx_old.await;
            }));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 1));
            let (tx_new, rx_new) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(p, 2, async move {
                let _ = rx_new.await;
            }));
            tokio::task::yield_now().await;
            // Old reader now exits normally (its connection closed).
            drop(tx_old);
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                reg.has_reader(p, 2),
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
            let p = test_peer();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(p, 9, async move {
                let _ = rx.await;
            }));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 9));
            reg.abort_all();
            assert!(!reg.has_reader(p, 9));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }
}
