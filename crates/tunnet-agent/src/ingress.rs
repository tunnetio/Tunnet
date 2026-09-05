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

/// How a supervised reader task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderEnd {
    /// Normal completion (shutdown, close, revocation).
    Completed,
    /// The reader future panicked: session failure + internal telemetry.
    Panicked,
}

/// End-of-reader monitor: invoked exactly once per normally-completing or
/// panicking reader (never for aborted tasks — abort drops the future, and
/// shutdown/install paths pre-remove the entry).
pub type ReaderMonitor = Box<dyn Fn(EndpointId, usize, ReaderEnd) + Send + 'static>;

/// Tracks active ingress readers per (endpoint, canonical connection).
#[derive(Clone, Default)]
pub struct IngressRegistry {
    readers: Arc<DashMap<ReaderKey, ReaderValue>>,
    generation: Arc<AtomicU64>,
    /// Serializes installations: check-replace-insert is one atomic
    /// transaction, so concurrent canonical transitions can never leave
    /// two registrations for one peer (installs are rare; the lock is
    /// never held across an await).
    install_lock: Arc<std::sync::Mutex<()>>,
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
    /// The whole check-replace-insert holds the install lock: for one
    /// endpoint there is always zero or one registration, even under
    /// concurrent canonical transitions. The spawned wrapper supervises
    /// the reader: panics are caught and reported through `monitor` (which
    /// must invalidate the exact canonical session — a panic never
    /// silently leaves a connection canonical); normal ends just
    /// unregister (generation-guarded, so a stale exit cannot remove its
    /// replacement).
    pub fn install<F>(
        &self,
        peer: EndpointId,
        stable_id: usize,
        fut: F,
        monitor: Option<ReaderMonitor>,
    ) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let _guard = self.install_lock.lock().expect("install lock");
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
            let end = match futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(fut))
                .await
            {
                Ok(()) => ReaderEnd::Completed,
                Err(_) => ReaderEnd::Panicked,
            };
            readers.remove_if(&(peer, stable_id), |_, (g, _)| *g == reader_gen);
            if let Some(monitor) = monitor {
                monitor(peer, stable_id, end);
            }
        });
        self.readers.insert((peer, stable_id), (reader_gen, handle));
        true
    }

    /// Remove exactly one reader registration (session teardown): removes
    /// the entry and aborts the task. Returns true when an entry existed.
    /// Never awaits: the task was aborted and finishes promptly.
    pub fn remove(&self, peer: EndpointId, stable_id: usize) -> bool {
        if let Some((_, (_, h))) = self.readers.remove(&(peer, stable_id)) {
            h.abort();
            true
        } else {
            false
        }
    }

    /// Current reader for a peer, if any: (stable id, alive). Used by
    /// session health and bring-up reconcile.
    pub fn current_reader(&self, peer: EndpointId) -> Option<(usize, bool)> {
        self.readers
            .iter()
            .find(|e| e.key().0 == peer)
            .map(|e| (e.key().1, !e.value().1.is_finished()))
    }

    /// Observed generation shutdown: abort every reader AND await their
    /// termination (bounded, abort + await stragglers — never detach a
    /// reader that can still touch generation state). After return, no
    /// reader of this registry exists.
    pub async fn shutdown(&self) {
        self.bump_generation();
        let keys: Vec<_> = self.readers.iter().map(|e| *e.key()).collect();
        let mut pending: Vec<JoinHandle<()>> = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some((_, (_, h))) = self.readers.remove(&k) {
                h.abort();
                pending.push(h);
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut i = 0;
        while i < pending.len() {
            if pending[i].is_finished() {
                let h = pending.remove(i);
                let _ = h.await;
            } else if std::time::Instant::now() >= deadline {
                break;
            } else {
                i += 1;
                if i >= pending.len() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    i = 0;
                }
            }
        }
        // Stragglers are already aborted above; await their termination
        // observably (aborted tasks finish promptly).
        for h in pending {
            let _ = h.await;
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

/// Escalation when a readerless canonical session cannot be repaired
/// (actor restarts the generation).
type SessionInvalidHandler = Arc<dyn Fn(String) + Send + Sync + 'static>;

/// Installs canonical connections + readers for one pool. Holds only a
/// [`std::sync::Weak`] pool reference: the pool's stored hook captures this
/// manager (strong), the manager never strongly owns the pool back.
///
/// Session model: a usable canonical tunnel is (connection, stable id,
/// orientation, dataplane generation, ingress reader, reader liveness).
/// The manager enforces readerless-canonical-never by construction:
/// installs are gated by generation, readers install synchronously with
/// publication, failures roll back, and every abnormal end funnels through
/// the idempotent [`IngressManager::session_failed`].
#[derive(Clone)]
pub struct IngressManager {
    pool: std::sync::Weak<ConnPool>,
    ingress: IngressRegistry,
    ctx: IngressContext,
    published: crate::actors::dataplane::PublishedPlane,
    status: tunnet_core::local_api::DataPlaneStatusSnapshot,
    gate: crate::actors::dataplane::LifecycleGate,
    /// Escalation when a readerless canonical session cannot be repaired
    /// (actor restarts the generation). Set by the actor at bring-up;
    /// absent in tests.
    on_session_invalid: Arc<std::sync::Mutex<Option<SessionInvalidHandler>>>,
    /// Per-peer session records (canonical sid, generation, reconnect
    /// count, last error). Reader liveness derives live from the registry.
    sessions: Arc<DashMap<EndpointId, SessionRecord>>,
    /// Last repair attempt per peer (storm guard: at most one repair per
    /// cooldown window, then escalate).
    last_repair: Arc<DashMap<EndpointId, std::time::Instant>>,
    /// Last-pushed session metric combos per peer (stale zeroing).
    pushed_metrics: Arc<DashMap<EndpointId, PushedCombo>>,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    canonical: Option<usize>,
    generation: u64,
    reconnects: u64,
    last_error: Option<String>,
    /// Opened-by-us orientation of the canonical connection (true =
    /// dialed, false = accepted). Set at install; repair preserves it.
    opened_by_us: Option<bool>,
}

/// Last-pushed metrics label combo per peer, for zeroing superseded
/// series (a stale `tunnet_session_info` series must never read live).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PushedCombo {
    generation: u64,
    canonical: String,
    reader: String,
    orientation: String,
}

/// Why a canonical session failed (unified transition input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFailReason {
    /// TX observed `ConnectionLost` on the canonical connection.
    TxConnLost,
    /// RX reader observed connection failure.
    RxConnFailed,
    /// The ingress reader task panicked.
    ReaderPanicked,
    /// DATAGRAMs unusable on the canonical connection.
    TransportFatal,
}

impl SessionFailReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::TxConnLost => "tx connection lost",
            Self::RxConnFailed => "reader connection failed",
            Self::ReaderPanicked => "reader panicked",
            Self::TransportFatal => "transport fatal",
        }
    }
}

impl IngressManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: &Arc<ConnPool>,
        ingress: IngressRegistry,
        ctx: IngressContext,
        published: crate::actors::dataplane::PublishedPlane,
        status: tunnet_core::local_api::DataPlaneStatusSnapshot,
        gate: crate::actors::dataplane::LifecycleGate,
        on_session_invalid: Option<SessionInvalidHandler>,
    ) -> Self {
        Self {
            pool: Arc::downgrade(pool),
            ingress,
            ctx,
            published,
            status,
            gate,
            on_session_invalid: Arc::new(std::sync::Mutex::new(on_session_invalid)),
            sessions: Arc::new(DashMap::new()),
            last_repair: Arc::new(DashMap::new()),
            pushed_metrics: Arc::new(DashMap::new()),
        }
    }

    /// Replace the invalid-session escalation handler (actor sets its
    /// restart hook at bring-up).
    pub fn set_invalid_handler(&self, handler: SessionInvalidHandler) {
        *self.on_session_invalid.lock().expect("handler lock") = Some(handler);
    }

    /// Canonical install for an ACCEPTED connection: gate, tie-break
    /// through the pool (no hook — this path installs its reader
    /// explicitly), then install exactly one reader for the winner.
    /// Rollback (invalidate + close) when no reader can install: a
    /// candidate must never remain canonical readerless.
    pub async fn install_accepted(&self, conn: Connection) {
        let peer = conn.remote_id();
        if conn.close_reason().is_some() {
            return;
        }
        let Some(generation) = self.gate.up_generation() else {
            // Down/Starting/Stopping: close immediately, install nothing
            // into the pool or the transport.
            conn.close(1u32.into(), b"dataplane_not_up");
            return;
        };
        let Some(pool) = self.pool.upgrade() else {
            conn.close(0u32.into(), b"pool_gone");
            return;
        };
        match pool
            .install_canonical(peer, conn.clone(), false, false)
            .await
        {
            InstallOutcome::Canonical(canonical) => {
                if !self
                    .spawn_reader_for(peer, canonical.clone(), generation, false)
                    .await
                {
                    tracing::warn!(%peer, "reader install failed; rolling back canonical");
                    if let Some(dead) = pool.invalidate_canonical(peer, canonical.stable_id()).await
                    {
                        dead.close(0u32.into(), b"install_rollback");
                    } else {
                        canonical.close(0u32.into(), b"install_rollback");
                    }
                }
            }
            InstallOutcome::KeepExisting(_) => {
                conn.close(0u32.into(), b"tie_break");
            }
        }
    }

    /// Reader install for a DIALED canonical connection (pool hook path:
    /// the pool already installed it canonically and fired the hook).
    /// Gate + generation refusal rolls the candidate back (invalidate +
    /// close) instead of leaving it canonical readerless.
    pub fn install_dialed(&self, peer: EndpointId, conn: Connection) {
        if conn.close_reason().is_some() {
            return;
        }
        let manager = self.clone();
        tokio::spawn(async move {
            let Some(generation) = manager.gate.up_generation() else {
                manager.rollback(peer, conn).await;
                return;
            };
            if !manager
                .spawn_reader_for(peer, conn.clone(), generation, true)
                .await
            {
                manager.rollback(peer, conn).await;
            }
        });
    }

    /// Roll back a candidate that may have become canonical without a
    /// reader: invalidate the exact stable id (no-op when replaced) and
    /// close best-effort.
    async fn rollback(&self, peer: EndpointId, conn: Connection) {
        let sid = conn.stable_id();
        if let Some(pool) = self.pool.upgrade()
            && let Some(dead) = pool.invalidate_canonical(peer, sid).await
        {
            dead.close(0u32.into(), b"install_rollback");
            return;
        }
        conn.close(0u32.into(), b"install_rollback");
    }

    /// Install the current-generation reader for a canonical connection.
    /// Returns false (caller rolls back) unless the gate is still Up for
    /// this generation AND the published plane is this generation.
    /// `opened_by_us` records orientation for health exposure.
    async fn spawn_reader_for(
        &self,
        peer: EndpointId,
        conn: Connection,
        generation: u64,
        opened_by_us: bool,
    ) -> bool {
        let stable_id = conn.stable_id();
        if self.gate.up_generation() != Some(generation) {
            return false;
        }
        let Some(plane) = self.published.load_full() else {
            tracing::debug!(%peer, "no dataplane generation; reader not installed");
            return false;
        };
        if plane.generation != generation {
            return false;
        }
        let deps = self.ctx.reader_deps(
            conn,
            plane.tun_writer.clone(),
            plane.tx_registry.clone(),
            plane.cancel.clone(),
        );
        // Session bookkeeping first: a different canonical sid for this
        // peer in this generation counts a reconnect.
        self.sessions
            .entry(peer)
            .and_modify(|r| {
                if r.canonical != Some(stable_id) && r.generation == generation {
                    r.reconnects += 1;
                }
                r.canonical = Some(stable_id);
                r.generation = generation;
                r.opened_by_us = Some(opened_by_us);
            })
            .or_insert_with(|| SessionRecord {
                canonical: Some(stable_id),
                generation,
                reconnects: 0,
                last_error: None,
                opened_by_us: Some(opened_by_us),
            });
        // Exit classification lives in the supervised future (it sees the
        // ReaderExit value): failures funnel through session_failed, clean
        // ends clear the record, panics arrive via the monitor below.
        let manager = self.clone();
        let fut = async move {
            match serve_tunnel_connection(deps).await {
                ReaderExit::ConnFailed { stable_id } => {
                    manager
                        .session_failed(peer, stable_id, SessionFailReason::RxConnFailed)
                        .await;
                    manager.ctx.metrics.dropped_inc("reader_conn_failed");
                }
                ReaderExit::GenerationDone | ReaderExit::MembershipGone => {
                    manager.on_reader_clean_end(peer, stable_id);
                }
            }
        };
        let manager = self.clone();
        let monitor: ReaderMonitor = Box::new(move |p, sid, end| {
            manager.on_reader_end(p, sid, end);
        });
        self.ingress.install(peer, stable_id, fut, Some(monitor));
        self.push_snapshot();
        true
    }

    /// Clean reader end (shutdown, revocation, locally closed): the session
    /// is over without failure — clear the canonical record (pool/transport
    /// already moved on or will via their own paths).
    fn on_reader_clean_end(&self, peer: EndpointId, stable_id: usize) {
        self.sessions.entry(peer).and_modify(|r| {
            if r.canonical == Some(stable_id) {
                r.canonical = None;
            }
        });
        self.push_snapshot();
    }

    /// Reader-end funnel (runs inside the reader task wrapper): normal ends
    /// refresh health; panics invalidate the exact session + telemetry.
    fn on_reader_end(&self, peer: EndpointId, stable_id: usize, end: ReaderEnd) {
        match end {
            ReaderEnd::Completed => {
                self.push_snapshot();
            }
            ReaderEnd::Panicked => {
                self.ctx.metrics.reader_panic_inc();
                tracing::error!(%peer, "ingress reader panicked; invalidating session");
                let manager = self.clone();
                tokio::spawn(async move {
                    manager
                        .session_failed(peer, stable_id, SessionFailReason::ReaderPanicked)
                        .await;
                });
            }
        }
    }

    /// THE unified session-failure transition (TX loss, RX failure, reader
    /// panic, transport fatal). Atomically/idempotently: verify the stable
    /// id is still canonical, clear the slot + transport, close best
    /// effort, remove its reader, record bookkeeping, then verify no
    /// readerless canonical remains (repair once per cooldown, else
    /// escalate). The in-flight TX cursor stays worker-owned throughout.
    pub async fn session_failed(
        &self,
        peer: EndpointId,
        stable_id: usize,
        reason: SessionFailReason,
    ) {
        // 1. Verify + clear the canonical slot and transport. `None` means
        // the slot already moved on — the rest still applies to this sid.
        let cleared = match self.pool.upgrade() {
            Some(pool) => pool.invalidate_canonical(peer, stable_id).await,
            None => None,
        };
        let was_cleared = cleared.is_some();
        if let Some(dead) = cleared {
            dead.close(0u32.into(), b"session_failed");
        }
        // 2. Stop/remove exactly this sid's ingress reader.
        self.ingress.remove(peer, stable_id);
        // 3. Bookkeeping.
        let reason_str = reason.as_str().to_string();
        let generation = self.gate.up_generation().unwrap_or(0);
        self.sessions
            .entry(peer)
            .and_modify(|r| {
                if was_cleared {
                    r.reconnects += 1;
                }
                r.canonical = None;
                r.generation = generation;
                r.last_error = Some(reason_str.clone());
            })
            .or_insert_with(|| SessionRecord {
                canonical: None,
                generation,
                reconnects: u8::from(was_cleared) as u64,
                last_error: Some(reason_str.clone()),
                opened_by_us: None,
            });
        // 4. Verify: a canonical session without a live reader must be
        // repaired or escalated — never left healthy.
        if let Some(pool) = self.pool.upgrade()
            && let Some(cur) = pool.canonical_stable_id(peer).await
        {
            let reader_ok = self
                .ingress
                .current_reader(peer)
                .is_some_and(|(s, alive)| s == cur && alive);
            if !reader_ok {
                self.repair_or_escalate(peer, cur);
            }
        }
        self.push_snapshot();
    }

    /// Repair a readerless canonical session once per cooldown (reinstall
    /// its reader for the current generation); escalate when repair is
    /// impossible or throttled. The install runs detached: awaiting it
    /// here would re-enter the install future through the session-failure
    /// path (obligation cycle); scheduling it is synchronous.
    fn repair_or_escalate(&self, peer: EndpointId, stable_id: usize) {
        let now = std::time::Instant::now();
        if self
            .last_repair
            .get(&peer)
            .is_some_and(|t| now.saturating_duration_since(*t) < std::time::Duration::from_secs(10))
        {
            self.escalate(format!(
                "readerless canonical session for {peer} (repair throttled)"
            ));
            return;
        }
        self.last_repair.insert(peer, now);
        let manager = self.clone();
        tokio::spawn(async move {
            let repaired = match (manager.pool.upgrade(), manager.gate.up_generation()) {
                (Some(pool), Some(generation)) => {
                    let opened = manager
                        .sessions
                        .get(&peer)
                        .and_then(|r| r.opened_by_us)
                        .unwrap_or(false);
                    let mut ok = false;
                    for (_, sid, conn) in pool.canonical_sessions() {
                        if conn.remote_id() == peer && sid == stable_id {
                            ok = manager
                                .spawn_reader_for(peer, conn, generation, opened)
                                .await;
                            break;
                        }
                    }
                    ok
                }
                _ => false,
            };
            if !repaired {
                manager.escalate(format!(
                    "readerless canonical session for {peer} (repair failed)"
                ));
            }
        });
    }

    fn escalate(&self, reason: String) {
        tracing::error!(reason = %reason, "escalating invalid session to dataplane restart");
        if let Some(handler) = self
            .on_session_invalid
            .lock()
            .expect("handler lock")
            .clone()
        {
            handler(reason);
        }
    }

    /// Bring-up reconcile (fail-safe belt-and-suspenders behind the gate):
    /// drop stale-generation records, then close/invalidate every pool
    /// canonical session that has no live current reader. Preconnect
    /// afterwards establishes fresh sessions. Never inherits ambiguity.
    pub async fn reconcile_generation(&self, generation: u64) {
        self.sessions.retain(|_, r| r.generation == generation);
        let orphans: Vec<(EndpointId, usize)> = match self.pool.upgrade() {
            Some(pool) => pool
                .canonical_sessions()
                .into_iter()
                .filter(|(peer, sid, _)| self.ingress.current_reader(*peer) != Some((*sid, true)))
                .map(|(peer, sid, _)| (peer, sid))
                .collect(),
            None => Vec::new(),
        };
        if let Some(pool) = self.pool.upgrade() {
            for (peer, sid) in orphans {
                tracing::warn!(%peer, stable_id = sid, "reconcile: closing orphan canonical session");
                if let Some(dead) = pool.invalidate_canonical(peer, sid).await {
                    dead.close(0u32.into(), b"reconcile");
                }
                self.sessions.entry(peer).and_modify(|r| {
                    r.canonical = None;
                    r.last_error = Some("reconciled orphan session".into());
                });
            }
        }
        self.push_snapshot();
    }

    /// Per-peer session health for status rendering (item 10).
    pub fn session_snapshot(&self) -> Vec<tunnet_common::local_api::SessionHealth> {
        // Pool orientation needs async locks; the snapshot mirrors the
        // manager's own records (orientation resolved best-effort below).
        self.sessions
            .iter()
            .map(|e| {
                let (reader_sid, reader_alive) = self
                    .ingress
                    .current_reader(*e.key())
                    .map(|(s, a)| (Some(s), a))
                    .unwrap_or((None, false));
                tunnet_common::local_api::SessionHealth {
                    peer_endpoint: format!("{}", e.key()),
                    canonical_stable_id: e.canonical,
                    canonical_state: if e.canonical.is_some() {
                        "live".into()
                    } else if e.last_error.is_some() {
                        "reconnecting".into()
                    } else {
                        "absent".into()
                    },
                    reader_stable_id: reader_sid,
                    reader_alive,
                    connection_orientation: e.opened_by_us.map(|b| {
                        if b {
                            "dialed".to_string()
                        } else {
                            "accepted".to_string()
                        }
                    }),
                    connection_generation: e.generation,
                    reconnect_count: e.reconnects,
                    last_error: e.last_error.clone(),
                }
            })
            .collect()
    }

    /// Push the session mirror into the status snapshot (health + API)
    /// and publish vitals + session series to metrics (benchmark session
    /// poisoning detection, local and peer side).
    pub fn push_snapshot(&self) {
        self.status.set_sessions(self.session_snapshot());
        let metrics = &self.ctx.metrics;
        metrics.dataplane_vitals(
            self.status.generation(),
            self.status.restart_count(),
            self.status.is_up(),
            self.status.outbound_alive(),
            self.status.writer_alive(),
        );
        // Session series with stale zeroing: superseded combos go to 0 so
        // no old series ever reads as the live session.
        let mut seen = std::collections::HashSet::new();
        for entry in self.sessions.iter() {
            let peer = *entry.key();
            seen.insert(peer);
            let rec = entry.value();
            let (reader_sid, reader_alive) = self
                .ingress
                .current_reader(peer)
                .map(|(s, a)| (Some(s), a))
                .unwrap_or((None, false));
            let canonical = rec
                .canonical
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".to_string());
            let reader = reader_sid
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".to_string());
            let orientation = rec
                .opened_by_us
                .map(|b| if b { "dialed" } else { "accepted" })
                .unwrap_or("none")
                .to_string();
            let alive = rec.canonical.is_some() && reader_alive;
            let combo = PushedCombo {
                generation: rec.generation,
                canonical: canonical.clone(),
                reader: reader.clone(),
                orientation: orientation.clone(),
            };
            let peer_hex = format!("{peer}");
            if self.pushed_metrics.get(&peer).is_some_and(|p| *p == combo) {
                // Same combo: refresh the value (aliveness may have flipped
                // without a combo change).
                metrics.session_set(
                    &peer_hex,
                    combo.generation,
                    &combo.canonical,
                    &combo.reader,
                    &combo.orientation,
                    alive,
                );
                continue;
            }
            if let Some(old) = self.pushed_metrics.insert(peer, combo.clone()) {
                metrics.session_set(
                    &peer_hex,
                    old.generation,
                    &old.canonical,
                    &old.reader,
                    &old.orientation,
                    false,
                );
            }
            metrics.session_set(
                &peer_hex,
                combo.generation,
                &combo.canonical,
                &combo.reader,
                &combo.orientation,
                alive,
            );
        }
        // Peers that vanished from the records: zero their series.
        let stale: Vec<_> = self
            .pushed_metrics
            .iter()
            .filter(|e| !seen.contains(e.key()))
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        for (peer, combo) in stale {
            self.pushed_metrics.remove(&peer);
            metrics.session_set(
                &format!("{peer}"),
                combo.generation,
                &combo.canonical,
                &combo.reader,
                &combo.orientation,
                false,
            );
        }
    }

    /// The pool hook closure (DIALED path only): the pool already installed
    /// the candidate canonically and fired the hook; install its reader
    /// (or roll back when the generation cannot take it). Register once,
    /// before the ALPN router and before any preconnect.
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
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(reg.shutdown());
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
            assert!(reg.install(
                p,
                42,
                async move {
                    let _ = rx.await;
                },
                None
            ));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 42));
            // Same connection again: no-op.
            assert!(!reg.install(p, 42, async {}, None));
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
            assert!(reg.install(
                p,
                1,
                async move {
                    let _ = rx_old.await;
                },
                None
            ));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 1));
            // New canonical connection: replaces, old aborted.
            assert!(reg.install(p, 2, async {}, None));
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
            assert!(reg.install(
                p,
                1,
                async move {
                    let _ = rx_old.await;
                },
                None
            ));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 1));
            let (tx_new, rx_new) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(
                p,
                2,
                async move {
                    let _ = rx_new.await;
                },
                None
            ));
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
    fn shutdown_observes_reader_termination() {
        // shutdown() must return promptly with no reader left behind —
        // aborted tasks are awaited, never detached.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let p = test_peer();
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            assert!(reg.install(
                p,
                9,
                async move {
                    let _ = rx.await;
                },
                None
            ));
            tokio::task::yield_now().await;
            assert!(reg.has_reader(p, 9));
            let start = std::time::Instant::now();
            reg.shutdown().await;
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "shutdown must be bounded"
            );
            assert!(!reg.has_reader(p, 9));
            drop(tx);
            tokio::task::yield_now().await;
        });
    }

    #[test]
    fn panic_is_classified_and_cleans_up() {
        // Item 8/16: a panicking reader must reach the monitor as
        // Panicked (never silently vanish), and its registration must go
        // — the session supervisor then invalidates the exact session.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let reg = IngressRegistry::new();
            let p = test_peer();
            let (tx_end, rx_end) = tokio::sync::oneshot::channel::<ReaderEnd>();
            let tx_end = std::sync::Mutex::new(Some(tx_end));
            let monitor: ReaderMonitor = Box::new(move |_p, _sid, end| {
                if let Some(tx) = tx_end.lock().expect("monitor lock").take() {
                    let _ = tx.send(end);
                }
            });
            assert!(reg.install(
                p,
                5,
                async {
                    panic!("injected reader panic");
                },
                Some(monitor)
            ));
            let end = tokio::time::timeout(std::time::Duration::from_secs(5), rx_end)
                .await
                .expect("monitor must fire")
                .expect("sender alive");
            assert_eq!(end, ReaderEnd::Panicked);
            assert!(!reg.has_reader(p, 5));
        });
    }
}
