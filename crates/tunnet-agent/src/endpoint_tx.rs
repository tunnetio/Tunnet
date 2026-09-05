//! Endpoint-global transmit ownership: one TX worker per remote endpoint.
//!
//! The QUIC connection is endpoint-global, so its scheduler and backpressure
//! owner are endpoint-global too. Every membership of an endpoint feeds the
//! same [`EndpointScheduler`] (flows keyed by network + 5-tuple); only the
//! endpoint worker submits DATAGRAMs to the connection.
//!
//! ```text
//! TUN reader -> routing/policy -> endpoint TX queue (scheduler)
//!   -> endpoint worker -> framing -> Connection::send_datagram_wait
//! ```
//!
//! `send_datagram_wait` has the correct semantics here (waits for buffer
//! space, prioritizes queued DATAGRAMs, never drop-oldest) because blocking
//! this worker blocks nothing else: TUN receive, QUIC ingress, TUN writes,
//! and other endpoints all run on their own tasks. There is exactly one
//! submitter per connection, so the check-then-send race is gone by
//! construction.
//!
//! The worker holds the current logical packet/cursor across reconnects —
//! packets are never reconstructed from wire frames, CoDel timestamps are
//! never reset by transport congestion, and nothing is reordered behind
//! newer packets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use iroh::EndpointId;
use iroh::endpoint::{Connection, SendDatagramError};
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tunnet_common::packet::{
    LogicalPacket, MAX_LOGICAL_LEN, MAX_SEGMENTS, MIN_SEGMENT_PAYLOAD, PacketPool,
    SEGMENT_OVERHEAD, SINGLE_OVERHEAD, SegmentHeader, encode_segment_prefix,
};
use tunnet_core::peers::{PeerMembershipState, PeerRegistry, PeerTransportState};
use tunnet_core::scheduler::{Dequeue, DropReason, EndpointScheduler, SchedReporter};
use tunnet_core::{CloudRelayMeter, ConnPool};
use uuid::Uuid;

use crate::ingress::{IngressManager, SessionFailReason};
use crate::metrics::AgentMetrics;

/// One endpoint's transmit state: scheduler + worker lifecycle. Created on
/// demand by the TUN reader path; torn down with the dataplane generation.
pub struct EndpointTxState {
    endpoint: EndpointId,
    transport: Arc<PeerTransportState>,
    sched: Mutex<EndpointScheduler>,
    reporter: Mutex<SchedReporter>,
    notify: Notify,
    running: AtomicBool,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl EndpointTxState {
    fn new(endpoint: EndpointId, transport: Arc<PeerTransportState>, quantum: usize) -> Self {
        let sched = EndpointScheduler::new(quantum);
        let reporter = SchedReporter::new(sched.snapshot());
        Self {
            endpoint,
            transport,
            sched: Mutex::new(sched),
            reporter: Mutex::new(reporter),
            notify: Notify::new(),
            running: AtomicBool::new(false),
            worker: Mutex::new(None),
        }
    }

    /// Start the worker if idle (exactly one runner per state). The task
    /// is supervised: a panic clears `running` and escalates to a full
    /// generation restart (never a silent dead worker with `running=true`).
    fn start_if_idle(self: &Arc<Self>, inner: &Arc<Inner>) {
        if !self.running.swap(true, Ordering::AcqRel) {
            let state = self.clone();
            let inner = inner.clone();
            let fatal = inner
                .fatal_handler
                .lock()
                .expect("fatal handler lock")
                .clone();
            let worker = run_endpoint_worker(state.clone(), inner);
            let handle = tokio::spawn(async move {
                supervise_worker(state, fatal, worker).await;
            });
            *self.worker.lock() = Some(handle);
        } else {
            self.notify.notify_one();
        }
    }
}

/// Worker supervision wrapper (item 9): normal exits (idle/cancel) already
/// cleared `running` on their own paths and are untouched here; a panic
/// clears `running` and escalates with the endpoint + reason. Never touches
/// `running` on success: an older task must not clobber a newer worker's
/// flag (see start_if_idle ordering).
async fn supervise_worker(
    state: Arc<EndpointTxState>,
    fatal: Option<FatalHandler>,
    worker: impl std::future::Future<Output = ()> + Send,
) {
    let endpoint = state.endpoint;
    match futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(worker)).await {
        Ok(()) => {}
        Err(_) => {
            state.running.store(false, Ordering::Release);
            tracing::error!(%endpoint, "endpoint TX worker panicked");
            if let Some(fatal) = fatal {
                fatal(endpoint, "endpoint TX worker panicked".to_string());
            }
        }
    }
}

/// Escalation for abnormal worker death (actor restarts the generation).
type FatalHandler = Arc<dyn Fn(EndpointId, String) + Send + Sync + 'static>;

struct Inner {
    states: DashMap<EndpointId, Arc<EndpointTxState>>,
    cancel: CancellationToken,
    pool: ConnPool,
    peer_registry: Arc<PeerRegistry>,
    metrics: AgentMetrics,
    bufs: Arc<PacketPool>,
    meter: CloudRelayMeter,
    /// Session manager for the unified failure transition (TX path).
    /// None in unit tests (worker falls back to direct pool invalidation).
    session_mgr: std::sync::Mutex<Option<Arc<IngressManager>>>,
    /// Escalation for abnormal worker death (actor restarts the
    /// generation). None in tests.
    fatal_handler: std::sync::Mutex<Option<FatalHandler>>,
}

/// Generation-owned registry of endpoint TX workers. A fresh registry per
/// dataplane generation guarantees no queued packet crosses generations.
#[derive(Clone)]
pub struct EndpointTxRegistry {
    inner: Arc<Inner>,
}

impl EndpointTxRegistry {
    pub fn new(
        cancel: CancellationToken,
        pool: ConnPool,
        peer_registry: Arc<PeerRegistry>,
        metrics: AgentMetrics,
        bufs: Arc<PacketPool>,
        meter: CloudRelayMeter,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                states: DashMap::new(),
                cancel,
                pool,
                peer_registry,
                metrics,
                bufs,
                meter,
                session_mgr: std::sync::Mutex::new(None),
                fatal_handler: std::sync::Mutex::new(None),
            }),
        }
    }

    /// Attach the session manager for the unified TX failure transition
    /// (item 3): TX-observed loss/incompatibility funnels through the same
    /// `session_failed` op as reader failures. Must be called before the
    /// registry publishes (actor does this at bring-up); without it the
    /// worker falls back to direct pool invalidation (tests).
    pub fn set_session_manager(&self, manager: Arc<IngressManager>) {
        *self.inner.session_mgr.lock().expect("session lock") = Some(manager);
    }

    /// Attach abnormal-worker-death escalation (actor restarts the whole
    /// generation). Must be called before publishing; without it a panic
    /// still clears `running` but escalates nowhere (tests).
    pub fn set_fatal_handler(&self, handler: FatalHandler) {
        *self.inner.fatal_handler.lock().expect("fatal lock") = Some(handler);
    }

    /// Get-or-create the endpoint state and ensure its worker runs.
    fn get_or_create(&self, endpoint: EndpointId) -> Arc<EndpointTxState> {
        let transport = self.inner.peer_registry.ensure_transport(endpoint);
        let quantum = transport.mps.load(Ordering::Relaxed).max(512);
        let state = self
            .inner
            .states
            .entry(endpoint)
            .or_insert_with(|| Arc::new(EndpointTxState::new(endpoint, transport, quantum)))
            .clone();
        state.start_if_idle(&self.inner);
        state
    }

    /// Shut down every worker and reconcile every queue. Discipline:
    /// signal cancellation, join boundedly, abort stragglers AND await
    /// their termination (a timed-out join must never detach a task that
    /// can still transmit), then purge + report every scheduler so gauges
    /// reconcile. After return, no worker of this registry exists and no
    /// packet of the generation can still be transmitted.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let handles: Vec<_> = self
            .inner
            .states
            .iter()
            .filter_map(|e| e.value().worker.lock().take())
            .collect();
        let pending = join_bounded(handles, Duration::from_secs(5)).await;
        for h in pending {
            h.abort();
            let _ = h.await;
        }
        // Workers that exited normally already purged + reported; aborted
        // stragglers did not — purge + report here so no gauge leaks.
        // Idempotent on empty schedulers (zero deltas).
        for entry in self.inner.states.iter() {
            let state = entry.value();
            state.sched.lock().purge_all(DropReason::GenerationEnd);
            report_state(state, &self.inner.metrics);
        }
        self.inner.states.clear();
    }

    #[cfg(test)]
    fn state_count(&self) -> usize {
        self.inner.states.len()
    }
}

/// Enqueue one outbound logical packet into its endpoint's TX queue.
/// Policy/routing already accepted it; `member` binds the frame network.
pub fn enqueue_packet(
    registry: &EndpointTxRegistry,
    member: &Arc<PeerMembershipState>,
    packet: LogicalPacket,
) {
    let endpoint = member.transport.endpoint;
    let net = member.identity.read().network_id;
    let state = registry.get_or_create(endpoint);
    {
        let mut sched = state.sched.lock();
        // Outcome already folded into the snapshot below (single-sourced);
        // acceptance and tail-rejection both surface through the diff.
        let _ = sched.enqueue(net, packet, Instant::now());
        let snapshot = sched.snapshot();
        drop(sched);
        let mut reporter = state.reporter.lock();
        let diff = reporter.diff(snapshot);
        drop(reporter);
        report_diff(&registry.inner.metrics, &diff);
    }
    state.notify.notify_one();
}

/// Map one scheduler diff onto telemetry (single reporting site per worker;
/// the enqueue path reports its own diffs the same way).
fn report_diff(metrics: &AgentMetrics, diff: &tunnet_core::scheduler::SchedDiff) {
    metrics.queue_add(diff.dq_packets, diff.dq_bytes, diff.dq_flows);
    metrics.queue_inflight_add(diff.dq_inflight_packets, diff.dq_inflight_bytes);
    if diff.sent_packets > 0 {
        metrics.packets_add("out", diff.sent_packets);
        metrics.bytes_add("out", diff.sent_bytes);
        metrics.overlay_tx_logical_add(diff.sent_packets);
    }
    for reason in DropReason::ALL {
        let n = diff.drop_packets[reason.index()];
        if n > 0 {
            metrics.dropped_add(reason.as_str(), n);
        }
    }
}

/// Report a scheduler snapshot diff for one state (worker + enqueue paths).
fn report_state(state: &EndpointTxState, metrics: &AgentMetrics) {
    let snapshot = state.sched.lock().snapshot();
    let diff = state.reporter.lock().diff(snapshot);
    report_diff(metrics, &diff);
}

struct TxCtx<'a> {
    transport: &'a Arc<PeerTransportState>,
    pool: &'a ConnPool,
    metrics: &'a AgentMetrics,
    bufs: &'a Arc<PacketPool>,
    meter: &'a CloudRelayMeter,
}

async fn run_endpoint_worker(state: Arc<EndpointTxState>, inner: Arc<Inner>) {
    let endpoint = state.endpoint;
    let ctx = TxCtx {
        transport: &state.transport,
        pool: &inner.pool,
        metrics: &inner.metrics,
        bufs: &inner.bufs,
        meter: &inner.meter,
    };
    // The worker-owned cursor: Some from dequeue until scheduler
    // resolution. NOTHING dequeues while this is set, and NOTHING drops
    // it except explicit complete/discard below.
    let mut inflight: Option<InFlightTx> = None;
    loop {
        if inner.cancel.is_cancelled() {
            // Generation teardown: resolve the owned packet, purge the
            // queue (both recorded under the generation reason), report,
            // and exit. No packet crosses generations.
            if let Some(it) = inflight.take() {
                state
                    .sched
                    .lock()
                    .discard_inflight(it.logical_len, DropReason::GenerationEnd);
            }
            state.sched.lock().purge_all(DropReason::GenerationEnd);
            report_state(&state, &inner.metrics);
            state.running.store(false, Ordering::Release);
            return;
        }
        // Permanent DATAGRAM incompatibility (item 13): never redial-loop
        // an incompatible peer. A live connection is a meaningful change
        // (accept path or reconfiguration installed one) — clear and try
        // it. Otherwise park without dialing; new generations start fresh.
        if ctx.transport.datagram_incompatible.load(Ordering::Relaxed) {
            if ctx.transport.live_conn().is_some() {
                ctx.transport
                    .datagram_incompatible
                    .store(false, Ordering::Relaxed);
            } else {
                tokio::select! {
                    _ = state.notify.notified() => {}
                    _ = inner.cancel.cancelled() => continue,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }
        }
        // Membership revocation is observed per attempt (not just at
        // dequeue): a revoked member's packets never transmit.
        if let Some(it) = inflight.as_ref() {
            let revoked = match inner.peer_registry.get_membership(endpoint, it.key.net) {
                Some(m) => {
                    !Arc::ptr_eq(&m, &it.member)
                        || m.epoch.load(Ordering::Relaxed) != it.member_epoch
                }
                None => true,
            };
            if revoked {
                let it = inflight.take().expect("checked");
                state
                    .sched
                    .lock()
                    .discard_inflight(it.logical_len, DropReason::MembershipRevoked);
                state
                    .sched
                    .lock()
                    .purge_network(it.key.net, DropReason::MembershipRevoked);
                report_state(&state, &inner.metrics);
                continue;
            }
        }
        // A live connection is required BEFORE a new dequeue: without one
        // the worker parks on reconnect instead of holding packets hostage.
        // (An already-owned cursor skips dequeue below and drives on the
        // reconnected connection.)
        let has_work = inflight.is_some() || state.sched.lock().has_queued_work();
        let conn = match ctx.transport.live_conn() {
            Some(c) => Some(c),
            None => {
                if !has_work {
                    if idle_exit(&state, &inner).await {
                        return;
                    }
                    continue;
                }
                match ctx.pool.get(endpoint).await {
                    Ok(c) => Some(c),
                    Err(_) => {
                        // Dial failed (5 s timeout paces retries): wait for
                        // new work or a settle delay, then retry.
                        tokio::select! {
                            _ = state.notify.notified() => {}
                            _ = inner.cancel.cancelled() => continue,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        }
                        continue;
                    }
                }
            }
        };
        let conn = conn.expect("live or just dialed");
        // Dequeue only when nothing is in-flight: one owned packet at a
        // time, never two.
        if inflight.is_none() {
            let item = {
                let mut sched = state.sched.lock();
                match sched.next(Instant::now()) {
                    Dequeue::Send(item) => Some(*item),
                    Dequeue::Empty => None,
                }
            };
            let Some(item) = item else {
                if idle_exit(&state, &inner).await {
                    return;
                }
                continue;
            };
            report_state(&state, &inner.metrics);
            ctx.metrics.observe_sojourn(item.sojourn);
            // Revoked membership: drop the in-flight packet and purge the
            // rest of this network's queue. Live memberships send normally.
            let member = inner.peer_registry.get_membership(endpoint, item.net);
            let Some(member) = member else {
                let len = item.packet.len();
                state
                    .sched
                    .lock()
                    .discard_inflight(len, DropReason::MembershipRevoked);
                state
                    .sched
                    .lock()
                    .purge_network(item.net, DropReason::MembershipRevoked);
                report_state(&state, &inner.metrics);
                continue;
            };
            let key = tunnet_core::scheduler::SchedFlowKey {
                net: item.net,
                flow: item.flow,
            };
            let len = item.packet.len();
            let member_epoch = member.epoch.load(Ordering::Relaxed);
            let mps = ctx.transport.mps.load(Ordering::Relaxed);
            let frame_id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
            inflight = Some(InFlightTx {
                key,
                logical_len: len,
                member,
                member_epoch,
                cur: PartialPacket::new(item.packet, item.net, mps, frame_id),
                last_conn: None,
            });
        }
        // Periodic MPS refresh covers silent path changes (plus
        // event-driven refresh in the pool's path watcher and TooLarge
        // recovery inside the drive).
        if ctx
            .transport
            .sends_since_mps_check
            .fetch_add(1, Ordering::Relaxed)
            >= 512
            && let Some(mps) = ctx.transport.refresh_mps()
        {
            ctx.transport
                .sends_since_mps_check
                .store(0, Ordering::Relaxed);
            state.sched.lock().set_quantum(mps.max(512));
        }
        // Connection change since the last drive: prefix segments accepted
        // by the old connection's send path may be lost with it. Replay
        // from byte 0 (same id when geometry holds, fresh id + replan
        // when it changed). Scheduler ownership and timestamps untouched.
        {
            let it = inflight.as_mut().expect("dequeued above");
            let sid = conn.stable_id();
            if it.last_conn != Some(sid) {
                if it.cur.next_index > 0 {
                    replay_for_new_connection(&ctx, it);
                }
                it.last_conn = Some(sid);
            }
        }
        let mut sender = ConnSender { conn: &conn };
        match drive_inflight(
            &ctx,
            &mut sender,
            inflight.as_mut().expect("dequeued above"),
            &inner.cancel,
        )
        .await
        {
            Drive::Done { wire, frames } => {
                let it = inflight.take().expect("driven");
                state.sched.lock().complete(&it.key, it.logical_len, wire);
                ctx.metrics.overlay_tx_datagrams_add(frames);
                report_state(&state, &inner.metrics);
            }
            Drive::Dropped { reason } => {
                let it = inflight.take().expect("driven");
                state.sched.lock().discard_inflight(it.logical_len, reason);
                report_state(&state, &inner.metrics);
            }
            Drive::ConnLost => {
                // TX-observed loss on THIS connection: the unified session
                // transition (same op as reader failures) invalidates
                // exactly this canonical connection, so the worker never
                // re-obtains or retries it. The cursor is retained with
                // everything intact; the loop redials and replays from
                // byte 0. Park briefly so an instantly-failing connection
                // cannot hot-spin.
                session_failed_for_worker(
                    &inner,
                    endpoint,
                    conn.stable_id(),
                    SessionFailReason::TxConnLost,
                )
                .await;
                tokio::select! {
                    _ = state.notify.notified() => {}
                    _ = inner.cancel.cancelled() => {}
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
            Drive::Fatal => {
                // Permanent DATAGRAM incompatibility (peer or local config
                // cannot carry DATAGRAMs): close + invalidate exactly this
                // canonical connection, mark the endpoint incompatible (no
                // redial loop), and resolve the packet explicitly. A new
                // canonical connection or generation clears the mark.
                let it = inflight.take().expect("driven");
                on_transport_fatal(&inner, &ctx, &state, endpoint, &conn, it).await;
                tokio::select! {
                    _ = state.notify.notified() => {}
                    _ = inner.cancel.cancelled() => {}
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
            Drive::Cancelled => {
                // The send itself observed cancellation: resolve and let
                // the loop top observe it and exit.
                let it = inflight.take().expect("driven");
                state
                    .sched
                    .lock()
                    .discard_inflight(it.logical_len, DropReason::GenerationEnd);
                report_state(&state, &inner.metrics);
            }
        }
    }
}

/// Unified session-failure transition for the TX path (item 3): funnels
/// TX-observed loss through the session manager's op when attached.
/// Falls back to direct pool invalidation in unit tests (no manager).
async fn session_failed_for_worker(
    inner: &Arc<Inner>,
    endpoint: EndpointId,
    stable_id: usize,
    reason: SessionFailReason,
) {
    let manager = inner.session_mgr.lock().expect("session lock").clone();
    if let Some(manager) = manager {
        manager.session_failed(endpoint, stable_id, reason).await;
    } else {
        ctx_pool_fallback(inner, endpoint, stable_id).await;
    }
}

async fn ctx_pool_fallback(inner: &Arc<Inner>, endpoint: EndpointId, stable_id: usize) {
    if let Some(dead) = inner.pool.invalidate_canonical(endpoint, stable_id).await {
        dead.close(0u32.into(), b"session_failed");
    }
}

/// Permanent DATAGRAM incompatibility (item 13): close + invalidate the
/// exact canonical connection through the unified op, mark the endpoint
/// incompatible so the worker never redial-loops, surface an explicit
/// counter, and resolve the packet explicitly with `Incompatible`.
async fn on_transport_fatal(
    inner: &Arc<Inner>,
    ctx: &TxCtx<'_>,
    state: &Arc<EndpointTxState>,
    endpoint: EndpointId,
    conn: &Connection,
    it: InFlightTx,
) {
    let sid = conn.stable_id();
    conn.close(0u32.into(), b"datagrams_unsupported");
    session_failed_for_worker(inner, endpoint, sid, SessionFailReason::TransportFatal).await;
    ctx.transport
        .datagram_incompatible
        .store(true, Ordering::Relaxed);
    ctx.metrics.endpoint_incompatible_inc();
    state
        .sched
        .lock()
        .discard_inflight(it.logical_len, DropReason::Incompatible);
    // Report through this state's reporter (single-sourced diffs).
    let snapshot = state.sched.lock().snapshot();
    let diff = state.reporter.lock().diff(snapshot);
    report_diff(ctx.metrics, &diff);
}
async fn idle_exit(state: &Arc<EndpointTxState>, inner: &Arc<Inner>) -> bool {
    report_state(state, &inner.metrics);
    tokio::select! {
        _ = state.notify.notified() => false,
        _ = inner.cancel.cancelled() => {
            state.sched.lock().purge_all(DropReason::GenerationEnd);
            report_state(state, &inner.metrics);
            state.running.store(false, Ordering::Release);
            true
        }
        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            if state.sched.lock().has_queued_work() || inner.cancel.is_cancelled() {
                false
            } else {
                state.running.store(false, Ordering::Release);
                if state.sched.lock().has_queued_work()
                    && !state.running.swap(true, Ordering::AcqRel)
                {
                    false
                } else {
                    report_state(state, &inner.metrics);
                    true
                }
            }
        }
    }
}

/// One owned in-flight packet: the worker holds this from dequeue to
/// scheduler resolution. The cursor (including the actual `LogicalPacket`
/// owner) lives here — never in a transient transmit call — so connection
/// loss, holds, and cancellation can never drop it.
struct InFlightTx {
    key: tunnet_core::scheduler::SchedFlowKey,
    logical_len: usize,
    member: Arc<PeerMembershipState>,
    member_epoch: u64,
    cur: PartialPacket,
    /// Stable id of the connection the cursor was last driven on. A change
    /// means `send_datagram_wait` success on the old connection no longer
    /// proves anything (no remote ack): replay from byte 0 below.
    last_conn: Option<usize>,
}

/// Re-drive the worker-owned cursor after a canonical connection change.
///
/// `send_datagram_wait` success only admitted the DATAGRAM into the local
/// QUIC send path — it never acknowledged remote delivery. Prefix segments
/// sent on the dead connection may be lost with it, so resuming only the
/// suffix is unsafe. Retained across the change: the exact `LogicalPacket`,
/// enqueue timestamp / CoDel ownership, scheduler in-flight ownership, and
/// accumulated wire/frame accounting. Replayed from byte 0:
/// - geometry unchanged: reuse the frame id and resend all segments (the
///   receiver's duplicate handling absorbs redeliveries and completes from
///   whichever prefix actually arrived);
/// - geometry changed: fresh frame id + the existing safe full replan
///   (a restart is a new accounting unit).
fn replay_for_new_connection(ctx: &TxCtx<'_>, it: &mut InFlightTx) {
    let cur = &mut it.cur;
    if cur.next_index == 0 {
        return;
    }
    let mps = ctx.transport.mps.load(Ordering::Relaxed);
    match plan_for_mps(cur.total, mps) {
        plan if plan == cur.plan => {
            cur.replay_from_start();
        }
        SegmentPlan::Impossible => {
            // Degenerate path: mark for the drive, which refreshes once
            // and then drops explicitly.
            cur.plan = SegmentPlan::Impossible;
            cur.next_index = 0;
        }
        plan => {
            let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
            cur.adopt(plan, id);
        }
    }
}

enum Drive {
    /// Logical packet fully transmitted (total wire bytes, frame count).
    Done { wire: usize, frames: u64 },
    /// Dropped with reason (worker resolves via `discard_inflight`).
    Dropped { reason: DropReason },
    /// Connection died mid-packet: cursor retained, worker reconnects.
    ConnLost,
    /// Datagrams unusable on this connection: worker closes/invalidates
    /// it and reconnects (cursor retained).
    Fatal,
    /// Generation cancelled mid-send: worker resolves `GenerationEnd`.
    Cancelled,
}

impl std::fmt::Debug for Drive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done { wire, frames } => {
                write!(f, "Done {{ wire: {wire}, frames: {frames} }}")
            }
            Self::Dropped { reason } => write!(f, "Dropped({})", reason.as_str()),
            Self::ConnLost => write!(f, "ConnLost"),
            Self::Fatal => write!(f, "Fatal"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

enum FrameError {
    TooLarge,
    ConnLost,
    /// Datagrams disabled/unsupported on this connection (degenerate).
    Fatal,
    Cancelled,
}

/// DATAGRAM submit behind a trait so tests can drive the exact cursor
/// state machine against a scripted mock transport (success / loss /
/// oversize / unsupported / blocked-until-cancel) while production uses
/// the real connection with cancel-aware `send_datagram_wait`.
#[async_trait::async_trait]
trait FrameSender: Send {
    async fn send_frame(
        &mut self,
        frame: Bytes,
        cancel: &CancellationToken,
    ) -> Result<(), FrameError>;
}

/// Production sender: `send_datagram_wait` (waits for buffer space, never
/// drop-oldest, never a precheck race — this worker is the only submitter)
/// raced against generation cancellation so shutdown never waits on QUIC.
struct ConnSender<'a> {
    conn: &'a Connection,
}

#[async_trait::async_trait]
impl FrameSender for ConnSender<'_> {
    async fn send_frame(
        &mut self,
        frame: Bytes,
        cancel: &CancellationToken,
    ) -> Result<(), FrameError> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(FrameError::Cancelled),
            res = self.conn.send_datagram_wait(frame) => match res {
                Ok(()) => Ok(()),
                Err(SendDatagramError::TooLarge) => Err(FrameError::TooLarge),
                Err(SendDatagramError::ConnectionLost(_)) => Err(FrameError::ConnLost),
                Err(_) => Err(FrameError::Fatal),
            },
        }
    }
}

/// Mid-packet transmit cursor: the worker owns the logical packet from
/// dequeue to completion or explicit drop. Segments encode from borrows, so
/// resume never re-parses and never loses bytes.
///
/// The cursor tracks the FULL segmentation geometry (plan + packet id +
/// next index), never just a count: any geometry change restarts the
/// logical packet from byte 0 with a fresh id, so old offsets are never
/// reused with a new MPS.
struct PartialPacket {
    packet: LogicalPacket,
    next_index: usize,
    frame_id: u32,
    /// Geometry the in-flight segments conform to (count + seg_cap, or
    /// Single for a fresh single-frame cursor).
    plan: SegmentPlan,
    total: usize,
    /// Wire bytes sent under the current accounting unit. Preserved across
    /// same-geometry replay (every transmission counts; the receiver
    /// dedups); reset on restart (fresh id = new unit). Completed once.
    wire_bytes: u64,
    /// DATAGRAM frames sent under the current accounting unit (same
    /// retention rule as `wire_bytes`): pre-reconnect transmissions are
    /// never lost from telemetry.
    frames_sent: u64,
    /// Network bound at enqueue from the route's membership.
    net: Uuid,
}

/// Outcome of re-planning a cursor against current MPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replan {
    /// Geometry changed (or first sizing): restart from byte 0, fresh id.
    Restarted,
    /// Geometry identical: retry the current segment in place.
    Retry,
    /// The path cannot carry this packet at all: drop it.
    Impossible,
}

impl PartialPacket {
    fn new(packet: LogicalPacket, net: Uuid, mps: usize, frame_id: u32) -> Self {
        let total = packet.len();
        let plan = plan_for_mps(total, mps);
        Self {
            packet,
            next_index: 0,
            frame_id,
            plan,
            total,
            wire_bytes: 0,
            frames_sent: 0,
            net,
        }
    }

    /// Adopt a geometry wholesale: fresh id, offset reset, accounting
    /// accumulators reset (a restart is a new accounting unit). Old offsets
    /// are never reused after this point.
    fn adopt(&mut self, plan: SegmentPlan, frame_id: u32) {
        self.plan = plan;
        self.next_index = 0;
        self.wire_bytes = 0;
        self.frames_sent = 0;
        self.frame_id = frame_id;
    }

    /// Replay from byte 0 on a NEW connection with UNCHANGED geometry:
    /// reuse the frame id and resend every segment (receiver duplicates
    /// fill or absorb). Accumulators persist — every transmission counts.
    /// Scheduler ownership, timestamps, and the logical owner are untouched.
    fn replay_from_start(&mut self) {
        self.next_index = 0;
    }

    /// Re-plan against current MPS (already refreshed by the caller).
    /// Compares the COMPLETE geometry — count AND segment capacity AND
    /// single/segmented shape — not just the count.
    fn replan(&mut self, mps: usize, frame_id: u32) -> Replan {
        match plan_for_mps(self.total, mps) {
            SegmentPlan::Impossible => Replan::Impossible,
            plan if plan == self.plan => Replan::Retry,
            plan => {
                self.adopt(plan, frame_id);
                Replan::Restarted
            }
        }
    }
}

/// Segmentation plan for a logical packet at one MPS snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentPlan {
    /// Fits in one DATAGRAM.
    Single,
    /// Split into `count` segments of at most `seg_cap` payload bytes.
    Segmented { count: usize, seg_cap: usize },
    /// Degenerate path (no useful segment fits).
    Impossible,
}

/// Pure sizing decision: single when it fits, else uniform segments;
/// impossible when the path cannot carry even minimal segments.
fn plan_for_mps(total: usize, mps: usize) -> SegmentPlan {
    if total == 0 || total > MAX_LOGICAL_LEN {
        return SegmentPlan::Impossible;
    }
    if total + SINGLE_OVERHEAD <= mps {
        return SegmentPlan::Single;
    }
    match usable_seg_cap(mps) {
        Some(seg_cap) => {
            let count = total.div_ceil(seg_cap).max(2);
            if count > MAX_SEGMENTS {
                SegmentPlan::Impossible
            } else {
                SegmentPlan::Segmented { count, seg_cap }
            }
        }
        None => SegmentPlan::Impossible,
    }
}

fn usable_seg_cap(mps: usize) -> Option<usize> {
    let cap = mps.checked_sub(SEGMENT_OVERHEAD)?;
    (cap >= MIN_SEGMENT_PAYLOAD).then_some(cap)
}

/// Drive the worker-owned cursor to completion, connection hold, fatal,
/// cancellation, or explicit drop. The logical packet stays in the cursor
/// throughout: singles encode from a staged copy and segments from
/// borrows, so a TooLarge replan restarts from the ORIGINAL packet — never
/// reconstructed from a wire frame, never re-timestamped.
async fn drive_inflight(
    ctx: &TxCtx<'_>,
    sender: &mut impl FrameSender,
    it: &mut InFlightTx,
    cancel: &CancellationToken,
) -> Drive {
    transmit_cursor(ctx, sender, &mut it.cur, cancel).await
}

async fn transmit_cursor(
    ctx: &TxCtx<'_>,
    sender: &mut impl FrameSender,
    cur: &mut PartialPacket,
    cancel: &CancellationToken,
) -> Drive {
    // Fresh cursors (nothing transmitted yet) size and adopt here.
    // Replayed cursors (replay_for_new_connection already validated the
    // geometry and reset the offset) MUST skip adopt: it would mint a new
    // id and wipe the retained accumulators.
    if cur.next_index == 0 && cur.frames_sent == 0 && cur.wire_bytes == 0 {
        let mps = ctx.transport.mps.load(Ordering::Relaxed);
        match plan_for_mps(cur.total, mps) {
            SegmentPlan::Single => return transmit_single(ctx, sender, cur, cancel).await,
            plan @ SegmentPlan::Segmented { .. } => {
                let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
                cur.adopt(plan, id);
                return transmit_segmented(ctx, sender, cur, 0, cancel).await;
            }
            SegmentPlan::Impossible => {
                // Degenerate path: refresh once, then give up if useless.
                ctx.transport.refresh_mps();
                let mps2 = ctx.transport.mps.load(Ordering::Relaxed);
                match plan_for_mps(cur.total, mps2) {
                    SegmentPlan::Single => {
                        return transmit_single(ctx, sender, cur, cancel).await;
                    }
                    plan @ SegmentPlan::Segmented { .. } => {
                        let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
                        cur.adopt(plan, id);
                        return transmit_segmented(ctx, sender, cur, 0, cancel).await;
                    }
                    SegmentPlan::Impossible => {
                        return Drive::Dropped {
                            reason: DropReason::TooLarge,
                        };
                    }
                }
            }
        }
    }
    // Replayed cursors drive their stored plan (validated by the replay).
    // A degenerate replay refreshes once, then drops explicitly.
    match cur.plan {
        SegmentPlan::Single => transmit_single(ctx, sender, cur, cancel).await,
        SegmentPlan::Segmented { .. } => transmit_segmented(ctx, sender, cur, 0, cancel).await,
        SegmentPlan::Impossible => {
            ctx.transport.refresh_mps();
            let mps2 = ctx.transport.mps.load(Ordering::Relaxed);
            match plan_for_mps(cur.total, mps2) {
                SegmentPlan::Single => transmit_single(ctx, sender, cur, cancel).await,
                plan @ SegmentPlan::Segmented { .. } => {
                    let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
                    cur.adopt(plan, id);
                    transmit_segmented(ctx, sender, cur, 0, cancel).await
                }
                SegmentPlan::Impossible => Drive::Dropped {
                    reason: DropReason::TooLarge,
                },
            }
        }
    }
}

/// Encode one frame as a staged copy and wait for buffer space. The logical
/// owner stays in the cursor, so any failure below keeps the packet.
async fn transmit_single(
    ctx: &TxCtx<'_>,
    sender: &mut impl FrameSender,
    cur: &mut PartialPacket,
    cancel: &CancellationToken,
) -> Drive {
    let frame = stage_single(ctx.bufs, cur.net, cur.packet.owner.as_bytes());
    let wire = frame.len();
    match sender.send_frame(frame, cancel).await {
        Ok(()) => {
            if ctx.transport.relay.load(Ordering::Relaxed) {
                ctx.meter.record(wire as u64);
            }
            ctx.transport.record_tx(wire as u64);
            cur.wire_bytes += wire as u64;
            cur.frames_sent += 1;
            Drive::Done {
                wire: cur.wire_bytes as usize,
                frames: cur.frames_sent,
            }
        }
        Err(FrameError::TooLarge) => {
            // Stale MPS: refresh and replan from the ORIGINAL packet.
            ctx.transport.refresh_mps();
            let mps = ctx.transport.mps.load(Ordering::Relaxed);
            let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
            match cur.replan(mps, id) {
                Replan::Restarted => Box::pin(transmit_cursor(ctx, sender, cur, cancel)).await,
                Replan::Retry => Box::pin(transmit_single(ctx, sender, cur, cancel)).await,
                Replan::Impossible => Drive::Dropped {
                    reason: DropReason::TooLarge,
                },
            }
        }
        Err(FrameError::ConnLost) => Drive::ConnLost,
        Err(FrameError::Fatal) => Drive::Fatal,
        Err(FrameError::Cancelled) => Drive::Cancelled,
    }
}

/// Transmit the cursor's remainder segment by segment, encoding incrementally
/// from the retained logical owner under the cursor's STORED geometry.
/// Connection loss retains everything (resume on the fresh connection with
/// the same id — orphaned prefix segments on the dead connection simply
/// expire); TooLarge re-plans against fresh MPS (full geometry compare).
async fn transmit_segmented(
    ctx: &TxCtx<'_>,
    sender: &mut impl FrameSender,
    cur: &mut PartialPacket,
    mut restarts: u8,
    cancel: &CancellationToken,
) -> Drive {
    let (count, seg_cap) = match cur.plan {
        SegmentPlan::Segmented { count, seg_cap } => (count, seg_cap),
        // A TooLarge replan can adopt Single — route out, boxed to break
        // the async cycle.
        SegmentPlan::Single => return Box::pin(transmit_single(ctx, sender, cur, cancel)).await,
        SegmentPlan::Impossible => {
            return Drive::Dropped {
                reason: DropReason::TooLarge,
            };
        }
    };
    // Bounded retries on flapping paths (budget shared across restarts).
    // Frame/wire totals live in the cursor (not locals): pre-loss
    // transmissions survive reconnects and complete exactly once.
    loop {
        if cur.next_index >= count {
            // Completion: the whole logical packet with total wire bytes.
            return Drive::Done {
                wire: cur.wire_bytes as usize,
                frames: cur.frames_sent,
            };
        }
        let i = cur.next_index;
        let off = i * seg_cap;
        let end = (off + seg_cap).min(cur.total);
        if off >= cur.total || end <= off {
            return Drive::Dropped {
                reason: DropReason::TooLarge,
            };
        }
        // Encode from a borrow (owner retained for resume/retry).
        let payload = &cur.packet.owner.as_bytes()[off..end];
        let mut buf = ctx.bufs.acquire(payload.len() + SEGMENT_OVERHEAD);
        {
            let region = buf.recv_region(payload.len() + SEGMENT_OVERHEAD);
            encode_segment_prefix(
                &mut region[..SEGMENT_OVERHEAD],
                cur.net,
                SegmentHeader {
                    id: cur.frame_id,
                    index: i as u16,
                    count: count as u16,
                    total: cur.total as u16,
                },
            );
            region[SEGMENT_OVERHEAD..].copy_from_slice(payload);
            buf.set_len(payload.len() + SEGMENT_OVERHEAD);
        }
        let frame = Bytes::from_owner(buf);
        let wire = frame.len();
        match sender.send_frame(frame, cancel).await {
            Ok(()) => {
                cur.frames_sent += 1;
                cur.wire_bytes += wire as u64;
                if ctx.transport.relay.load(Ordering::Relaxed) {
                    ctx.meter.record(wire as u64);
                }
                ctx.transport.record_tx(wire as u64);
                cur.next_index += 1;
            }
            Err(FrameError::TooLarge) => {
                ctx.transport.refresh_mps();
                restarts += 1;
                if restarts > 2 {
                    return Drive::Dropped {
                        reason: DropReason::TooLarge,
                    };
                }
                let mps = ctx.transport.mps.load(Ordering::Relaxed);
                let id = ctx.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
                match cur.replan(mps, id) {
                    Replan::Restarted => {
                        return Box::pin(transmit_segmented(ctx, sender, cur, restarts, cancel))
                            .await;
                    }
                    Replan::Retry => {
                        // Same geometry: retry this segment in place.
                    }
                    Replan::Impossible => {
                        return Drive::Dropped {
                            reason: DropReason::TooLarge,
                        };
                    }
                }
            }
            Err(FrameError::ConnLost) => {
                // Owner, accumulator, and geometry intact: the worker-owned
                // cursor survives; the outer loop reconnects and resumes.
                return Drive::ConnLost;
            }
            Err(FrameError::Fatal) => {
                return Drive::Fatal;
            }
            Err(FrameError::Cancelled) => {
                return Drive::Cancelled;
            }
        }
    }
}

fn stage_single(pool: &Arc<PacketPool>, net: Uuid, payload: &[u8]) -> Bytes {
    let mut buf = pool.acquire(payload.len() + SINGLE_OVERHEAD);
    let region = buf.recv_region(payload.len() + SINGLE_OVERHEAD);
    tunnet_common::packet::encode_single_prefix(&mut region[..SINGLE_OVERHEAD], net);
    region[SINGLE_OVERHEAD..].copy_from_slice(payload);
    buf.set_len(payload.len() + SINGLE_OVERHEAD);
    Bytes::from_owner(buf)
}

/// Join every handle boundedly. Returns the handles that did not finish in
/// time (the caller aborts them AND awaits termination — never detaches).
async fn join_bounded(
    handles: Vec<tokio::task::JoinHandle<()>>,
    timeout: Duration,
) -> Vec<tokio::task::JoinHandle<()>> {
    if handles.is_empty() {
        return Vec::new();
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let mut pending = handles;
    let mut done_idx = Vec::new();
    loop {
        done_idx.clear();
        for (i, h) in pending.iter_mut().enumerate() {
            if h.is_finished() {
                let _ = (&mut *h).await;
                done_idx.push(i);
            }
        }
        for i in done_idx.drain(..).rev() {
            pending.swap_remove(i);
        }
        if pending.is_empty() {
            return pending;
        }
        if tokio::time::Instant::now() >= deadline {
            return pending;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
}

/// Keep-alive preconnect: dial known peers NOW so the first real packet
/// doesn't pay connection setup. Gated on ingress readiness — no preconnect
/// may run before the ingress installer exists, otherwise dials become
/// canonical with no reader. Bounded concurrency (8) visits EVERY eligible
/// peer (no skip-past-the-window); cancellation stops pending/new dials.
/// `dial` is injectable for tests.
pub async fn preconnect_peers<Fut>(
    peers: Vec<EndpointId>,
    local: EndpointId,
    ingress_ready: bool,
    cancel: &CancellationToken,
    dial: impl Fn(EndpointId) -> Fut + Send + Sync + 'static,
) where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if !ingress_ready {
        return;
    }
    use futures_util::StreamExt as _;
    let dial = Arc::new(dial);
    let dials = futures_util::stream::iter(peers.into_iter().filter(|p| *p != local).map(|peer| {
        let make_dial = dial.clone();
        async move {
            (make_dial(peer)).await;
        }
    }))
    .buffer_unordered(8);
    tokio::pin!(dials);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            next = dials.next() => {
                if next.is_none() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_common::packet::PacketPool;

    async fn test_registry() -> (PeerRegistry, EndpointTxRegistry) {
        let peer_registry = PeerRegistry::new();
        // A ConnPool needs a real endpoint; bind on the test runtime.
        let ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let pool = ConnPool::new(ep, b"test/tx");
        let reg = EndpointTxRegistry::new(
            CancellationToken::new(),
            pool,
            Arc::new(peer_registry.clone()),
            crate::actors::test_support::test_metrics(),
            PacketPool::new(8),
            CloudRelayMeter::new(),
        );
        (peer_registry, reg)
    }

    fn test_member(
        reg: &PeerRegistry,
        endpoint: EndpointId,
        net: Uuid,
        ip: [u8; 4],
    ) -> Arc<PeerMembershipState> {
        reg.ensure_membership(Arc::new(tunnet_core::peers::PeerIdentity {
            endpoint,
            endpoint_hex: format!("{endpoint}"),
            hostname: "peer".into(),
            ip: std::net::Ipv4Addr::from(ip),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }))
    }

    fn test_packet(size: usize) -> LogicalPacket {
        test_packet_fill(size, 0xAB)
    }

    fn test_packet_fill(size: usize, fill: u8) -> LogicalPacket {
        let pool = PacketPool::new(8);
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut raw = Vec::new();
        b.write(&mut raw, &vec![fill; size.saturating_sub(28)])
            .unwrap();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        LogicalPacket::from_pooled(buf, raw.len()).unwrap()
    }

    /// Scripted mock transport: success / loss / oversize / unsupported /
    /// blocked-until-cancel, recording every submitted frame. Drives the
    /// EXACT production cursor state machine (`drive_inflight`).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum FrameScript {
        Ok,
        TooLarge,
        ConnLost,
        Fatal,
        BlockForever,
    }

    struct ScriptSender {
        script: std::collections::VecDeque<FrameScript>,
        sent: Vec<Bytes>,
    }

    impl ScriptSender {
        fn new(script: Vec<FrameScript>) -> Self {
            Self {
                script: script.into(),
                sent: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl FrameSender for ScriptSender {
        async fn send_frame(
            &mut self,
            frame: Bytes,
            cancel: &CancellationToken,
        ) -> Result<(), FrameError> {
            match self.script.pop_front().unwrap_or(FrameScript::Ok) {
                FrameScript::Ok => {
                    self.sent.push(frame);
                    Ok(())
                }
                FrameScript::TooLarge => Err(FrameError::TooLarge),
                FrameScript::ConnLost => Err(FrameError::ConnLost),
                FrameScript::Fatal => Err(FrameError::Fatal),
                FrameScript::BlockForever => {
                    cancel.cancelled().await;
                    Err(FrameError::Cancelled)
                }
            }
        }
    }

    /// Exact-conservation tracker across drive/resolve transitions:
    /// offered == completed + dropped + owned (packets and bytes) after
    /// EVERY transition, and the surviving packet bytes are asserted.
    struct Conservation {
        offered_packets: u64,
        offered_bytes: u64,
        completed: u64,
        dropped: u64,
    }

    impl Conservation {
        fn new() -> Self {
            Self {
                offered_packets: 0,
                offered_bytes: 0,
                completed: 0,
                dropped: 0,
            }
        }

        fn offered(&mut self, len: usize) {
            self.offered_packets += 1;
            self.offered_bytes += len as u64;
        }

        fn check(&self, sched: &EndpointScheduler) {
            let snap = sched.snapshot();
            assert!(
                snap.conserves(self.offered_packets, self.offered_bytes),
                "conservation violated: offered=({},{}) completed={} dropped={} snapshot={:?}",
                self.offered_packets,
                self.offered_bytes,
                self.completed,
                self.dropped,
                snap,
            );
            assert_eq!(
                snap.owned_packets(),
                self.offered_packets - self.completed - self.dropped,
                "exactly-one-current-inflight ownership"
            );
        }
    }

    fn drive_ctx<'a>(
        tx_reg: &'a EndpointTxRegistry,
        transport: &'a Arc<PeerTransportState>,
    ) -> TxCtx<'a> {
        TxCtx {
            transport,
            pool: &tx_reg.inner.pool,
            metrics: &tx_reg.inner.metrics,
            bufs: &tx_reg.inner.bufs,
            meter: &tx_reg.inner.meter,
        }
    }

    fn dequeue_inflight(
        sched: &mut EndpointScheduler,
        member: &Arc<PeerMembershipState>,
        mps: usize,
        frame_id: u32,
    ) -> InFlightTx {
        let item = match sched.next(Instant::now()) {
            Dequeue::Send(item) => *item,
            Dequeue::Empty => panic!("expected queued packet"),
        };
        let key = tunnet_core::scheduler::SchedFlowKey {
            net: item.net,
            flow: item.flow,
        };
        let len = item.packet.len();
        let epoch = member.epoch.load(Ordering::Relaxed);
        InFlightTx {
            key,
            logical_len: len,
            member: member.clone(),
            member_epoch: epoch,
            cur: PartialPacket::new(item.packet, item.net, mps, frame_id),
            last_conn: None,
        }
    }

    /// Resolve one drive outcome exactly like the worker layer, returning
    /// the cursor for re-drive on `ConnLost`. Conservation is asserted
    /// after EVERY transition.
    async fn resolve_drive(
        sched: &mut EndpointScheduler,
        acc: &mut Conservation,
        it: InFlightTx,
        drive: Drive,
    ) -> Option<InFlightTx> {
        match drive {
            Drive::Done { wire, .. } => {
                sched.complete(&it.key, it.logical_len, wire);
                acc.completed += 1;
                acc.check(sched);
                None
            }
            Drive::Dropped { .. } => {
                sched.discard_inflight(it.logical_len, DropReason::TooLarge);
                acc.dropped += 1;
                acc.check(sched);
                None
            }
            Drive::Fatal => {
                // Production retains the cursor, closes/invalidates the
                // connection, and reconnects. The harness models the same
                // ownership: retained, conservation holding with the
                // packet still owned.
                acc.check(sched);
                Some(it)
            }
            Drive::Cancelled => {
                // The worker observes generation end; the harness records
                // the explicit drop the worker layer performs.
                sched.discard_inflight(it.logical_len, DropReason::GenerationEnd);
                acc.dropped += 1;
                acc.check(sched);
                None
            }
            Drive::ConnLost => {
                // Retained: conservation must hold with the packet still
                // owned (exactly one in-flight).
                acc.check(sched);
                Some(it)
            }
        }
    }

    #[tokio::test]
    async fn same_endpoint_two_networks_share_one_worker() {
        // One EndpointId in networks A and B: a single endpoint TX state,
        // a single worker, two scheduler flows.
        let (peer_reg, tx_reg) = test_registry().await;
        let ep = iroh::SecretKey::generate().public();
        let net_a = Uuid::from_u128(0x0a0a);
        let net_b = Uuid::from_u128(0x0b0b);
        let a = test_member(&peer_reg, ep, net_a, [10, 0, 0, 2]);
        let b = test_member(&peer_reg, ep, net_b, [10, 0, 1, 2]);
        enqueue_packet(&tx_reg, &a, test_packet(200));
        enqueue_packet(&tx_reg, &b, test_packet(200));
        assert_eq!(tx_reg.state_count(), 1, "one sender per endpoint");
        let state = tx_reg.inner.states.get(&ep).unwrap().clone();
        let snap = state.sched.lock().snapshot();
        assert_eq!(snap.queued_packets, 2);
        assert_eq!(snap.active_flows, 2, "networks never merge flows");
    }

    #[tokio::test]
    async fn revoked_membership_packets_purge() {
        // Revoking network A purges A's queued packets; B is untouched.
        let (peer_reg, tx_reg) = test_registry().await;
        let ep = iroh::SecretKey::generate().public();
        let net_a = Uuid::from_u128(0x0a0a);
        let net_b = Uuid::from_u128(0x0b0b);
        let a = test_member(&peer_reg, ep, net_a, [10, 0, 0, 2]);
        let b = test_member(&peer_reg, ep, net_b, [10, 0, 1, 2]);
        for _ in 0..3 {
            enqueue_packet(&tx_reg, &a, test_packet(200));
            enqueue_packet(&tx_reg, &b, test_packet(200));
        }
        peer_reg.remove_membership(ep, net_a);
        let state = tx_reg.inner.states.get(&ep).unwrap().clone();
        state
            .sched
            .lock()
            .purge_network(net_a, DropReason::MembershipRevoked);
        let snap = state.sched.lock().snapshot();
        assert_eq!(snap.queued_packets, 3);
        assert_eq!(snap.drop_packets[DropReason::MembershipRevoked.index()], 3);
        assert!(snap.conserves(6, snap.queued_bytes + snap.dropped_bytes()));
    }

    #[tokio::test]
    async fn preconnect_gated_on_ingress() {
        // Gate closed: returns immediately without dialing (far below the
        // 5 s dial timeout for an undiallable peer).
        let rt_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let local = rt_ep.id();
        let dead = iroh::SecretKey::generate().public();
        let cancel = CancellationToken::new();
        let dialed = Arc::new(AtomicBool::new(false));
        let dialed2 = dialed.clone();
        let start = Instant::now();
        preconnect_peers(vec![dead], local, false, &cancel, move |_peer| {
            let dialed2 = dialed2.clone();
            async move {
                dialed2.store(true, Ordering::Relaxed);
            }
        })
        .await;
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "gated preconnect must not dial"
        );
        assert!(!dialed.load(Ordering::Relaxed));
    }

    #[test]
    fn replan_restarts_on_segcap_change_with_same_count() {
        // 2800 bytes needs 3 segments at both MPS 1350 (cap 1323) and MPS
        // 1400 (cap 1373) — same count, different geometry. Restart with a
        // fresh id, never reuse old offsets with the new MPS.
        let mut cur = PartialPacket::new(test_packet(2800), Uuid::nil(), 1350, 41);
        assert!(matches!(
            cur.plan,
            SegmentPlan::Segmented {
                count: 3,
                seg_cap: 1323
            }
        ));
        cur.next_index = 2;
        cur.wire_bytes = 2700;
        assert_eq!(cur.replan(1400, 42), Replan::Restarted);
        assert!(matches!(
            cur.plan,
            SegmentPlan::Segmented {
                count: 3,
                seg_cap: 1373
            }
        ));
        assert_eq!(cur.next_index, 0, "restart from byte 0");
        assert_eq!(cur.wire_bytes, 0, "fresh accounting unit");
        assert_eq!(cur.frame_id, 42, "fresh packet id");
    }

    #[test]
    fn replan_retries_in_place_on_identical_geometry() {
        let mut cur = PartialPacket::new(test_packet(2800), Uuid::nil(), 1350, 41);
        cur.next_index = 1;
        assert_eq!(cur.replan(1350, 41), Replan::Retry);
        assert_eq!(cur.next_index, 1);
        assert_eq!(cur.frame_id, 41);
    }

    #[test]
    fn replan_handles_shape_transitions() {
        let mut cur = PartialPacket::new(test_packet(2800), Uuid::nil(), 1350, 41);
        assert!(matches!(cur.plan, SegmentPlan::Segmented { .. }));
        assert_eq!(cur.replan(9000, 42), Replan::Restarted);
        assert_eq!(cur.plan, SegmentPlan::Single);
        assert_eq!(cur.next_index, 0);
        let mut cur = PartialPacket::new(test_packet(1200), Uuid::nil(), 9000, 7);
        assert_eq!(cur.plan, SegmentPlan::Single);
        assert_eq!(cur.replan(1100, 8), Replan::Restarted);
        assert!(matches!(cur.plan, SegmentPlan::Segmented { .. }));
        assert_eq!(cur.replan(64, 9), Replan::Impossible);
    }

    #[test]
    fn plan_single_segmented_impossible() {
        // Exact fit → single (single overhead is 17: net-bound frames).
        assert_eq!(plan_for_mps(1184, 1201), SegmentPlan::Single);
        // One byte over → segmented.
        assert!(matches!(
            plan_for_mps(1185, 1201),
            SegmentPlan::Segmented { .. }
        ));
        // 2800 logical at 1350 MPS → 3 segments of ≤1323.
        match plan_for_mps(2800, 1350) {
            SegmentPlan::Segmented { count, seg_cap } => {
                assert_eq!(count, 3);
                assert_eq!(seg_cap, 1350 - SEGMENT_OVERHEAD);
            }
            other => panic!("expected segmented, got {other:?}"),
        }
        assert_eq!(plan_for_mps(0, 1350), SegmentPlan::Impossible);
        assert_eq!(plan_for_mps(9001, 1500), SegmentPlan::Impossible);
        assert_eq!(plan_for_mps(100, 10), SegmentPlan::Impossible);
    }

    #[test]
    fn plan_path_shrink_grows_count() {
        let total = 2800;
        let before = plan_for_mps(total, 1350);
        let after = plan_for_mps(total, 1200);
        match (before, after) {
            (
                SegmentPlan::Segmented { count: c1, .. },
                SegmentPlan::Segmented { count: c2, .. },
            ) => assert!(c2 >= c1, "shrink must not reduce segments"),
            other => panic!("expected segmented plans, got {other:?}"),
        }
        // 9000 at tiny MPS exceeds the segment cap (20 > 16).
        assert_eq!(plan_for_mps(9000, 500), SegmentPlan::Impossible);
    }

    #[test]
    fn single_encode_round_trip() {
        use tunnet_common::packet::SINGLE_OVERHEAD;
        let pool = PacketPool::new(8);
        let net = Uuid::from_u128(0x0c);
        let payload = vec![0xABu8; 200];
        let frame = stage_single(&pool, net, &payload);
        assert_eq!(frame.len(), SINGLE_OVERHEAD + 200);
        assert_eq!(frame[0], tunnet_common::packet::KIND_SINGLE);
        assert_eq!(&frame[1..SINGLE_OVERHEAD], net.as_bytes());
    }

    #[test]
    fn cursor_binds_network_at_enqueue() {
        let cur = PartialPacket::new(test_packet(200), Uuid::nil(), 1280, 1);
        assert_eq!(cur.net, Uuid::nil());
    }

    fn drive_sched() -> EndpointScheduler {
        // Direct scheduler (no worker): the harness owns dequeue/resolve
        // exactly like run_endpoint_worker.
        EndpointScheduler::new(1536)
    }

    #[tokio::test]
    async fn conn_loss_before_first_frame_retains_packet() {
        // Loss before any frame: cursor retained with owner, geometry, and
        // accumulator untouched; resume completes; bytes identical.
        let (_peer_reg, tx_reg) = test_registry().await;
        let dead = iroh::SecretKey::generate().public();
        let transport = tx_reg.inner.peer_registry.ensure_transport(dead);
        let ctx = drive_ctx(&tx_reg, &transport);
        let mut sched = drive_sched();
        let peer_reg = PeerRegistry::new();
        let ep = iroh::SecretKey::generate().public();
        let net = Uuid::from_u128(0xaa);
        let member = test_member(&peer_reg, ep, net, [10, 0, 0, 2]);
        let mut acc = Conservation::new();
        let pkt = test_packet_fill(300, 0x11);
        let want = pkt.owner.as_bytes().to_vec();
        acc.offered(pkt.len());
        assert!(sched.enqueue(net, pkt, Instant::now()).is_accepted());
        let cancel = CancellationToken::new();
        let mut sender = ScriptSender::new(vec![FrameScript::ConnLost]);
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 7);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::ConnLost));
        // Nothing sent, cursor pristine, packet bytes intact.
        assert!(sender.sent.is_empty());
        assert_eq!(it.cur.next_index, 0);
        assert_eq!(it.cur.wire_bytes, 0);
        assert_eq!(it.cur.packet.owner.as_bytes(), &want[..]);
        let mut it = resolve_drive(&mut sched, &mut acc, it, drive)
            .await
            .expect("retained");
        // Resume on the fresh connection: completes, same packet.
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Done { .. }));
        assert_eq!(it.cur.packet.owner.as_bytes(), &want[..]);
        assert_eq!(sender.sent.len(), 1);
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.completed, 1);
    }

    /// Feed DATAGRAM frames into a real receiver reassembly table,
    /// collecting every completed logical payload. Returns the completions
    /// in arrival order.
    fn receive_all(frames: &[Bytes], budget: &Arc<std::sync::atomic::AtomicU64>) -> Vec<Vec<u8>> {
        use tunnet_common::packet::decode_frame;
        use tunnet_core::reassembly::{InsertOut, ReassemblyTable};
        let mut table = ReassemblyTable::new(budget.clone());
        let now = Instant::now();
        let mut completed = Vec::new();
        for f in frames {
            let frame = decode_frame(f).expect("sender emits valid frames");
            match frame {
                tunnet_common::packet::Frame::Single { payload, .. } => {
                    completed.push(payload.to_vec());
                }
                tunnet_common::packet::Frame::Segment {
                    header, payload, ..
                } => {
                    let off = payload.as_ptr() as usize - f.as_ptr() as usize;
                    let owned = f.slice(off..off + payload.len());
                    match table.insert(header, owned, now) {
                        InsertOut::Complete(logical) => completed.push(logical),
                        InsertOut::Pending | InsertOut::Duplicate => {}
                        InsertOut::Dropped(reason) => {
                            panic!("receiver must not drop test frames: {reason:?}")
                        }
                    }
                }
            }
        }
        completed
    }

    async fn replay_setup(
        fill: u8,
    ) -> (
        EndpointTxRegistry,
        Arc<PeerTransportState>,
        EndpointScheduler,
        Arc<PeerMembershipState>,
        Uuid,
        Conservation,
        CancellationToken,
        Vec<u8>,
    ) {
        let (_peer_reg, tx_reg) = test_registry().await;
        let dead = iroh::SecretKey::generate().public();
        let transport = tx_reg.inner.peer_registry.ensure_transport(dead);
        let mut sched = drive_sched();
        let peer_reg = PeerRegistry::new();
        let ep = iroh::SecretKey::generate().public();
        let net = Uuid::from_u128(0xbb);
        let member = test_member(&peer_reg, ep, net, [10, 0, 0, 2]);
        let mut acc = Conservation::new();
        let pkt = test_packet_fill(2700, fill);
        let want = pkt.owner.as_bytes().to_vec();
        acc.offered(pkt.len());
        assert!(sched.enqueue(net, pkt, Instant::now()).is_accepted());
        let cancel = CancellationToken::new();
        (tx_reg, transport, sched, member, net, acc, cancel, want)
    }

    #[tokio::test]
    async fn replay_after_loss_reconstructs_at_receiver_same_geometry() {
        // 2700 B at MPS 1280 -> 3 segments. Prefix frames return Ok (then
        // are deliberately considered LOST), the connection fails, the new
        // connection replays from byte 0 with the SAME frame id, and the
        // receiver still reconstructs the exact original logical packet —
        // from the replay alone AND mixed with stale duplicates.
        let (tx_reg, transport, mut sched, member, net, mut acc, cancel, want) =
            replay_setup(0x22).await;
        let ctx = drive_ctx(&tx_reg, &transport);
        let budget = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut sender = ScriptSender::new(vec![
            FrameScript::Ok,
            FrameScript::Ok,
            FrameScript::ConnLost,
        ]);
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 41);
        assert!(matches!(
            it.cur.plan,
            SegmentPlan::Segmented { count: 3, .. }
        ));
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::ConnLost));
        assert_eq!(sender.sent.len(), 2, "prefix accepted by old send path");
        // New canonical connection: worker replays from byte 0 (same id,
        // same geometry). Model it exactly as run_endpoint_worker does.
        let mut it = resolve_drive(&mut sched, &mut acc, it, drive)
            .await
            .expect("retained");
        it.last_conn = Some(1000);
        replay_for_new_connection(&ctx, &mut it);
        assert_eq!(it.cur.next_index, 0, "replay restarts at byte 0");
        assert_eq!(it.cur.packet.owner.as_bytes(), &want[..]);
        it.last_conn = Some(1001);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        let (wire, frames) = match drive {
            Drive::Done { wire, frames } => (wire, frames),
            other => panic!("expected Done, got {other:?}"),
        };
        // 2 prefix + 3 replayed transmissions, all counted.
        assert_eq!(sender.sent.len(), 5);
        let total_wire: usize = sender.sent.iter().map(|b| b.len()).sum();
        assert_eq!(wire, total_wire);
        assert_eq!(frames, 5);
        resolve_drive(&mut sched, &mut acc, it, Drive::Done { wire, frames }).await;
        assert_eq!(acc.completed, 1);

        // Receiver view, prefix truly lost: replay alone completes exactly.
        let replayed = &sender.sent[2..];
        assert_eq!(replayed.len(), 3);
        let completed = receive_all(replayed, &budget);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], want, "replay reconstructs the original");

        // Receiver view, prefix arrived after all (duplicates): exactly one
        // completion with the original bytes, duplicates absorbed.
        let completed = receive_all(&sender.sent, &budget);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], want);
        let _ = net;
    }

    #[tokio::test]
    async fn replay_after_loss_replans_on_changed_mps() {
        // Same loss, but the new path is smaller (MPS 1280 -> 700):
        // replay adopts a fresh frame id with new geometry, and the
        // receiver reconstructs the original from the new frame set while
        // the stale old-id partial never completes.
        let (tx_reg, transport, mut sched, member, _net, mut acc, cancel, want) =
            replay_setup(0x33).await;
        let ctx = drive_ctx(&tx_reg, &transport);
        let budget = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut sender = ScriptSender::new(vec![
            FrameScript::Ok,
            FrameScript::Ok,
            FrameScript::ConnLost,
        ]);
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 41);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::ConnLost));
        let old_id = it.cur.frame_id;
        let mut it = resolve_drive(&mut sched, &mut acc, it, drive)
            .await
            .expect("retained");
        // New path shrank before the replay.
        ctx.transport.mps.store(700, Ordering::Relaxed);
        it.last_conn = Some(1000);
        replay_for_new_connection(&ctx, &mut it);
        assert_ne!(it.cur.frame_id, old_id, "changed geometry mints fresh id");
        assert!(matches!(
            it.cur.plan,
            SegmentPlan::Segmented { count: 5, .. }
        ));
        it.last_conn = Some(1001);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Done { .. }));
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.completed, 1);

        // Receiver: old-id prefix (2 segs, never completes) + new-id full
        // set (5 segs) -> exactly one completion, original bytes.
        let completed = receive_all(&sender.sent, &budget);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], want);
    }

    #[tokio::test]
    async fn several_packets_mixed_fates_conserve() {
        // Four packets: clean send, repeated TooLarge -> explicit drop,
        // Fatal -> retained across invalidation -> replacement connection
        // completes it, cancel-mid-block -> exactly one GenerationEnd.
        // Conservation after EVERY transition.
        let (_peer_reg, tx_reg) = test_registry().await;
        let dead = iroh::SecretKey::generate().public();
        let transport = tx_reg.inner.peer_registry.ensure_transport(dead);
        let ctx = drive_ctx(&tx_reg, &transport);
        let mut sched = drive_sched();
        let peer_reg = PeerRegistry::new();
        let ep = iroh::SecretKey::generate().public();
        let net = Uuid::from_u128(0xcc);
        let member = test_member(&peer_reg, ep, net, [10, 0, 0, 2]);
        let mut acc = Conservation::new();
        let cancel = CancellationToken::new();

        // p0: clean single-frame send.
        let p0 = test_packet_fill(200, 0x01);
        acc.offered(p0.len());
        assert!(sched.enqueue(net, p0, Instant::now()).is_accepted());
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 1);
        let mut sender = ScriptSender::new(vec![]);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Done { frames: 1, .. }));
        assert_eq!(sender.sent.len(), 1);
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.completed, 1);

        // p1: persistently shrinking path (TooLarge x3) -> explicit drop.
        // No connection is needed: the MPS refresh is a no-op without one
        // and the geometry never fits a shrinking script... use a jumbo
        // packet with a tiny scripted MPS? The mock has no MPS: TooLarge
        // comes from the script. Replan against the unchanged real MPS
        // (1280) retries in place until the restart budget drops it.
        let p1 = test_packet_fill(2700, 0x02);
        acc.offered(p1.len());
        assert!(sched.enqueue(net, p1, Instant::now()).is_accepted());
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 2);
        let mut sender = ScriptSender::new(vec![
            FrameScript::TooLarge,
            FrameScript::TooLarge,
            FrameScript::TooLarge,
        ]);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(
            matches!(
                drive,
                Drive::Dropped {
                    reason: DropReason::TooLarge
                }
            ),
            "restart budget must bound flapping paths"
        );
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.dropped, 1);

        // p2: Fatal (unsupported) -> retained while production
        // closes/invalidates the old connection; the replacement
        // connection (mocked by the continuing script) completes it.
        let p2 = test_packet_fill(200, 0x03);
        let want2 = p2.owner.as_bytes().to_vec();
        acc.offered(p2.len());
        assert!(sched.enqueue(net, p2, Instant::now()).is_accepted());
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 3);
        let mut sender = ScriptSender::new(vec![FrameScript::Fatal]);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Fatal));
        // Production ownership: logical packet remains in-flight across
        // the invalidation (never reconstructed, never re-timestamped).
        assert_eq!(it.cur.packet.owner.as_bytes(), &want2[..]);
        assert_eq!(it.cur.next_index, 0);
        let mut it = resolve_drive(&mut sched, &mut acc, it, drive)
            .await
            .expect("retained across invalidation");
        assert_eq!(acc.dropped, 1, "still only the TooLarge drop");
        // Replacement connection: the SAME cursor completes.
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Done { frames: 1, .. }));
        assert_eq!(it.cur.packet.owner.as_bytes(), &want2[..]);
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.completed, 2);

        // p3: blocked send + generation cancel -> GenerationEnd.
        let p3 = test_packet_fill(200, 0x04);
        let want3 = p3.owner.as_bytes().to_vec();
        acc.offered(p3.len());
        assert!(sched.enqueue(net, p3, Instant::now()).is_accepted());
        let mut it = dequeue_inflight(&mut sched, &member, 1280, 4);
        let cancel3 = CancellationToken::new();
        let canceller = cancel3.clone();
        let canceller_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            canceller.cancel();
        });
        let mut sender = ScriptSender::new(vec![FrameScript::BlockForever]);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel3).await;
        assert!(matches!(drive, Drive::Cancelled));
        // Cancellation never consumes the logical packet.
        assert_eq!(it.cur.packet.owner.as_bytes(), &want3[..]);
        let _ = canceller_task.await;
        resolve_drive(&mut sched, &mut acc, it, drive).await;
        assert_eq!(acc.dropped, 2);

        // End state: everything resolved, nothing owned.
        let snap = sched.snapshot();
        assert_eq!(snap.owned_packets(), 0);
        assert!(snap.conserves(acc.offered_packets, acc.offered_bytes));
    }

    #[tokio::test]
    async fn join_bounded_aborts_stragglers_and_never_detaches() {
        // Item 3: a permanently-blocked mock sender stands in for a stuck
        // worker. join_bounded returns it; the caller aborts AND awaits
        // termination — the task is never detached.
        let quick = tokio::spawn(async {});
        let stuck = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let pending = join_bounded(vec![quick, stuck], Duration::from_millis(200)).await;
        assert_eq!(pending.len(), 1, "the stuck task must be reported");
        for h in pending {
            h.abort();
            let res = h.await;
            assert!(
                res.unwrap_err().is_cancelled(),
                "aborted task must terminate observably"
            );
        }
    }

    #[tokio::test]
    async fn shutdown_with_stuck_dial_reconciles() {
        // A worker parked in pool.get (5 s dial timeout for an undiallable
        // peer) cannot exit promptly: shutdown must still return bounded,
        // leave no worker behind, and reconcile every gauge.
        let (peer_reg, tx_reg) = test_registry().await;
        let dead = iroh::SecretKey::generate().public();
        let net = Uuid::from_u128(0xdd);
        let member = test_member(&peer_reg, dead, net, [10, 0, 0, 9]);
        enqueue_packet(&tx_reg, &member, test_packet_fill(200, 0x05));
        // Let the worker spawn and enter its dial.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let start = Instant::now();
        tx_reg.shutdown().await;
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "shutdown must be bounded even with a stuck worker"
        );
        assert_eq!(tx_reg.state_count(), 0, "no worker may survive");
    }

    #[tokio::test]
    async fn supervise_worker_clears_running_and_escalates_on_panic() {
        // Item 9/16: a panicking worker must clear `running` (never a
        // one-way black hole with running=true on a dead task) and invoke
        // the escalation hook exactly once with the endpoint + reason.
        // A normal exit must NOT touch `running` (no clobbering a newer
        // worker's flag).
        let (peer_reg, _tx_reg) = test_registry().await;
        let ep = iroh::SecretKey::generate().public();
        let transport = peer_reg.ensure_transport(ep);
        let state = Arc::new(EndpointTxState::new(ep, transport, 1536));
        let fired = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fired_ep = Arc::new(std::sync::Mutex::new(None));
        let fired2 = fired.clone();
        let fired_ep2 = fired_ep.clone();
        let handler: FatalHandler = Arc::new(move |endpoint, _reason| {
            fired2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *fired_ep2.lock().unwrap() = Some(endpoint);
        });
        // Panic path.
        state.running.store(true, Ordering::Release);
        supervise_worker(state.clone(), Some(handler.clone()), async {
            panic!("injected TX worker panic");
        })
        .await;
        assert!(
            !state.running.load(Ordering::Acquire),
            "running must clear on panic"
        );
        assert_eq!(fired.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(*fired_ep.lock().unwrap(), Some(ep));
        // Normal path: untouched.
        state.running.store(true, Ordering::Release);
        supervise_worker(state.clone(), Some(handler), async {}).await;
        assert!(
            state.running.load(Ordering::Acquire),
            "normal exit must not clobber running"
        );
        assert_eq!(fired.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// Real connected pair for transport-fatal tests (sender side only
    /// needs a live Connection object + canonical pool slot).
    async fn fatal_fixture() -> (
        ConnPool,
        iroh::endpoint::Connection,
        EndpointId,
        Arc<PeerTransportState>,
    ) {
        use iroh::endpoint::presets::N0;
        let alpn = tunnet_common::TUNNEL_ALPN;
        let ep_a = iroh::Endpoint::builder(N0)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let ep_b = iroh::Endpoint::builder(N0)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let id_b = ep_b.id();
        let addr_b = ep_b.addr();
        let ep_b2 = ep_b.clone();
        let accept_b = tokio::spawn(async move { ep_b2.accept().await.unwrap().await.unwrap() });
        let conn_a = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ep_a.connect(addr_b, alpn),
        )
        .await
        .expect("dial must succeed")
        .unwrap();
        let _conn_b: iroh::endpoint::Connection =
            tokio::time::timeout(std::time::Duration::from_secs(10), accept_b)
                .await
                .expect("accept")
                .unwrap();
        let pool_a = ConnPool::new(ep_a, alpn);
        let reg = PeerRegistry::new();
        pool_a.set_peer_registry(Arc::new(reg.clone()));
        use tunnet_core::InstallOutcome;
        assert!(matches!(
            pool_a
                .install_canonical(id_b, conn_a.clone(), true, false)
                .await,
            InstallOutcome::Canonical(_)
        ));
        let transport = reg.ensure_transport(id_b);
        (pool_a, conn_a, id_b, transport)
    }

    #[tokio::test]
    async fn transport_fatal_invalidates_sets_flag_and_drops() {
        // Item 13/16: the exact production path (not the harness):
        // close + invalidate the canonical conn, mark incompatible,
        // explicit Incompatible drop, exact conservation — and the flag
        // provably stops redialing below. The canonical slot lives in the
        // registry's own pool (as in production).
        let (_peer_reg, tx_reg) = test_registry().await;
        let (_pool_a, conn_a, id_b, _transport) = fatal_fixture().await;
        let tx_pool = tx_reg.inner.pool.clone();
        tx_pool.set_peer_registry(Arc::new(PeerRegistry::new()));
        use tunnet_core::InstallOutcome;
        assert!(matches!(
            tx_pool
                .install_canonical(id_b, conn_a.clone(), true, false)
                .await,
            InstallOutcome::Canonical(_)
        ));
        let transport = tx_reg.inner.peer_registry.ensure_transport(id_b);
        let peer_reg = PeerRegistry::new();
        let net = Uuid::from_u128(0xee);
        let member = test_member(&peer_reg, id_b, net, [10, 0, 0, 2]);
        let ctx = TxCtx {
            transport: &transport,
            pool: &tx_pool,
            metrics: &tx_reg.inner.metrics,
            bufs: &tx_reg.inner.bufs,
            meter: &tx_reg.inner.meter,
        };
        let mut acc = Conservation::new();
        let pkt = test_packet_fill(200, 0x06);
        acc.offered(pkt.len());
        // Production invariant: dequeue and discard hit the SAME
        // scheduler (state.sched). Drive through it directly.
        let state = Arc::new(EndpointTxState::new(id_b, transport.clone(), 1536));
        let mut it = {
            let mut guard = state.sched.lock();
            assert!(guard.enqueue(net, pkt, Instant::now()).is_accepted());
            dequeue_inflight(&mut guard, &member, 1280, 9)
        };
        // Dequeue + drive with a Fatal script, then the production
        // incompatibility path (as the worker calls it).
        let cancel = CancellationToken::new();
        let mut sender = ScriptSender::new(vec![FrameScript::Fatal]);
        let drive = drive_inflight(&ctx, &mut sender, &mut it, &cancel).await;
        assert!(matches!(drive, Drive::Fatal));
        // Cursor fully intact across the Fatal observation.
        assert_eq!(it.cur.next_index, 0);
        // Exact production path: invalidate + flag + explicit drop.
        on_transport_fatal(&tx_reg.inner, &ctx, &state, id_b, &conn_a, it).await;
        assert!(
            !tx_pool.has_live(id_b),
            "canonical session must be invalidated"
        );
        assert!(
            transport.datagram_incompatible.load(Ordering::Relaxed),
            "endpoint must be marked incompatible (no redial loop)"
        );
        let snap = state.sched.lock().snapshot();
        assert_eq!(
            snap.drop_packets[DropReason::Incompatible.index()],
            1,
            "explicit Incompatible resolution"
        );
        acc.dropped += 1;
        acc.check(&state.sched.lock());
        assert_eq!(snap.owned_packets(), 0);
    }

    #[tokio::test]
    async fn incompatible_endpoint_never_redials() {
        // Item 13/16: with the incompatibility mark set and no connection,
        // the worker parks without dialing — reconnect_attempts stays zero
        // while the packet waits queued (bounded by caps, never a loop).
        let (peer_reg, tx_reg) = test_registry().await;
        let dead = iroh::SecretKey::generate().public();
        let transport = peer_reg.ensure_transport(dead);
        transport
            .datagram_incompatible
            .store(true, Ordering::Relaxed);
        let net = Uuid::from_u128(0xef);
        let member = test_member(&peer_reg, dead, net, [10, 0, 0, 9]);
        enqueue_packet(&tx_reg, &member, test_packet_fill(200, 0x07));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let pool = tx_reg.inner.pool.clone();
        assert_eq!(
            pool.on_demand_stats().reconnect_attempts,
            0,
            "incompatible peer must never be redialed"
        );
        let state = tx_reg.inner.states.get(&dead).unwrap().clone();
        let snap = state.sched.lock().snapshot();
        assert_eq!(snap.queued_packets, 1, "packet waits queued, not lost");
        assert_eq!(snap.dropped_packets(), 0);
        tx_reg.shutdown().await;
    }
}
