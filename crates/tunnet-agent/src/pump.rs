//! Per-peer outbound pump: FQ-CoDel → tunnel segmenter → Model A transport.
//!
//! Each peer's pump owns one loop over its [`PeerMembershipState`]:
//!
//! ```text
//! scheduler.next() → logical packet (or resume stashed cursor)
//!   → single frame (header in headroom, from_owner, no copy) or
//!     segments (incremental cursor, pooled staging per segment)
//!   → transport.try_send_frame (Model A: space must fit the whole frame;
//!     the frame is returned on failure, so stalls never consume bytes)
//!   → TransportFull: stash cursor (segmented) or requeue (single),
//!     adaptive backoff (notify + RTT/4, no fixed 5 ms, no spin)
//!   → NoConnection: requeue whole packet, slow dial, wake on completion
//!   → TooLarge: refresh MPS, restart with fresh id (path shrank)
//! ```
//!
//! One logical packet emits at most [`MAX_SEGMENTS`] DATAGRAMs, so no packet
//! monopolizes the connection for an arbitrary burst (§7). Scheduler and
//! transport never see fragments — only logical packets and frames.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tunnet_common::packet::{
    FlowKey, LogicalPacket, MAX_LOGICAL_LEN, MAX_SEGMENTS, MIN_SEGMENT_PAYLOAD, PacketOwner,
    PacketPool, SEGMENT_OVERHEAD, SINGLE_OVERHEAD, SegmentHeader, encode_segment_prefix,
    encode_single_prefix,
};
use tunnet_core::peers::{FastSendError, PeerMembershipState, PeerRegistry};
use tunnet_core::{ConnPool, scheduler::Dequeue};

use crate::metrics::AgentMetrics;

/// Ensure the peer's pump task is running; otherwise wake it.
pub fn ensure_pump(
    fast: &Arc<PeerMembershipState>,
    pool: ConnPool,
    metrics: AgentMetrics,
    bufs: Arc<PacketPool>,
    meter: tunnet_core::CloudRelayMeter,
) {
    if !fast.pump_running.swap(true, Ordering::AcqRel) {
        let ctx = PumpCtx {
            fast: fast.clone(),
            pool,
            metrics,
            bufs,
            meter,
        };
        tokio::spawn(async move {
            run_peer_pump(ctx).await;
        });
    } else {
        fast.notify.notify_one();
    }
}

struct PumpCtx {
    fast: Arc<PeerMembershipState>,
    pool: ConnPool,
    metrics: AgentMetrics,
    bufs: Arc<PacketPool>,
    meter: tunnet_core::CloudRelayMeter,
}

/// Shared transmit context: one struct instead of eight parameters.
struct Tx<'a> {
    fast: &'a Arc<PeerMembershipState>,
    pool: &'a ConnPool,
    metrics: &'a AgentMetrics,
    bufs: &'a Arc<PacketPool>,
    meter: &'a tunnet_core::CloudRelayMeter,
    peer: iroh::EndpointId,
}

/// Mid-packet transmit cursor (§7): stashed only across TransportFull waits.
/// The logical owner is retained untouched; segments encode from borrows, so
/// resume never re-parses and never loses bytes.
///
/// The cursor tracks the FULL segmentation geometry (plan + packet id +
/// next index), never just a count: any geometry change restarts the
/// logical packet from byte 0 with a fresh id, so old offsets are never
/// reused with a new MPS (§2.1-1).
struct PartialPacket {
    packet: Option<LogicalPacket>,
    flow: FlowKey,
    next_index: usize,
    frame_id: u32,
    /// Geometry the in-flight segments conform to (count + seg_cap, or
    /// Single for a fresh single-frame cursor).
    plan: SegmentPlan,
    total: usize,
    /// Wire bytes sent under the current frame id (preserved across
    /// TransportFull resume; reset on restart). Accounted exactly once at
    /// completion, so segmented traffic is never double-charged (§2.1-2).
    wire_bytes: u64,
    /// Network bound at dequeue from the route's membership. Every frame
    /// of this packet carries it (§2.2-1).
    net: uuid::Uuid,
}

/// Outcome of re-planning a cursor against current MPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replan {
    /// Geometry changed (or first sizing): restart from byte 0, fresh id.
    Restarted,
    /// Geometry identical: retry the current segment in place (transient
    /// TooLarge, no bytes wasted on a redundant restart).
    Retry,
    /// The path cannot carry this packet at all: drop it.
    Impossible,
}

impl PartialPacket {
    fn new(packet: LogicalPacket, flow: FlowKey, fast: &PeerMembershipState) -> Self {
        let total = packet.len();
        let plan = plan_for_mps(total, fast.transport.mps.load(Ordering::Relaxed));
        Self {
            packet: Some(packet),
            flow,
            next_index: 0,
            frame_id: fast.transport.next_frame_id.fetch_add(1, Ordering::Relaxed),
            plan,
            total,
            wire_bytes: 0,
            // Bound at dequeue: every frame of this packet carries this
            // network, resolved from the route (§2.2-1).
            net: fast.identity.read().network_id,
        }
    }

    /// Adopt a geometry wholesale: fresh id, offset reset, wire accumulator
    /// reset. Old offsets are never reused after this point.
    fn adopt(&mut self, plan: SegmentPlan, fast: &PeerMembershipState) {
        self.plan = plan;
        self.next_index = 0;
        self.wire_bytes = 0;
        self.frame_id = fast.transport.next_frame_id.fetch_add(1, Ordering::Relaxed);
    }

    /// Re-plan against current MPS after a TooLarge (MPS already refreshed
    /// by the caller). Compares the COMPLETE geometry — count AND segment
    /// capacity AND single/segmented shape — not just the count: an MPS
    /// change that keeps the segment count but alters seg_cap still
    /// restarts with a fresh id.
    fn replan(&mut self, fast: &PeerMembershipState) -> Replan {
        let mps = fast.transport.mps.load(Ordering::Relaxed);
        match plan_for_mps(self.total, mps) {
            SegmentPlan::Impossible => Replan::Impossible,
            plan if plan == self.plan => Replan::Retry,
            plan => {
                self.adopt(plan, fast);
                Replan::Restarted
            }
        }
    }
}

async fn run_peer_pump(ctx: PumpCtx) {
    let PumpCtx {
        fast,
        pool,
        metrics,
        bufs,
        meter,
    } = ctx;
    let peer = fast.identity.read().endpoint;
    let mut partial: Option<PartialPacket> = None;
    // Unstarted remainder of the current DRR burst (gauges debited at
    // dequeue; requeued with re-credit on stall, drained packet by packet).
    let mut pending: std::collections::VecDeque<PartialPacket> = std::collections::VecDeque::new();
    // Ownership epoch at pump start; teardown advances it so this task
    // drains and exits instead of parking on a dead generation.
    let epoch0 = fast.epoch.load(Ordering::Relaxed);
    // Last-seen queue levels for gauge-delta reconciliation (global gauges
    // are sums; per-pump deltas keep them correct without overwrites).
    let mut last_levels: (i64, i64, i64) = (0, 0, 0);
    let reconcile =
        |fast: &Arc<PeerMembershipState>, metrics: &AgentMetrics, last: &mut (i64, i64, i64)| {
            let (p, b, f) = fast.scheduler.lock().levels();
            let (p, b, f) = (p as i64, b as i64, f as i64);
            metrics.queue_add(p - last.0, b - last.1, f - last.2);
            *last = (p, b, f);
        };

    loop {
        // Ownership change (teardown/drop): shed queued packets, zero the
        // gauges, and exit. The scheduler contents belong to the old
        // generation and must not cross into a new TUN generation.
        // (Enqueue/dequeue deltas were emitted as they happened, so the
        // peer's live contribution equals its current levels: negate them.)
        if fast.epoch.load(Ordering::Relaxed) != epoch0 {
            // Return in-flight packets (stashed cursor + burst remainder)
            // to the scheduler first, so the clear below reconciles every
            // outstanding gauge debit in one place.
            if let Some(cur) = partial.take()
                && let Some(packet) = cur.packet
            {
                let flow = packet.flow;
                fast.scheduler.lock().requeue_head(flow, packet);
            }
            while let Some(cur) = pending.pop_front() {
                if let Some(packet) = cur.packet {
                    let flow = packet.flow;
                    fast.scheduler.lock().requeue_head(flow, packet);
                }
            }
            let (p, b, f) = fast.scheduler.lock().clear();
            metrics.queue_add(-(p as i64), -(b as i64), -(f as i64));
            fast.pump_running.store(false, Ordering::Release);
            return;
        }
        // 1) Resume a stashed cursor, else dequeue the next burst. A burst
        // is one DRR service opportunity (all packets the visited flow
        // could afford); the pump transmits every packet in order.
        if partial.is_none() && pending.is_empty() {
            let dequeued = {
                let mut sched = fast.scheduler.lock();
                sched.next(Instant::now())
            };
            match dequeued {
                Dequeue::Empty => {
                    reconcile(&fast, &metrics, &mut last_levels);
                    // Idle: wait for work or exit after a quiet period.
                    tokio::select! {
                        _ = fast.notify.notified() => continue,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {
                            if fast.scheduler.lock().is_empty() {
                                fast.pump_running.store(false, Ordering::Release);
                                if !fast.scheduler.lock().is_empty()
                                    && !fast.pump_running.swap(true, Ordering::AcqRel)
                                {
                                    continue;
                                }
                                if fast.scheduler.lock().is_empty() {
                                    // Zero this peer's gauge contribution from
                                    // live levels (deltas were emitted live).
                                    let (p, b, f) = fast.scheduler.lock().levels();
                                    metrics.queue_add(-(p as i64), -(b as i64), -(f as i64));
                                    return;
                                }
                            }
                            continue;
                        }
                    }
                }
                Dequeue::Send(burst) => {
                    for (packet, sample) in burst.packets {
                        metrics.observe_sojourn(sample.sojourn);
                        let flow = packet.flow;
                        metrics.queue_add(-1, -(packet.len() as i64), 0);
                        pending.push_back(PartialPacket::new(*packet, flow, &fast));
                    }
                }
            }
        }

        // Periodic MPS refresh covers silent path changes (plus event-driven
        // refresh in the pool's path watcher and TooLarge recovery below).
        if fast
            .transport
            .sends_since_mps_check
            .fetch_add(1, Ordering::Relaxed)
            >= 512
        {
            fast.transport
                .sends_since_mps_check
                .store(0, Ordering::Relaxed);
            fast.refresh_mps();
        }

        // 2) Transmit one cursor to completion, stall, or drop. A stashed
        // cursor resumes next iteration; the burst remainder waits in
        // `pending` (gauges already debited at dequeue; requeues below
        // re-credit).
        let mut cur = partial
            .take()
            .or_else(|| pending.pop_front())
            .expect("cursor");
        let tx = Tx {
            fast: &fast,
            pool: &pool,
            metrics: &metrics,
            bufs: &bufs,
            meter: &meter,
            peer,
        };
        match transmit_cursor(&tx, &mut cur).await {
            TransmitOut::Done { logical, frames } => {
                metrics.frame_sent_inc(frames);
                metrics.packets_inc("out");
                metrics.bytes_add("out", logical as u64);
                reconcile(&fast, &metrics, &mut last_levels);
            }
            TransmitOut::Stash => {
                partial = Some(cur);
                // Return the unstarted remainder to the scheduler head in
                // order (gauges re-credited per packet).
                requeue_pending(&fast, &metrics, &mut pending);
                metrics.sched_transport_full_inc();
                // Adaptive backoff (§0.7): wake on new work or timeout.
                tokio::select! {
                    _ = fast.notify.notified() => {}
                    _ = tokio::time::sleep(PeerRegistry::backoff_for(&fast.transport)) => {}
                }
            }
            TransmitOut::Wait => {
                // Requeue the working packet if transmit left it intact
                // (the NoConnection arm usually requeues itself; this
                // covers the re-parse-failure path losslessly), then the
                // unstarted remainder. Dial was kicked inside.
                if let Some(packet) = cur.packet.take() {
                    let flow = packet.flow;
                    let len = packet.len() as i64;
                    fast.scheduler.lock().requeue_head(flow, packet);
                    metrics.queue_add(1, len, 0);
                }
                requeue_pending(&fast, &metrics, &mut pending);
                tokio::select! {
                    _ = fast.notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
            TransmitOut::Dropped(reason) => {
                metrics.dropped_inc(reason);
                reconcile(&fast, &metrics, &mut last_levels);
            }
        }
        // Report dequeue-side drops (CoDel/emergency inside next()): they
        // have no enqueue decision site, so the pump drains them here.
        // Deltas partition across lock holders; the sum stays exact.
        let deltas = fast.scheduler.lock().drain_drops();
        metrics.sched_drops_add(deltas.codel, deltas.emergency);
    }
}

/// Return unstarted burst packets to the scheduler head, preserving order.
/// The stashed/working cursor is handled separately by the caller.
fn requeue_pending(
    fast: &Arc<PeerMembershipState>,
    metrics: &AgentMetrics,
    pending: &mut std::collections::VecDeque<PartialPacket>,
) {
    if pending.is_empty() {
        return;
    }
    let mut sched = fast.scheduler.lock();
    while let Some(cur) = pending.pop_back() {
        if let Some(packet) = cur.packet {
            let flow = packet.flow;
            let len = packet.len() as i64;
            sched.requeue_head(flow, packet);
            metrics.queue_add(1, len, 0);
        }
    }
}

enum TransmitOut {
    /// Logical packet fully transmitted (logical bytes, segment frames).
    Done { logical: usize, frames: u64 },
    /// Transport full: caller stashes `cur` and backs off.
    Stash,
    /// Stalled but handled inside (requeued, dial kicked): caller waits.
    Wait,
    /// Dropped with reason.
    Dropped(&'static str),
}

/// Segmentation plan for a logical packet at one MPS snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentPlan {
    /// Fits in one DATAGRAM (plus 1-byte prefix).
    Single,
    /// Split into `count` segments of at most `seg_cap` payload bytes.
    Segmented { count: usize, seg_cap: usize },
    /// Degenerate path (no useful segment fits).
    Impossible,
}

/// Pure sizing decision (§3, §7): single when it fits, else uniform
/// segments; impossible when the path cannot carry even minimal segments.
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

/// Transmit one cursor to completion, stall, or drop. At most MAX_SEGMENTS
/// DATAGRAMs per packet — bounded by construction.
///
/// Fresh cursors adopt the CURRENT geometry wholesale; resumed cursors
/// (next_index > 0) continue their stored geometry even if the path has
/// changed — only a TooLarge re-plans them. Either way old offsets are
/// never mixed with a new MPS: adoption restarts from byte 0.
async fn transmit_cursor(tx: &Tx<'_>, cur: &mut PartialPacket) -> TransmitOut {
    if cur.next_index == 0 {
        let mps = tx.fast.transport.mps.load(Ordering::Relaxed);
        match plan_for_mps(cur.total, mps) {
            SegmentPlan::Single => return transmit_single(tx, cur).await,
            plan @ SegmentPlan::Segmented { .. } => {
                cur.adopt(plan, tx.fast);
                return transmit_segmented(tx, cur).await;
            }
            SegmentPlan::Impossible => {
                // Degenerate path: refresh once, then give up if useless.
                tx.fast.refresh_mps();
                let mps2 = tx.fast.transport.mps.load(Ordering::Relaxed);
                match plan_for_mps(cur.total, mps2) {
                    SegmentPlan::Single => return transmit_single(tx, cur).await,
                    plan @ SegmentPlan::Segmented { .. } => {
                        cur.adopt(plan, tx.fast);
                        return transmit_segmented(tx, cur).await;
                    }
                    SegmentPlan::Impossible => {
                        return TransmitOut::Dropped("datagram_too_large");
                    }
                }
            }
        }
    }
    debug_assert!(
        matches!(cur.plan, SegmentPlan::Segmented { .. }),
        "resumed cursors are always segmented (singles never stash)"
    );
    transmit_segmented(tx, cur).await
}

/// Encode a logical packet as one frame: pooled owners prepend the header
/// in headroom (no copy); shared owners stage through a pooled buffer.
async fn transmit_single(tx: &Tx<'_>, cur: &mut PartialPacket) -> TransmitOut {
    let Tx {
        fast,
        pool,
        metrics,
        bufs,
        meter,
        peer,
    } = tx;
    let packet = cur.packet.take().expect("cursor holds packet");
    let total = packet.len();
    let owner = packet.owner;
    let frame = match owner {
        PacketOwner::Pooled(mut buf) => match buf.header_slot(SINGLE_OVERHEAD) {
            Some(slot) => {
                encode_single_prefix(slot, cur.net);
                Bytes::from_owner(buf)
            }
            None => {
                // No headroom (should not happen): stage a copy.
                let src = buf.as_ref().to_vec();
                drop(buf);
                stage_single(bufs, cur.net, &src)
            }
        },
        PacketOwner::Shared(s) => stage_single(bufs, cur.net, &s),
    };
    let wire = frame.len();
    match fast.transport.try_send_frame(frame) {
        Ok(()) => {
            account_sent(fast, cur.flow, total, wire);
            if fast.transport.relay.load(Ordering::Relaxed) {
                meter.record(wire as u64);
            }
            TransmitOut::Done {
                logical: total,
                frames: 1,
            }
        }
        Err((FastSendError::TransportFull, frame)) => {
            // Recover the frame, strip the prefix, requeue losslessly.
            if let Some(rebuilt) = LogicalPacket::from_shared(strip_single_prefix(frame)) {
                let flow = rebuilt.flow;
                let len = rebuilt.len() as i64;
                fast.scheduler.lock().requeue_head(flow, rebuilt);
                metrics.queue_add(1, len, 0);
            } else {
                metrics.dropped_inc("datagram_too_large");
            }
            TransmitOut::Wait
        }
        Err((FastSendError::NoConnection | FastSendError::Closed, frame)) => {
            if let Some(rebuilt) = LogicalPacket::from_shared(strip_single_prefix(frame)) {
                let flow = rebuilt.flow;
                let len = rebuilt.len() as i64;
                fast.scheduler.lock().requeue_head(flow, rebuilt);
                metrics.queue_add(1, len, 0);
            } else {
                // Our own encoding failed to re-parse: count it and still
                // kick the dial, since connectivity is suspect anyway.
                metrics.dropped_inc("no_connection");
            }
            kick_dial(pool, *peer, fast);
            TransmitOut::Wait
        }
        Err((FastSendError::TooLarge, frame)) => {
            // Stale MPS: refresh, rebuild the logical packet from the
            // recovered frame, and re-route through the cursor (which
            // adopts the current geometry wholesale). Boxed: rare path
            // (stale MPS on a single frame) that would otherwise close a
            // single↔segmented async cycle.
            fast.refresh_mps();
            let Some(rebuilt) = LogicalPacket::from_shared(strip_single_prefix(frame)) else {
                return TransmitOut::Dropped("datagram_too_large");
            };
            cur.packet = Some(rebuilt);
            cur.next_index = 0;
            cur.total = cur.packet.as_ref().map(|p| p.len()).unwrap_or(0);
            cur.wire_bytes = 0;
            return Box::pin(transmit_cursor(tx, cur)).await;
        }
    }
}

fn kick_dial(pool: &ConnPool, peer: iroh::EndpointId, fast: &Arc<PeerMembershipState>) {
    let pool2 = pool.clone();
    let fast2 = fast.clone();
    tokio::spawn(async move {
        let _ = pool2.get(peer).await;
        fast2.notify.notify_one();
    });
}

fn stage_single(pool: &Arc<PacketPool>, net: uuid::Uuid, payload: &[u8]) -> Bytes {
    let mut buf = pool.acquire(payload.len() + SINGLE_OVERHEAD);
    let region = buf.recv_region(payload.len() + SINGLE_OVERHEAD);
    encode_single_prefix(&mut region[..SINGLE_OVERHEAD], net);
    region[SINGLE_OVERHEAD..].copy_from_slice(payload);
    buf.set_len(payload.len() + SINGLE_OVERHEAD);
    Bytes::from_owner(buf)
}

/// Remove the single-frame header (kind + network), returning the payload.
fn strip_single_prefix(frame: Bytes) -> Bytes {
    if frame.first() == Some(&tunnet_common::packet::KIND_SINGLE) && frame.len() > SINGLE_OVERHEAD {
        frame.slice(SINGLE_OVERHEAD..)
    } else {
        frame
    }
}

/// Transmit the cursor's remainder segment by segment, encoding
/// incrementally from the retained logical owner under the cursor's STORED
/// geometry. TransportFull stashes (wire accumulator preserved for resume);
/// TooLarge re-plans against fresh MPS (full geometry compare → restart or
/// in-place retry); completion accounts the whole logical packet exactly
/// once with total wire bytes.
async fn transmit_segmented(tx: &Tx<'_>, cur: &mut PartialPacket) -> TransmitOut {
    transmit_segmented_budgeted(tx, cur, 0).await
}

/// Continue a restarted cursor under its newly adopted geometry.
/// Split out so the TooLarge arm stays readable; the restart budget is
/// threaded through to bound flapping paths.
async fn transmit_segmented_restarted(
    tx: &Tx<'_>,
    cur: &mut PartialPacket,
    restarts: u8,
) -> TransmitOut {
    transmit_segmented_budgeted(tx, cur, restarts).await
}

async fn transmit_segmented_budgeted(
    tx: &Tx<'_>,
    cur: &mut PartialPacket,
    mut restarts: u8,
) -> TransmitOut {
    let Tx {
        fast,
        pool,
        metrics,
        bufs,
        meter,
        peer,
    } = tx;
    let (count, seg_cap) = match cur.plan {
        SegmentPlan::Segmented { count, seg_cap } => (count, seg_cap),
        // Fresh cursors never arrive here (transmit_cursor routes them);
        // a TooLarge replan can adopt Single — route out, boxed to break
        // the async cycle.
        SegmentPlan::Single => return Box::pin(transmit_single(tx, cur)).await,
        SegmentPlan::Impossible => return TransmitOut::Dropped("datagram_too_large"),
    };
    let mut frames = 0u64;
    // Bounded retries on flapping paths (budget shared across restarts).
    loop {
        if cur.next_index >= count {
            // Completion: account the whole logical packet ONCE with total
            // wire bytes (never per segment — no double charge).
            account_sent(fast, cur.flow, cur.total, cur.wire_bytes as usize);
            return TransmitOut::Done {
                logical: cur.total,
                frames,
            };
        }
        let i = cur.next_index;
        let off = i * seg_cap;
        let end = (off + seg_cap).min(cur.total);
        if off >= cur.total || end <= off {
            return TransmitOut::Dropped("datagram_too_large");
        }
        // Encode from a borrow (owner retained for resume/retry).
        let Some(packet) = cur.packet.as_ref() else {
            return TransmitOut::Dropped("datagram_too_large");
        };
        let payload = &packet.owner.as_bytes()[off..end];
        let mut buf = bufs.acquire(payload.len() + SEGMENT_OVERHEAD);
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
        match fast.transport.try_send_frame(frame) {
            Ok(()) => {
                frames += 1;
                // Accumulate; accounted once at completion. Preserved
                // across TransportFull resume via the stashed cursor.
                cur.wire_bytes += wire as u64;
                if fast.transport.relay.load(Ordering::Relaxed) {
                    meter.record(wire as u64);
                }
                cur.next_index += 1;
            }
            Err((FastSendError::TransportFull, _)) => {
                // Owner intact, accumulator intact: stash the cursor,
                // resume after backoff.
                return TransmitOut::Stash;
            }
            Err((FastSendError::NoConnection | FastSendError::Closed, _)) => {
                // Owner intact: requeue the whole logical packet (fresh id
                // on retry; orphaned prefix expires), then dial.
                if let Some(packet) = cur.packet.take() {
                    let flow = packet.flow;
                    let len = packet.len() as i64;
                    fast.scheduler.lock().requeue_head(flow, packet);
                    metrics.queue_add(1, len, 0);
                } else {
                    metrics.dropped_inc("no_connection");
                }
                kick_dial(pool, *peer, fast);
                return TransmitOut::Wait;
            }
            Err((FastSendError::TooLarge, _)) => {
                // Stale MPS mid-packet: refresh and re-plan with a FULL
                // geometry compare. Changed geometry (count, seg_cap, or
                // shape) restarts from byte 0 with a fresh id — old
                // offsets are never reused with the new MPS. Identical
                // geometry retries the segment in place (transient).
                fast.refresh_mps();
                restarts += 1;
                if restarts > 2 {
                    return TransmitOut::Dropped("datagram_too_large");
                }
                match cur.replan(fast) {
                    Replan::Restarted => {
                        // Adopted the new geometry wholesale (fresh id,
                        // offset 0, wire accumulator reset); continue under
                        // it with the remaining restart budget. Boxed: the
                        // restart cycle would otherwise recurse unboundedly.
                        return Box::pin(transmit_segmented_restarted(tx, cur, restarts)).await;
                    }
                    Replan::Retry => {
                        // Same geometry: retry this segment in place.
                    }
                    Replan::Impossible => {
                        return TransmitOut::Dropped("datagram_too_large");
                    }
                }
            }
        }
    }
}

fn usable_seg_cap(mps: usize) -> Option<usize> {
    let cap = mps.checked_sub(SEGMENT_OVERHEAD)?;
    (cap >= MIN_SEGMENT_PAYLOAD).then_some(cap)
}

fn account_sent(
    fast: &Arc<PeerMembershipState>,
    flow: FlowKey,
    logical_len: usize,
    wire_len: usize,
) {
    // Debit DRR by logical bytes; wire overhead leans future rounds.
    fast.scheduler
        .lock()
        .account_sent(flow, logical_len, wire_len);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_core::peers::{PeerIdentity, PeerRegistry};

    fn test_fast() -> (PeerRegistry, Arc<PeerMembershipState>) {
        let reg = PeerRegistry::new();
        let ep = iroh::SecretKey::generate().public();
        let fast = reg.ensure(Arc::new(PeerIdentity {
            endpoint: ep,
            endpoint_hex: format!("{ep}"),
            hostname: "peer".into(),
            ip: std::net::Ipv4Addr::new(10, 0, 0, 2),
            tags: vec![],
            network_id: uuid::Uuid::nil(),
            network_name: "net".into(),
        }));
        (reg, fast)
    }

    fn test_packet(size: usize) -> (LogicalPacket, FlowKey) {
        let pool = PacketPool::new(8);
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut raw = Vec::new();
        b.write(&mut raw, &vec![0xABu8; size.saturating_sub(28)])
            .unwrap();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        let pkt = LogicalPacket::from_pooled(buf, raw.len()).unwrap();
        let flow = pkt.flow;
        (pkt, flow)
    }

    #[test]
    fn replan_restarts_on_segcap_change_with_same_count() {
        // §2.1-1: 2800 bytes needs 3 segments at both MPS 1350 (cap 1323)
        // and MPS 1400 (cap 1373) — same count, different geometry. The
        // cursor must still restart with a fresh id, never reusing old
        // offsets with the new MPS.
        let (_reg, fast) = test_fast();
        fast.transport.mps.store(1350, Ordering::Relaxed);
        let (pkt, flow) = test_packet(2800);
        let mut cur = PartialPacket::new(pkt, flow, &fast);
        assert!(matches!(
            cur.plan,
            SegmentPlan::Segmented {
                count: 3,
                seg_cap: 1323
            }
        ));
        // Simulate two sent segments, then a path change (no conn needed:
        // replan only reads MPS and mints ids).
        cur.next_index = 2;
        cur.wire_bytes = 2700;
        let old_id = cur.frame_id;
        fast.transport.mps.store(1400, Ordering::Relaxed);
        assert_eq!(cur.replan(&fast), Replan::Restarted);
        assert!(matches!(
            cur.plan,
            SegmentPlan::Segmented {
                count: 3,
                seg_cap: 1373
            }
        ));
        assert_eq!(cur.next_index, 0, "restart from byte 0");
        assert_eq!(cur.wire_bytes, 0, "fresh accounting unit");
        assert_ne!(cur.frame_id, old_id, "fresh packet id");
    }

    #[test]
    fn replan_retries_in_place_on_identical_geometry() {
        // Spurious TooLarge with unchanged MPS: retry the segment in place
        // (same id, same offset), don't waste a redundant restart.
        let (_reg, fast) = test_fast();
        fast.transport.mps.store(1350, Ordering::Relaxed);
        let (pkt, flow) = test_packet(2800);
        let mut cur = PartialPacket::new(pkt, flow, &fast);
        cur.next_index = 1;
        let old_id = cur.frame_id;
        assert_eq!(cur.replan(&fast), Replan::Retry);
        assert_eq!(cur.next_index, 1);
        assert_eq!(cur.frame_id, old_id);
    }

    #[test]
    fn replan_handles_shape_transitions() {
        let (_reg, fast) = test_fast();
        // Segmented → single (path grew).
        fast.transport.mps.store(1350, Ordering::Relaxed);
        let (pkt, flow) = test_packet(2800);
        let mut cur = PartialPacket::new(pkt, flow, &fast);
        assert!(matches!(cur.plan, SegmentPlan::Segmented { .. }));
        fast.transport.mps.store(9000, Ordering::Relaxed);
        assert_eq!(cur.replan(&fast), Replan::Restarted);
        assert_eq!(cur.plan, SegmentPlan::Single);
        assert_eq!(cur.next_index, 0);
        // Single → segmented (path shrank).
        fast.transport.mps.store(9000, Ordering::Relaxed);
        let (pkt, flow) = test_packet(1200);
        let mut cur = PartialPacket::new(pkt, flow, &fast);
        assert_eq!(cur.plan, SegmentPlan::Single);
        fast.transport.mps.store(1100, Ordering::Relaxed);
        assert_eq!(cur.replan(&fast), Replan::Restarted);
        assert!(matches!(cur.plan, SegmentPlan::Segmented { .. }));
        // Degenerate path: impossible, caller drops.
        fast.transport.mps.store(64, Ordering::Relaxed);
        assert_eq!(cur.replan(&fast), Replan::Impossible);
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
        // §3: the same logical packet needs more segments on a smaller path;
        // the pump restarts it with a fresh id (tested here via the planner).
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
        let net = uuid::Uuid::from_u128(0x0c);
        let payload = vec![0xABu8; 200];
        let frame = stage_single(&pool, net, &payload);
        assert_eq!(frame.len(), SINGLE_OVERHEAD + 200);
        assert_eq!(frame[0], tunnet_common::packet::KIND_SINGLE);
        assert_eq!(&frame[1..SINGLE_OVERHEAD], net.as_bytes());
        let back = strip_single_prefix(frame);
        assert_eq!(&back[..], &payload[..]);
    }

    #[test]
    fn cursor_binds_network_at_dequeue() {
        // §2.2-1: every frame of a packet carries the route's membership
        // network, captured at dequeue.
        let (_reg, fast) = test_fast();
        assert_eq!(
            fast.identity.read().network_id,
            uuid::Uuid::nil(),
            "test membership network"
        );
        let (pkt, flow) = test_packet(200);
        let cur = PartialPacket::new(pkt, flow, &fast);
        assert_eq!(cur.net, uuid::Uuid::nil());
    }
}
