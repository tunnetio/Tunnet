//! Endpoint-global FQ-CoDel packet scheduler (RFC 8290, Tunnet-sized).
//!
//! Pure state machine: no I/O, no transport calls, no metrics registry. One
//! scheduler is owned by each endpoint TX worker; every membership of that
//! endpoint feeds it. Flows are keyed by `(NetworkId, FlowKey)` so the same
//! 5-tuple in two Direct networks never merges into one flow.
//!
//! ```text
//! EndpointScheduler
//!   ├─ new flows (sparse/interactive, bounded epoch budget)
//!   ├─ old flows (backlogged, byte-DRR across flows, one packet per visit)
//!   ├─ per-flow FIFO (ordering preserved within a flow)
//!   ├─ per-flow CoDel state (first_above_time/dropping/drop_next/count)
//!   └─ endpoint byte/packet hard caps (memory safety only) + emergency ceiling
//! ```
//!
//! The scheduler queues LOGICAL packets: one inner packet is one scheduling
//! object. Segmentation happens after dequeue; the worker reports each
//! logical packet ONCE at completion via [`EndpointScheduler::complete`]
//! with `(logical_len, total_wire_len)`.
//!
//! Accounting is exact and single-sourced: every mutation updates cumulative
//! counters, and [`SchedReporter`] diffs snapshots into telemetry deltas.
//! There is no snapshot-reconcile pass, no partitioned drain, and no
//! double-report path. Conservation holds by construction:
//!
//! ```text
//! accepted == delivered + explicitly_dropped + currently_owned
//! owned    == queued + inflight        (packets and bytes)
//! ```
//!
//! Dequeue serves ONE logical packet at a time and moves it to explicitly
//! tracked in-flight ownership (`queued -> inflight`); `complete`,
//! `discard_inflight`, or a purge resolves it. No packet disappears between
//! states. `Empty` means genuinely no queued work.
//!
//! Hard caps are tail-rejection only: when an endpoint cap is reached the
//! ARRIVING packet is shed with its reason. There is no per-flow cap and no
//! old-head replacement — CoDel (not a tiny packet count) controls queue
//! latency; the caps are memory safety bounds.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tunnet_common::packet::{FlowKey, LogicalPacket};
use uuid::Uuid;

/// CoDel target: minimum sojourn indicating a standing queue (~5 ms baseline;
/// consider serialization time on slow links per RFC 8290 §4.2).
pub const CODEL_TARGET: Duration = Duration::from_millis(5);
/// CoDel interval: standing-queue observation window.
pub const CODEL_INTERVAL: Duration = Duration::from_millis(100);
/// Emergency maximum queue lifetime: hard safety bound only, not the AQM.
pub const EMERGENCY_CEILING: Duration = Duration::from_millis(1000);
/// Total queued bytes per endpoint (queueing budget shared with transport).
pub const ENDPOINT_BYTE_CAP: usize = 256 * 1024;
/// Hard packet cap per endpoint (memory bound for tiny packets).
pub const ENDPOINT_PACKET_CAP: usize = 512;
/// New flows stay "sparse" until they send this many bytes.
pub const NEW_FLOW_BYTE_BUDGET: usize = 16 * 1024;
/// Sparse flow sojourn bar: heads older than this are not "interactive".
pub const SPARSE_SOJOURN_BAR: Duration = Duration::from_millis(25);
/// Upper bound on immediate DRR rounds inside one `next()` call.
/// One quantum (≥512 B) per round per flow; 64 is a safe deterministic
/// margin; typical calls send on the first round.
pub const MAX_DRR_ROUNDS: u8 = 64;

/// Scheduler flow key: the 5-tuple PLUS the network it belongs to. The same
/// 5-tuple in two Direct networks is two flows, never one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchedFlowKey {
    pub net: Uuid,
    pub flow: FlowKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    EndpointByteCap,
    EndpointPacketCap,
    Codel,
    EmergencyCeiling,
    TooLarge,
    NoConnection,
    /// Packet belonged to a revoked membership (worker-owned discard or
    /// network purge).
    MembershipRevoked,
    /// Packet belonged to a torn-down dataplane generation.
    GenerationEnd,
}

impl DropReason {
    pub const ALL: [DropReason; 8] = [
        DropReason::EndpointByteCap,
        DropReason::EndpointPacketCap,
        DropReason::Codel,
        DropReason::EmergencyCeiling,
        DropReason::TooLarge,
        DropReason::NoConnection,
        DropReason::MembershipRevoked,
        DropReason::GenerationEnd,
    ];

    pub fn index(self) -> usize {
        match self {
            Self::EndpointByteCap => 0,
            Self::EndpointPacketCap => 1,
            Self::Codel => 2,
            Self::EmergencyCeiling => 3,
            Self::TooLarge => 4,
            Self::NoConnection => 5,
            Self::MembershipRevoked => 6,
            Self::GenerationEnd => 7,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndpointByteCap => "sched_endpoint_bytes",
            Self::EndpointPacketCap => "sched_endpoint_packets",
            Self::Codel => "sched_codel",
            Self::EmergencyCeiling => "sched_emergency",
            Self::TooLarge => "datagram_too_large",
            Self::NoConnection => "no_connection",
            Self::MembershipRevoked => "sched_membership_revoked",
            Self::GenerationEnd => "sched_generation_end",
        }
    }
}

/// Per-flow CoDel state (RFC 8290 §5.2, adapted to logical packets).
#[derive(Debug, Clone, Copy)]
struct CodelState {
    /// When the current above-target episode started (None = below target).
    first_above_time: Option<Instant>,
    /// In dropping state (sustained standing queue).
    dropping: bool,
    /// Next scheduled drop time while dropping.
    drop_next: Instant,
    /// Drops in the current episode (controls drop frequency).
    count: u32,
}

impl CodelState {
    fn new() -> Self {
        Self {
            first_above_time: None,
            dropping: false,
            drop_next: Instant::now(),
            count: 0,
        }
    }
}

struct QueuedPacket {
    packet: LogicalPacket,
    len: usize,
}

struct FlowQueue {
    packets: VecDeque<QueuedPacket>,
    bytes: usize,
    deficit: isize,
    epoch_bytes: usize,
    is_new: bool,
    codel: CodelState,
}

impl FlowQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            bytes: 0,
            deficit: 0,
            epoch_bytes: 0,
            is_new: true,
            codel: CodelState::new(),
        }
    }
}

/// Cumulative scheduler counters — the ONE accounting source. Every mutation
/// updates these; [`SchedReporter`] diffs consecutive snapshots into exact
/// telemetry deltas. Levels (`queued_*`, `active_flows`, `inflight_*`) are
/// state; `sent_*`/`wire_bytes`/`drop_*` are monotonic totals.
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedSnapshot {
    pub queued_packets: u64,
    pub queued_bytes: u64,
    pub active_flows: u64,
    pub inflight_packets: u64,
    pub inflight_bytes: u64,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub wire_bytes: u64,
    pub drop_packets: [u64; 8],
    pub drop_bytes: [u64; 8],
}

impl SchedSnapshot {
    /// Packets currently owned by the scheduler (queued + in-flight).
    pub fn owned_packets(self) -> u64 {
        self.queued_packets + self.inflight_packets
    }

    /// Bytes currently owned by the scheduler (queued + in-flight).
    pub fn owned_bytes(self) -> u64 {
        self.queued_bytes + self.inflight_bytes
    }

    /// Total explicitly dropped packets across all reasons.
    pub fn dropped_packets(self) -> u64 {
        self.drop_packets.iter().sum()
    }

    /// Total explicitly dropped bytes across all reasons.
    pub fn dropped_bytes(self) -> u64 {
        self.drop_bytes.iter().sum()
    }

    /// Conservation: every offered packet is delivered, explicitly
    /// dropped (including tail-rejected newcomers), or still owned.
    pub fn conserves(self, offered_packets: u64, offered_bytes: u64) -> bool {
        offered_packets == self.sent_packets + self.dropped_packets() + self.owned_packets()
            && offered_bytes == self.sent_bytes + self.dropped_bytes() + self.owned_bytes()
    }
}

/// Exact delta between two snapshots, for telemetry. Level deltas are signed
/// (gauges); sent/drop deltas are unsigned (counters). Computed by
/// [`SchedReporter`]; saturates rather than wraps on misuse.
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedDiff {
    pub dq_packets: i64,
    pub dq_bytes: i64,
    pub dq_flows: i64,
    pub dq_inflight_packets: i64,
    pub dq_inflight_bytes: i64,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub wire_bytes: u64,
    pub drop_packets: [u64; 8],
    pub drop_bytes: [u64; 8],
}

/// Diffs scheduler snapshots into exact telemetry deltas. Owned by the single
/// endpoint TX worker, so baselines are race-free by construction.
#[derive(Debug, Default)]
pub struct SchedReporter {
    last: SchedSnapshot,
}

impl SchedReporter {
    pub fn new(initial: SchedSnapshot) -> Self {
        Self { last: initial }
    }

    pub fn diff(&mut self, cur: SchedSnapshot) -> SchedDiff {
        let out = SchedDiff {
            dq_packets: cur.queued_packets as i64 - self.last.queued_packets as i64,
            dq_bytes: cur.queued_bytes as i64 - self.last.queued_bytes as i64,
            dq_flows: cur.active_flows as i64 - self.last.active_flows as i64,
            dq_inflight_packets: cur.inflight_packets as i64 - self.last.inflight_packets as i64,
            dq_inflight_bytes: cur.inflight_bytes as i64 - self.last.inflight_bytes as i64,
            sent_packets: cur.sent_packets.saturating_sub(self.last.sent_packets),
            sent_bytes: cur.sent_bytes.saturating_sub(self.last.sent_bytes),
            wire_bytes: cur.wire_bytes.saturating_sub(self.last.wire_bytes),
            drop_packets: std::array::from_fn(|i| {
                cur.drop_packets[i].saturating_sub(self.last.drop_packets[i])
            }),
            drop_bytes: std::array::from_fn(|i| {
                cur.drop_bytes[i].saturating_sub(self.last.drop_bytes[i])
            }),
        };
        self.last = cur;
        out
    }
}

/// Enqueue decision. Rejection sheds the ARRIVING packet (tail drop) with its
/// reason — the queue is never reordered or replaced to admit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Admitted (`new_flow` tells the caller whether a flow gauge +1 applies).
    Accepted { new_flow: bool },
    /// Shed (report `reason` to telemetry; gauges untouched).
    Rejected { reason: DropReason },
}

impl EnqueueOutcome {
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// One owned logical packet handed to the endpoint worker. Ownership moved
/// queued -> in-flight; the worker resolves it via [`EndpointScheduler::complete`]
/// (delivered) or [`EndpointScheduler::discard_inflight`] (revoked/torn down).
pub struct DequeuedPacket {
    pub net: Uuid,
    pub flow: FlowKey,
    pub packet: LogicalPacket,
    pub sojourn: Duration,
}

/// Dequeue decision returned to the endpoint worker.
pub enum Dequeue {
    /// Transmit this packet (single logical packet, in order). Boxed: the
    /// packet is heap-sized and Empty is unit-sized.
    Send(Box<DequeuedPacket>),
    /// No queued work.
    Empty,
}

/// Endpoint-global FQ-CoDel scheduler. Not thread-safe; owned by the
/// endpoint's single TX worker behind a lock.
pub struct EndpointScheduler {
    flows: HashMap<SchedFlowKey, FlowQueue>,
    /// New (sparse) flows first, oldest-first.
    new_list: VecDeque<SchedFlowKey>,
    /// Backlogged flows in DRR order.
    old_list: VecDeque<SchedFlowKey>,
    /// In-progress DRR visit: the last-served backlogged flow still owns
    /// its quantum grant, so the next dequeue continues its affordable
    /// heads instead of granting a fresh quantum elsewhere. This keeps
    /// single-packet dequeue byte-fair exactly like classic burst DRR.
    drr_turn: Option<SchedFlowKey>,
    bytes: usize,
    packets: usize,
    inflight_packets: u64,
    inflight_bytes: u64,
    quantum: usize,
    target: Duration,
    interval: Duration,
    sent_packets: u64,
    sent_bytes: u64,
    wire_bytes: u64,
    drop_packets: [u64; 8],
    drop_bytes: [u64; 8],
}

impl EndpointScheduler {
    pub fn new(quantum: usize) -> Self {
        Self::with_params(quantum, CODEL_TARGET, CODEL_INTERVAL)
    }

    /// Custom CoDel timing (tests, link-specific tuning). Production uses
    /// [`CODEL_TARGET`]/[`CODEL_INTERVAL`].
    pub fn with_params(quantum: usize, target: Duration, interval: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            new_list: VecDeque::new(),
            old_list: VecDeque::new(),
            drr_turn: None,
            bytes: 0,
            packets: 0,
            inflight_packets: 0,
            inflight_bytes: 0,
            quantum: quantum.max(512),
            target,
            interval: interval.max(Duration::from_millis(1)),
            sent_packets: 0,
            sent_bytes: 0,
            wire_bytes: 0,
            drop_packets: [0; 8],
            drop_bytes: [0; 8],
        }
    }

    pub fn set_quantum(&mut self, quantum: usize) {
        self.quantum = quantum.max(512);
    }

    /// True when queued (not in-flight) work exists.
    pub fn has_queued_work(&self) -> bool {
        self.packets > 0
    }

    /// Current cumulative counters (the accounting source).
    pub fn snapshot(&self) -> SchedSnapshot {
        SchedSnapshot {
            queued_packets: self.packets as u64,
            queued_bytes: self.bytes as u64,
            active_flows: self.flows.len() as u64,
            inflight_packets: self.inflight_packets,
            inflight_bytes: self.inflight_bytes,
            sent_packets: self.sent_packets,
            sent_bytes: self.sent_bytes,
            wire_bytes: self.wire_bytes,
            drop_packets: self.drop_packets,
            drop_bytes: self.drop_bytes,
        }
    }

    fn record_drop(
        drop_packets: &mut [u64; 8],
        drop_bytes: &mut [u64; 8],
        reason: DropReason,
        packets: u64,
        bytes: u64,
    ) {
        let i = reason.index();
        drop_packets[i] += packets;
        drop_bytes[i] += bytes;
    }

    /// Enqueue one logical packet for `net`. Tail-rejects the newcomer when
    /// an endpoint hard cap is reached — never evicts, never reorders.
    /// `now` should be the packet's observation time (usually Instant::now()).
    pub fn enqueue(&mut self, net: Uuid, packet: LogicalPacket, now: Instant) -> EnqueueOutcome {
        let key = SchedFlowKey {
            net,
            flow: packet.flow,
        };
        let len = packet.len();
        // Memory safety bounds only: shed the ARRIVING packet.
        if self.packets >= ENDPOINT_PACKET_CAP {
            Self::record_drop(
                &mut self.drop_packets,
                &mut self.drop_bytes,
                DropReason::EndpointPacketCap,
                1,
                len as u64,
            );
            return EnqueueOutcome::Rejected {
                reason: DropReason::EndpointPacketCap,
            };
        }
        if self.bytes + len > ENDPOINT_BYTE_CAP {
            Self::record_drop(
                &mut self.drop_packets,
                &mut self.drop_bytes,
                DropReason::EndpointByteCap,
                1,
                len as u64,
            );
            return EnqueueOutcome::Rejected {
                reason: DropReason::EndpointByteCap,
            };
        }
        let is_new_flow = !self.flows.contains_key(&key);
        let q = self.flows.entry(key).or_insert_with(FlowQueue::new);
        let _ = now;
        q.bytes += len;
        q.packets.push_back(QueuedPacket { packet, len });
        self.bytes += len;
        self.packets += 1;
        if is_new_flow && !self.new_list.contains(&key) && !self.old_list.contains(&key) {
            self.new_list.push_back(key);
        }
        EnqueueOutcome::Accepted {
            new_flow: is_new_flow,
        }
    }

    /// Dequeue the next service opportunity: sparse flows first (one packet:
    /// bounded epoch budget, young head), then the in-progress DRR visit,
    /// else byte-DRR across old flows (one packet per visit) with per-flow
    /// CoDel standing-queue control.
    ///
    /// The served packet moves to in-flight ownership. `Empty` is returned
    /// ONLY when no queued work remains.
    pub fn next(&mut self, now: Instant) -> Dequeue {
        // 1) Sparse/new flows: single packet (interactive latency first).
        // Drain Gone heads; one Demote breaks to DRR.
        while let Some(key) = self.new_list.pop_front() {
            match self.serve_sparse(key, now) {
                SparseOut::Send(item) => return Dequeue::Send(item),
                SparseOut::Gone => continue,
                SparseOut::Demoted => break,
            }
        }
        // 2) In-progress DRR visit: continue the affordable heads of the
        // last-served backlogged flow under its existing quantum grant.
        if let Some(key) = self.drr_turn.take() {
            match self.resume_turn(key, now) {
                TurnOut::Send(item) => return Dequeue::Send(item),
                TurnOut::Ended | TurnOut::Gone => {}
            }
        }
        // 2) Byte-DRR across old flows with CoDel. List rotation lives
        // here: serve_old only signals, never pushes (one owner, no dupes,
        // no zombie keys for emptied flows).
        for _ in 0..MAX_DRR_ROUNDS {
            let n = self.old_list.len();
            if n == 0 {
                return Dequeue::Empty;
            }
            let mut served: Option<Box<DequeuedPacket>> = None;
            for _ in 0..n {
                let Some(key) = self.old_list.pop_front() else {
                    break;
                };
                match self.serve_old(key, now) {
                    OldOut::Send(item) => {
                        if self.flows.get(&key).is_some_and(|q| !q.packets.is_empty()) {
                            self.old_list.push_back(key);
                            // Continue this visit next call under the same
                            // quantum grant (single-packet burst fairness).
                            self.drr_turn = Some(key);
                        }
                        served = Some(item);
                        break;
                    }
                    OldOut::Rotate => {
                        if self.flows.get(&key).is_some_and(|q| !q.packets.is_empty()) {
                            self.old_list.push_back(key);
                        }
                    }
                    OldOut::Gone => {}
                }
            }
            if let Some(item) = served {
                return Dequeue::Send(item);
            }
            // No send this round: every visit either dropped a packet
            // (CoDel/emergency, strictly reducing queued packets) or
            // retired a flow/stale key (strictly shrinking the list) or
            // rotated an unaffordable head (deficit grew by one quantum).
            // Loop for another immediate round — never Empty with work.
        }
        // Unreachable safety: the deficit gap is bounded, so 64 rounds always
        // serve or drain. Never hang the worker.
        debug_assert!(false, "scheduler DRR round bound exhausted");
        Dequeue::Empty
    }

    /// Resolve one in-flight packet as DELIVERED. Called exactly once per
    /// dequeued logical packet when transmission finishes — never per
    /// segment — so segmented traffic is charged once. The DRR deficit lean
    /// for wire overhead applies best-effort (the flow may have retired).
    pub fn complete(&mut self, key: &SchedFlowKey, logical_len: usize, wire_len: usize) {
        self.inflight_packets = self.inflight_packets.saturating_sub(1);
        self.inflight_bytes = self.inflight_bytes.saturating_sub(logical_len as u64);
        self.sent_packets += 1;
        self.sent_bytes += logical_len as u64;
        self.wire_bytes += wire_len as u64;
        if let Some(q) = self.flows.get_mut(key) {
            // Extra wire overhead beyond the DRR deficit debit leans future
            // rounds slightly against overhead-heavy flows.
            let overhead = wire_len.saturating_sub(logical_len);
            q.deficit -= overhead as isize;
        }
    }

    /// Resolve one in-flight packet as DROPPED (revoked membership, torn-down
    /// generation). The worker owns the bytes; the scheduler records the
    /// exact drop so conservation holds.
    pub fn discard_inflight(&mut self, len: usize, reason: DropReason) {
        self.inflight_packets = self.inflight_packets.saturating_sub(1);
        self.inflight_bytes = self.inflight_bytes.saturating_sub(len as u64);
        Self::record_drop(
            &mut self.drop_packets,
            &mut self.drop_bytes,
            reason,
            1,
            len as u64,
        );
    }

    /// Drop every QUEUED packet bound to `net` (membership revoked). In-flight
    /// packets are worker-owned; the worker discards them via
    /// [`Self::discard_inflight`]. Drops are recorded with exact
    /// packets/bytes under `reason`.
    pub fn purge_network(&mut self, net: Uuid, reason: DropReason) {
        if self.drr_turn.is_some_and(|k| k.net == net) {
            self.drr_turn = None;
        }
        let keys: Vec<SchedFlowKey> = self
            .flows
            .keys()
            .filter(|k| k.net == net)
            .cloned()
            .collect();
        for key in keys {
            if let Some(q) = self.flows.remove(&key) {
                let (mut p, mut b) = (0u64, 0u64);
                for qp in q.packets {
                    p += 1;
                    b += qp.len as u64;
                }
                self.packets -= p as usize;
                self.bytes -= b as usize;
                Self::record_drop(&mut self.drop_packets, &mut self.drop_bytes, reason, p, b);
            }
        }
        self.new_list.retain(|k| k.net != net);
        self.old_list.retain(|k| k.net != net);
    }

    /// Drop every QUEUED packet (generation teardown). In-flight packets are
    /// worker-owned and discarded by the exiting worker.
    pub fn purge_all(&mut self, reason: DropReason) {
        let p = self.packets as u64;
        let b = self.bytes as u64;
        Self::record_drop(&mut self.drop_packets, &mut self.drop_bytes, reason, p, b);
        self.flows.clear();
        self.new_list.clear();
        self.old_list.clear();
        self.drr_turn = None;
        self.bytes = 0;
        self.packets = 0;
    }

    fn remove_flow(&mut self, key: &SchedFlowKey) {
        self.flows.remove(key);
        self.new_list.retain(|k| k != key);
        self.old_list.retain(|k| k != key);
        if self.drr_turn == Some(*key) {
            self.drr_turn = None;
        }
    }

    /// Continue an in-progress DRR visit: serve ONE more affordable head of
    /// the last-served flow under its existing quantum grant (no new grant,
    /// no CoDel re-check — same visit). Ends the turn when the head is
    /// unaffordable or the flow is gone.
    fn resume_turn(&mut self, key: SchedFlowKey, now: Instant) -> TurnOut {
        // The flow sits in the old list (pushed back when the visit
        // started); take it out to serve without duplicating the key.
        let in_list = if let Some(pos) = self.old_list.iter().position(|k| *k == key) {
            self.old_list.remove(pos);
            true
        } else {
            false
        };
        let Some(q) = self.flows.get_mut(&key) else {
            return TurnOut::Gone;
        };
        // Emergency ceiling applies per packet, like the burst loop.
        while let Some(h) = q.packets.front() {
            if now.saturating_duration_since(h.packet.enqueued_at) > EMERGENCY_CEILING {
                let old = q.packets.pop_front().expect("head");
                q.bytes -= old.len;
                self.bytes -= old.len;
                self.packets -= 1;
                Self::record_drop(
                    &mut self.drop_packets,
                    &mut self.drop_bytes,
                    DropReason::EmergencyCeiling,
                    1,
                    old.len as u64,
                );
            } else {
                break;
            }
        }
        let Some(head_len) = q.packets.front().map(|h| h.len) else {
            self.remove_flow(&key);
            return TurnOut::Gone;
        };
        if (head_len as isize) > q.deficit {
            // Quantum exhausted: end the turn, re-list for a later visit.
            if (in_list || self.flows.contains_key(&key)) && !self.old_list.contains(&key) {
                self.old_list.push_back(key);
            }
            return TurnOut::Ended;
        }
        let qp = q.packets.pop_front().expect("head");
        let sojourn = now.saturating_duration_since(qp.packet.enqueued_at);
        q.bytes -= qp.len;
        self.bytes -= qp.len;
        self.packets -= 1;
        q.deficit -= qp.len as isize;
        q.epoch_bytes += qp.len;
        if q.packets.is_empty() {
            self.remove_flow(&key);
        } else {
            if !self.old_list.contains(&key) {
                self.old_list.push_back(key);
            }
            self.drr_turn = Some(key);
        }
        self.inflight_packets += 1;
        self.inflight_bytes += qp.len as u64;
        TurnOut::Send(Box::new(DequeuedPacket {
            net: key.net,
            flow: key.flow,
            packet: qp.packet,
            sojourn,
        }))
    }

    fn serve_sparse(&mut self, key: SchedFlowKey, now: Instant) -> SparseOut {
        enum Prep {
            Send,
            Demote,
            Gone,
        }
        let prep = {
            let Some(q) = self.flows.get_mut(&key) else {
                return SparseOut::Gone;
            };
            // Emergency ceiling applies everywhere (safety bound only).
            while let Some(h) = q.packets.front() {
                if now.saturating_duration_since(h.packet.enqueued_at) > EMERGENCY_CEILING {
                    let old = q.packets.pop_front().expect("head");
                    q.bytes -= old.len;
                    self.bytes -= old.len;
                    self.packets -= 1;
                    Self::record_drop(
                        &mut self.drop_packets,
                        &mut self.drop_bytes,
                        DropReason::EmergencyCeiling,
                        1,
                        old.len as u64,
                    );
                } else {
                    break;
                }
            }
            if q.packets.is_empty() {
                Prep::Gone
            } else {
                let young = q.packets.front().is_some_and(|h| {
                    now.saturating_duration_since(h.packet.enqueued_at) <= SPARSE_SOJOURN_BAR
                });
                if !q.is_new || q.epoch_bytes >= NEW_FLOW_BYTE_BUDGET || !young {
                    q.is_new = false;
                    Prep::Demote
                } else {
                    Prep::Send
                }
            }
        };
        match prep {
            Prep::Gone => {
                self.remove_flow(&key);
                SparseOut::Gone
            }
            Prep::Demote => {
                self.old_list.push_back(key);
                SparseOut::Demoted
            }
            Prep::Send => {
                let q = self.flows.get_mut(&key).expect("present");
                let qp = q.packets.pop_front().expect("head");
                let sojourn = now.saturating_duration_since(qp.packet.enqueued_at);
                q.bytes -= qp.len;
                self.bytes -= qp.len;
                self.packets -= 1;
                q.epoch_bytes += qp.len;
                q.deficit += self.quantum as isize;
                q.deficit -= qp.len as isize;
                if q.packets.is_empty() {
                    self.remove_flow(&key);
                } else if q.epoch_bytes >= NEW_FLOW_BYTE_BUDGET {
                    q.is_new = false;
                    self.old_list.push_back(key);
                } else {
                    self.new_list.push_front(key);
                }
                self.inflight_packets += 1;
                self.inflight_bytes += qp.len as u64;
                SparseOut::Send(Box::new(DequeuedPacket {
                    net: key.net,
                    flow: key.flow,
                    packet: qp.packet,
                    sojourn,
                }))
            }
        }
    }

    fn serve_old(&mut self, key: SchedFlowKey, now: Instant) -> OldOut {
        // Emergency ceiling + CoDel observe the head first.
        enum Head {
            Ready,
            Dropped,
            Gone,
        }
        let head = {
            let Some(q) = self.flows.get_mut(&key) else {
                return OldOut::Gone;
            };
            // Emergency safety bound.
            while let Some(h) = q.packets.front() {
                if now.saturating_duration_since(h.packet.enqueued_at) > EMERGENCY_CEILING {
                    let old = q.packets.pop_front().expect("head");
                    q.bytes -= old.len;
                    self.bytes -= old.len;
                    self.packets -= 1;
                    Self::record_drop(
                        &mut self.drop_packets,
                        &mut self.drop_bytes,
                        DropReason::EmergencyCeiling,
                        1,
                        old.len as u64,
                    );
                } else {
                    break;
                }
            }
            let sojourn = match q.packets.front() {
                Some(h) => now.saturating_duration_since(h.packet.enqueued_at),
                None => {
                    self.remove_flow(&key);
                    return OldOut::Gone;
                }
            };
            // CoDel control law (RFC 8290 §5.2) on head sojourn.
            let target = self.target;
            let interval = self.interval;
            let c = &mut q.codel;
            if sojourn < target {
                c.first_above_time = None;
                Head::Ready
            } else if c.first_above_time.is_none() {
                c.first_above_time = Some(now + interval);
                Head::Ready
            } else if now < c.first_above_time.expect("set") {
                Head::Ready
            } else {
                // Standing queue: enter/continue dropping state.
                if !c.dropping {
                    c.dropping = true;
                    // First drop is immediate on entering dropping state.
                    c.drop_next = now;
                    c.count = 0;
                }
                if now < c.drop_next {
                    Head::Ready
                } else {
                    c.count += 1;
                    // Next drop scheduled per control law: interval/sqrt(count).
                    let div = (c.count as f64).sqrt().max(1.0);
                    let step = interval.div_f64(div);
                    c.drop_next = now + step;
                    // Drop the head now.
                    let old = q.packets.pop_front().expect("head");
                    q.bytes -= old.len;
                    self.bytes -= old.len;
                    self.packets -= 1;
                    Self::record_drop(
                        &mut self.drop_packets,
                        &mut self.drop_bytes,
                        DropReason::Codel,
                        1,
                        old.len as u64,
                    );
                    // Re-observe the new head next visit.
                    if q.packets.is_empty() {
                        Head::Gone
                    } else {
                        Head::Dropped
                    }
                }
            }
        };
        match head {
            Head::Gone => {
                self.remove_flow(&key);
                OldOut::Gone
            }
            Head::Dropped => {
                // Dropped above; the caller requeues this flow for its next
                // packet (list ownership lives in `next`). An emptied flow
                // is removed outright so no zombie key lingers.
                if self.flows.get(&key).is_some_and(|q| q.packets.is_empty()) {
                    self.remove_flow(&key);
                    OldOut::Gone
                } else {
                    OldOut::Rotate
                }
            }
            Head::Ready => {
                let q = self.flows.get_mut(&key).expect("present");
                // Classic DRR: exactly ONE quantum per visit, ONE packet per
                // service. An unaffordable head rotates for a later round
                // (the caller's round loop retries immediately — no Empty,
                // no sleep).
                q.deficit += self.quantum as isize;
                let head_len = match q.packets.front() {
                    Some(h) => {
                        let sojourn = now.saturating_duration_since(h.packet.enqueued_at);
                        if sojourn > EMERGENCY_CEILING {
                            let old = q.packets.pop_front().expect("head");
                            q.bytes -= old.len;
                            self.bytes -= old.len;
                            self.packets -= 1;
                            Self::record_drop(
                                &mut self.drop_packets,
                                &mut self.drop_bytes,
                                DropReason::EmergencyCeiling,
                                1,
                                old.len as u64,
                            );
                            if q.packets.is_empty() {
                                self.remove_flow(&key);
                                return OldOut::Gone;
                            }
                            return OldOut::Rotate;
                        }
                        h.len
                    }
                    None => {
                        self.remove_flow(&key);
                        return OldOut::Gone;
                    }
                };
                if (head_len as isize) > q.deficit {
                    return OldOut::Rotate;
                }
                let qp = q.packets.pop_front().expect("head");
                let sojourn = now.saturating_duration_since(qp.packet.enqueued_at);
                q.bytes -= qp.len;
                self.bytes -= qp.len;
                self.packets -= 1;
                q.deficit -= qp.len as isize;
                q.epoch_bytes += qp.len;
                // Leaving dropping state: sojourn fell below target on a
                // previous observation (first_above_time cleared above).
                if q.codel.first_above_time.is_none() {
                    q.codel.dropping = false;
                    q.codel.count = 0;
                }
                if q.packets.is_empty() {
                    self.remove_flow(&key);
                }
                // List rotation belongs to the caller (`next` requeues on
                // Send/Rotate); serve_old never pushes.
                self.inflight_packets += 1;
                self.inflight_bytes += qp.len as u64;
                OldOut::Send(Box::new(DequeuedPacket {
                    net: key.net,
                    flow: key.flow,
                    packet: qp.packet,
                    sojourn,
                }))
            }
        }
    }
}

enum SparseOut {
    Send(Box<DequeuedPacket>),
    Gone,
    Demoted,
}

enum OldOut {
    Send(Box<DequeuedPacket>),
    Rotate,
    Gone,
}

enum TurnOut {
    Send(Box<DequeuedPacket>),
    Ended,
    Gone,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tunnet_common::packet::PacketPool;

    const NET: Uuid = Uuid::from_u128(0x2e2e);
    const NET_OTHER: Uuid = Uuid::from_u128(0x3e3e);

    fn pool() -> Arc<PacketPool> {
        PacketPool::new(64)
    }

    fn logical(pool: &Arc<PacketPool>, sport: u16, size: usize) -> LogicalPacket {
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(sport, 443);
        let mut raw = Vec::new();
        b.write(&mut raw, &vec![0u8; size]).unwrap();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        LogicalPacket::from_pooled(buf, raw.len()).unwrap()
    }

    fn enqueue(pool: &Arc<PacketPool>, s: &mut EndpointScheduler, sport: u16, size: usize) {
        assert!(
            s.enqueue(NET, logical(pool, sport, size), Instant::now())
                .is_accepted()
        );
    }

    fn drain_all(s: &mut EndpointScheduler) -> Vec<(FlowKey, usize)> {
        let mut out = Vec::new();
        let mut guard = 8192;
        while guard > 0 {
            guard -= 1;
            match s.next(Instant::now()) {
                Dequeue::Send(item) => {
                    let key = SchedFlowKey {
                        net: item.net,
                        flow: item.flow,
                    };
                    let l = item.packet.len();
                    s.complete(&key, l, l);
                    out.push((item.flow, l));
                }
                Dequeue::Empty => break,
            }
        }
        out
    }

    /// Demote every flow to the old/DRR list, as the worker would observe
    /// after the sparse budget is spent.
    fn demote_all(s: &mut EndpointScheduler) {
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
        }
        s.new_list.clear();
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            s.old_list.push_back(k);
        }
    }

    #[test]
    fn large_heads_serve_without_stall() {
        // Logical packets far larger than the DRR quantum must be served via
        // immediate internal rounds — Empty means empty, never deferred.
        for (size, quantum) in [(2800usize, 1200usize), (9000, 1400), (9000, 512)] {
            let p = pool();
            let mut s = EndpointScheduler::new(quantum);
            enqueue(&p, &mut s, 1111, size - 28);
            demote_all(&mut s);
            let mut empties = 0u32;
            let mut sent = 0u32;
            while s.has_queued_work() {
                match s.next(Instant::now()) {
                    Dequeue::Send(item) => {
                        let l = item.packet.len();
                        assert_eq!(l, logical(&p, 1111, size - 28).len());
                        let key = SchedFlowKey {
                            net: item.net,
                            flow: item.flow,
                        };
                        s.complete(&key, l, l + 12);
                        sent += 1;
                    }
                    Dequeue::Empty => empties += 1,
                }
                assert!(sent + empties < 10, "stall: Empty with work queued");
            }
            assert_eq!(sent, 1);
            assert_eq!(
                empties, 0,
                "size={size} quantum={quantum}: no Empty while queued"
            );
        }
    }

    #[test]
    fn wire_accounted_once_per_logical() {
        let p = pool();
        let mut s = EndpointScheduler::new(1200);
        let want = logical(&p, 1111, 2800 - 28);
        let (flow, len) = (want.flow, want.len());
        assert!(s.enqueue(NET, want, Instant::now()).is_accepted());
        let (f, l) = match s.next(Instant::now()) {
            Dequeue::Send(item) => (item.flow, item.packet.len()),
            Dequeue::Empty => panic!("expected packet"),
        };
        assert_eq!((f, l), (flow, len));
        // Worker transmits 3 segments then completes once with total wire.
        let total_wire = l + 3 * 11;
        s.complete(&SchedFlowKey { net: NET, flow: f }, l, total_wire);
        let snap = s.snapshot();
        assert_eq!(snap.sent_packets, 1);
        assert_eq!(snap.sent_bytes, len as u64);
        assert_eq!(snap.wire_bytes, total_wire as u64);
        assert_eq!(snap.inflight_packets, 0);
        assert!(snap.conserves(1, len as u64));
    }

    /// Queued length of one flow (by sport) for backlog maintenance.
    fn qlen(s: &EndpointScheduler, sport: u16) -> usize {
        s.flows
            .iter()
            .filter(|(k, _)| k.flow.sport == sport)
            .map(|(_, q)| q.packets.len())
            .sum()
    }

    /// Continuously-backlogged byte shares for two flows.
    fn fairness_ratio(
        big_payload: usize,
        small_payload: usize,
        quantum: usize,
        calls: usize,
    ) -> (u64, u64) {
        let p = pool();
        let mut s = EndpointScheduler::new(quantum);
        for _ in 0..12 {
            enqueue(&p, &mut s, 1111, big_payload);
        }
        for _ in 0..64 {
            enqueue(&p, &mut s, 2222, small_payload);
        }
        demote_all(&mut s);
        let mut bytes = [0u64; 2];
        for _ in 0..calls {
            while qlen(&s, 1111) < 12 {
                if !s
                    .enqueue(NET, logical(&p, 1111, big_payload), Instant::now())
                    .is_accepted()
                {
                    break;
                }
            }
            while qlen(&s, 2222) < 64 {
                if !s
                    .enqueue(NET, logical(&p, 2222, small_payload), Instant::now())
                    .is_accepted()
                {
                    break;
                }
            }
            match s.next(Instant::now()) {
                Dequeue::Send(item) => {
                    let l = item.packet.len();
                    let key = SchedFlowKey {
                        net: item.net,
                        flow: item.flow,
                    };
                    s.complete(&key, l, l);
                    if item.flow.sport == 1111 {
                        bytes[0] += l as u64;
                    } else {
                        bytes[1] += l as u64;
                    }
                }
                Dequeue::Empty => panic!("stall with work queued"),
            }
        }
        (bytes[0], bytes[1])
    }

    #[test]
    fn drr_byte_fairness_jumbo_vs_small() {
        let (big, small) = fairness_ratio(9000 - 28, 100 - 28, 1200, 400);
        let ratio = big as f64 / small as f64;
        assert!(
            (0.65..=1.5).contains(&ratio),
            "byte shares must be ~equal, got big={big} small={small} ratio={ratio:.2}"
        );
    }

    #[test]
    fn drr_byte_fairness_matrix() {
        for (big_total, small_total, quantum) in [
            (2800usize, 100usize, 1200usize),
            (9000, 1200, 1400),
            (2800, 1200, 512),
        ] {
            let (big, small) = fairness_ratio(big_total - 28, small_total - 28, quantum, 300);
            let ratio = big as f64 / small as f64;
            assert!(
                (0.6..=1.7).contains(&ratio),
                "big={big_total} small={small_total} q={quantum}: ratio={ratio:.2}"
            );
        }
    }

    #[test]
    fn drr_byte_fairness_three_flows() {
        let p = pool();
        let mut s = EndpointScheduler::new(1200);
        let sizes = [
            (1111u16, 9000usize - 28),
            (2222, 1200 - 28),
            (3333, 100 - 28),
        ];
        let depths = [12usize, 32, 64];
        for (i, (sport, size)) in sizes.iter().enumerate() {
            for _ in 0..depths[i] {
                enqueue(&p, &mut s, *sport, *size);
            }
        }
        demote_all(&mut s);
        let mut bytes = [0u64; 3];
        for _ in 0..600 {
            for (i, (sport, size)) in sizes.iter().enumerate() {
                while qlen(&s, *sport) < depths[i] {
                    if !s
                        .enqueue(NET, logical(&p, *sport, *size), Instant::now())
                        .is_accepted()
                    {
                        break;
                    }
                }
            }
            match s.next(Instant::now()) {
                Dequeue::Send(item) => {
                    let l = item.packet.len();
                    let key = SchedFlowKey {
                        net: item.net,
                        flow: item.flow,
                    };
                    s.complete(&key, l, l);
                    let i = sizes
                        .iter()
                        .position(|(sp, _)| *sp == item.flow.sport)
                        .unwrap();
                    bytes[i] += l as u64;
                }
                Dequeue::Empty => panic!("stall with work queued"),
            }
        }
        let total: u64 = bytes.iter().sum();
        for (i, b) in bytes.iter().enumerate() {
            let share = *b as f64 / total as f64;
            assert!(
                (0.22..=0.45).contains(&share),
                "flow {i} share must be ~1/3, got {share:.2} (bytes={bytes:?})"
            );
        }
    }

    #[test]
    fn same_tuple_two_networks_never_merge() {
        // The same 5-tuple in two networks is two flows with independent
        // budgets and FIFOs.
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        let one_len = logical(&p, 1111, 100).len() as u64;
        for _ in 0..5 {
            assert!(
                s.enqueue(NET, logical(&p, 1111, 100), Instant::now())
                    .is_accepted()
            );
            assert!(
                s.enqueue(NET_OTHER, logical(&p, 1111, 100), Instant::now())
                    .is_accepted()
            );
        }
        assert_eq!(s.snapshot().active_flows, 2);
        // Purge one network: the other is untouched.
        s.purge_network(NET, DropReason::NoConnection);
        let snap = s.snapshot();
        assert_eq!(snap.queued_packets, 5);
        assert_eq!(snap.active_flows, 1);
        assert_eq!(snap.drop_packets[DropReason::NoConnection.index()], 5);
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 5);
        assert!(s.snapshot().conserves(10, 10 * one_len));
    }

    #[test]
    fn hard_cap_tail_rejects_newcomer() {
        // No old-head replacement: the arriving packet is shed, the queue
        // keeps its oldest packets.
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        let mut admitted = 0u64;
        let mut offered_bytes = 0u64;
        for i in 0..(ENDPOINT_PACKET_CAP + 64) {
            let pkt = logical(&p, 1000 + (i % 8) as u16, 100);
            offered_bytes += pkt.len() as u64;
            match s.enqueue(NET, pkt, Instant::now()) {
                EnqueueOutcome::Accepted { .. } => admitted += 1,
                EnqueueOutcome::Rejected { reason } => {
                    assert_eq!(reason, DropReason::EndpointPacketCap);
                }
            }
        }
        let snap = s.snapshot();
        assert_eq!(snap.queued_packets, ENDPOINT_PACKET_CAP as u64);
        assert_eq!(snap.drop_packets[DropReason::EndpointPacketCap.index()], 64);
        // Conservation over the whole sequence (offered = delivered +
        // tail-rejected).
        let out = drain_all(&mut s);
        assert_eq!(out.len() as u64, admitted);
        let snap = s.snapshot();
        assert!(snap.conserves(ENDPOINT_PACKET_CAP as u64 + 64, offered_bytes));
        assert_eq!(snap.owned_packets(), 0);
    }

    /// Move every new-list flow to the old/DRR list (backlogged). Used by
    /// tests that recycle served packets back into the queue: a recycled
    /// packet must rejoin the standing queue, not jump it as "new".
    fn demote_new(s: &mut EndpointScheduler) {
        while let Some(k) = s.new_list.pop_front() {
            if let Some(q) = s.flows.get_mut(&k) {
                q.is_new = false;
                q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
                s.old_list.push_back(k);
            }
        }
    }

    #[test]
    fn codel_drops_surface_in_snapshot() {
        // CoDel drops surface in the snapshot exactly once (monotonic).
        let target = Duration::from_millis(2);
        let interval = Duration::from_millis(10);
        let p = pool();
        let mut s = EndpointScheduler::with_params(1536, target, interval);
        let t0 = Instant::now() - interval - Duration::from_millis(5);
        for _ in 0..10 {
            let mut pkt = logical(&p, 1111, 1200);
            pkt.enqueued_at = t0;
            assert!(s.enqueue(NET, pkt, t0).is_accepted());
        }
        demote_all(&mut s);
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut reported = 0u64;
        while Instant::now() < deadline {
            match s.next(Instant::now()) {
                Dequeue::Send(item) => {
                    // Hold as in-flight (worker stalled on transport), then
                    // return the packet to the queue through a fresh enqueue
                    // with the ORIGINAL timestamp (CoDel sojourn preserved).
                    let enq = item.packet.enqueued_at;
                    let pkt = item.packet;
                    assert!(s.enqueue(NET, pkt, enq).is_accepted());
                    demote_new(&mut s);
                }
                Dequeue::Empty => {}
            }
            reported = s.snapshot().drop_packets[DropReason::Codel.index()];
            if reported > 0 {
                break;
            }
        }
        assert!(reported > 0, "CoDel drops must surface in the snapshot");
        // Monotonic: the count never decreases, never double-counts.
        let again = s.snapshot().drop_packets[DropReason::Codel.index()];
        assert!(again >= reported);
    }

    #[test]
    fn per_flow_order_preserved() {
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        for _ in 0..5 {
            enqueue(&p, &mut s, 1111, 100);
        }
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 5);
        assert!(out.windows(2).all(|w| w[0].0 == w[1].0));
        assert!(!s.has_queued_work());
    }

    #[test]
    fn sparse_flow_jumps_bulk_backlog() {
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        for _ in 0..20 {
            enqueue(&p, &mut s, 1111, 1200);
        }
        // Age the bulk flow out of sparsity.
        let bulk_key = {
            let k = *s.new_list.iter().next().unwrap();
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
            s.new_list.clear();
            s.old_list.push_back(k);
            k
        };
        enqueue(&p, &mut s, 2222, 100);
        match s.next(Instant::now()) {
            Dequeue::Send(item) => assert_ne!(item.flow, bulk_key.flow),
            Dequeue::Empty => panic!("expected sparse packet"),
        }
    }

    #[test]
    fn byte_drr_no_starvation() {
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        for sport in [1111u16, 2222] {
            for _ in 0..4 {
                enqueue(&p, &mut s, sport, 1200);
            }
        }
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
        }
        s.new_list.clear();
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            s.old_list.push_back(k);
        }
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 8);
        assert!(out.iter().any(|(f, _)| f.sport == 1111));
        assert!(out.iter().any(|(f, _)| f.sport == 2222));
    }

    #[test]
    fn codel_drops_standing_queue() {
        let target = Duration::from_millis(2);
        let interval = Duration::from_millis(10);
        let p = pool();
        let mut s = EndpointScheduler::with_params(1536, target, interval);
        let t0 = Instant::now() - interval - Duration::from_millis(5);
        for _ in 0..10 {
            let mut pkt = logical(&p, 1111, 1200);
            pkt.enqueued_at = t0;
            assert!(s.enqueue(NET, pkt, t0).is_accepted());
        }
        demote_all(&mut s);
        // Keep the queue standing past the interval: serve + re-enqueue
        // with the original timestamp (sojourn preserved, never reset).
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut codel_drops = 0u64;
        while Instant::now() < deadline {
            match s.next(Instant::now()) {
                Dequeue::Send(item) => {
                    let enq = item.packet.enqueued_at;
                    let pkt = item.packet;
                    let key = SchedFlowKey {
                        net: item.net,
                        flow: item.flow,
                    };
                    let l = pkt.len();
                    s.complete(&key, l, l);
                    let mut rp = pkt;
                    rp.enqueued_at = enq;
                    let _ = s.enqueue(NET, rp, enq);
                    demote_new(&mut s);
                }
                Dequeue::Empty => {}
            }
            codel_drops = s.snapshot().drop_packets[DropReason::Codel.index()];
            if codel_drops > 0 {
                break;
            }
        }
        assert!(codel_drops > 0, "CoDel must drop a standing queue");
        assert_eq!(
            s.snapshot().drop_packets[DropReason::EmergencyCeiling.index()],
            0
        );
    }

    #[test]
    fn emergency_ceiling_is_safety_only() {
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        for _ in 0..8 {
            enqueue(&p, &mut s, 1111, 200);
        }
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 8);
        let snap = s.snapshot();
        assert_eq!(snap.drop_packets[DropReason::EmergencyCeiling.index()], 0);
        assert_eq!(snap.drop_packets[DropReason::Codel.index()], 0);
    }

    #[test]
    fn memory_bounds_enforced_without_scan() {
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        let offered = ENDPOINT_PACKET_CAP + 64;
        let mut admitted = 0u64;
        let mut offered_bytes = 0u64;
        let mut rejected = 0u64;
        for i in 0..offered {
            let pkt = logical(&p, 1000 + (i % 8) as u16, 1400);
            offered_bytes += pkt.len() as u64;
            match s.enqueue(NET, pkt, Instant::now()) {
                EnqueueOutcome::Accepted { .. } => admitted += 1,
                EnqueueOutcome::Rejected { .. } => rejected += 1,
            }
        }
        let snap = s.snapshot();
        assert!(snap.queued_packets as usize <= ENDPOINT_PACKET_CAP);
        assert!(snap.queued_bytes as usize <= ENDPOINT_BYTE_CAP + 1500);
        assert_eq!(admitted + rejected, offered as u64);
        // Offered = retained + tail-rejected (rejections are recorded drops).
        assert!(snap.conserves(offered as u64, offered_bytes));
        // Fresh traffic: no CoDel/emergency drops.
        assert_eq!(snap.drop_packets[DropReason::Codel.index()], 0);
        assert_eq!(snap.drop_packets[DropReason::EmergencyCeiling.index()], 0);
    }

    #[test]
    fn icmp_isolates_from_tcp_bulk() {
        use tunnet_common::packet::LogicalPacket as LP;
        let icmp_raw = {
            let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
                .icmpv4_echo_request(7, 1);
            let mut o = Vec::new();
            b.write(&mut o, &[0; 32]).unwrap();
            o
        };
        let tcp_raw = {
            let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
                .tcp(40000, 443, 1, 1);
            let mut o = Vec::new();
            b.write(&mut o, &[0; 1200]).unwrap();
            o
        };
        let icmp = LP::from_slice(&icmp_raw).unwrap();
        let tcp = LP::from_slice(&tcp_raw).unwrap();
        assert_ne!(icmp.flow, tcp.flow);
        let mut s = EndpointScheduler::new(1536);
        for _ in 0..20 {
            let mut t = LP::from_slice(&tcp_raw).unwrap();
            t.enqueued_at = Instant::now();
            assert!(s.enqueue(NET, t, Instant::now()).is_accepted());
        }
        // Bulk is backlogged (demoted), so the fresh ICMP flow must jump it.
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
        }
        s.new_list.clear();
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            s.old_list.push_back(k);
        }
        assert!(s.enqueue(NET, icmp, Instant::now()).is_accepted());
        match s.next(Instant::now()) {
            Dequeue::Send(item) => assert_ne!(item.flow, tcp.flow),
            Dequeue::Empty => panic!("expected icmp"),
        }
    }

    #[test]
    fn inflight_conservation_across_revoke() {
        // accepted = delivered + dropped + owned across dequeue (in-flight),
        // revoke-purge (queued drops), and inflight discard.
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        let lens: Vec<usize> = (0..6)
            .map(|i| logical(&p, 1111 + i as u16, 200).len())
            .collect();
        for (i, l) in lens.iter().enumerate() {
            let _ = l;
            enqueue(&p, &mut s, 1111 + i as u16, 200);
        }
        let accepted_bytes: u64 = lens.iter().sum::<usize>() as u64;
        // Dequeue two into in-flight; deliver one, hold one.
        let held = match s.next(Instant::now()) {
            Dequeue::Send(item) => {
                let key = SchedFlowKey {
                    net: item.net,
                    flow: item.flow,
                };
                let l = item.packet.len();
                s.complete(&key, l, l);
                match s.next(Instant::now()) {
                    Dequeue::Send(held) => held,
                    Dequeue::Empty => panic!("expected second packet"),
                }
            }
            Dequeue::Empty => panic!("expected packet"),
        };
        assert_eq!(s.snapshot().inflight_packets, 1);
        // Revoke the network: queued drops recorded; worker discards held.
        s.purge_network(NET, DropReason::NoConnection);
        let held_len = held.packet.len();
        let held_key = SchedFlowKey {
            net: held.net,
            flow: held.flow,
        };
        let _ = held_key;
        s.discard_inflight(held_len, DropReason::NoConnection);
        let snap = s.snapshot();
        assert_eq!(snap.owned_packets(), 0);
        assert!(snap.conserves(6, accepted_bytes));
        assert_eq!(snap.sent_packets, 1);
        assert_eq!(snap.dropped_packets(), 5);
    }

    #[test]
    fn reporter_diffs_are_exact_and_single_sourced() {
        // One mutation stream, one reporter: gauge deltas and counter
        // deltas each account every packet exactly once.
        let p = pool();
        let mut s = EndpointScheduler::new(1536);
        let mut r = SchedReporter::new(s.snapshot());
        let lens: Vec<usize> = (0..4).map(|_| logical(&p, 1111, 200).len()).collect();
        for _ in 0..4 {
            enqueue(&p, &mut s, 1111, 200);
        }
        let d = r.diff(s.snapshot());
        assert_eq!(d.dq_packets, 4);
        assert_eq!(d.dq_bytes, lens.iter().sum::<usize>() as i64);
        assert_eq!(d.dq_flows, 1);
        assert_eq!(d.sent_packets, 0);
        // Deliver one.
        let item = match s.next(Instant::now()) {
            Dequeue::Send(item) => item,
            Dequeue::Empty => panic!("expected"),
        };
        let d = r.diff(s.snapshot());
        assert_eq!(d.dq_packets, -1);
        assert_eq!(d.dq_inflight_packets, 1);
        let l = item.packet.len();
        s.complete(
            &SchedFlowKey {
                net: item.net,
                flow: item.flow,
            },
            l,
            l,
        );
        let d = r.diff(s.snapshot());
        assert_eq!(d.dq_inflight_packets, -1);
        assert_eq!(d.sent_packets, 1);
        assert_eq!(d.sent_bytes, l as u64);
        // Purge the rest: drops surface with packets AND bytes.
        s.purge_all(DropReason::NoConnection);
        let d = r.diff(s.snapshot());
        assert_eq!(d.dq_packets, -3);
        assert_eq!(d.drop_packets[DropReason::NoConnection.index()], 3);
        assert_eq!(
            d.drop_bytes[DropReason::NoConnection.index()],
            lens.iter().sum::<usize>() as u64 - l as u64
        );
        // Quiet afterwards: no phantom deltas.
        let d = r.diff(s.snapshot());
        assert_eq!(d.dq_packets, 0);
        assert_eq!(d.sent_packets, 0);
        assert_eq!(d.drop_packets, [0; 8]);
    }
}
