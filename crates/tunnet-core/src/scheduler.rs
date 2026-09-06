//! Per-peer FQ-CoDel packet scheduler state (RFC 8290, Tunnet-sized).
//!
//! Pure state machine: no I/O, no transport calls, no metrics registry. The
//! agent pump drives it (`next` → transmit or drop) and reports counters.
//!
//! ```text
//! PeerScheduler
//!   ├─ new flows (sparse/interactive, bounded epoch budget)
//!   ├─ old flows (backlogged, byte-DRR across flows)
//!   ├─ per-flow FIFO (ordering preserved within a flow)
//!   ├─ per-flow CoDel state (first_above_time/dropping/drop_next/count)
//!   └─ byte caps + emergency sojourn ceiling (safety bound only)
//! ```
//!
//! Complexity: dequeue performs rotation rounds over old flows (one
//! quantum per flow per round); rounds repeat immediately only while no
//! flow could send, bounded by [`MAX_DRR_ROUNDS`]. No linear scans for
//! drops, no per-packet allocation on the dequeue path.
//!
//! The scheduler queues LOGICAL packets (§7): one inner packet is one
//! scheduling object. Segmentation happens after dequeue; the pump reports
//! each logical packet ONCE at completion via
//! [`PeerScheduler::account_sent`] with `(logical_len, total_wire_len)` so
//! fairness reflects transmitted bytes including framing overhead (and
//! segmented traffic is never double-charged).
//!
//! `Empty` means genuinely no schedulable work: rounds repeat immediately
//! inside the call, so a flow whose head exceeds one quantum is served
//! after enough rounds — never deferred to a 50 ms pump sleep. Service is
//! proper byte-DRR: each visit grants one quantum and serves every
//! affordable head as a burst, so a 9000-byte flow and a 100-byte flow
//! receive equal byte shares over time, not equal packet counts.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tunnet_common::packet::{FlowKey, LogicalPacket};

/// CoDel target: minimum sojourn indicating a standing queue (~5 ms baseline;
/// consider serialization time on slow links per RFC 8290 §4.2).
pub const CODEL_TARGET: Duration = Duration::from_millis(5);
/// CoDel interval: standing-queue observation window.
pub const CODEL_INTERVAL: Duration = Duration::from_millis(100);
/// Emergency maximum queue lifetime: hard safety bound only, not the AQM.
pub const EMERGENCY_CEILING: Duration = Duration::from_millis(1000);
/// Total queued bytes per peer (queueing budget shared with transport).
pub const PEER_BYTE_CAP: usize = 256 * 1024;
/// Hard packet cap per peer (memory bound for tiny packets).
pub const PEER_PACKET_CAP: usize = 512;
/// Per-flow packet cap default (diagnostic override via
/// `TUNNET_FLOW_PACKET_CAP`, e.g. 64 vs 256 A/B runs). One flow cannot
/// dominate peer memory.
pub const FLOW_PACKET_CAP: usize = 64;

/// Default per-flow packet cap, honoring the diagnostic override.
fn flow_packet_cap_default() -> usize {
    std::env::var("TUNNET_FLOW_PACKET_CAP")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 8)
        .unwrap_or(FLOW_PACKET_CAP)
}
/// New flows stay "sparse" until they send this many bytes.
pub const NEW_FLOW_BYTE_BUDGET: usize = 16 * 1024;
/// Sparse flow sojourn bar: heads older than this are not "interactive".
pub const SPARSE_SOJOURN_BAR: Duration = Duration::from_millis(25);
/// Cap-pressure probe bound (flows inspected per enqueue tdrops).
pub const CAP_PROBE_BOUND: usize = 4;
/// Upper bound on immediate DRR rounds inside one `next()` call (§2.2-3).
/// One quantum (≥512 B) per round per flow; worst-case deficit gap is one
/// max head plus accumulated wire overshoot (~19 KB ⇒ ≤37 rounds). 64 is a
/// safe deterministic margin; typical calls send on the first round.
pub const MAX_DRR_ROUNDS: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    PeerByteCap,
    PeerPacketCap,
    FlowCap,
    Codel,
    EmergencyCeiling,
    TooLarge,
    NoConnection,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerByteCap => "sched_peer_bytes",
            Self::PeerPacketCap => "sched_peer_packets",
            Self::FlowCap => "sched_flow_cap",
            Self::Codel => "sched_codel",
            Self::EmergencyCeiling => "sched_emergency",
            Self::TooLarge => "datagram_too_large",
            Self::NoConnection => "no_connection",
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
    fn new(now: Instant) -> Self {
        let _ = now;
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

/// Scheduler counters reported to telemetry (deltas applied by the pump).
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedCounters {
    pub enqueued: u64,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub wire_bytes: u64,
    pub drops_codel: u64,
    pub drops_cap: u64,
    pub drops_emergency: u64,
    pub transport_full: u64,
}

/// Sojourn observation for histogram telemetry (filled by dequeue).
#[derive(Debug, Clone, Copy)]
pub struct SojournSample {
    pub sojourn: Duration,
}

/// One DRR service opportunity: every queued packet the visited flow could
/// afford with its deficit (§2.2-3). Non-empty by construction. Classic DRR
/// serves a flow's eligible packets together — this is what makes byte
/// shares fair when packet sizes differ wildly (a 9000 B flow and a 100 B
/// flow each receive ~one quantum of service per visit, not one packet).
pub struct DequeueBurst {
    pub packets: Vec<(Box<LogicalPacket>, SojournSample)>,
}

/// Dequeue decision returned to the pump.
pub enum Dequeue {
    /// Transmit this burst (all packets, in order). Boxed: a burst is
    /// heap-sized and Empty is unit-sized.
    Send(Box<DequeueBurst>),
    /// Scheduler empty.
    Empty,
}

/// Per-peer FQ-CoDel scheduler. Not thread-safe; owned by the peer's pump
/// (either behind the fast-state lock or by a single pump task).
pub struct PeerScheduler {
    flows: HashMap<FlowKey, FlowQueue>,
    /// New (sparse) flows first, oldest-first.
    new_list: VecDeque<FlowKey>,
    /// Backlogged flows in DRR order.
    old_list: VecDeque<FlowKey>,
    bytes: usize,
    packets: usize,
    quantum: usize,
    /// Per-flow packet cap (diagnostic override via TUNNET_FLOW_PACKET_CAP).
    flow_packet_cap: usize,
    target: Duration,
    interval: Duration,
    counters: SchedCounters,
    /// Baselines for [`Self::drain_drops`]: cumulative counters already
    /// reported to telemetry (codel, emergency). Split across however many
    /// threads drain — the sum stays exact, never double-counted.
    reported_codel: u64,
    reported_emergency: u64,
}

/// Enqueue decision. EVERY shed or evicted packet is reported here — there
/// are no invisible drops: the caller reconciles gauges and telemetry for
/// both the admitted packet and any evicted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Admitted (gauges: +1 packet, +len bytes).
    Accepted,
    /// Admitted, but an older packet was evicted to make room (gauges: +1
    /// packet/+len for the newcomer AND -1/-evicted_len for the victim;
    /// report `reason` to telemetry).
    AcceptedEvicted {
        reason: DropReason,
        evicted_len: usize,
    },
    /// Shed (report `reason` to telemetry; gauges untouched).
    Rejected { reason: DropReason },
}

impl EnqueueOutcome {
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedEvicted { .. })
    }
}

/// CoDel/emergency drops since the last drain (see [`Self::drain_drops`]).
/// Cap-pressure sheds are reported at the enqueue decision site instead
/// (see [`EnqueueOutcome`]), so the two paths never double-count.
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedDropDeltas {
    pub codel: u64,
    pub emergency: u64,
}

impl SchedDropDeltas {
    pub fn is_empty(self) -> bool {
        self.codel == 0 && self.emergency == 0
    }
}

impl PeerScheduler {
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
            bytes: 0,
            packets: 0,
            quantum: quantum.max(512),
            flow_packet_cap: flow_packet_cap_default(),
            target,
            interval: interval.max(Duration::from_millis(1)),
            counters: SchedCounters::default(),
            reported_codel: 0,
            reported_emergency: 0,
        }
    }

    pub fn set_quantum(&mut self, quantum: usize) {
        self.quantum = quantum.max(512);
    }

    /// Override the per-flow packet cap (diagnostic A/B only).
    pub fn set_flow_packet_cap(&mut self, cap: usize) {
        self.flow_packet_cap = cap.max(8);
    }

    pub fn levels(&self) -> (u64, u64, u64) {
        (
            self.packets as u64,
            self.bytes as u64,
            self.flows.len() as u64,
        )
    }

    pub fn counters(&self) -> SchedCounters {
        self.counters
    }

    /// Take unreported CoDel/emergency drops since the last drain (for
    /// telemetry; call after `next()` batches and after enqueues). Safe to
    /// call from multiple threads sharing the scheduler lock: deltas are
    /// partitioned, the sum stays exact.
    pub fn drain_drops(&mut self) -> SchedDropDeltas {
        let out = SchedDropDeltas {
            codel: self.counters.drops_codel - self.reported_codel,
            emergency: self.counters.drops_emergency - self.reported_emergency,
        };
        self.reported_codel = self.counters.drops_codel;
        self.reported_emergency = self.counters.drops_emergency;
        out
    }

    pub fn is_empty(&self) -> bool {
        self.packets == 0
    }

    /// Drop all queued packets (teardown ownership change). Returns the
    /// dropped (packets, bytes, flows) for gauge reconciliation.
    pub fn clear(&mut self) -> (u64, u64, u64) {
        let out = (
            self.packets as u64,
            self.bytes as u64,
            self.flows.len() as u64,
        );
        self.flows.clear();
        self.new_list.clear();
        self.old_list.clear();
        self.bytes = 0;
        self.packets = 0;
        out
    }

    /// Enqueue a logical packet. The outcome reports EVERYTHING: admission,
    /// eviction (with the victim's length for gauge reconciliation), or
    /// rejection with its reason. Callers must reconcile gauges and report
    /// telemetry for evictions/rejections — no invisible drops.
    /// `now` should be the packet's observation time (usually Instant::now()).
    pub fn enqueue(&mut self, packet: LogicalPacket, now: Instant) -> EnqueueOutcome {
        let flow = packet.flow;
        let len = packet.len();
        // Memory bounds first: probe a bounded number of flows for an
        // over-ceiling head to evict; otherwise shed the newcomer (tail drop
        // keeps the work O(1) instead of scanning all flows).
        if self.packets >= PEER_PACKET_CAP || self.bytes + len > PEER_BYTE_CAP {
            if !self.evict_one(now) && self.packets >= PEER_PACKET_CAP {
                self.counters.drops_cap += 1;
                return EnqueueOutcome::Rejected {
                    reason: DropReason::PeerPacketCap,
                };
            }
            if self.bytes + len > PEER_BYTE_CAP {
                self.counters.drops_cap += 1;
                return EnqueueOutcome::Rejected {
                    reason: if self.packets >= PEER_PACKET_CAP {
                        DropReason::PeerPacketCap
                    } else {
                        DropReason::PeerByteCap
                    },
                };
            }
        }
        let is_new_flow = !self.flows.contains_key(&flow);
        let flow_cap = self.flow_packet_cap;
        let q = self
            .flows
            .entry(flow)
            .or_insert_with(|| FlowQueue::new(now));
        if q.packets.len() >= flow_cap {
            // Per-flow cap: drop the flow's own stalest head (tail stays
            // fresh: retransmits and sparse signals survive). REPORTED via
            // the outcome (with victim length) — never silent.
            if let Some(old) = q.packets.pop_front() {
                let evicted_len = old.len;
                q.bytes -= evicted_len;
                self.bytes -= evicted_len;
                self.packets -= 1;
                self.counters.drops_cap += 1;
                q.bytes += len;
                q.packets.push_back(QueuedPacket { packet, len });
                self.bytes += len;
                self.packets += 1;
                self.counters.enqueued += 1;
                if is_new_flow && !self.new_list.contains(&flow) && !self.old_list.contains(&flow) {
                    self.new_list.push_back(flow);
                }
                return EnqueueOutcome::AcceptedEvicted {
                    reason: DropReason::FlowCap,
                    evicted_len,
                };
            }
            self.counters.drops_cap += 1;
            return EnqueueOutcome::Rejected {
                reason: DropReason::FlowCap,
            };
        }
        q.bytes += len;
        q.packets.push_back(QueuedPacket { packet, len });
        self.bytes += len;
        self.packets += 1;
        self.counters.enqueued += 1;
        if is_new_flow && !self.new_list.contains(&flow) && !self.old_list.contains(&flow) {
            self.new_list.push_back(flow);
        }
        EnqueueOutcome::Accepted
    }

    /// Bounded cap-pressure eviction: inspect at most CAP_PROBE_BOUND flows
    /// (round-robin from the old list, then new list) for an emergency head.
    /// Returns true when something was evicted.
    fn evict_one(&mut self, now: Instant) -> bool {
        for _ in 0..CAP_PROBE_BOUND {
            let key = if let Some(k) = self.old_list.pop_front() {
                k
            } else if let Some(k) = self.new_list.pop_front() {
                k
            } else {
                return false;
            };
            let evicted = match self.flows.get_mut(&key) {
                Some(q) => match q.packets.front() {
                    Some(h)
                        if now.saturating_duration_since(h.packet.enqueued_at)
                            > EMERGENCY_CEILING =>
                    {
                        let old = q.packets.pop_front().expect("head");
                        q.bytes -= old.len;
                        self.bytes -= old.len;
                        self.packets -= 1;
                        self.counters.drops_emergency += 1;
                        true
                    }
                    Some(_) => {
                        // Not evictable: rotate to the back and keep probing.
                        if q.is_new {
                            self.new_list.push_back(key);
                        } else {
                            self.old_list.push_back(key);
                        }
                        false
                    }
                    None => false,
                },
                None => false,
            };
            if evicted {
                // Keep a non-empty flow scheduled.
                if let Some(q) = self.flows.get(&key) {
                    if !q.packets.is_empty() {
                        if q.is_new {
                            self.new_list.push_front(key);
                        } else {
                            self.old_list.push_front(key);
                        }
                    } else {
                        self.flows.remove(&key);
                    }
                }
                return true;
            }
        }
        false
    }

    /// Dequeue the next service opportunity: sparse flows first (one
    /// packet: bounded epoch budget, young head), else proper byte-DRR
    /// across old flows with per-flow CoDel standing-queue control.
    ///
    /// DRR discipline (§2.2-3): each visit grants the flow exactly ONE
    /// quantum; the flow serves every head packet it can afford (burst);
    /// unaffordable heads rotate for a later round. Rounds repeat
    /// immediately — no `Empty`, no sleep — until some flow sends, drops,
    /// or retires. `Empty` is returned ONLY when no schedulable work
    /// remains. Each round strictly grows deficits or shrinks the queue,
    /// and rounds are hard-bounded, so the loop terminates.
    pub fn next(&mut self, now: Instant) -> Dequeue {
        // 1) Sparse/new flows: single packet (interactive latency first).
        // Drain Gone heads; one Demote breaks to DRR.
        while let Some(key) = self.new_list.pop_front() {
            match self.serve_sparse(key, now) {
                SparseOut::Send(packet, sample) => {
                    return Dequeue::Send(Box::new(DequeueBurst {
                        packets: vec![(packet, sample)],
                    }));
                }
                SparseOut::Gone => continue,
                SparseOut::Demoted => break,
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
            let mut burst: Option<DequeueBurst> = None;
            for _ in 0..n {
                let Some(key) = self.old_list.pop_front() else {
                    break;
                };
                match self.serve_old(key, now) {
                    OldOut::Send(b) => {
                        if self.flows.get(&key).is_some_and(|q| !q.packets.is_empty()) {
                            self.old_list.push_back(key);
                        }
                        burst = Some(b);
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
            if let Some(b) = burst {
                return Dequeue::Send(Box::new(b));
            }
            // No send this round: every visit either dropped a packet
            // (CoDel/emergency, strictly reducing queued packets) or
            // retired a flow/stale key (strictly shrinking the list) or
            // rotated an unaffordable head (deficit grew by one quantum).
            // Loop for another immediate round — never Empty with work.
        }
        // Unreachable safety: the deficit gap is bounded (~19 KB worst
        // case ⇒ ≤37 rounds at minimum quantum), so 64 rounds always
        // serve or drain. Never hang the pump.
        debug_assert!(false, "scheduler DRR round bound exhausted");
        Dequeue::Empty
    }

    /// Requeue a packet at its flow head (transport-full: retry later without
    /// losing order). Restores both flow and global accounting so a
    /// dequeue→requeue cycle is a no-op on the books. Counts a
    /// transport-full event for backoff telemetry.
    pub fn requeue_head(&mut self, flow: FlowKey, packet: LogicalPacket) {
        let len = packet.len();
        match self.flows.get_mut(&flow) {
            Some(q) => {
                q.bytes += len;
                q.packets.push_front(QueuedPacket { packet, len });
            }
            None => {
                let mut q = FlowQueue::new(Instant::now());
                q.bytes = len;
                q.packets.push_front(QueuedPacket { packet, len });
                self.flows.insert(flow, q);
                self.old_list.push_front(flow);
            }
        }
        self.bytes += len;
        self.packets += 1;
        self.counters.transport_full += 1;
    }

    /// Account one COMPLETED logical packet (logical + total wire bytes).
    /// Called exactly once per logical packet when transmission finishes —
    /// never per segment — so segmented traffic is charged once: the
    /// dequeue already debited the logical length from DRR deficit, and
    /// only the wire overhead beyond it leans future rounds here.
    pub fn account_sent(&mut self, flow: FlowKey, logical_len: usize, wire_len: usize) {
        self.counters.sent_packets += 1;
        self.counters.sent_bytes += logical_len as u64;
        self.counters.wire_bytes += wire_len as u64;
        if let Some(q) = self.flows.get_mut(&flow) {
            // Extra wire overhead beyond the DRR deficit debit leans future
            // rounds slightly against overhead-heavy flows.
            let overhead = wire_len.saturating_sub(logical_len);
            q.deficit -= overhead as isize;
        }
    }

    fn remove_flow(&mut self, key: &FlowKey) {
        self.flows.remove(key);
        self.new_list.retain(|k| k != key);
        self.old_list.retain(|k| k != key);
    }

    fn serve_sparse(&mut self, key: FlowKey, now: Instant) -> SparseOut {
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
                    self.counters.drops_emergency += 1;
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
                let sample = SojournSample {
                    sojourn: now.saturating_duration_since(qp.packet.enqueued_at),
                };
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
                SparseOut::Send(Box::new(qp.packet), sample)
            }
        }
    }

    fn serve_old(&mut self, key: FlowKey, now: Instant) -> OldOut {
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
                    self.counters.drops_emergency += 1;
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
                    self.counters.drops_codel += 1;
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
                // Proper DRR (§2.2-3): exactly ONE quantum per visit. Serve
                // every head the flow can afford as one burst; an
                // unaffordable head rotates for a later round (the caller's
                // round loop retries immediately — no Empty, no sleep).
                // Burst bytes are naturally bounded: at most one quantum
                // plus one max head per visit.
                q.deficit += self.quantum as isize;
                let mut burst = DequeueBurst {
                    packets: Vec::new(),
                };
                while let Some(h) = q.packets.front() {
                    let sojourn = now.saturating_duration_since(h.packet.enqueued_at);
                    let head_len = h.len;
                    // Emergency ceiling applies per packet inside bursts too.
                    if sojourn > EMERGENCY_CEILING {
                        let old = q.packets.pop_front().expect("head");
                        q.bytes -= old.len;
                        self.bytes -= old.len;
                        self.packets -= 1;
                        self.counters.drops_emergency += 1;
                        continue;
                    }
                    if (head_len as isize) > q.deficit {
                        break;
                    }
                    let qp = q.packets.pop_front().expect("head");
                    let sample = SojournSample { sojourn };
                    q.bytes -= qp.len;
                    self.bytes -= qp.len;
                    self.packets -= 1;
                    q.deficit -= qp.len as isize;
                    q.epoch_bytes += qp.len;
                    burst.packets.push((Box::new(qp.packet), sample));
                }
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
                if burst.packets.is_empty() {
                    OldOut::Rotate
                } else {
                    OldOut::Send(burst)
                }
            }
        }
    }
}

enum SparseOut {
    Send(Box<LogicalPacket>, SojournSample),
    Gone,
    Demoted,
}

enum OldOut {
    Send(DequeueBurst),
    Rotate,
    Gone,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tunnet_common::packet::PacketPool;

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

    fn drain_all(s: &mut PeerScheduler) -> Vec<(FlowKey, usize)> {
        let mut out = Vec::new();
        let mut guard = 4096;
        while guard > 0 {
            guard -= 1;
            match s.next(Instant::now()) {
                Dequeue::Send(burst) => {
                    for (p, _) in burst.packets {
                        let (f, l) = (p.flow, p.len());
                        s.account_sent(f, l, l);
                        out.push((f, l));
                    }
                }
                Dequeue::Empty => break,
            }
        }
        out
    }

    /// Demote every flow to the old/DRR list, as the pump would.
    fn demote_all(s: &mut PeerScheduler) {
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
        // §2.2-3: logical packets far larger than the DRR quantum (2800 and
        // 9000 byte packets against ~1200-byte MPS-scaled quanta) must be
        // served via immediate internal rounds — Empty means empty, never
        // "needs more rounds", and never a 50 ms pump sleep with work.
        for (size, quantum) in [(2800usize, 1200usize), (9000, 1400), (9000, 512)] {
            let p = pool();
            let mut s = PeerScheduler::new(quantum);
            assert!(
                s.enqueue(logical(&p, 1111, size - 28), Instant::now())
                    .is_accepted()
            );
            demote_all(&mut s);
            let mut empties = 0u32;
            let mut sent = 0u32;
            while !s.is_empty() {
                match s.next(Instant::now()) {
                    Dequeue::Send(burst) => {
                        for (pkt, _) in burst.packets {
                            let (f, l) = (pkt.flow, pkt.len());
                            assert_eq!(l, logical(&p, 1111, size - 28).len());
                            s.account_sent(f, l, l + 12);
                            sent += 1;
                        }
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
        // §2.1-2: one logical packet => exactly one account_sent at
        // completion with (logical, total_wire); segmented traffic must not
        // be double-charged through per-segment calls.
        let p = pool();
        let mut s = PeerScheduler::new(1200);
        let want = logical(&p, 1111, 2800 - 28);
        let (flow, len) = (want.flow, want.len());
        assert!(s.enqueue(want, Instant::now()).is_accepted());
        let (f, l) = match s.next(Instant::now()) {
            Dequeue::Send(burst) => {
                assert_eq!(burst.packets.len(), 1);
                let (pkt, _) = &burst.packets[0];
                (pkt.flow, pkt.len())
            }
            Dequeue::Empty => panic!("expected packet"),
        };
        assert_eq!((f, l), (flow, len));
        // Pump transmits 3 segments then accounts once with total wire.
        let total_wire = l + 3 * 11;
        s.account_sent(f, l, total_wire);
        let c = s.counters();
        assert_eq!(c.sent_packets, 1);
        assert_eq!(c.sent_bytes, len as u64);
        assert_eq!(c.wire_bytes, total_wire as u64);
    }

    /// Queued length of one flow (by sport) for backlog maintenance.
    fn qlen(s: &PeerScheduler, sport: u16) -> usize {
        s.flows
            .iter()
            .filter(|(k, _)| k.sport == sport)
            .map(|(_, q)| q.packets.len())
            .sum()
    }

    /// Continuously-backlogged byte shares for two flows.
    /// Returns (big_bytes, small_bytes) served over `calls` dequeue calls.
    /// Backlogs are TOPPED UP to bounded depths that fit the peer byte cap
    /// together (a blind refill lets the jumbo flow hog the cap and sheds
    /// the small flow's packets, which measures cap hogging, not DRR).
    /// Depths stay >0 so flows never empty/recreate as "new" (which would
    /// measure sparse priority, not DRR).
    fn fairness_ratio(
        big_payload: usize,
        small_payload: usize,
        quantum: usize,
        calls: usize,
    ) -> (u64, u64) {
        let p = pool();
        let mut s = PeerScheduler::new(quantum);
        for _ in 0..12 {
            let _ = s.enqueue(logical(&p, 1111, big_payload), Instant::now());
        }
        for _ in 0..64 {
            let _ = s.enqueue(logical(&p, 2222, small_payload), Instant::now());
        }
        demote_all(&mut s);
        let mut bytes = [0u64; 2];
        for _ in 0..calls {
            while qlen(&s, 1111) < 12 {
                if !s
                    .enqueue(logical(&p, 1111, big_payload), Instant::now())
                    .is_accepted()
                {
                    break;
                }
            }
            while qlen(&s, 2222) < 64 {
                if !s
                    .enqueue(logical(&p, 2222, small_payload), Instant::now())
                    .is_accepted()
                {
                    break;
                }
            }
            match s.next(Instant::now()) {
                Dequeue::Send(burst) => {
                    for (pkt, _) in burst.packets {
                        let (f, l) = (pkt.flow, pkt.len());
                        s.account_sent(f, l, l);
                        if f.sport == 1111 {
                            bytes[0] += l as u64;
                        } else {
                            bytes[1] += l as u64;
                        }
                    }
                }
                Dequeue::Empty => panic!("stall with work queued"),
            }
        }
        (bytes[0], bytes[1])
    }

    #[test]
    fn drr_byte_fairness_jumbo_vs_small() {
        // §2.2-3: 9000 B vs 100 B backlogged flows with a 1200 quantum must
        // split BYTES ~evenly (real DRR), not 90:1 by packet count. Packet-
        // count fairness would give ratio ≈ 90; byte fairness gives ≈ 1.
        let (big, small) = fairness_ratio(9000 - 28, 100 - 28, 1200, 400);
        let ratio = big as f64 / small as f64;
        assert!(
            (0.65..=1.5).contains(&ratio),
            "byte shares must be ~equal, got big={big} small={small} ratio={ratio:.2}"
        );
    }

    #[test]
    fn drr_byte_fairness_matrix() {
        // Same property across size pairs: byte shares, not packet shares.
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
        // Three mixed-size backlogged flows split bytes ~three ways.
        let p = pool();
        let mut s = PeerScheduler::new(1200);
        let sizes = [
            (1111u16, 9000usize - 28),
            (2222, 1200 - 28),
            (3333, 100 - 28),
        ];
        let depths = [12usize, 32, 64];
        for (i, (sport, size)) in sizes.iter().enumerate() {
            for _ in 0..depths[i] {
                let _ = s.enqueue(logical(&p, *sport, *size), Instant::now());
            }
        }
        demote_all(&mut s);
        let mut bytes = [0u64; 3];
        for _ in 0..600 {
            for (i, (sport, size)) in sizes.iter().enumerate() {
                while qlen(&s, *sport) < depths[i] {
                    if !s
                        .enqueue(logical(&p, *sport, *size), Instant::now())
                        .is_accepted()
                    {
                        break;
                    }
                }
            }
            match s.next(Instant::now()) {
                Dequeue::Send(burst) => {
                    for (pkt, _) in burst.packets {
                        let (f, l) = (pkt.flow, pkt.len());
                        s.account_sent(f, l, l);
                        let i = sizes.iter().position(|(sp, _)| *sp == f.sport).unwrap();
                        bytes[i] += l as u64;
                    }
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
    fn eviction_reports_victim_for_gauge_reconcile() {
        // The silent-drop bug: flow-cap eviction used to return None.
        // Now the victim length rides the outcome so gauges stay exact.
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        let one = logical(&p, 1111, 100).len();
        for _ in 0..64 {
            assert!(
                s.enqueue(logical(&p, 1111, 100), Instant::now())
                    .is_accepted()
            );
        }
        match s.enqueue(logical(&p, 1111, 100), Instant::now()) {
            EnqueueOutcome::AcceptedEvicted {
                reason,
                evicted_len,
            } => {
                assert_eq!(reason, DropReason::FlowCap);
                assert_eq!(evicted_len, one);
            }
            other => panic!("expected eviction report, got {other:?}"),
        }
        // Still exactly at cap (evict-one-accept-one is net-zero).
        assert_eq!(s.levels().0 as usize, 64);
        assert_eq!(s.counters().drops_cap, 1);
        // No codel/emergency involved.
        assert!(s.drain_drops().is_empty());
    }

    #[test]
    fn drain_drops_reports_codel_then_quiet() {
        // CoDel drops surface through drain_drops exactly once.
        let target = Duration::from_millis(2);
        let interval = Duration::from_millis(10);
        let p = pool();
        let mut s = PeerScheduler::with_params(1536, target, interval);
        let t0 = Instant::now() - interval - Duration::from_millis(5);
        for _ in 0..10 {
            let mut pkt = logical(&p, 1111, 1200);
            pkt.enqueued_at = t0;
            assert!(s.enqueue(pkt, t0).is_accepted());
        }
        demote_all(&mut s);
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut reported = 0u64;
        while Instant::now() < deadline {
            match s.next(Instant::now()) {
                Dequeue::Send(burst) => {
                    for (pkt, _) in burst.packets.into_iter().rev() {
                        s.requeue_head(pkt.flow, *pkt);
                    }
                }
                Dequeue::Empty => {}
            }
            reported += s.drain_drops().codel;
            if reported > 0 {
                break;
            }
        }
        assert!(reported > 0, "CoDel drops must surface via drain");
        // Second drain is quiet (deltas partition, never double-count).
        assert!(s.drain_drops().is_empty());
    }

    #[test]
    fn per_flow_order_preserved() {
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        for _ in 0..5 {
            assert!(
                s.enqueue(logical(&p, 1111, 100), Instant::now())
                    .is_accepted()
            );
        }
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 5);
        assert!(out.windows(2).all(|w| w[0].0 == w[1].0));
        assert!(s.is_empty());
    }

    #[test]
    fn sparse_flow_jumps_bulk_backlog() {
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        for _ in 0..20 {
            assert!(
                s.enqueue(logical(&p, 1111, 1200), Instant::now())
                    .is_accepted()
            );
        }
        // Age the bulk flow out of sparsity, as the pump would via demotion.
        let bulk_key = {
            let k = *s.new_list.iter().next().unwrap();
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
            s.new_list.clear();
            s.old_list.push_back(k);
            k
        };
        assert!(
            s.enqueue(logical(&p, 2222, 100), Instant::now())
                .is_accepted()
        );
        match s.next(Instant::now()) {
            Dequeue::Send(burst) => assert_ne!(burst.packets[0].0.flow, bulk_key),
            Dequeue::Empty => panic!("expected sparse packet"),
        }
    }

    #[test]
    fn byte_drr_no_starvation() {
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        for sport in [1111u16, 2222] {
            for _ in 0..4 {
                assert!(
                    s.enqueue(logical(&p, sport, 1200), Instant::now())
                        .is_accepted()
                );
            }
        }
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
        }
        // Move both to the old list like the pump would via demotion.
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
        // A persistently backlogged flow with old arrivals must see CoDel
        // drops (not just emergency-ceiling drops) once its sojourn exceeds
        // target for longer than the interval. Custom short timing keeps the
        // test fast while exercising the real control law.
        let target = Duration::from_millis(2);
        let interval = Duration::from_millis(10);
        let p = pool();
        let mut s = PeerScheduler::with_params(1536, target, interval);
        let t0 = Instant::now() - interval - Duration::from_millis(5);
        for _ in 0..10 {
            let mut pkt = logical(&p, 1111, 1200);
            pkt.enqueued_at = t0;
            assert!(s.enqueue(pkt, t0).is_accepted());
        }
        // Demote to old so CoDel (not sparse preference) governs.
        demote_all(&mut s);
        // Keep the queue standing past the interval: serve + requeue.
        // Note: a CoDel drop ends the current drain round (the pump then
        // waits briefly and continues), so Empty does not end the test —
        // only the deadline or an observed drop does.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut codel_drops = 0u64;
        while Instant::now() < deadline {
            match s.next(Instant::now()) {
                Dequeue::Send(burst) => {
                    // Requeue the whole burst to keep the queue standing.
                    for (pkt, _) in burst.packets.into_iter().rev() {
                        s.requeue_head(pkt.flow, *pkt);
                    }
                }
                Dequeue::Empty => {}
            }
            codel_drops = s.counters().drops_codel;
            if codel_drops > 0 {
                break;
            }
        }
        assert!(codel_drops > 0, "CoDel must drop a standing queue");
        assert_eq!(s.counters().drops_emergency, 0);
    }

    #[test]
    fn emergency_ceiling_is_safety_only() {
        // Fresh traffic never hits the emergency path.
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        for _ in 0..8 {
            assert!(
                s.enqueue(logical(&p, 1111, 200), Instant::now())
                    .is_accepted()
            );
        }
        let out = drain_all(&mut s);
        assert_eq!(out.len(), 8);
        assert_eq!(s.counters().drops_emergency, 0);
        assert_eq!(s.counters().drops_codel, 0);
    }

    #[test]
    fn memory_bounds_enforced_without_scan() {
        let p = pool();
        let mut s = PeerScheduler::new(1536);
        let offered = PEER_PACKET_CAP + 64;
        let mut admitted = 0usize;
        let mut evicted_victims = 0usize;
        let mut rejected = 0usize;
        for i in 0..offered {
            match s.enqueue(logical(&p, 1000 + (i % 8) as u16, 1400), Instant::now()) {
                EnqueueOutcome::Accepted => admitted += 1,
                EnqueueOutcome::AcceptedEvicted { .. } => {
                    admitted += 1;
                    evicted_victims += 1;
                }
                EnqueueOutcome::Rejected { .. } => rejected += 1,
            }
        }
        let (packets, bytes, _) = s.levels();
        assert!((packets as usize) <= PEER_PACKET_CAP);
        assert!((bytes as usize) <= PEER_BYTE_CAP + 1500);
        // Packet conservation under the reporting model: every admission
        // is either still retained or was later evicted; every offered
        // packet is retained, rejected, or an evicted victim — each
        // reported exactly once.
        assert_eq!(admitted, (packets as usize) + evicted_victims);
        assert_eq!((packets as usize) + rejected + evicted_victims, offered);
        let c = s.counters();
        assert_eq!(c.drops_cap as usize, rejected + evicted_victims);
        assert_eq!(c.drops_emergency, 0);
        // Fresh traffic: no CoDel/emergency drops to drain.
        assert!(s.drain_drops().is_empty());
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
        let mut s = PeerScheduler::new(1536);
        for _ in 0..20 {
            let mut t = LP::from_slice(&tcp_raw).unwrap();
            t.enqueued_at = Instant::now();
            assert!(s.enqueue(t, Instant::now()).is_accepted());
        }
        // Bulk is backlogged (demoted as the pump would), so the fresh ICMP
        // flow must jump it.
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            let q = s.flows.get_mut(&k).unwrap();
            q.is_new = false;
            q.epoch_bytes = NEW_FLOW_BYTE_BUDGET;
        }
        s.new_list.clear();
        for k in s.flows.keys().cloned().collect::<Vec<_>>() {
            s.old_list.push_back(k);
        }
        assert!(s.enqueue(icmp, Instant::now()).is_accepted());
        match s.next(Instant::now()) {
            Dequeue::Send(burst) => assert_ne!(burst.packets[0].0.flow, tcp.flow),
            Dequeue::Empty => panic!("expected icmp"),
        }
    }

    #[test]
    fn requeue_preserves_order_per_peer() {
        // Transport-full requeue restores the head packet in order, and peer
        // schedulers are fully independent objects (no global HOL).
        let p = pool();
        let mut a = PeerScheduler::new(1536);
        let mut b = PeerScheduler::new(1536);
        for _ in 0..3 {
            assert!(
                a.enqueue(logical(&p, 1111, 100), Instant::now())
                    .is_accepted()
            );
        }
        assert!(
            b.enqueue(logical(&p, 9999, 100), Instant::now())
                .is_accepted()
        );
        // Simulate transport-full on A: dequeue (sparse serves one packet)
        // then requeue the burst.
        let burst = match a.next(Instant::now()) {
            Dequeue::Send(burst) => burst,
            Dequeue::Empty => panic!("expected packet"),
        };
        assert_eq!(burst.packets.len(), 1, "sparse serves one packet");
        for (pkt, _) in burst.packets.into_iter().rev() {
            a.requeue_head(pkt.flow, *pkt);
        }
        // B drains independently (same packet shape, same length).
        let expect_len = logical(&p, 9999, 100).len();
        match b.next(Instant::now()) {
            Dequeue::Send(burst) => assert_eq!(burst.packets[0].0.len(), expect_len),
            Dequeue::Empty => panic!("peer B must be independent of A"),
        }
        // A still holds all 3 packets in order.
        let mut n = 0;
        while !a.is_empty() {
            match a.next(Instant::now()) {
                Dequeue::Send(burst) => n += burst.packets.len() as u32,
                Dequeue::Empty => break,
            }
        }
        assert_eq!(n, 3);
        assert!(a.is_empty());
    }
}
