//! Bounded per-peer overlay reassembly (§4).
//!
//! Handles out-of-order/duplicate/missing segments, timeouts, path changes,
//! ID wrap and collisions, malformed indexes, inconsistent lengths, and
//! conflicting duplicates. Never allocates from an untrusted claimed length
//! without validating against hard limits; authentication of the QUIC peer
//! does not grant unlimited memory amplification.
//!
//! A lost segment means the logical packet is eventually discarded — no
//! overlay retransmission (QUIC DATAGRAM semantics preserved; inner TCP
//! recovers).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

use bytes::Bytes;
use tunnet_common::packet::{Frame, MAX_LOGICAL_LEN, MAX_SEGMENTS, SegmentHeader, decode_frame};

/// Maximum concurrent reassemblies per peer.
pub const MAX_ENTRIES_PER_PEER: usize = 32;
/// Maximum bytes held in reassembly per peer.
pub const MAX_BYTES_PER_PEER: usize = 256 * 1024;
/// Hard GLOBAL reassembly budget across all peers (§2.1-5): enforced by
/// atomic reservation, impossible to exceed even with concurrent peers.
/// 4 MiB = 16 fully-loaded peers; beyond that, senders back off via QUIC
/// DATAGRAM drops (inner TCP recovers).
pub const MAX_BYTES_GLOBAL: usize = 4 * 1024 * 1024;
/// Reassembly lifetime: a missing segment kills the packet after this.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyDrop {
    Malformed,
    TooManyEntries,
    OverBytes,
    Timeout,
    Conflict,
    Incomplete,
}

#[derive(Debug)]
pub enum InsertOut {
    /// Logical packet complete (single assembled buffer).
    Complete(Vec<u8>),
    /// Segment stored, waiting for more.
    Pending,
    /// Exact duplicate segment (same bytes): ignored.
    Duplicate,
    /// Dropped with reason (conflict/timeout/caps). Entry removed.
    Dropped(ReassemblyDrop),
}

struct Entry {
    total: u16,
    count: u16,
    segments: Vec<Option<Bytes>>,
    have: usize,
    bytes: usize,
    deadline: Instant,
}

pub struct ReassemblyTable {
    entries: HashMap<u32, Entry>,
    order: VecDeque<u32>,
    bytes: usize,
    global_bytes: Arc<AtomicU64>,
    max_bytes_global: u64,
}

impl ReassemblyTable {
    pub fn new(global_bytes: Arc<AtomicU64>) -> Self {
        Self::with_global_cap(global_bytes, MAX_BYTES_GLOBAL as u64)
    }

    pub fn with_global_cap(global_bytes: Arc<AtomicU64>, max_bytes_global: u64) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            global_bytes,
            max_bytes_global,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Insert a validated segment (decoder already bounds-checked it).
    /// `now` is the observation time (allows deterministic tests).
    pub fn insert(&mut self, h: SegmentHeader, payload: Bytes, now: Instant) -> InsertOut {
        self.expire(now);
        let total = h.total as usize;
        let count = h.count as usize;
        // Defensive re-validation (decoder guarantees, but tables outlive frames).
        if total == 0
            || total > MAX_LOGICAL_LEN
            || !(2..=MAX_SEGMENTS).contains(&count)
            || (h.index as usize) >= count
            || payload.is_empty()
            || payload.len() > total
        {
            return InsertOut::Dropped(ReassemblyDrop::Malformed);
        }
        // ID collision with incompatible shape: drop the old generation and
        // start over (bounded loss, never mixed bytes).
        if let Some(e) = self.entries.get(&h.id)
            && (e.total != h.total || e.count != h.count)
        {
            self.remove(h.id);
            return self.insert(h, payload, now);
        }
        // Admit or fetch the entry, enforcing caps first.
        if !self.entries.contains_key(&h.id) {
            if self.entries.len() >= MAX_ENTRIES_PER_PEER {
                // Evict the oldest to make room (bounded eviction).
                if let Some(old) = self.order.pop_front() {
                    self.remove(old);
                }
            }
            if self.entries.len() >= MAX_ENTRIES_PER_PEER {
                return InsertOut::Dropped(ReassemblyDrop::TooManyEntries);
            }
            let mut segments = Vec::with_capacity(count);
            segments.resize_with(count, || None);
            self.entries.insert(
                h.id,
                Entry {
                    total: h.total,
                    count: h.count,
                    segments,
                    have: 0,
                    bytes: 0,
                    deadline: now + REASSEMBLY_TIMEOUT,
                },
            );
            self.order.push_back(h.id);
        }
        let idx = h.index as usize;
        // Duplicate handling needs no mutation: check first.
        if let Some(existing) = self
            .entries
            .get(&h.id)
            .and_then(|e| e.segments[idx].as_ref())
        {
            // Identical bytes are harmless; conflicting bytes mean someone
            // is rewriting history → drop the whole reassembly.
            if existing.as_ref() == payload.as_ref() {
                return InsertOut::Duplicate;
            }
            self.remove(h.id);
            return InsertOut::Dropped(ReassemblyDrop::Conflict);
        }
        // Byte caps (per-peer + hard global) before retaining.
        // Per-peer first (no shared state touched), then the global atomic
        // reservation (CAS: impossible to exceed, even concurrently).
        if self.bytes + payload.len() > MAX_BYTES_PER_PEER {
            // Try one bounded eviction of the oldest entry, then give up.
            if let Some(old) = self.order.front().cloned()
                && old != h.id
            {
                self.remove(old);
            }
            if self.bytes + payload.len() > MAX_BYTES_PER_PEER {
                return InsertOut::Dropped(ReassemblyDrop::OverBytes);
            }
        }
        if !self.reserve_global(payload.len() as u64) {
            // Global pressure: evict the oldest entry (releases global
            // bytes), then re-check BOTH caps — the eviction may have been
            // a same-peer entry (per-peer changed too) or another shape.
            if let Some(old) = self.order.front().cloned()
                && old != h.id
            {
                self.remove(old);
            }
            if self.bytes + payload.len() > MAX_BYTES_PER_PEER {
                return InsertOut::Dropped(ReassemblyDrop::OverBytes);
            }
            if !self.reserve_global(payload.len() as u64) {
                return InsertOut::Dropped(ReassemblyDrop::OverBytes);
            }
        }
        let entry = self.entries.get_mut(&h.id).expect("admitted");
        entry.bytes += payload.len();
        self.bytes += payload.len();
        // Global bytes were already reserved (CAS) above; removal paths
        // release exactly entry.bytes, so the counter stays exact.
        entry.segments[idx] = Some(payload);
        entry.have += 1;
        if entry.have < count {
            return InsertOut::Pending;
        }
        // Complete: assemble in index order into one bounded buffer.
        let mut out = Vec::with_capacity(total);
        for seg in entry.segments.iter().flatten() {
            out.extend_from_slice(seg);
        }
        // `entry` is dead here; removal below is safe.
        if out.len() != total {
            // Overlapping/gapped indexes or short writes: fail closed.
            self.remove(h.id);
            return InsertOut::Dropped(ReassemblyDrop::Incomplete);
        }
        self.remove(h.id);
        InsertOut::Complete(out)
    }

    /// Feed a raw DATAGRAM through frame decode + insert (convenience for the
    /// inbound path and tests). Singles are returned directly, with their
    /// bound network.
    pub fn feed_datagram(&mut self, data: Bytes, now: Instant) -> FeedOut {
        match decode_frame(&data) {
            Ok(Frame::Single { net, payload: p }) => FeedOut::Single(net, p.to_vec()),
            Ok(Frame::Segment {
                header: h, payload, ..
            }) => {
                // Retain the payload without copying: slice the DATAGRAM.
                let start = data.len() - payload.len();
                let owned = data.slice(start..);
                match self.insert(h, owned, now) {
                    InsertOut::Complete(logical) => FeedOut::Complete(logical),
                    InsertOut::Pending => FeedOut::Pending,
                    InsertOut::Duplicate => FeedOut::Duplicate,
                    InsertOut::Dropped(reason) => FeedOut::Dropped(reason),
                }
            }
            Err(_) => FeedOut::Dropped(ReassemblyDrop::Malformed),
        }
    }

    fn remove(&mut self, id: u32) {
        if let Some(e) = self.entries.remove(&id) {
            self.bytes = self.bytes.saturating_sub(e.bytes);
            self.global_bytes
                .fetch_sub(e.bytes as u64, Ordering::Relaxed);
            self.order.retain(|k| *k != id);
        }
    }

    /// Atomically reserve `n` global bytes (CAS loop via fetch_update).
    /// Returns false without changing anything when the hard cap would be
    /// exceeded. Every successful reservation is paired with exactly one
    /// release in `remove` (which subtracts entry.bytes), so the counter
    /// is exact and the cap is impossible to exceed — even with concurrent
    /// peers racing on the shared counter.
    fn reserve_global(&self, n: u64) -> bool {
        self.global_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                cur.checked_add(n)
                    .filter(|next| *next <= self.max_bytes_global)
                    .map(|_| cur.saturating_add(n))
            })
            .is_ok()
    }

    fn expire(&mut self, now: Instant) {
        // Bounded sweep: entries are capped (32), so a full pass is O(1).
        let mut timed_out = Vec::new();
        for (id, e) in self.entries.iter() {
            if now >= e.deadline {
                timed_out.push(*id);
            }
        }
        for id in timed_out {
            self.remove(id);
        }
    }

    #[cfg(test)]
    fn force_expire_all(&mut self) {
        let ids: Vec<u32> = self.entries.keys().cloned().collect();
        for id in ids {
            self.remove(id);
        }
    }
}

impl Drop for ReassemblyTable {
    /// Release outstanding global reservations (§2.2-4): dropping a table
    /// with pending reassemblies (peer churn) must return its bytes to the
    /// shared budget, or repeated churn would permanently exhaust the cap
    /// with no live reassemblies. Invariant: after all operations,
    /// `global_bytes == sum(bytes of live tables)`.
    fn drop(&mut self) {
        let held = self.bytes;
        self.bytes = 0;
        self.entries.clear();
        self.order.clear();
        self.global_bytes.fetch_sub(held as u64, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub enum FeedOut {
    Single(Uuid, Vec<u8>),
    Complete(Vec<u8>),
    Pending,
    Duplicate,
    Dropped(ReassemblyDrop),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tunnet_common::packet::{SegmentHeader, encode_segment_prefix};

    fn table() -> ReassemblyTable {
        ReassemblyTable::new(Arc::new(AtomicU64::new(0)))
    }

    fn seg(h: SegmentHeader, payload: &[u8]) -> (SegmentHeader, Bytes) {
        (h, Bytes::copy_from_slice(payload))
    }

    fn logical_bytes(n: usize) -> Vec<u8> {
        // Minimal valid IPv4/UDP packet of exactly n bytes.
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut o = Vec::new();
        b.write(&mut o, &vec![0xABu8; n.saturating_sub(28)])
            .unwrap();
        o
    }

    #[test]
    fn out_of_order_round_trip() {
        let mut t = table();
        let total = 3000u16;
        let now = Instant::now();
        // 3 segments of 1000 (last may be short).
        let s0 = vec![1u8; 1000];
        let s1 = vec![2u8; 1000];
        let s2 = vec![3u8; 1000];
        // Arrive 2, 0, 1.
        let (h, p) = seg(
            SegmentHeader {
                id: 9,
                index: 2,
                count: 3,
                total,
            },
            &s2,
        );
        assert!(matches!(t.insert(h, p, now), InsertOut::Pending));
        let (h, p) = seg(
            SegmentHeader {
                id: 9,
                index: 0,
                count: 3,
                total,
            },
            &s0,
        );
        assert!(matches!(t.insert(h, p, now), InsertOut::Pending));
        let (h, p) = seg(
            SegmentHeader {
                id: 9,
                index: 1,
                count: 3,
                total,
            },
            &s1,
        );
        match t.insert(h, p, now) {
            InsertOut::Complete(logical) => {
                assert_eq!(logical.len(), 3000);
                assert_eq!(&logical[..1000], &s0[..]);
                assert_eq!(&logical[1000..2000], &s1[..]);
                assert_eq!(&logical[2000..], &s2[..]);
            }
            other => panic!("expected complete, got {other:?}"),
        }
        assert!(t.is_empty());
    }

    #[test]
    fn duplicates_and_conflicts() {
        let mut t = table();
        let now = Instant::now();
        let (h, p) = seg(
            SegmentHeader {
                id: 1,
                index: 0,
                count: 2,
                total: 200,
            },
            &[5u8; 100],
        );
        assert!(matches!(t.insert(h, p.clone(), now), InsertOut::Pending));
        // Identical duplicate: ignored.
        assert!(matches!(t.insert(h, p, now), InsertOut::Duplicate));
        // Conflicting duplicate: whole reassembly dropped.
        let (h2, p2) = seg(
            SegmentHeader {
                id: 1,
                index: 0,
                count: 2,
                total: 200,
            },
            &[6u8; 100],
        );
        assert!(matches!(
            t.insert(h2, p2, now),
            InsertOut::Dropped(ReassemblyDrop::Conflict)
        ));
        assert!(t.is_empty());
    }

    #[test]
    fn timeout_discards() {
        let mut t = table();
        let now = Instant::now();
        let (h, p) = seg(
            SegmentHeader {
                id: 2,
                index: 0,
                count: 2,
                total: 200,
            },
            &[1u8; 100],
        );
        assert!(matches!(t.insert(h, p, now), InsertOut::Pending));
        // Late second segment past the deadline starts over (old entry gone).
        let late = now + REASSEMBLY_TIMEOUT + Duration::from_millis(10);
        let (h2, p2) = seg(
            SegmentHeader {
                id: 2,
                index: 1,
                count: 2,
                total: 200,
            },
            &[2u8; 100],
        );
        // Old entry expired on insert sweep; index-1 alone cannot complete.
        assert!(matches!(t.insert(h2, p2, late), InsertOut::Pending));
        assert_eq!(t.len(), 1);
        t.force_expire_all();
        assert!(t.is_empty());
    }

    #[test]
    fn id_collision_with_different_shape_restarts() {
        let mut t = table();
        let now = Instant::now();
        let (h, p) = seg(
            SegmentHeader {
                id: 3,
                index: 0,
                count: 2,
                total: 200,
            },
            &[1u8; 100],
        );
        assert!(matches!(t.insert(h, p, now), InsertOut::Pending));
        // Same ID, different shape (wrap/collision): old dropped, new pending.
        let (h2, p2) = seg(
            SegmentHeader {
                id: 3,
                index: 0,
                count: 3,
                total: 300,
            },
            &[1u8; 100],
        );
        assert!(matches!(t.insert(h2, p2, now), InsertOut::Pending));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn caps_bound_memory() {
        let global = Arc::new(AtomicU64::new(0));
        let mut t = ReassemblyTable::with_global_cap(global.clone(), 500);
        let now = Instant::now();
        // Fill per-peer entries to the cap.
        for id in 0..40u32 {
            let (h, p) = seg(
                SegmentHeader {
                    id,
                    index: 0,
                    count: 2,
                    total: 200,
                },
                &[1u8; 100],
            );
            let _ = t.insert(h, p, now);
        }
        assert!(t.len() <= MAX_ENTRIES_PER_PEER);
        // Hard global cap: NEVER exceeded (no intentional overshoot).
        assert!(
            global.load(Ordering::Relaxed) <= 500,
            "global cap is a limit, not telemetry"
        );
    }

    #[test]
    fn global_cap_holds_under_concurrent_peers() {
        // §2.1-5: many peers sharing one counter hammer inserts from
        // threads; the shared counter must never exceed the cap, and every
        // table must respect the per-peer cap.
        use std::sync::Mutex;
        let global = Arc::new(AtomicU64::new(0));
        let tables: Vec<Mutex<ReassemblyTable>> = (0..8)
            .map(|_| Mutex::new(ReassemblyTable::with_global_cap(global.clone(), 4096)))
            .collect();
        let peak = Arc::new(AtomicU64::new(0));
        std::thread::scope(|s| {
            for (pi, table) in tables.iter().enumerate() {
                let peak = peak.clone();
                let global = global.clone();
                s.spawn(move || {
                    let now = Instant::now();
                    for i in 0..200u32 {
                        let id = (pi as u32) * 1000 + (i % 40);
                        let h = SegmentHeader {
                            id,
                            index: (i % 2) as u16,
                            count: 2,
                            total: 200,
                        };
                        let mut payload = vec![0u8; 100];
                        payload[0] = (i & 0xff) as u8;
                        let _ = table.lock().unwrap().insert(h, Bytes::from(payload), now);
                        // Sample the shared counter mid-race.
                        let cur = global.load(Ordering::Relaxed);
                        peak.fetch_max(cur, Ordering::Relaxed);
                        assert!(cur <= 4096, "global cap exceeded under concurrency");
                    }
                });
            }
        });
        assert!(global.load(Ordering::Relaxed) <= 4096);
        assert!(peak.load(Ordering::Relaxed) <= 4096);
        for t in &tables {
            assert!((t.lock().unwrap().bytes() as u64) <= MAX_BYTES_PER_PEER as u64);
        }
    }

    #[test]
    fn malicious_huge_total_rejected() {
        let mut t = table();
        let now = Instant::now();
        // Decoder rejects total > MAX; insert double-checks too.
        let (h, p) = seg(
            SegmentHeader {
                id: 4,
                index: 0,
                count: 2,
                total: 9001,
            },
            &[1u8; 100],
        );
        assert!(matches!(
            t.insert(h, p, now),
            InsertOut::Dropped(ReassemblyDrop::Malformed)
        ));
        assert!(t.is_empty());
    }

    #[test]
    fn feed_single_passthrough() {
        use tunnet_common::packet::{KIND_SINGLE, SINGLE_OVERHEAD};
        let mut t = table();
        let now = Instant::now();
        let net = Uuid::from_u128(0x0e);
        let mut raw = vec![KIND_SINGLE];
        raw.extend_from_slice(net.as_bytes());
        raw.extend_from_slice(&logical_bytes(200));
        match t.feed_datagram(Bytes::from(raw.clone()), now) {
            FeedOut::Single(got_net, v) => {
                assert_eq!(got_net, net);
                assert_eq!(v, raw[SINGLE_OVERHEAD..]);
            }
            other => panic!("expected single, got {other:?}"),
        }
    }

    #[test]
    fn drop_releases_global_reservation() {
        // §2.2-4: dropping a table with pending reassemblies returns its
        // bytes; repeated churn cannot exhaust the cap.
        let global = Arc::new(AtomicU64::new(0));
        {
            let mut t = ReassemblyTable::with_global_cap(global.clone(), 4096);
            let now = Instant::now();
            let (h, p) = seg(
                SegmentHeader {
                    id: 11,
                    index: 0,
                    count: 2,
                    total: 200,
                },
                &[9u8; 100],
            );
            assert!(matches!(t.insert(h, p, now), InsertOut::Pending));
            assert_eq!(global.load(Ordering::Relaxed), 100);
        }
        assert_eq!(global.load(Ordering::Relaxed), 0, "drop must release");
        // Churn stress: create/fill/drop repeatedly, counter returns to 0.
        for round in 0..25u32 {
            let mut t = ReassemblyTable::with_global_cap(global.clone(), 4096);
            let now = Instant::now();
            for id in 0..8u32 {
                let (h, p) = seg(
                    SegmentHeader {
                        id: round * 100 + id,
                        index: 0,
                        count: 2,
                        total: 200,
                    },
                    &[7u8; 100],
                );
                let _ = t.insert(h, p, now);
            }
            drop(t);
            assert_eq!(
                global.load(Ordering::Relaxed),
                0,
                "round {round}: counter must return to zero"
            );
        }
    }

    #[test]
    fn multiple_peers_same_id_isolated() {
        // Tables are per-peer: identical IDs never interact.
        let mut a = table();
        let mut b = table();
        let now = Instant::now();
        let (h, p) = seg(
            SegmentHeader {
                id: 7,
                index: 0,
                count: 2,
                total: 200,
            },
            &[1u8; 100],
        );
        assert!(matches!(a.insert(h, p, now), InsertOut::Pending));
        let (h2, p2) = seg(
            SegmentHeader {
                id: 7,
                index: 1,
                count: 2,
                total: 200,
            },
            &[2u8; 100],
        );
        assert!(matches!(b.insert(h2, p2, now), InsertOut::Pending));
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
    }

    proptest! {
        /// Random segment streams never panic, never exceed caps, and either
        /// complete with exactly `total` bytes or stay bounded.
        #[test]
        fn segment_streams_bounded(
            id in 0..4u32,
            count in 2..5u16,
            total in 128..3000u16,
            idxs in prop::collection::vec(0..5u16, 0..12),
            seed in any::<u64>(),
        ) {
            let mut t = table();
            let now = Instant::now();
            // Deterministic payload per (seed, index) so duplicates are exact.
            for idx in idxs {
                let index = idx % count;
                let h = SegmentHeader { id, index, count, total };
                let plen = if index + 1 < count { 64 } else { 1 };
                let mut pb = vec![0u8; plen.min(total as usize)];
                for (i, b) in pb.iter_mut().enumerate() {
                    *b = (seed.wrapping_add(index as u64).wrapping_add(i as u64) & 0xff) as u8;
                }
                match t.insert(h, Bytes::from(pb), now) {
                    InsertOut::Complete(v) => {
                        prop_assert_eq!(v.len(), total as usize);
                    }
                    InsertOut::Pending | InsertOut::Duplicate | InsertOut::Dropped(_) => {}
                }
                prop_assert!(t.len() <= MAX_ENTRIES_PER_PEER);
                prop_assert!((t.bytes() as u64) <= MAX_BYTES_PER_PEER as u64);
            }
        }
    }

    #[test]
    fn large_mtu_full_pipeline() {
        // §22: a 2800-byte logical packet through planning → segmentation →
        // out-of-order delivery → reassembly → IP parse, with identity intact.
        use tunnet_common::packet::{PacketMeta, parse, segment_count};
        let logical = logical_bytes(2800);
        assert_eq!(logical.len(), 2800);
        let mps = 1350;
        let count = segment_count(2800, mps).expect("segmentable");
        assert!(count > 1);
        let seg_cap = mps - tunnet_common::packet::SEGMENT_OVERHEAD;
        let mut t = table();
        let now = Instant::now();
        let id = 0xABCDu32;
        // Encode segments like the pump does.
        let mut frames: Vec<(SegmentHeader, Bytes)> = Vec::new();
        for i in 0..count {
            let off = i * seg_cap;
            let end = (off + seg_cap).min(2800);
            let h = SegmentHeader {
                id,
                index: i as u16,
                count: count as u16,
                total: 2800,
            };
            frames.push((h, Bytes::copy_from_slice(&logical[off..end])));
        }
        // Deliver in reverse order.
        let mut completed = None;
        for (h, p) in frames.into_iter().rev() {
            match t.insert(h, p, now) {
                InsertOut::Complete(v) => completed = Some(v),
                InsertOut::Pending => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        let out = completed.expect("must complete");
        assert_eq!(out, logical);
        // The reassembled bytes parse as the original IP packet.
        let pkt = parse(&out).unwrap();
        let meta = PacketMeta::from_packet(&pkt);
        assert_eq!(meta.dst_v4, Some(std::net::Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(meta.transport.dst_port(), Some(443));
    }

    #[test]
    fn encode_prefix_shapes_match_decoder() {
        // encode_segment_prefix output must always decode (property bridge).
        use tunnet_common::packet::SEGMENT_OVERHEAD;
        let net = Uuid::from_u128(0x0f);
        let h = SegmentHeader {
            id: 42,
            index: 1,
            count: 4,
            total: 5000,
        };
        let mut buf = [0u8; 128];
        let n = encode_segment_prefix(&mut buf, net, h);
        assert_eq!(n, SEGMENT_OVERHEAD);
        buf[SEGMENT_OVERHEAD..SEGMENT_OVERHEAD + 64].fill(0xCC);
        match tunnet_common::packet::decode_frame(&buf[..SEGMENT_OVERHEAD + 64]) {
            Ok(tunnet_common::packet::Frame::Segment {
                net: got_net,
                header: got,
                ..
            }) => {
                assert_eq!(got_net, net);
                assert_eq!(got, h);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
