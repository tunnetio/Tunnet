//! Bounded deferred-fragment holder for unordered QUIC DATAGRAM delivery.
//!
//! A later IP fragment may arrive before its first fragment — the overlay
//! transport is explicitly unordered. Denying it immediately would turn
//! transport reordering into false policy denies. Instead, when the scoped
//! fragment context is missing, the COMPLETE fragment packet is HELD
//! briefly (bounded); the first fragment's verdict then releases the held
//! packets in offset order or discards them.
//!
//! Rules:
//! - frame decoded/authenticated/network-bound and anti-spoofed BEFORE hold
//!   (the caller does that; this module only defers policy evaluation);
//! - first fragment evaluates normal ACL/firewall with real L4 metadata;
//! - Allow publishes context (inside `check`) and releases followers;
//! - Deny/Reject discards the key's held packets;
//! - expiry without a first fragment fails closed (counted, never staged);
//! - NO IP reassembly: the OS still receives the original fragments.
//!
//! Hard bounds: key cap, per-key packet cap, total byte cap, short TTL,
//! scoped keys (network + direction + fragment identity).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tunnet_common::packet::{FragKey, FragmentTable, Fragmentation, LogicalPacket, PacketMeta};
use tunnet_common::policy::Direction;
use tunnet_core::policy_runtime::PolicyVerdict;
use uuid::Uuid;

/// Max held keys per table (per TUN-reader task / per ingress reader).
pub const DEFERRED_KEY_CAP: usize = 32;
/// Max held packets per fragment key.
pub const DEFERRED_PER_KEY: usize = 4;
/// Max held bytes per table.
pub const DEFERRED_BYTE_CAP: usize = 256 * 1024;
/// A first fragment that takes longer than this never comes: fail closed.
pub const DEFERRED_TTL: Duration = Duration::from_secs(2);

struct HeldPacket {
    meta: PacketMeta,
    packet: LogicalPacket,
    offset: u16,
}

struct KeyEntry {
    queue: VecDeque<HeldPacket>,
    bytes: usize,
    first_seen: Instant,
}

pub struct DeferredFragments {
    keys: HashMap<FragKey, KeyEntry>,
    bytes: usize,
    ttl: Duration,
}

/// Policy evaluation outcome with fragment deferral.
pub enum FragOutcome {
    /// Evaluate-now verdict for this packet.
    Immediate(PolicyVerdict, LogicalPacket),
    /// Held for the first fragment (bounded, counted by the caller as
    /// pending — not a drop; resolves on release or expiry).
    Held,
    /// First-fragment verdict plus released followers in offset order,
    /// each with its own verdict.
    Released(Vec<(PolicyVerdict, LogicalPacket)>),
}

impl DeferredFragments {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            bytes: 0,
            ttl: DEFERRED_TTL,
        }
    }

    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            bytes: 0,
            ttl,
        }
    }

    /// Drop expired holds. Returns the expired packet count (the caller
    /// reports it as an explicit fail-closed drop).
    pub fn sweep(&mut self, now: Instant) -> u64 {
        let ttl = self.ttl;
        let mut expired = 0u64;
        self.keys.retain(|_, e| {
            if now.saturating_duration_since(e.first_seen) >= ttl {
                expired += e.queue.len() as u64;
                self.bytes -= e.bytes;
                false
            } else {
                true
            }
        });
        expired
    }

    #[cfg(test)]
    fn held_keys(&self) -> usize {
        self.keys.len()
    }

    /// Evaluate one packet with unordered-fragment tolerance.
    ///
    /// - Later fragment with context → `Immediate(check)`.
    /// - Later fragment without context → `Held` (bounded; bounds-hit
    ///   falls through to `Immediate(check)` which denies fail-closed).
    /// - First/whole packet → `check` now; an allowed first additionally
    ///   releases held followers in offset order as `Released`; a
    ///   denied/rejected first discards its key's holds.
    ///
    /// Returns the outcome plus expired-hold count for telemetry.
    pub fn eval(
        &mut self,
        net: Uuid,
        direction: Direction,
        meta: PacketMeta,
        packet: LogicalPacket,
        has_context: impl Fn() -> bool,
        check: impl Fn(&PacketMeta) -> PolicyVerdict,
    ) -> (FragOutcome, u64) {
        let now = Instant::now();
        let expired = self.sweep(now);
        if meta.is_later_fragment() {
            if has_context() {
                let verdict = check(&meta);
                return (FragOutcome::Immediate(verdict, packet), expired);
            }
            let Some(key) = FragmentTable::key_for_meta(&meta, net, direction) else {
                // No key (should not happen for later fragments): evaluate
                // now, which denies fail-closed without context.
                let verdict = check(&meta);
                return (FragOutcome::Immediate(verdict, packet), expired);
            };
            let offset = match meta.fragmentation {
                Fragmentation::Later { offset, .. } => offset,
                _ => 0,
            };
            match self.hold(key, meta, packet, offset, now) {
                Ok(()) => (FragOutcome::Held, expired),
                // Bounds hit: fail closed through the normal check (no
                // context → deny) instead of holding unboundedly.
                Err(packet) => {
                    let verdict = check(&meta);
                    (FragOutcome::Immediate(verdict, *packet), expired)
                }
            }
        } else {
            let verdict = check(&meta);
            if !matches!(meta.fragmentation, Fragmentation::First { .. }) {
                return (FragOutcome::Immediate(verdict, packet), expired);
            }
            // First fragment: release or discard the key's held followers.
            let Some(key) = FragmentTable::key_for_meta(&meta, net, direction) else {
                return (FragOutcome::Immediate(verdict, packet), expired);
            };
            match verdict {
                PolicyVerdict::Allow => {
                    let mut out = vec![(PolicyVerdict::Allow, packet)];
                    if let Some(entry) = self.keys.remove(&key) {
                        self.bytes -= entry.bytes;
                        let mut followers: Vec<HeldPacket> = entry.queue.into();
                        followers.sort_by_key(|h| h.offset);
                        for h in followers {
                            let v = check(&h.meta);
                            out.push((v, h.packet));
                        }
                    }
                    (FragOutcome::Released(out), expired)
                }
                _ => {
                    // Denied first poisons the key: discard followers.
                    if let Some(entry) = self.keys.remove(&key) {
                        self.bytes -= entry.bytes;
                    }
                    (FragOutcome::Immediate(verdict, packet), expired)
                }
            }
        }
    }

    /// Hold one later fragment. `Ok` consumes the packet; `Err` returns it
    /// untouched when a bound rejects the hold (fail-closed path). The
    /// error is boxed: `LogicalPacket` is large for a Result variant.
    fn hold(
        &mut self,
        key: FragKey,
        meta: PacketMeta,
        packet: LogicalPacket,
        offset: u16,
        now: Instant,
    ) -> Result<(), Box<LogicalPacket>> {
        let len = packet.len();
        if self.bytes + len > DEFERRED_BYTE_CAP {
            return Err(Box::new(packet));
        }
        if !self.keys.contains_key(&key) && self.keys.len() >= DEFERRED_KEY_CAP {
            return Err(Box::new(packet));
        }
        if self
            .keys
            .get(&key)
            .is_some_and(|e| e.queue.len() >= DEFERRED_PER_KEY)
        {
            return Err(Box::new(packet));
        }
        let entry = self.keys.entry(key).or_insert_with(|| KeyEntry {
            queue: VecDeque::new(),
            bytes: 0,
            first_seen: now,
        });
        entry.bytes += len;
        self.bytes += len;
        entry.queue.push_back(HeldPacket {
            meta,
            packet,
            offset,
        });
        Ok(())
    }
}

impl Default for DeferredFragments {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_raw(src: [u8; 4], dst: [u8; 4], ident: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src, dst, 64).udp(40000, 443);
        let mut o = Vec::new();
        b.write(&mut o, &[0xABu8; 64]).unwrap();
        o[4..6].copy_from_slice(&ident.to_be_bytes());
        o
    }

    /// (first, middle, last) fragments of one datagram, distinct offsets.
    fn frag_trio() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut first = udp_raw([10, 0, 0, 1], [10, 0, 0, 2], 0x1111);
        first[6] |= 0x20; // MF, offset 0
        let mut middle = udp_raw([10, 0, 0, 1], [10, 0, 0, 2], 0x1111);
        middle[6] |= 0x20;
        middle[6] &= 0xE0;
        middle[7] = 8; // offset 64
        let mut last = udp_raw([10, 0, 0, 1], [10, 0, 0, 2], 0x1111);
        last[6] &= 0x1F; // no MF
        last[7] = 16; // offset 128
        (first, middle, last)
    }

    fn logical(raw: Vec<u8>) -> LogicalPacket {
        LogicalPacket::from_vec(raw).expect("valid test packet")
    }

    fn meta_of(raw: &[u8]) -> PacketMeta {
        logical(raw.to_vec()).meta
    }

    const NET_A: Uuid = Uuid::from_u128(0x0a0a);
    const NET_B: Uuid = Uuid::from_u128(0x0b0b);

    fn allow(_: &PacketMeta) -> PolicyVerdict {
        PolicyVerdict::Allow
    }

    fn deny(_: &PacketMeta) -> PolicyVerdict {
        PolicyVerdict::Deny
    }

    #[test]
    fn first_then_later_evaluates() {
        // In-order: first releases (nothing held), later with context
        // evaluates immediately.
        let mut t = DeferredFragments::new();
        let (first, _, _) = frag_trio();
        let (o, e) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&first),
            logical(first),
            || false,
            allow,
        );
        assert_eq!(e, 0);
        match o {
            FragOutcome::Released(items) => assert_eq!(items.len(), 1),
            _ => panic!("first must release itself"),
        }
    }

    #[test]
    fn later_then_first_releases_in_offset_order() {
        // Reordered: later holds, first releases both in offset order.
        let mut t = DeferredFragments::new();
        let (first, middle, last) = frag_trio();
        for raw in [&last, &middle] {
            let (o, _) = t.eval(
                NET_A,
                Direction::Outbound,
                meta_of(raw),
                logical(raw.clone()),
                || false,
                allow,
            );
            assert!(
                matches!(o, FragOutcome::Held),
                "context-less later must hold"
            );
        }
        assert_eq!(t.held_keys(), 1);
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&first),
            logical(first),
            || false,
            allow,
        );
        match o {
            FragOutcome::Released(items) => {
                assert_eq!(items.len(), 3, "first + two followers");
                assert!(items.iter().all(|(v, _)| *v == PolicyVerdict::Allow));
                // Followers in offset order: middle (64) before last (128).
                let offs: Vec<u16> = items[1..]
                    .iter()
                    .map(|(_, p)| match p.meta.fragmentation {
                        Fragmentation::Later { offset, .. } => offset,
                        _ => panic!("follower must be a later fragment"),
                    })
                    .collect();
                assert_eq!(offs, vec![8, 16]);
            }
            _ => panic!("first must release"),
        }
        assert_eq!(t.held_keys(), 0);
    }

    #[test]
    fn denied_first_discards_followers() {
        let mut t = DeferredFragments::new();
        let (first, middle, _) = frag_trio();
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&middle),
            logical(middle),
            || false,
            allow,
        );
        assert!(matches!(o, FragOutcome::Held));
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&first),
            logical(first),
            || false,
            deny,
        );
        match o {
            FragOutcome::Immediate(PolicyVerdict::Deny, _) => {}
            _ => panic!("denied first must evaluate immediately"),
        }
        assert_eq!(t.held_keys(), 0, "followers discarded with the verdict");
    }

    #[test]
    fn missing_first_expires_fail_closed() {
        let mut t = DeferredFragments::with_ttl(Duration::from_millis(50));
        let (_, middle, _) = frag_trio();
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&middle),
            logical(middle),
            || false,
            allow,
        );
        assert!(matches!(o, FragOutcome::Held));
        std::thread::sleep(Duration::from_millis(80));
        let expired = t.sweep(Instant::now());
        assert_eq!(expired, 1, "expiry fails closed with a count");
        assert_eq!(t.held_keys(), 0);
    }

    #[test]
    fn network_a_first_never_matches_network_b_later() {
        let mut t = DeferredFragments::new();
        let (first, middle, _) = frag_trio();
        // B's later holds under B's scope.
        let (o, _) = t.eval(
            NET_B,
            Direction::Outbound,
            meta_of(&middle),
            logical(middle),
            || false,
            allow,
        );
        assert!(matches!(o, FragOutcome::Held));
        // A's first releases only A's (empty) scope.
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&first),
            logical(first),
            || false,
            allow,
        );
        match o {
            FragOutcome::Released(items) => assert_eq!(items.len(), 1),
            _ => panic!("A releases only A"),
        }
        assert_eq!(t.held_keys(), 1, "B's hold survives A's verdict");
    }

    #[test]
    fn inbound_first_never_matches_outbound_later() {
        let mut t = DeferredFragments::new();
        let (first, middle, _) = frag_trio();
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&middle),
            logical(middle),
            || false,
            allow,
        );
        assert!(matches!(o, FragOutcome::Held));
        let (o, _) = t.eval(
            NET_A,
            Direction::Inbound,
            meta_of(&first),
            logical(first),
            || false,
            allow,
        );
        match o {
            FragOutcome::Released(items) => assert_eq!(items.len(), 1),
            _ => panic!("inbound releases only inbound"),
        }
        assert_eq!(t.held_keys(), 1, "outbound hold survives inbound verdict");
    }

    #[test]
    fn bounds_reject_without_consume_or_panic() {
        // Per-key cap: the 5th later fragment for one key cannot hold;
        // it evaluates now (fail-closed deny via the check stub).
        let mut t = DeferredFragments::new();
        let (_, middle, _) = frag_trio();
        for _ in 0..DEFERRED_PER_KEY {
            let (o, _) = t.eval(
                NET_A,
                Direction::Outbound,
                meta_of(&middle),
                logical(middle.clone()),
                || false,
                allow,
            );
            assert!(matches!(o, FragOutcome::Held));
        }
        let (o, _) = t.eval(
            NET_A,
            Direction::Outbound,
            meta_of(&middle),
            logical(middle.clone()),
            || false,
            deny,
        );
        match o {
            FragOutcome::Immediate(PolicyVerdict::Deny, _) => {}
            _ => panic!("bounds-hit must fail closed through check"),
        }
    }
}
