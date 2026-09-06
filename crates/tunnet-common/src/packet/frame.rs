//! Tunnel framing: the only tunnel wire format.
//!
//! A logical (inner IP) packet that fits the current QUIC DATAGRAM payload
//! limit travels as one `Single` frame. Larger logical packets are split into
//! `Segment` frames and reassembled by the peer. Endpoints negotiate
//! `tunnet/tunnel/3` and reject anything else; there is no legacy decoder.
//!
//! Every frame carries the full `NetworkId` it belongs to (§2.2-1): the
//! receiver binds each logical packet to exactly one authenticated network
//! membership, even for out-of-order segments, with no negotiation
//! handshake and no per-connection channel tables. 16 bytes per frame is
//! the deliberate price for unambiguous binding.
//!
//! Layout (all integers little-endian, minimal overhead):
//!
//! ```text
//! Single:  [0x30][net_id 16B][logical packet bytes...]          (17 bytes overhead)
//! Segment: [0x31][net_id 16B][id u32][index u16][count u16][total u16][payload]
//!                                                          (27 bytes overhead)
//! ```
//!
//! Kinds `0x32..=0x3F` are reserved for future extensions (e.g. GSO-aware
//! frames); the version nibble `0x3_` leaves `0x4_`.. for future wire versions.
//! The old `0x20`/`0x21` kinds decode as `UnknownKind` (fail fast on wire
//! mismatch, never misparse). Decoder properties: fixed/cheap header parse,
//! no allocation to decode a header, malformed frames rejected before
//! allocation, no integer overflow (checked arithmetic throughout), no
//! ambiguous encodings, deterministic encoding, fuzzable decoder.

use super::owned::MAX_LOGICAL_LEN;
use uuid::Uuid;

/// Maximum segments per logical packet (9000 B / ~1200 B MPS ≈ 8; headroom 2×).
pub const MAX_SEGMENTS: usize = 16;
/// Minimum useful segment payload (pathological tiny segments rejected).
pub const MIN_SEGMENT_PAYLOAD: usize = 64;
/// Full NetworkId discriminator in every frame (§2.2-1).
pub const NET_ID_LEN: usize = 16;

pub const KIND_SINGLE: u8 = 0x30;
pub const KIND_SEGMENT: u8 = 0x31;
const KIND_RESERVED_MAX: u8 = 0x3F;
const KIND_NIBBLE: u8 = 0x30;
const SEG_HEADER_LEN: usize = 1 + NET_ID_LEN + 4 + 2 + 2 + 2;
const SINGLE_HEADER_LEN: usize = 1 + NET_ID_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub id: u32,
    pub index: u16,
    pub count: u16,
    pub total: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Single {
        net: Uuid,
        payload: &'a [u8],
    },
    Segment {
        net: Uuid,
        header: SegmentHeader,
        payload: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Empty,
    UnknownKind(u8),
    ReservedKind(u8),
    TruncatedHeader,
    TruncatedPayload,
    EmptyPayload,
    BadCount,
    BadIndex,
    BadTotal,
    SingleSegment,
    OversizeSegment,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// Decode a tunnel frame header + payload borrows. No allocation.
/// Returns the bound network alongside the frame: the caller MUST resolve
/// the (endpoint, network) membership and authenticate it — never deliver
/// a frame to whichever membership was resolved last.
pub fn decode_frame(data: &[u8]) -> Result<Frame<'_>, DecodeError> {
    let Some((&kind, rest)) = data.split_first() else {
        return Err(DecodeError::Empty);
    };
    match kind {
        KIND_SINGLE => {
            if rest.len() < NET_ID_LEN {
                return Err(DecodeError::TruncatedHeader);
            }
            let net = Uuid::from_bytes(rest[..NET_ID_LEN].try_into().expect("len"));
            let payload = &rest[NET_ID_LEN..];
            if payload.is_empty() {
                return Err(DecodeError::EmptyPayload);
            }
            if payload.len() > MAX_LOGICAL_LEN {
                return Err(DecodeError::BadTotal);
            }
            Ok(Frame::Single { net, payload })
        }
        KIND_SEGMENT => {
            if rest.len() < SEG_HEADER_LEN - 1 {
                return Err(DecodeError::TruncatedHeader);
            }
            let net = Uuid::from_bytes(rest[..NET_ID_LEN].try_into().expect("len"));
            let h = &rest[NET_ID_LEN..];
            let id = u32::from_le_bytes(h[0..4].try_into().expect("len"));
            let index = u16::from_le_bytes(h[4..6].try_into().expect("len"));
            let count = u16::from_le_bytes(h[6..8].try_into().expect("len"));
            let total = u16::from_le_bytes(h[8..10].try_into().expect("len"));
            let payload = &h[10..];
            if count < 2 || (count as usize) > MAX_SEGMENTS {
                return Err(DecodeError::BadCount);
            }
            if index >= count {
                return Err(DecodeError::BadIndex);
            }
            if total == 0 || (total as usize) > MAX_LOGICAL_LEN {
                return Err(DecodeError::BadTotal);
            }
            if payload.is_empty() {
                return Err(DecodeError::EmptyPayload);
            }
            // Last segment may be short; non-last segments must carry a
            // meaningful payload (prevents index/count smuggling games).
            if index + 1 < count && payload.len() < MIN_SEGMENT_PAYLOAD {
                return Err(DecodeError::TruncatedPayload);
            }
            // A segment can never carry more than the whole logical packet.
            // (Non-last segments are sized by the sender's path MPS, which
            // the decoder cannot know; the reassembly layer additionally
            // caps count × total per peer, so no allocation amplification.)
            if payload.len() > total as usize {
                return Err(DecodeError::OversizeSegment);
            }
            if payload.len() > MAX_LOGICAL_LEN {
                return Err(DecodeError::OversizeSegment);
            }
            Ok(Frame::Segment {
                net,
                header: SegmentHeader {
                    id,
                    index,
                    count,
                    total,
                },
                payload,
            })
        }
        k if (k & 0xF0) == KIND_NIBBLE && k <= KIND_RESERVED_MAX => {
            Err(DecodeError::ReservedKind(k))
        }
        k => Err(DecodeError::UnknownKind(k)),
    }
}

/// Encode a single frame header ([kind][net]) into `out[..17]`. Returns 17.
pub fn encode_single_prefix(out: &mut [u8], net: Uuid) -> usize {
    out[0] = KIND_SINGLE;
    out[1..SINGLE_HEADER_LEN].copy_from_slice(net.as_bytes());
    SINGLE_HEADER_LEN
}

/// Encode a 27-byte segment header into `out[..27]`. Returns 27.
pub fn encode_segment_prefix(out: &mut [u8], net: Uuid, h: SegmentHeader) -> usize {
    out[0] = KIND_SEGMENT;
    out[1..1 + NET_ID_LEN].copy_from_slice(net.as_bytes());
    let b = 1 + NET_ID_LEN;
    out[b..b + 4].copy_from_slice(&h.id.to_le_bytes());
    out[b + 4..b + 6].copy_from_slice(&h.index.to_le_bytes());
    out[b + 6..b + 8].copy_from_slice(&h.count.to_le_bytes());
    out[b + 8..b + 10].copy_from_slice(&h.total.to_le_bytes());
    SEG_HEADER_LEN
}

pub const SINGLE_OVERHEAD: usize = SINGLE_HEADER_LEN;
pub const SEGMENT_OVERHEAD: usize = SEG_HEADER_LEN;

/// Number of segments needed for `logical_len` bytes at `mps` payload bytes
/// per DATAGRAM (accounting framing overhead). None when impossible.
pub fn segment_count(logical_len: usize, mps: usize) -> Option<usize> {
    if logical_len == 0 || logical_len > MAX_LOGICAL_LEN {
        return None;
    }
    let single_cap = mps.checked_sub(SINGLE_OVERHEAD)?;
    if logical_len <= single_cap {
        return Some(1);
    }
    let seg_cap = mps.checked_sub(SEGMENT_OVERHEAD)?;
    if seg_cap < MIN_SEGMENT_PAYLOAD {
        return None;
    }
    Some(logical_len.div_ceil(seg_cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_A: Uuid = Uuid::from_u128(0x0a0a);
    const NET_B: Uuid = Uuid::from_u128(0x0b0b);

    #[test]
    fn single_round_trip() {
        let mut buf = [0u8; 64];
        assert_eq!(encode_single_prefix(&mut buf, NET_A), SINGLE_HEADER_LEN);
        buf[SINGLE_HEADER_LEN..SINGLE_HEADER_LEN + 5].copy_from_slice(b"hello");
        match decode_frame(&buf[..SINGLE_HEADER_LEN + 5]).unwrap() {
            Frame::Single { net, payload } => {
                assert_eq!(net, NET_A);
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected single"),
        }
    }

    #[test]
    fn segment_round_trip() {
        let mut buf = [0u8; 1024];
        let h = SegmentHeader {
            id: 0xdead_beef,
            index: 2,
            count: 5,
            total: 4000,
        };
        assert_eq!(encode_segment_prefix(&mut buf, NET_A, h), SEG_HEADER_LEN);
        // Non-last segments carry full payloads.
        buf[SEG_HEADER_LEN..SEG_HEADER_LEN + 800].fill(0xAB);
        match decode_frame(&buf[..SEG_HEADER_LEN + 800]).unwrap() {
            Frame::Segment {
                net,
                header: got,
                payload: p,
            } => {
                assert_eq!(net, NET_A);
                assert_eq!(got, h);
                assert_eq!(p.len(), 800);
            }
            _ => panic!("expected segment"),
        }
        // Last segment may be short.
        let last = SegmentHeader { index: 4, ..h };
        assert_eq!(encode_segment_prefix(&mut buf, NET_B, last), SEG_HEADER_LEN);
        buf[SEG_HEADER_LEN..SEG_HEADER_LEN + 5].copy_from_slice(b"world");
        match decode_frame(&buf[..SEG_HEADER_LEN + 5]).unwrap() {
            Frame::Segment {
                net,
                header: got,
                payload: p,
            } => {
                assert_eq!(net, NET_B);
                assert_eq!(got, last);
                assert_eq!(p, b"world");
            }
            _ => panic!("expected segment"),
        }
    }

    #[test]
    fn old_wire_kinds_rejected() {
        // Pre-multinetwork kinds fail fast as unknown (never misparsed).
        assert_eq!(
            decode_frame(&[0x20, 1, 2, 3]),
            Err(DecodeError::UnknownKind(0x20))
        );
        assert_eq!(
            decode_frame(&[0x21, 1, 2, 3]),
            Err(DecodeError::UnknownKind(0x21))
        );
    }

    #[test]
    fn rejects_garbage_before_allocation() {
        assert_eq!(decode_frame(&[]), Err(DecodeError::Empty));
        assert_eq!(decode_frame(&[0x99]), Err(DecodeError::UnknownKind(0x99)));
        assert_eq!(decode_frame(&[0x32]), Err(DecodeError::ReservedKind(0x32)));
        assert_eq!(
            decode_frame(&[KIND_SINGLE]),
            Err(DecodeError::TruncatedHeader)
        );
        // Kind + full net but no payload.
        let mut single = vec![KIND_SINGLE];
        single.extend_from_slice(NET_A.as_bytes());
        assert_eq!(decode_frame(&single), Err(DecodeError::EmptyPayload));
        assert_eq!(
            decode_frame(&[KIND_SEGMENT]),
            Err(DecodeError::TruncatedHeader)
        );
        assert_eq!(
            decode_frame(&[KIND_SEGMENT, 1, 2, 3]),
            Err(DecodeError::TruncatedHeader)
        );
        // count < 2
        let mut bad = [0u8; 32];
        encode_segment_prefix(
            &mut bad,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 0,
                count: 1,
                total: 100,
            },
        );
        assert_eq!(decode_frame(&bad[..32]), Err(DecodeError::BadCount));
        // count > MAX
        encode_segment_prefix(
            &mut bad,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 0,
                count: 99,
                total: 100,
            },
        );
        assert_eq!(decode_frame(&bad[..32]), Err(DecodeError::BadCount));
        // index >= count
        encode_segment_prefix(
            &mut bad,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 3,
                count: 3,
                total: 300,
            },
        );
        bad[SEG_HEADER_LEN] = 7;
        assert_eq!(
            decode_frame(&bad[..SEG_HEADER_LEN + 1]),
            Err(DecodeError::BadIndex)
        );
    }

    #[test]
    fn rejects_bad_totals_and_tiny_segments() {
        let mut buf = [0u8; 96];
        // total 0
        encode_segment_prefix(
            &mut buf,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 0,
                count: 2,
                total: 0,
            },
        );
        buf[SEG_HEADER_LEN] = 1;
        assert_eq!(
            decode_frame(&buf[..SEG_HEADER_LEN + 1]),
            Err(DecodeError::BadTotal)
        );
        // total > max
        encode_segment_prefix(
            &mut buf,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 0,
                count: 2,
                total: 9001,
            },
        );
        assert_eq!(
            decode_frame(&buf[..SEG_HEADER_LEN + 1]),
            Err(DecodeError::BadTotal)
        );
        // non-last tiny payload
        encode_segment_prefix(
            &mut buf,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 0,
                count: 3,
                total: 3000,
            },
        );
        buf[SEG_HEADER_LEN] = 1;
        assert_eq!(
            decode_frame(&buf[..SEG_HEADER_LEN + 1]),
            Err(DecodeError::TruncatedPayload)
        );
        // empty payload
        encode_segment_prefix(
            &mut buf,
            NET_A,
            SegmentHeader {
                id: 1,
                index: 2,
                count: 3,
                total: 3000,
            },
        );
        assert_eq!(
            decode_frame(&buf[..SEG_HEADER_LEN]),
            Err(DecodeError::EmptyPayload)
        );
    }

    #[test]
    fn segment_count_boundaries() {
        // exact fit → single (single overhead is now 17)
        assert_eq!(segment_count(1184, 1201), Some(1));
        // one byte over → segmented
        assert_eq!(segment_count(1185, 1201), Some(2));
        assert_eq!(segment_count(0, 1200), None);
        assert_eq!(segment_count(9001, 1500), None);
        // 2800 logical at 1350 MPS: seg cap 1323 → 3 segments
        assert_eq!(segment_count(2800, 1350), Some(3));
        // degenerate MPS
        assert_eq!(segment_count(100, 10), None);
    }

    #[test]
    fn deterministic_encoding() {
        let h = SegmentHeader {
            id: 7,
            index: 1,
            count: 4,
            total: 5000,
        };
        let mut a = [0u8; SEG_HEADER_LEN];
        let mut b = [0u8; SEG_HEADER_LEN];
        encode_segment_prefix(&mut a, NET_A, h);
        encode_segment_prefix(&mut b, NET_A, h);
        assert_eq!(a, b);
        assert_eq!(a[0], KIND_SEGMENT);
        // Network binding participates in the encoding.
        encode_segment_prefix(&mut b, NET_B, h);
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any byte string either decodes deterministically or fails with a
        /// stable error; decoding never panics and never allocates.
        #[test]
        fn decode_never_panics(data in prop::collection::vec(any::<u8>(), 0..64)) {
            let a = decode_frame(&data).map_err(|e| format!("{e:?}"));
            let b = decode_frame(&data).map_err(|e| format!("{e:?}"));
            prop_assert_eq!(a.as_ref().map(|_| ()), b.as_ref().map(|_| ()));
            prop_assert_eq!(a.is_ok(), b.is_ok());
            if let Ok(frame) = a {
                match frame {
                    Frame::Single { payload: p, .. } => {
                        prop_assert!(!p.is_empty() && p.len() <= MAX_LOGICAL_LEN);
                    }
                    Frame::Segment { header: h, payload: p, .. } => {
                        prop_assert!((h.count as usize) >= 2 && (h.count as usize) <= MAX_SEGMENTS);
                        prop_assert!(h.index < h.count);
                        prop_assert!(!p.is_empty() && p.len() <= h.total as usize);
                    }
                }
            }
        }

        /// Encoded segment headers always decode to themselves.
        #[test]
        fn segment_header_round_trip(
            id in any::<u32>(),
            index in 0..16u16,
            count in 2..16u16,
            total in 1..9000u16,
        ) {
            // Non-last segments must carry full payloads, so only test
            // totals that admit them (small totals are covered by unit tests).
            prop_assume!((total as usize) >= (count as usize) * MIN_SEGMENT_PAYLOAD);
            let index = index % count;
            let net = Uuid::from_u128(id as u128);
            let h = SegmentHeader { id, index, count, total };
            let mut buf = [0u8; SEG_HEADER_LEN];
            prop_assert_eq!(encode_segment_prefix(&mut buf, net, h), SEG_HEADER_LEN);
            let payload_len = if index + 1 < count {
                MIN_SEGMENT_PAYLOAD
            } else {
                1usize
            };
            let mut full = vec![0u8; SEG_HEADER_LEN + payload_len];
            full[..SEG_HEADER_LEN].copy_from_slice(&buf);
            for (i, b) in full[SEG_HEADER_LEN..].iter_mut().enumerate() {
                *b = (i & 0xff) as u8;
            }
            match decode_frame(&full) {
                Ok(Frame::Segment {
                    net: got_net,
                    header: got,
                    payload: p,
                }) => {
                    prop_assert_eq!(got_net, net);
                    prop_assert_eq!(got, h);
                    prop_assert_eq!(p.len(), payload_len);
                }
                Ok(Frame::Single { .. }) => prop_assert!(false, "segment must not decode as single"),
                Err(e) => prop_assert!(false, "unexpected decode error: {e:?}"),
            }
        }
    }
}
