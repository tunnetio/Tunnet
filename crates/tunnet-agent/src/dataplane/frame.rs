//! `tunnet/tunnel/2` framing and connection-local overlay reassembly.
//!
//! Every logical IP packet carries an explicit [`Uuid`] network id. Overlay
//! segmentation exists only so one configured TUN packet can cross a smaller
//! current QUIC DATAGRAM size. There is no replay, no resume, and no
//! cross-connection state.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use uuid::Uuid;

pub const TYPE_SINGLE: u8 = 0;
pub const TYPE_SEGMENT: u8 = 1;

pub const SINGLE_HEADER_LEN: usize = 1 + 16;
pub const SEGMENT_HEADER_LEN: usize = 1 + 16 + 4 + 2 + 2 + 2;

pub const REASSEMBLY_TTL: Duration = Duration::from_millis(500);
pub const REASSEMBLY_MAX_ENTRIES: usize = 16;
pub const REASSEMBLY_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Single {
        network_id: Uuid,
        packet: &'a [u8],
    },
    Segment {
        network_id: Uuid,
        packet_id: u32,
        index: u16,
        count: u16,
        total_len: u16,
        payload: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    UnknownType,
    EmptyPacket,
    BadSegment,
}

pub fn decode(buf: &[u8]) -> Result<Frame<'_>, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::Truncated);
    }
    match buf[0] {
        TYPE_SINGLE => {
            if buf.len() < SINGLE_HEADER_LEN {
                return Err(FrameError::Truncated);
            }
            let network_id = uuid_from_slice(&buf[1..17])?;
            let packet = &buf[SINGLE_HEADER_LEN..];
            if packet.is_empty() {
                return Err(FrameError::EmptyPacket);
            }
            Ok(Frame::Single { network_id, packet })
        }
        TYPE_SEGMENT => {
            if buf.len() < SEGMENT_HEADER_LEN {
                return Err(FrameError::Truncated);
            }
            let network_id = uuid_from_slice(&buf[1..17])?;
            let packet_id = u32::from_be_bytes(buf[17..21].try_into().unwrap());
            let index = u16::from_be_bytes(buf[21..23].try_into().unwrap());
            let count = u16::from_be_bytes(buf[23..25].try_into().unwrap());
            let total_len = u16::from_be_bytes(buf[25..27].try_into().unwrap());
            let payload = &buf[SEGMENT_HEADER_LEN..];
            if count == 0 || index >= count || total_len == 0 || payload.is_empty() {
                return Err(FrameError::BadSegment);
            }
            Ok(Frame::Segment {
                network_id,
                packet_id,
                index,
                count,
                total_len,
                payload,
            })
        }
        _ => Err(FrameError::UnknownType),
    }
}

fn uuid_from_slice(bytes: &[u8]) -> Result<Uuid, FrameError> {
    let arr: [u8; 16] = bytes.try_into().map_err(|_| FrameError::Truncated)?;
    Ok(Uuid::from_bytes(arr))
}

pub fn encode_single(network_id: Uuid, packet: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(SINGLE_HEADER_LEN + packet.len());
    out.put_u8(TYPE_SINGLE);
    out.put_slice(network_id.as_bytes());
    out.put_slice(packet);
    out.freeze()
}

pub fn encode_segment(
    network_id: Uuid,
    packet_id: u32,
    index: u16,
    count: u16,
    total_len: u16,
    payload: &[u8],
) -> Bytes {
    let mut out = BytesMut::with_capacity(SEGMENT_HEADER_LEN + payload.len());
    out.put_u8(TYPE_SEGMENT);
    out.put_slice(network_id.as_bytes());
    out.put_u32(packet_id);
    out.put_u16(index);
    out.put_u16(count);
    out.put_u16(total_len);
    out.put_slice(payload);
    out.freeze()
}

/// Encode one logical IP packet into the fewest DATAGRAM frames that fit
/// `max_datagram`. Returns `None` if the packet cannot be represented (max
/// datagram smaller than a segment header, or total length over `u16::MAX`).
pub fn encode_logical(
    network_id: Uuid,
    packet: &[u8],
    max_datagram: usize,
    packet_id: u32,
) -> Option<Vec<Bytes>> {
    if packet.is_empty() {
        return None;
    }
    if packet.len() > u16::MAX as usize {
        return None;
    }
    if SINGLE_HEADER_LEN + packet.len() <= max_datagram {
        return Some(vec![encode_single(network_id, packet)]);
    }
    if max_datagram <= SEGMENT_HEADER_LEN {
        return None;
    }
    let chunk = max_datagram - SEGMENT_HEADER_LEN;
    if chunk == 0 {
        return None;
    }
    let total_len = packet.len() as u16;
    let count = packet.len().div_ceil(chunk);
    if count == 0 || count > u16::MAX as usize {
        return None;
    }
    let count = count as u16;
    let mut frames = Vec::with_capacity(count as usize);
    for index in 0..count {
        let start = index as usize * chunk;
        let end = (start + chunk).min(packet.len());
        frames.push(encode_segment(
            network_id,
            packet_id,
            index,
            count,
            total_len,
            &packet[start..end],
        ));
    }
    Some(frames)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyError {
    Malformed,
    Evicted,
}

pub struct Reassembly {
    max_packet: usize,
    entries: HashMap<(Uuid, u32), Partial>,
    total_bytes: usize,
    expired: u64,
}

struct Partial {
    count: u16,
    total_len: u16,
    slots: Vec<Option<Bytes>>,
    filled: u16,
    bytes: usize,
    deadline: Instant,
}

impl Reassembly {
    pub fn new(max_packet: usize) -> Self {
        Self {
            max_packet,
            entries: HashMap::new(),
            total_bytes: 0,
            expired: 0,
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_bytes = 0;
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        network_id: Uuid,
        packet_id: u32,
        index: u16,
        count: u16,
        total_len: u16,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<Bytes>, ReassemblyError> {
        self.expire(now);
        if count == 0
            || index >= count
            || total_len == 0
            || total_len as usize > self.max_packet
            || payload.is_empty()
        {
            return Err(ReassemblyError::Malformed);
        }

        let key = (network_id, packet_id);
        if let Some(partial) = self.entries.get(&key)
            && (partial.count != count || partial.total_len != total_len)
        {
            self.remove(key);
            return Err(ReassemblyError::Malformed);
        }

        if !self.entries.contains_key(&key) {
            while self.entries.len() >= REASSEMBLY_MAX_ENTRIES {
                self.evict_oldest();
            }
            self.entries.insert(
                key,
                Partial {
                    count,
                    total_len,
                    slots: vec![None; count as usize],
                    filled: 0,
                    bytes: 0,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
        }

        let partial = self.entries.get_mut(&key).unwrap();
        let slot = &mut partial.slots[index as usize];
        if slot.is_some() {
            return Ok(None);
        }
        if self.total_bytes + payload.len() > REASSEMBLY_MAX_BYTES {
            self.remove(key);
            return Err(ReassemblyError::Evicted);
        }
        *slot = Some(Bytes::copy_from_slice(payload));
        partial.filled += 1;
        partial.bytes += payload.len();
        self.total_bytes += payload.len();

        if partial.filled != partial.count {
            return Ok(None);
        }

        let mut assembled = BytesMut::with_capacity(partial.total_len as usize);
        for piece in &partial.slots {
            assembled.extend_from_slice(piece.as_ref().unwrap());
        }
        if assembled.len() != partial.total_len as usize {
            self.remove(key);
            return Err(ReassemblyError::Malformed);
        }
        self.remove(key);
        Ok(Some(assembled.freeze()))
    }

    fn expire(&mut self, now: Instant) {
        let stale: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            self.remove(key);
            self.expired += 1;
        }
    }

    pub fn take_expired(&mut self) -> u64 {
        let n = self.expired;
        self.expired = 0;
        n
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, p)| p.deadline)
            .map(|(k, _)| *k);
        if let Some(key) = oldest {
            self.remove(key);
        }
    }

    fn remove(&mut self, key: (Uuid, u32)) {
        if let Some(partial) = self.entries.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(partial.bytes);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Uuid {
        Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888)
    }

    fn ip_packet(n: usize) -> Vec<u8> {
        let mut p = vec![0x45; n];
        p[0] = 0x45;
        p
    }

    #[test]
    fn single_round_trip() {
        let pkt = ip_packet(40);
        let framed = encode_single(net(), &pkt);
        match decode(&framed).unwrap() {
            Frame::Single { network_id, packet } => {
                assert_eq!(network_id, net());
                assert_eq!(packet, pkt);
            }
            _ => panic!("expected single"),
        }
    }

    #[test]
    fn segmented_reassembly_in_order() {
        let pkt = ip_packet(200);
        let frames = encode_logical(net(), &pkt, 80, 7).unwrap();
        assert!(frames.len() > 1);
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        let mut out = None;
        for f in &frames {
            match decode(f).unwrap() {
                Frame::Segment {
                    network_id,
                    packet_id,
                    index,
                    count,
                    total_len,
                    payload,
                } => {
                    out = reasm
                        .insert(network_id, packet_id, index, count, total_len, payload, now)
                        .unwrap();
                }
                _ => panic!("expected segment"),
            }
        }
        assert_eq!(out.unwrap().as_ref(), pkt);
        assert_eq!(reasm.len(), 0);
    }

    #[test]
    fn out_of_order_segments() {
        let pkt = ip_packet(200);
        let mut frames = encode_logical(net(), &pkt, 80, 1).unwrap();
        frames.reverse();
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        let mut out = None;
        for f in &frames {
            let Frame::Segment {
                network_id,
                packet_id,
                index,
                count,
                total_len,
                payload,
            } = decode(f).unwrap()
            else {
                panic!("segment");
            };
            out = reasm
                .insert(network_id, packet_id, index, count, total_len, payload, now)
                .unwrap();
        }
        assert_eq!(out.unwrap().as_ref(), pkt);
    }

    #[test]
    fn duplicate_segment_ignored() {
        let pkt = ip_packet(120);
        let frames = encode_logical(net(), &pkt, 70, 3).unwrap();
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        let Frame::Segment {
            network_id,
            packet_id,
            index,
            count,
            total_len,
            payload,
        } = decode(&frames[0]).unwrap()
        else {
            panic!("segment");
        };
        assert!(
            reasm
                .insert(network_id, packet_id, index, count, total_len, payload, now)
                .unwrap()
                .is_none()
        );
        assert!(
            reasm
                .insert(network_id, packet_id, index, count, total_len, payload, now)
                .unwrap()
                .is_none()
        );
        assert_eq!(reasm.len(), 1);
    }

    #[test]
    fn missing_segment_expires() {
        let pkt = ip_packet(120);
        let frames = encode_logical(net(), &pkt, 70, 4).unwrap();
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        let Frame::Segment {
            network_id,
            packet_id,
            index,
            count,
            total_len,
            payload,
        } = decode(&frames[0]).unwrap()
        else {
            panic!("segment");
        };
        reasm
            .insert(network_id, packet_id, index, count, total_len, payload, now)
            .unwrap();
        reasm.expire(now + REASSEMBLY_TTL + Duration::from_millis(1));
        assert_eq!(reasm.len(), 0);
    }

    #[test]
    fn conflicting_metadata_rejected() {
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        reasm.insert(net(), 1, 0, 2, 40, &[1, 2, 3], now).unwrap();
        let err = reasm
            .insert(net(), 1, 1, 3, 40, &[4, 5, 6], now)
            .unwrap_err();
        assert_eq!(err, ReassemblyError::Malformed);
        assert_eq!(reasm.len(), 0);
    }

    #[test]
    fn hard_entry_bound() {
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        for id in 0..REASSEMBLY_MAX_ENTRIES + 3 {
            reasm
                .insert(net(), id as u32, 0, 2, 40, &[1, 2, 3], now)
                .unwrap();
        }
        assert!(reasm.len() <= REASSEMBLY_MAX_ENTRIES);
    }

    #[test]
    fn packet_larger_than_datagram_segments() {
        let pkt = ip_packet(400);
        let frames = encode_logical(net(), &pkt, 100, 9).expect("segments");
        assert!(frames.iter().all(|f| f.len() <= 100));
        assert!(frames.len() > 1);
    }

    #[test]
    fn max_datagram_change_is_per_packet() {
        let pkt = ip_packet(200);
        let a = encode_logical(net(), &pkt, 80, 1).unwrap();
        let b = encode_logical(net(), &pkt, 1000, 2).unwrap();
        assert!(a.len() > 1);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn connection_replacement_clears_reassembly() {
        let mut reasm = Reassembly::new(1280);
        reasm
            .insert(net(), 1, 0, 2, 40, &[1, 2], Instant::now())
            .unwrap();
        reasm.clear();
        assert_eq!(reasm.len(), 0);
    }

    #[test]
    fn oversized_total_len_rejected() {
        let mut reasm = Reassembly::new(100);
        let err = reasm
            .insert(net(), 1, 0, 1, 200, &[1; 10], Instant::now())
            .unwrap_err();
        assert_eq!(err, ReassemblyError::Malformed);
    }

    #[test]
    fn single_frame_carries_explicit_network_id() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let pkt = ip_packet(40);
        let fa = encode_single(a, &pkt);
        let fb = encode_single(b, &pkt);
        let Frame::Single {
            network_id: na,
            packet: pa,
        } = decode(&fa).unwrap()
        else {
            panic!("single");
        };
        let Frame::Single { network_id: nb, .. } = decode(&fb).unwrap() else {
            panic!("single");
        };
        assert_eq!(na, a);
        assert_eq!(nb, b);
        assert_eq!(pa, pkt.as_slice());
        assert_ne!(fa, fb);
    }

    #[test]
    fn reassembly_keys_include_network_id() {
        let a = Uuid::from_u128(11);
        let b = Uuid::from_u128(12);
        let mut reasm = Reassembly::new(1280);
        let now = Instant::now();
        assert!(
            reasm
                .insert(a, 1, 0, 2, 6, &[1, 2, 3], now)
                .unwrap()
                .is_none()
        );
        assert!(
            reasm
                .insert(b, 1, 0, 2, 6, &[4, 5, 6], now)
                .unwrap()
                .is_none()
        );
        assert_eq!(reasm.len(), 2);
        let done = reasm.insert(a, 1, 1, 2, 6, &[7, 8, 9], now).unwrap();
        assert_eq!(done.unwrap().as_ref(), &[1, 2, 3, 7, 8, 9]);
        assert_eq!(reasm.len(), 1);
    }
}
