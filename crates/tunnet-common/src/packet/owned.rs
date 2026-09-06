//! Dataplane packet ownership: zero/minimal-copy logical packets.
//!
//! One packet owner moves through TUN receive → parse → scheduler →
//! segmentation → Iroh without repeated allocation:
//!
//! ```text
//! PooledBuffer (Vec storage + pool handle, AsRef<[u8]>)
//!   -- transmit path --> Bytes::from_owner(owner)  (no copy; pool recycle on Drop)
//!   -- shared path   --> Bytes kept directly       (inbound, no mutation)
//! ```
//!
//! Safety rules: no lifetime tricks (owners are `'static`), no OS-ring
//! pinning (pool buffers are plain heap memory), bounded pools with MTU
//! capacity classes (no 64 KiB retention for normal packets).

use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;

use super::{FlowKey, PacketMeta, parse};

/// Headroom reserved at the front of every pooled buffer for the tunnel
/// frame header, so single-frame encoding never copies the payload.
pub const FRAME_HEADROOM: usize = 32;

/// Logical/virtual MTU default for the dataplane.
pub const DEFAULT_VIRTUAL_MTU: usize = 2800;
/// Hard ceiling for a logical packet (framing `total_len` is u16-compatible).
pub const MAX_LOGICAL_LEN: usize = 9000;
/// Smallest usable logical MTU.
pub const MIN_VIRTUAL_MTU: usize = 576;

/// Pool capacity classes (bytes). A buffer is always drawn from the smallest
/// class that fits, so normal packets never retain huge allocations.
const CLASSES: [usize; 5] = [512, 1536, 2816, 4096, 9216];

#[derive(Debug)]
struct ClassPool {
    free: Mutex<Vec<Vec<u8>>>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

/// Bounded packet buffer pool with MTU capacity classes.
#[derive(Debug)]
pub struct PacketPool {
    classes: [ClassPool; 5],
    per_class_cap: usize,
}

impl Default for PacketPool {
    fn default() -> Self {
        Self::for_new(64)
    }
}

impl PacketPool {
    fn for_new(per_class_cap: usize) -> Self {
        let mk = || ClassPool {
            free: Mutex::new(Vec::new()),
            hits: Default::default(),
            misses: Default::default(),
        };
        Self {
            classes: [mk(), mk(), mk(), mk(), mk()],
            per_class_cap: per_class_cap.max(4),
        }
    }

    pub fn new(per_class_cap: usize) -> Arc<Self> {
        Arc::new(Self::for_new(per_class_cap))
    }

    fn class_for(need: usize) -> usize {
        CLASSES
            .iter()
            .position(|c| *c >= need)
            .unwrap_or(CLASSES.len() - 1)
    }

    /// Acquire storage for `need` bytes of packet payload plus frame headroom.
    pub fn acquire(self: &Arc<Self>, need: usize) -> PooledBuffer {
        let total = need.saturating_add(FRAME_HEADROOM).min(CLASSES[4]);
        let class = Self::class_for(total);
        let pool = &self.classes[class];
        let mut storage = pool.free.lock().expect("pool").pop().unwrap_or_default();
        if storage.capacity() < total {
            storage.reserve(total - storage.capacity());
            pool.misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            pool.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        storage.clear();
        let start = FRAME_HEADROOM.min(storage.capacity());
        PooledBuffer {
            storage,
            start,
            len: 0,
            pool: Arc::downgrade(self),
            class: class as u8,
        }
    }

    fn release(&self, mut storage: Vec<u8>, class: usize) {
        // Never retain absurd buffers: drop storage far above its class.
        if storage.capacity() > CLASSES[class] * 2 {
            return;
        }
        storage.clear();
        let pool = &self.classes[class];
        let mut free = pool.free.lock().expect("pool");
        if free.len() < self.per_class_cap {
            free.push(storage);
        }
    }

    /// (hits, misses) across all classes for telemetry.
    pub fn hit_miss(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut h = 0;
        let mut m = 0;
        for c in &self.classes {
            h += c.hits.load(Relaxed);
            m += c.misses.load(Relaxed);
        }
        (h, m)
    }
}

/// Owned packet storage with frame headroom. `AsRef<[u8]>` exposes exactly
/// the live packet bytes, so `Bytes::from_owner` views the frame with no
/// copy and the pool recycles the storage on final drop.
pub struct PooledBuffer {
    storage: Vec<u8>,
    start: usize,
    len: usize,
    pool: Weak<PacketPool>,
    class: u8,
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("len", &self.len)
            .field("class", &self.class)
            .finish()
    }
}

impl PooledBuffer {
    /// Region with capacity for receiving up to `cap` bytes.
    pub fn recv_region(&mut self, cap: usize) -> &mut [u8] {
        let need = self.start + cap;
        if self.storage.len() < need {
            self.storage.resize(need, 0);
        }
        &mut self.storage[self.start..self.start + cap]
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mutable headroom for in-place single-frame header encoding.
    /// Returns `None` when the header does not fit (caller falls back to a
    /// staged encode, never corrupting the payload).
    pub fn header_slot(&mut self, hdr_len: usize) -> Option<&mut [u8]> {
        if hdr_len > self.start {
            return None;
        }
        self.start -= hdr_len;
        self.len += hdr_len;
        Some(&mut self.storage[self.start..self.start + hdr_len])
    }

    /// Mutable receive area from the headroom start to the end of storage,
    /// for TUN batch slots used with `recv_multiple` at offset 0. Size it
    /// first with [`recv_region`]; the received length is then set via
    /// [`set_len`] (or `from_pooled`). Headroom stays intact, so a later
    /// single-frame encode prepends its header with no copy.
    pub fn recv_area_mut(&mut self) -> &mut [u8] {
        debug_assert!(self.start <= self.storage.len());
        &mut self.storage[self.start..]
    }

    /// Immutable receive area: exactly the same region and length as
    /// [`recv_area_mut`](Self::recv_area_mut). Batch-slot `AsRef`/`AsMut`
    /// impls must return the same region — tun-rs validates capacity
    /// against `AsRef::len()` and writes into `AsMut`, so divergent views
    /// fail or misframe batches.
    pub fn recv_area(&self) -> &[u8] {
        debug_assert!(self.start <= self.storage.len());
        &self.storage[self.start..]
    }

    pub fn packet_bytes(&self) -> &[u8] {
        debug_assert!(self.start + self.len <= self.storage.len());
        let end = (self.start + self.len).min(self.storage.len());
        &self.storage[self.start..end]
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.packet_bytes()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            let storage = std::mem::take(&mut self.storage);
            pool.release(storage, self.class as usize);
        }
    }
}

/// Ownership of logical packet bytes through the dataplane pipeline.
#[derive(Debug)]
pub enum PacketOwner {
    /// Pooled heap storage; converts to `Bytes` via `from_owner` (no copy).
    Pooled(PooledBuffer),
    /// Already-owned bytes (inbound DATAGRAM, no mutation needed).
    Shared(Bytes),
}

impl PacketOwner {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Pooled(b) => b.as_ref(),
            Self::Shared(b) => b.as_ref(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Consume into a QUIC DATAGRAM payload without copying the payload.
    pub fn into_datagram(self) -> Bytes {
        match self {
            Self::Pooled(b) => Bytes::from_owner(b),
            Self::Shared(b) => b,
        }
    }
}

/// Owned logical (inner IP) packet: bytes + parse-once metadata + flow key.
#[derive(Debug)]
pub struct LogicalPacket {
    pub owner: PacketOwner,
    pub meta: PacketMeta,
    pub flow: FlowKey,
    pub enqueued_at: std::time::Instant,
}

impl LogicalPacket {
    /// Parse-and-own from a slice (copies once; prefer the pooled constructors
    /// on hot paths).
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        let (meta, flow) = {
            let pkt = parse(data).ok()?;
            (PacketMeta::from_packet(&pkt), FlowKey::for_packet(&pkt))
        };
        Some(Self {
            owner: PacketOwner::Shared(Bytes::copy_from_slice(data)),
            meta,
            flow,
            enqueued_at: std::time::Instant::now(),
        })
    }

    /// Take ownership of pooled storage filled with exactly `len` bytes.
    pub fn from_pooled(mut buf: PooledBuffer, len: usize) -> Option<Self> {
        buf.set_len(len);
        let (meta, flow) = {
            let pkt = parse(buf.as_ref()).ok()?;
            (PacketMeta::from_packet(&pkt), FlowKey::for_packet(&pkt))
        };
        Some(Self {
            owner: PacketOwner::Pooled(buf),
            meta,
            flow,
            enqueued_at: std::time::Instant::now(),
        })
    }

    /// Zero-copy inbound: retain the DATAGRAM's bytes, parse directly.
    pub fn from_shared(bytes: Bytes) -> Option<Self> {
        let (meta, flow) = {
            let pkt = parse(&bytes).ok()?;
            (PacketMeta::from_packet(&pkt), FlowKey::for_packet(&pkt))
        };
        Some(Self {
            owner: PacketOwner::Shared(bytes),
            meta,
            flow,
            enqueued_at: std::time::Instant::now(),
        })
    }

    /// Take ownership of a `Vec<u8>` without copying (`Bytes::from` moves
    /// the allocation). Used for batch-slot transfers and reassembly output.
    pub fn from_vec(data: Vec<u8>) -> Option<Self> {
        let (meta, flow) = {
            let pkt = parse(&data).ok()?;
            (PacketMeta::from_packet(&pkt), FlowKey::for_packet(&pkt))
        };
        Some(Self {
            owner: PacketOwner::Shared(Bytes::from(data)),
            meta,
            flow,
            enqueued_at: std::time::Instant::now(),
        })
    }

    pub fn len(&self) -> usize {
        self.owner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owner.is_empty()
    }

    pub fn sojourn(&self) -> std::time::Duration {
        self.enqueued_at.elapsed()
    }

    /// Materialize mutable pooled storage (NAT rewrite and other rare
    /// mutations only). Returns false when the packet cannot be materialized.
    pub fn materialize(&mut self, pool: &Arc<PacketPool>) -> bool {
        if matches!(self.owner, PacketOwner::Pooled(_)) {
            return true;
        }
        let bytes = self.owner.as_bytes();
        let mut buf = pool.acquire(bytes.len());
        let region = buf.recv_region(bytes.len());
        region.copy_from_slice(bytes);
        buf.set_len(bytes.len());
        // Re-derive metadata only if a later mutation needs it; the caller
        // refreshes after mutating.
        self.owner = PacketOwner::Pooled(buf);
        true
    }

    /// Refresh metadata/flow after an in-place mutation (rare path).
    pub fn refresh(&mut self) -> bool {
        let Ok(pkt) = parse(self.owner.as_bytes()) else {
            return false;
        };
        self.meta = PacketMeta::from_packet(&pkt);
        self.flow = FlowKey::for_packet(&pkt);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet() -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut o = Vec::new();
        b.write(&mut o, &[0; 200]).unwrap();
        o
    }

    #[test]
    fn pooled_round_trip_no_copy_view() {
        let pool = PacketPool::new(8);
        let raw = udp_packet();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        let p = LogicalPacket::from_pooled(buf, raw.len()).unwrap();
        assert_eq!(p.len(), raw.len());
        assert_eq!(p.owner.as_bytes(), raw.as_slice());
    }

    #[test]
    fn header_slot_prepends_without_copy() {
        let pool = PacketPool::new(8);
        let raw = udp_packet();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        buf.set_len(raw.len());
        let slot = buf.header_slot(4).unwrap();
        slot.copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(&buf.as_ref()[..4], &[9, 9, 9, 9]);
        assert_eq!(&buf.as_ref()[4..], raw.as_slice());
    }

    #[test]
    fn from_owner_keeps_storage_alive() {
        let pool = PacketPool::new(8);
        let raw = udp_packet();
        let mut buf = pool.acquire(raw.len());
        buf.recv_region(raw.len()).copy_from_slice(&raw);
        buf.set_len(raw.len());
        let b = Bytes::from_owner(buf);
        assert_eq!(&b[..], raw.as_slice());
        let c = b.clone();
        drop(b);
        assert_eq!(&c[..], raw.as_slice());
    }

    #[test]
    fn pool_recycles_and_reports() {
        let pool = PacketPool::new(8);
        {
            let _ = pool.acquire(100);
        }
        let (h, m) = pool.hit_miss();
        assert_eq!(h + m, 1);
        let _ = pool.acquire(100);
        let (h2, _) = pool.hit_miss();
        assert_eq!(h2, h + 1, "second acquire should hit the pool");
    }

    #[test]
    fn shared_inbound_no_copy() {
        let raw = udp_packet();
        let bytes = Bytes::from(raw.clone());
        let p = LogicalPacket::from_shared(bytes).unwrap();
        assert_eq!(p.owner.as_bytes(), raw.as_slice());
    }
}
