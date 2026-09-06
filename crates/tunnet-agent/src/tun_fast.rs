//! Platform-specific TUN fast paths sharing one packet semantics (§9).
//!
//! Linux: offload + `recv_multiple` into pool-owned batch slots (ownership
//! transferred to logical packets, no per-packet copy) and genuine
//! multi-packet `send_multiple` batches that let GSO coalesce.
//! Windows: Wintun ring drained as bursts into pooled buffers and filled
//! from an explicit pending batch that retains its unsent tail — no silent
//! loss. Ring capacity stays deliberate; bigger rings only mask queueing.
//!
//! All slot sizes derive from the configured virtual MTU (§6): a 2800+ byte
//! logical packet is never truncated by a fixed 2 KiB assumption.

#[cfg(not(target_os = "linux"))]
use std::collections::VecDeque;
use std::sync::Arc;

#[cfg(not(target_os = "linux"))]
use bytes::Bytes;
use tun_rs::AsyncDevice;
#[cfg(any(target_os = "linux", test))]
use tunnet_common::packet::PooledBuffer;
use tunnet_common::packet::{LogicalPacket, MAX_LOGICAL_LEN, PacketPool};

/// Desired TUN batch depth (starting point; tun-rs `IDEAL_BATCH_SIZE` = 128).
#[cfg(target_os = "linux")]
pub const BATCH_SIZE: usize = tun_rs::IDEAL_BATCH_SIZE;
/// Windows burst budget per readiness wakeup.
pub const BURST_BUDGET: usize = 64;
/// Inbound TUN write batch: packets accumulated per drain iteration (§9).
pub const TUN_WRITE_BATCH: usize = 32;

/// Slot size for a virtual MTU: payload room plus virtio headroom on Linux.
pub fn slot_cap_for_mtu(mtu: usize) -> usize {
    mtu.clamp(576, MAX_LOGICAL_LEN) + 256
}

/// Preallocated batch engine for Linux `recv_multiple`.
///
/// Batch slots are pool-owned buffers with frame headroom intact: on
/// receipt each slot moves wholesale into the logical packet
/// (`from_pooled` — zero copy, and single-frame transmit later prepends
/// its header with no staging copy) and the slot is refilled from the
/// pool. `recv_multiple` writes at offset 0 of the slot's receive area,
/// which starts after the headroom.
#[cfg(target_os = "linux")]
pub struct LinuxBatchEngine {
    pub orig: Vec<u8>,
    bufs: Vec<BatchSlot>,
    sizes: Vec<usize>,
    pool: Arc<PacketPool>,
    slot_cap: usize,
}

/// A pool-owned TUN receive slot.
///
/// tun-rs `recv_multiple` contract (see `tun-rs/src/platform/linux/device.rs`
/// `handle_virtio_read` / `gso_split`): `as_ref().len()` is the RECEIVE
/// CAPACITY tun-rs checks writes against, and packets land at
/// `as_mut()[offset..]`. The two views therefore differ on purpose:
/// - `AsRef` reports the WHOLE backing storage (headroom + sized area),
///   independent of the current packet length (fresh slots hold no packet
///   yet — reporting the packet view here fails every batch with
///   "overflows bufs element len");
/// - `AsMut` exposes the headroomed receive area sized by `prepare`.
///
/// Receipt transfers the whole buffer into a logical packet with ownership
/// and headroom intact. Platform-independent by design so the contract is
/// unit-tested everywhere, not only on Linux.
#[cfg(any(target_os = "linux", test))]
struct BatchSlot(PooledBuffer);

#[cfg(any(target_os = "linux", test))]
impl BatchSlot {
    fn new(pool: &Arc<PacketPool>, slot_cap: usize) -> Self {
        let mut buf = pool.acquire(slot_cap);
        buf.recv_region(slot_cap);
        Self(buf)
    }

    /// Size the receive area for the next batch.
    fn prepare(&mut self, slot_cap: usize) {
        self.0.recv_region(slot_cap);
        // tun-rs capacity gate: the AsRef view must cover the slot even
        // when no packet is stored yet (fresh/recycled buffers).
        debug_assert!(self.as_ref().len() >= slot_cap);
    }

    fn into_pooled(self) -> PooledBuffer {
        self.0
    }
}

#[cfg(any(target_os = "linux", test))]
impl AsRef<[u8]> for BatchSlot {
    fn as_ref(&self) -> &[u8] {
        // Same region and length as the AsMut view below: tun-rs
        // validates `AsRef::len()` as capacity and writes into `AsMut`,
        // so these must never diverge (a packet-length view here fails
        // every batch on fresh slots).
        self.0.recv_area()
    }
}

#[cfg(any(target_os = "linux", test))]
impl AsMut<[u8]> for BatchSlot {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.recv_area_mut()
    }
}

#[cfg(target_os = "linux")]
impl LinuxBatchEngine {
    pub fn new(pool: Arc<PacketPool>, mtu: usize) -> Self {
        let slot_cap = slot_cap_for_mtu(mtu);
        let mut bufs = Vec::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            bufs.push(BatchSlot::new(&pool, slot_cap));
        }
        Self {
            orig: vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 65535],
            bufs,
            sizes: vec![0usize; BATCH_SIZE],
            pool,
            slot_cap,
        }
    }

    /// Receive a batch; each packet takes ownership of its slot storage.
    /// Reuses preallocated/pooled buffers; no per-packet copy, and the
    /// common single-frame path never copies afterwards either.
    pub async fn recv_batch(&mut self, dev: &AsyncDevice) -> anyhow::Result<Vec<LogicalPacket>> {
        for b in &mut self.bufs {
            b.prepare(self.slot_cap);
        }
        let n = dev
            .recv_multiple(&mut self.orig, &mut self.bufs, &mut self.sizes, 0)
            .await?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let len = self.sizes[i];
            if len == 0 || len > self.slot_cap {
                continue;
            }
            // Move the pool-owned slot into the packet (zero copy,
            // headroom intact); refill the slot from the pool.
            let slot =
                std::mem::replace(&mut self.bufs[i], BatchSlot::new(&self.pool, self.slot_cap));
            if let Some(p) = LogicalPacket::from_pooled(slot.into_pooled(), len) {
                out.push(p);
            }
            // else: malformed; the fresh replacement slot stays.
        }
        Ok(out)
    }
}

/// Genuine multi-packet TUN writer for Linux (§9).
///
/// Accumulates decoded logical packets and flushes with ONE
/// `send_multiple`, letting GSO coalesce same-flow segments into fewer
/// syscalls. GRO state and staging storage are reused across iterations.
///
/// Staging uses DEDICATED reusable byte buffers with the exact layout the
/// device expects — `[12B virtio header][IP packet]` — never `PooledBuffer`
/// (whose 32-byte tunnel-frame headroom would shift the packet and hand
/// the kernel 32 zero bytes instead of an IPv4 header; that misframing
/// silently black-holed all Linux TUN writes).
#[cfg(target_os = "linux")]
pub struct LinuxTunBatchWriter {
    gro: tun_rs::GROTable,
    staging: Vec<Vec<u8>>,
    /// Empty buffers retained for reuse (capacity kept, no per-packet alloc
    /// after warmup).
    free: Vec<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl LinuxTunBatchWriter {
    pub fn new() -> Self {
        Self {
            gro: tun_rs::GROTable::default(),
            staging: Vec::with_capacity(TUN_WRITE_BATCH),
            free: Vec::new(),
        }
    }

    /// Stage one packet. Layout is exactly `[VIRTIO header zeros][packet]`
    /// so `flush` can pass `VIRTIO_NET_HDR_LEN` as the packet offset:
    /// tun-rs reads the IP packet at `buf[offset..]` and encodes the
    /// virtio header into `buf[offset-12..offset]` itself.
    pub fn push(&mut self, pkt: &[u8]) {
        const HDR: usize = tun_rs::VIRTIO_NET_HDR_LEN;
        let mut buf = self.free.pop().unwrap_or_default();
        buf.clear();
        buf.resize(HDR, 0);
        buf.extend_from_slice(pkt);
        debug_assert_eq!(&buf[HDR..], pkt, "packet must start exactly at the offset");
        self.staging.push(buf);
    }

    pub fn is_empty(&self) -> bool {
        self.staging.is_empty()
    }

    /// Flush the staged batch with one `send_multiple` call. Buffers are
    /// cleared and retained for the next batch (capacity kept).
    pub async fn flush(&mut self, dev: &AsyncDevice) -> anyhow::Result<usize> {
        if self.staging.is_empty() {
            return Ok(0);
        }
        const HDR: usize = tun_rs::VIRTIO_NET_HDR_LEN;
        let n = dev
            .send_multiple(&mut self.gro, &mut self.staging, HDR)
            .await?;
        for mut buf in std::mem::take(&mut self.staging) {
            buf.clear();
            if self.free.len() < TUN_WRITE_BATCH * 2 {
                self.free.push(buf);
            }
        }
        Ok(n)
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxTunBatchWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows burst drain into pooled buffers: after readiness, `try_recv`
/// until WouldBlock/budget. Each packet owns its pooled storage (no copy).
pub async fn windows_recv_burst(
    dev: &AsyncDevice,
    pool: &Arc<PacketPool>,
    mtu: usize,
    budget: usize,
) -> anyhow::Result<Vec<LogicalPacket>> {
    let slot_cap = slot_cap_for_mtu(mtu);
    let mut out = Vec::with_capacity(budget.min(BURST_BUDGET));
    // Prime with one async recv so we wait only when the ring is empty.
    {
        let mut buf = pool.acquire(slot_cap);
        let n = dev.recv(buf.recv_region(slot_cap)).await?;
        if n == 0 {
            return Ok(out);
        }
        if let Some(p) = LogicalPacket::from_pooled(buf, n) {
            out.push(p);
        }
    }
    for _ in 1..budget.min(BURST_BUDGET) {
        let mut buf = pool.acquire(slot_cap);
        match dev.try_recv(buf.recv_region(slot_cap)) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(p) = LogicalPacket::from_pooled(buf, n) {
                    out.push(p);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

/// Pending TUN write batch (§9, no silent loss).
///
/// `drain_pending` fills the device with repeated `try_send`; when it is
/// full it waits once via async `send`, then resumes the SAME batch. The
/// unsent tail is retained in `pending` across waits — ownership is explicit
/// (`Bytes`, no copy) and nothing is silently discarded.
///
/// Used by the Windows Wintun burst writer and by platforms without GSO
/// batching (same ring discipline everywhere outside Linux, where the GSO
/// writer owns TUN output instead).
#[cfg(not(target_os = "linux"))]
pub struct TunWriteBatch {
    pub pending: VecDeque<Bytes>,
}

#[cfg(not(target_os = "linux"))]
impl TunWriteBatch {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
        }
    }

    pub fn push(&mut self, pkt: Bytes) {
        self.pending.push_back(pkt);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Drain as much as the ring accepts right now. Returns the number of
    /// packets written; the remainder stays queued.
    pub fn drain_pending(&mut self, dev: &AsyncDevice) -> anyhow::Result<usize> {
        let mut wrote = 0;
        while let Some(front) = self.pending.front() {
            match dev.try_send(front) {
                Ok(_) => {
                    self.pending.pop_front();
                    wrote += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(wrote)
    }

    /// Drain with one async wait when the ring is full; the tail is retained.
    pub async fn drain_or_wait(&mut self, dev: &AsyncDevice) -> anyhow::Result<usize> {
        let wrote = self.drain_pending(dev)?;
        if self.pending.is_empty() {
            return Ok(wrote);
        }
        // Ring full: exactly one async send to wait for space, then resume
        // the same batch (no tail loss, no async-send pileup).
        if let Some(front) = self.pending.front().cloned() {
            dev.send(&front).await?;
            self.pending.pop_front();
            Ok(wrote + 1)
        } else {
            Ok(wrote)
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Default for TunWriteBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(BURST_BUDGET >= 16 && BURST_BUDGET <= 256);
        assert!(TUN_WRITE_BATCH >= 8);
    };

    #[test]
    fn slot_cap_tracks_mtu() {
        // No fixed 2048 assumption: large logical packets must fit.
        assert!(slot_cap_for_mtu(1280) >= 1280);
        assert!(slot_cap_for_mtu(2800) >= 2800);
        assert!(slot_cap_for_mtu(9000) >= 9000);
        assert!(slot_cap_for_mtu(100) >= 576);
        assert!(slot_cap_for_mtu(99_999) <= MAX_LOGICAL_LEN + 256);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn tun_batch_writer_stages_virtio_layout() {
        // Regression test for silently misframed Linux TUN writes (kernel
        // received zeros instead of IPv4): the staged buffer must be
        // exactly [12B virtio zeros][IP packet] so `flush` with offset 12
        // hands tun-rs the packet at the right place. No device needed.
        let mut w = LinuxTunBatchWriter::new();
        assert!(w.is_empty());
        let mut pkt = vec![0u8; 100];
        pkt[0] = 0x45; // IPv4-shaped, like a real packet
        w.push(&pkt);
        assert!(!w.is_empty());
        assert_eq!(w.staging.len(), 1);
        let staged = &w.staging[0];
        assert_eq!(staged.len(), tun_rs::VIRTIO_NET_HDR_LEN + pkt.len());
        assert!(staged[..tun_rs::VIRTIO_NET_HDR_LEN].iter().all(|b| *b == 0));
        assert_eq!(&staged[tun_rs::VIRTIO_NET_HDR_LEN..], pkt.as_slice());
        assert_eq!(staged[tun_rs::VIRTIO_NET_HDR_LEN], 0x45);
    }

    /// Real privileged Linux TUN round trip: writer → actual kernel TUN →
    /// kernel ICMP reply → engine receive. Exercises BOTH real contracts
    /// (device write framing AND `recv_multiple` slot semantics) that unit
    /// tests cannot reach.
    ///
    /// Ignored by default: needs `CAP_NET_ADMIN` (real TUN device). Run on
    /// a Linux dev machine with privileges:
    /// `sudo -E cargo test -p tunnet-agent --lib tun_kernel_round_trip -- --ignored --nocapture`
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "needs CAP_NET_ADMIN + real TUN device"]
    fn tun_kernel_round_trip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ip = std::net::Ipv4Addr::new(10, 99, 0, 1);
            let ifname = format!("tnt{:x}", std::process::id() & 0xffff);
            let dev = std::sync::Arc::new(
                crate::tun_io::build_tun(&ifname, ip, 30, 2800)
                    .expect("TUN device (need CAP_NET_ADMIN)"),
            );
            // Echo request to self: the kernel answers locally.
            let echo_id = 0xbeefu16;
            let b = etherparse::PacketBuilder::ipv4(ip.octets(), ip.octets(), 64)
                .icmpv4_echo_request(echo_id, 1);
            let mut req = Vec::new();
            b.write(&mut req, &[0xCCu8; 32]).unwrap();
            let mut writer = LinuxTunBatchWriter::new();
            writer.push(&req);
            writer
                .flush(&dev)
                .await
                .expect("flush echo request into the kernel");
            // Read back through the REAL batch engine (pooled slots).
            let pool = PacketPool::new(8);
            let mut engine = LinuxBatchEngine::new(pool, 2800);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no kernel echo reply within 5s"
                );
                let packets = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    engine.recv_batch(&dev),
                )
                .await
                .expect("recv_batch must not hang")
                .expect("recv_batch must succeed on a live device");
                for p in packets {
                    let meta = p.meta;
                    let is_reply = matches!(
                        meta.transport,
                        tunnet_common::packet::Transport::Icmpv4 {
                            type_u8: 0,
                            echo_id: Some(id),
                            ..
                        } if id == echo_id
                    );
                    if !is_reply {
                        continue;
                    }
                    assert_eq!(meta.src_v4, Some(ip));
                    assert_eq!(meta.dst_v4, Some(ip));
                    assert_eq!(
                        &p.owner.as_bytes()[p.owner.as_bytes().len() - 32..],
                        &[0xCCu8; 32]
                    );
                    return;
                }
            }
        });
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn tun_write_batch_retains_tail() {
        // Pure state-machine coverage (no device): pending ownership is
        // explicit; nothing is silently discarded.
        let mut b = TunWriteBatch::new();
        assert!(b.is_empty());
        b.push(Bytes::from_static(&[1, 2, 3]));
        b.push(Bytes::from_static(&[4, 5]));
        assert!(!b.is_empty());
    }

    #[test]
    fn batch_slot_satisfies_tun_rs_contract() {
        // Regression test for total Linux outbound loss (recv_batch failed
        // every batch with "overflows bufs element len"): tun-rs validates
        // writes against `as_ref().len()` (capacity) and writes into
        // `as_mut()[offset..]`. The AsRef view must therefore cover the
        // slot even when the slot holds NO packet yet (fresh buffers) or a
        // smaller stale one — the packet view (`len`) is the wrong view.
        // No TUN device needed: replicates tun-rs's exact checks.
        use tunnet_common::packet::FRAME_HEADROOM;
        let pool = PacketPool::new(8);
        for mtu in [1280usize, 2800, 9000] {
            let cap = slot_cap_for_mtu(mtu);
            let mut slot = BatchSlot::new(&pool, cap);
            slot.prepare(cap);
            // Fresh slot: packet view empty, capacity view full.
            assert_eq!(slot.0.len(), 0);
            assert!(
                slot.as_ref().len() >= cap,
                "mtu={mtu}: AsRef must report receive capacity"
            );
            assert!(
                slot.as_mut().len() >= cap,
                "mtu={mtu}: AsMut must expose the receive area"
            );
            // tun-rs handle_virtio_read / gso_split checks, offset 0.
            let offset = 0usize;
            for packet_len in [60usize, 1400, cap] {
                assert!(
                    !(offset > slot.as_ref().len()),
                    "mtu={mtu}: invalid offset must not trigger"
                );
                assert!(
                    !(slot.as_ref().len() - offset < packet_len),
                    "mtu={mtu} len={packet_len}: output buffer too small must not trigger"
                );
            }
            // Simulate a kernel write at as_mut()[0..len], then take
            // ownership exactly like recv_batch does.
            let pkt = {
                let b = etherparse::PacketBuilder::ipv4([10, 7, 0, 1], [10, 7, 0, 2], 64)
                    .udp(40000, 443);
                let mut o = Vec::new();
                b.write(&mut o, &[0xABu8; 200]).unwrap();
                o
            };
            slot.as_mut()[..pkt.len()].copy_from_slice(&pkt);
            let mut pooled = slot.into_pooled();
            let parsed = LogicalPacket::from_pooled(pooled, pkt.len()).expect("must parse");
            assert_eq!(parsed.owner.as_bytes(), pkt.as_slice());
            // Headroom intact for the single-frame prepend (zero-copy path).
            pooled = match parsed.owner {
                tunnet_common::packet::PacketOwner::Pooled(b) => b,
                _ => panic!("must stay pooled"),
            };
            assert!(pooled.header_slot(FRAME_HEADROOM).is_some());
            // Recycled slot with a SMALLER stale packet length still
            // reports full capacity (the stale-len trap).
            let mut slot2 = BatchSlot::new(&pool, cap);
            slot2.prepare(cap);
            let mut reused = slot2.into_pooled();
            reused.set_len(60);
            drop(reused);
            let mut slot3 = BatchSlot::new(&pool, cap);
            slot3.prepare(cap);
            assert!(
                slot3.as_ref().len() >= cap,
                "recycled slot must still report full capacity"
            );
        }
    }
}
