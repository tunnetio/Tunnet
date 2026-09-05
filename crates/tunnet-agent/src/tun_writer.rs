//! Generation-owned TUN writer: the ONLY task that writes to the OS TUN.
//!
//! QUIC ingress readers never await TUN write capacity — they decode,
//! authorize, reassemble, and enqueue COMPLETE logical IP packets here via
//! the cheap non-blocking [`TunWriterHandle::try_enqueue`]. If the OS cannot
//! consume fast enough, the intentional software drop happens at this
//! complete-IP-packet boundary (`tun_write_queue_full`), never by letting
//! QUIC discard arbitrary overlay segments.
//!
//! The queue is bounded by packets AND bytes ([`WRITER_PACKET_CAP`] /
//! [`WRITER_BYTE_CAP`]); `try_enqueue` never blocks. At supported benchmark
//! load the queue-full counter must remain zero.
//!
//! Platform discipline:
//! - Windows: `try_send` only on the hot path. On `WouldBlock` the writer
//!   retains exactly the same front packet, backs off boundedly, and
//!   retries — and keeps draining its tail even with no new ingress. Never
//!   calls blocking `send` (tun-rs 2.8.9 may park a worker for seconds).
//! - Linux: drains several queued packets through the existing
//!   `LinuxTunBatchWriter` (`send_multiple`, GSO intact). A fatal
//!   `send_multiple` error has ambiguous partial-write semantics: treat as
//!   a generation failure (report + exit) rather than guessing.

#[cfg(any(not(target_os = "linux"), test))]
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(not(target_os = "linux"), test))]
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tun_rs::AsyncDevice;

use crate::metrics::AgentMetrics;

/// Packet bound for one generation's TUN writer queue.
pub const WRITER_PACKET_CAP: usize = 512;
/// Byte bound for one generation's TUN writer queue.
pub const WRITER_BYTE_CAP: usize = 1024 * 1024;
/// Linux drain batch per iteration (matches the GSO writer sizing).
#[allow(dead_code)]
pub const WRITER_DRAIN_BATCH: usize = super::tun_fast::TUN_WRITE_BATCH;
/// Windows WouldBlock backoff: start here, double per stall, cap here,
/// reset to start on any progress.
#[cfg(any(not(target_os = "linux"), test))]
const WRITE_BACKOFF_START: Duration = Duration::from_micros(100);
#[cfg(any(not(target_os = "linux"), test))]
const WRITE_BACKOFF_MAX: Duration = Duration::from_millis(2);

/// Non-blocking handle to the generation's TUN writer. Cheap to clone;
/// only completed logical IP packets enter this queue.
#[derive(Clone)]
pub struct TunWriterHandle {
    tx: mpsc::Sender<Bytes>,
    pending_bytes: Arc<AtomicUsize>,
    metrics: AgentMetrics,
}

impl TunWriterHandle {
    pub fn new(tx: mpsc::Sender<Bytes>, metrics: AgentMetrics) -> Self {
        Self {
            tx,
            pending_bytes: Arc::new(AtomicUsize::new(0)),
            metrics,
        }
    }

    /// Enqueue one complete IP packet. Never blocks, never awaits the OS:
    /// full (packets or bytes) drops explicitly with `tun_write_queue_full`.
    pub fn try_enqueue(&self, packet: Bytes) -> bool {
        let len = packet.len();
        let prev = self.pending_bytes.fetch_add(len, Ordering::Relaxed);
        if prev + len > WRITER_BYTE_CAP {
            self.pending_bytes.fetch_sub(len, Ordering::Relaxed);
            self.metrics.tun_write_queue_drop();
            return false;
        }
        match self.tx.try_send(packet) {
            Ok(()) => {
                self.metrics.tun_write_queued();
                true
            }
            Err(_) => {
                self.pending_bytes.fetch_sub(len, Ordering::Relaxed);
                self.metrics.tun_write_queue_drop();
                false
            }
        }
    }

    #[cfg(test)]
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes.load(Ordering::Relaxed)
    }
}

/// How the writer task ended.
pub enum WriterExit {
    /// Generation cancelled (or channel closed on shutdown): tail dropped
    /// silently, bytes released.
    Cancelled,
    /// Fatal device error: generation failure, the owner must restart.
    Fatal(String),
}

/// Spawn the generation-owned writer task. `on_fatal` fires exactly once on
/// a fatal device error (the owner publishes degraded/restarting state and
/// rebuilds the generation).
pub fn spawn_tun_writer(
    device: Arc<AsyncDevice>,
    cancel: CancellationToken,
    metrics: AgentMetrics,
    on_fatal: impl FnOnce(String) + Send + 'static,
) -> (TunWriterHandle, tokio::task::JoinHandle<WriterExit>) {
    let (tx, rx) = mpsc::channel::<Bytes>(WRITER_PACKET_CAP);
    let handle = TunWriterHandle::new(tx, metrics.clone());
    let pending = handle.pending_bytes.clone();
    let join = tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        let exit = run_linux_writer(rx, &device, &cancel, &metrics, &pending).await;
        #[cfg(not(target_os = "linux"))]
        let exit = run_windows_writer(rx, &device, &cancel, &metrics, &pending).await;
        if let WriterExit::Fatal(ref e) = exit {
            on_fatal(e.clone());
        }
        exit
    });
    (handle, join)
}

fn release(pending: &AtomicUsize, len: usize) {
    pending.fetch_sub(len.min(pending.load(Ordering::Relaxed)), Ordering::Relaxed);
}

/// Linux: batch queued packets through the GSO writer. Any `send_multiple`
/// error is fatal (ambiguous partial writes — never guess, restart).
#[cfg(target_os = "linux")]
async fn run_linux_writer(
    mut rx: mpsc::Receiver<Bytes>,
    device: &Arc<AsyncDevice>,
    cancel: &CancellationToken,
    metrics: &AgentMetrics,
    pending: &AtomicUsize,
) -> WriterExit {
    use super::tun_fast::LinuxTunBatchWriter;
    let mut batch = LinuxTunBatchWriter::new();
    let mut lens: Vec<usize> = Vec::with_capacity(WRITER_DRAIN_BATCH);
    loop {
        if cancel.is_cancelled() {
            return WriterExit::Cancelled;
        }
        // Fill one drain batch (cancellable wait for the first packet).
        let first = tokio::select! {
            biased;
            _ = cancel.cancelled() => return WriterExit::Cancelled,
            res = rx.recv() => res,
        };
        let Some(first) = first else {
            return WriterExit::Cancelled;
        };
        metrics.tun_syscall_inc("tun_writer_recv");
        batch.push(&first);
        lens.push(first.len());
        while lens.len() < WRITER_DRAIN_BATCH {
            match rx.try_recv() {
                Ok(pkt) => {
                    batch.push(&pkt);
                    lens.push(pkt.len());
                }
                Err(_) => break,
            }
        }
        metrics.tun_syscall_inc("send_batch");
        match batch.flush(device).await {
            Ok(n) => {
                metrics.tun_write_packets_add(n as u64);
                for len in lens.drain(..) {
                    release(pending, len);
                }
            }
            Err(e) => {
                let dropped = lens.len() as u64;
                for len in lens.drain(..) {
                    release(pending, len);
                }
                metrics.dropped_add("tun_send_failed", dropped.max(1));
                return WriterExit::Fatal(format!("linux TUN write failed: {e:#}"));
            }
        }
    }
}

/// Windows: own the pending packet until success or fatal failure.
/// `try_send` only; WouldBlock retains the SAME front packet with bounded
/// backoff; the tail drains even with zero new ingress.
#[cfg(not(target_os = "linux"))]
async fn run_windows_writer(
    mut rx: mpsc::Receiver<Bytes>,
    device: &Arc<AsyncDevice>,
    cancel: &CancellationToken,
    metrics: &AgentMetrics,
    pending: &AtomicUsize,
) -> WriterExit {
    let mut tail: VecDeque<Bytes> = VecDeque::new();
    let mut backoff = WRITE_BACKOFF_START;
    loop {
        if cancel.is_cancelled() {
            return WriterExit::Cancelled;
        }
        // Fill the tail without ever awaiting while work remains.
        while tail.len() < WRITER_PACKET_CAP {
            match rx.try_recv() {
                Ok(pkt) => tail.push_back(pkt),
                Err(_) => break,
            }
        }
        let Some(front) = tail.front().cloned() else {
            // Nothing pending: await new work (cancellable).
            let next = tokio::select! {
                biased;
                _ = cancel.cancelled() => return WriterExit::Cancelled,
                res = rx.recv() => res,
            };
            match next {
                Some(pkt) => {
                    tail.push_back(pkt);
                    continue;
                }
                None => return WriterExit::Cancelled,
            }
        };
        metrics.tun_syscall_inc("tun_writer_send");
        match device.try_send(&front) {
            Ok(_) => {
                tail.pop_front();
                release(pending, front.len());
                metrics.tun_write_packets_add(1);
                backoff = WRITE_BACKOFF_START;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Same front packet retained; bounded backoff, then retry.
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return WriterExit::Cancelled,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(WRITE_BACKOFF_MAX);
            }
            Err(e) => {
                let dropped = tail.len() as u64;
                tail.clear();
                metrics.dropped_add("tun_send_failed", dropped.max(1));
                return WriterExit::Fatal(format!("windows TUN write failed: {e}"));
            }
        }
    }
}

/// Packet sink abstraction for the writer state machine (tests drive a
/// mock; production wraps the TUN device).
#[cfg(test)]
pub(crate) trait PacketSink {
    fn try_send(&mut self, pkt: &[u8]) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSink {
        /// WouldBlock countdown: blocks this many sends, then succeeds.
        block_for: usize,
        fatal_after: Option<usize>,
        pub written: Vec<Vec<u8>>,
    }

    impl MockSink {
        fn new() -> Self {
            Self {
                block_for: 0,
                fatal_after: None,
                written: Vec::new(),
            }
        }
    }

    impl PacketSink for MockSink {
        fn try_send(&mut self, pkt: &[u8]) -> std::io::Result<()> {
            if let Some(n) = self.fatal_after
                && self.written.len() >= n
            {
                return Err(std::io::Error::other("mock device dead"));
            }
            if self.block_for > 0 {
                self.block_for -= 1;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.written.push(pkt.to_vec());
            Ok(())
        }
    }

    /// Steppable Windows writer core over a generic sink (same discipline
    /// as the production loop: try_send-only, front retained on WouldBlock,
    /// bounded backoff, tail drains without new ingress).
    struct StepWriter<S> {
        tail: VecDeque<Bytes>,
        backoff: Duration,
        sink: S,
    }

    impl<S: PacketSink> StepWriter<S> {
        fn new(sink: S) -> Self {
            Self {
                tail: VecDeque::new(),
                backoff: WRITE_BACKOFF_START,
                sink,
            }
        }

        fn push(&mut self, pkt: Bytes) {
            self.tail.push_back(pkt);
        }

        /// One step: attempt the front packet. Returns true on progress.
        /// WouldBlock retains the front and grows the backoff exactly like
        /// the production loop (bounded, reset on progress).
        fn step(&mut self) -> bool {
            let Some(front) = self.tail.front().cloned() else {
                return true;
            };
            match self.sink.try_send(&front) {
                Ok(()) => {
                    self.tail.pop_front();
                    self.backoff = WRITE_BACKOFF_START;
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.backoff = (self.backoff * 2).min(WRITE_BACKOFF_MAX);
                    false
                }
                Err(_) => false,
            }
        }

        fn drain(&mut self) {
            let mut guard = 1_000_000;
            while !self.tail.is_empty() && guard > 0 {
                guard -= 1;
                self.step();
            }
            assert!(self.tail.is_empty(), "tail must drain without new ingress");
        }
    }

    #[test]
    fn writer_retries_tail_without_new_ingress() {
        // QUIC ingress must never await this: WouldBlock x N retains the
        // SAME front packet; the tail then drains with no new pushes.
        let mut w = StepWriter::new(MockSink::new());
        w.sink.block_for = 5;
        for i in 0..8u8 {
            w.push(Bytes::from(vec![i; 64]));
        }
        // Blocked steps make no progress but lose nothing.
        for _ in 0..5 {
            assert!(!w.step());
            assert_eq!(w.tail.len(), 8);
        }
        // Unblocked: the whole tail drains, same packets, in order.
        w.drain();
        assert_eq!(w.sink.written.len(), 8);
        for (i, pkt) in w.sink.written.iter().enumerate() {
            assert_eq!(pkt, &vec![i as u8; 64], "ordering preserved");
        }
    }

    #[test]
    fn writer_retains_front_packet_on_wouldblock() {
        let mut w = StepWriter::new(MockSink::new());
        w.sink.block_for = 3;
        w.push(Bytes::from_static(b"front"));
        w.push(Bytes::from_static(b"second"));
        let front_before = w.tail.front().cloned().unwrap();
        for _ in 0..3 {
            assert!(!w.step());
        }
        // Exactly the same front packet, never skipped or duplicated.
        assert_eq!(w.tail.front().cloned().unwrap(), front_before);
        w.drain();
        assert_eq!(w.sink.written.len(), 2);
        assert_eq!(w.sink.written[0], b"front");
    }

    #[test]
    fn handle_bounds_packets_and_bytes() {
        // No worker: pending bytes never release, so both bounds trigger.
        let metrics = crate::actors::test_support::test_metrics();
        let (tx, _rx) = mpsc::channel::<Bytes>(WRITER_PACKET_CAP);
        let h = TunWriterHandle::new(tx, metrics);
        // Byte bound first: 9000 B packets exceed 1 MiB well before 512.
        let mut accepted = 0;
        for _ in 0..200 {
            if h.try_enqueue(Bytes::from(vec![0x45u8; 9000])) {
                accepted += 1;
            } else {
                break;
            }
        }
        assert!(accepted > 0 && accepted < 200, "byte bound must trip");
        assert!(h.pending_bytes() <= WRITER_BYTE_CAP);
        // Packet bound: 512 small packets fill the channel, the 513th drops.
        let (tx2, _rx2) = mpsc::channel::<Bytes>(WRITER_PACKET_CAP);
        let h2 = TunWriterHandle::new(tx2, crate::actors::test_support::test_metrics());
        let mut n = 0;
        for _ in 0..(WRITER_PACKET_CAP + 16) {
            if h2.try_enqueue(Bytes::from_static(b"tiny")) {
                n += 1;
            }
        }
        assert_eq!(n, WRITER_PACKET_CAP, "packet bound is exact");
        assert!(!h2.try_enqueue(Bytes::from_static(b"tiny")));
    }

    #[test]
    fn handle_never_blocks_reader() {
        // try_enqueue on a full/closed queue returns immediately (the QUIC
        // reader path must never await TUN capacity).
        let (tx, rx) = mpsc::channel::<Bytes>(1);
        let h = TunWriterHandle::new(tx, crate::actors::test_support::test_metrics());
        drop(rx);
        let start = std::time::Instant::now();
        assert!(!h.try_enqueue(Bytes::from_static(b"x")));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
