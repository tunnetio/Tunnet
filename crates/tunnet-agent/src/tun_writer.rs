//! Generation-owned TUN writer: the ONLY task that writes to the OS TUN.
//!
//! QUIC ingress readers never await TUN write capacity — they decode,
//! authorize, and enqueue COMPLETE logical IP packets here via
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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(not(target_os = "linux"), test))]
use std::time::Duration;

use bytes::Bytes;
use futures_util::FutureExt;
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
        let run = run_linux_writer(rx, &device, &cancel, &metrics, &pending);
        #[cfg(not(target_os = "linux"))]
        let run = run_windows_writer(rx, &device, &cancel, &metrics, &pending);
        let exit = std::panic::AssertUnwindSafe(run)
            .catch_unwind()
            .await
            .unwrap_or_else(|_| WriterExit::Fatal("TUN writer panicked".into()));
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
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return WriterExit::Cancelled,
            result = batch.flush(device) => result,
        };
        match result {
            Ok(n) => {
                metrics.tun_write_packets_add(n as u64, lens.iter().sum());
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
    rx: mpsc::Receiver<Bytes>,
    device: &Arc<AsyncDevice>,
    cancel: &CancellationToken,
    metrics: &AgentMetrics,
    pending: &AtomicUsize,
) -> WriterExit {
    run_packet_writer(
        rx,
        |packet| device.try_send(packet),
        cancel,
        metrics,
        pending,
    )
    .await
}

#[cfg(any(not(target_os = "linux"), test))]
async fn run_packet_writer(
    mut rx: mpsc::Receiver<Bytes>,
    mut send: impl FnMut(&[u8]) -> std::io::Result<usize>,
    cancel: &CancellationToken,
    metrics: &AgentMetrics,
    pending: &AtomicUsize,
) -> WriterExit {
    let mut front: Option<Bytes> = None;
    let mut backoff = WRITE_BACKOFF_START;
    loop {
        if cancel.is_cancelled() {
            return WriterExit::Cancelled;
        }
        if front.is_none() {
            front = tokio::select! {
                biased;
                _ = cancel.cancelled() => return WriterExit::Cancelled,
                next = rx.recv() => next,
            };
        }
        let Some(packet) = front.as_ref() else {
            return WriterExit::Cancelled;
        };
        metrics.tun_syscall_inc("tun_writer_send");
        match send(packet) {
            Ok(_) => {
                release(pending, packet.len());
                metrics.tun_write_packets_add(1, packet.len());
                front = None;
                backoff = WRITE_BACKOFF_START;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                metrics::counter!("tunnet_tun_write_would_block_total").increment(1);
                // Same front packet retained; bounded backoff, then retry.
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return WriterExit::Cancelled,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(WRITE_BACKOFF_MAX);
            }
            Err(e) => {
                metrics.dropped_inc("tun_send_failed");
                return WriterExit::Fatal(format!("windows TUN write failed: {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn production_writer_retains_front_until_capacity_returns() {
        let (tx, rx) = mpsc::channel(4);
        let metrics = AgentMetrics::for_tests();
        let handle = TunWriterHandle::new(tx, metrics.clone());
        let cancel = CancellationToken::new();
        assert!(handle.try_enqueue(Bytes::from_static(b"first")));
        assert!(handle.try_enqueue(Bytes::from_static(b"second")));
        let mut attempts = 0;
        let mut written = Vec::new();
        let result = run_packet_writer(
            rx,
            |packet| {
                attempts += 1;
                if attempts <= 3 {
                    assert_eq!(packet, b"first");
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                written.push(packet.to_vec());
                if written.len() == 2 {
                    cancel.cancel();
                }
                Ok(packet.len())
            },
            &cancel,
            &metrics,
            &handle.pending_bytes,
        )
        .await;
        assert!(matches!(result, WriterExit::Cancelled));
        assert_eq!(written, vec![b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(handle.pending_bytes(), 0);
    }
    #[test]
    fn writer_queue_has_hard_byte_limit() {
        let (tx, _rx) = mpsc::channel(WRITER_PACKET_CAP);
        let handle = TunWriterHandle::new(tx, AgentMetrics::for_tests());
        let packet = Bytes::from(vec![0; 9000]);
        let mut accepted = 0;
        for _ in 0..WRITER_PACKET_CAP {
            accepted += usize::from(handle.try_enqueue(packet.clone()));
        }
        assert_eq!(accepted, WRITER_BYTE_CAP / 9000);
        assert_eq!(handle.pending_bytes(), accepted * 9000);
    }
    #[tokio::test]
    async fn cancellation_stops_a_full_sink() {
        let (tx, rx) = mpsc::channel(4);
        let metrics = AgentMetrics::for_tests();
        let handle = TunWriterHandle::new(tx, metrics.clone());
        let cancel = CancellationToken::new();
        assert!(handle.try_enqueue(Bytes::from_static(b"first")));
        let mut attempts = 0;
        let result = run_packet_writer(
            rx,
            |_| {
                attempts += 1;
                cancel.cancel();
                Err(std::io::ErrorKind::WouldBlock.into())
            },
            &cancel,
            &metrics,
            &handle.pending_bytes,
        )
        .await;
        assert!(matches!(result, WriterExit::Cancelled));
        assert_eq!(attempts, 1);
    }
}
