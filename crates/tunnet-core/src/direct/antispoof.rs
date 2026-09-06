//! Ingress anti-spoofing: mesh IP must match the peer that sent the datagram.
//!
//! Hot-path only: header compare + O(1) route lookup. No allocations on allow.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// Returns `true` when the packet source IP matches the mesh IP assigned to the peer.
#[inline]
pub fn source_matches_peer(packet_src: Ipv4Addr, peer_mesh_ip: Ipv4Addr) -> bool {
    packet_src == peer_mesh_ip
}

/// Per-peer spoof counters with rate-limited warnings (at most once per window).
#[derive(Clone, Default)]
pub struct SpoofTracker {
    inner: std::sync::Arc<SpoofInner>,
}

struct SpoofInner {
    by_peer: DashMap<String, AtomicU64>,
    total: AtomicU64,
    last_log: Mutex<Instant>,
    window: Duration,
}

impl Default for SpoofInner {
    fn default() -> Self {
        Self {
            by_peer: DashMap::new(),
            total: AtomicU64::new(0),
            last_log: Mutex::new(Instant::now() - Duration::from_secs(120)),
            window: Duration::from_secs(60),
        }
    }
}

impl SpoofTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a spoofed packet. Returns true if a warning should be logged now.
    pub fn record(&self, peer_endpoint_hex: &str) -> bool {
        self.inner.total.fetch_add(1, Ordering::Relaxed);
        self.inner
            .by_peer
            .entry(peer_endpoint_hex.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        let mut last = self.inner.last_log.lock();
        if last.elapsed() >= self.inner.window {
            *last = Instant::now();
            true
        } else {
            false
        }
    }

    /// Snapshot and reset per-peer counters for logging.
    pub fn drain_window_counts(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for entry in self.inner.by_peer.iter() {
            let n = entry.value().swap(0, Ordering::Relaxed);
            if n > 0 {
                out.push((entry.key().clone(), n));
            }
        }
        out
    }

    pub fn total(&self) -> u64 {
        self.inner.total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::assigned_address("10.21.0.1", "10.21.0.1", true)]
    #[case::different_host("10.21.0.1", "10.21.0.2", false)]
    #[case::different_subnet("10.21.0.1", "10.22.0.1", false)]
    #[case::unspecified_is_not_peer("0.0.0.0", "10.21.0.1", false)]
    fn source_must_match_assigned_peer(
        #[case] packet_source: &str,
        #[case] assigned_peer: &str,
        #[case] expected: bool,
    ) {
        let packet_source = packet_source.parse().unwrap();
        let assigned_peer = assigned_peer.parse().unwrap();
        assert_eq!(source_matches_peer(packet_source, assigned_peer), expected);
    }
}
