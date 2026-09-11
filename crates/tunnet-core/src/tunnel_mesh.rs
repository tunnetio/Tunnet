//! Read-only tunnel dataplane telemetry and keep-alive policy.
//!
//! Packet I/O lives in the agent. This handle is what heartbeat, local API, and
//! cloud-relay metering read. The active [`TunnelHub`] (agent) updates it.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use iroh::EndpointId;
use parking_lot::RwLock;

use crate::cloud_relay_meter::CloudRelayMeter;
use crate::iroh_pool::{OnDemandStats, PeerConnSnapshot};

#[derive(Clone)]
pub struct TunnelMesh {
    inner: Arc<Inner>,
}

struct Inner {
    keep_alive: AtomicBool,
    keep_alive_hosts: DashMap<String, ()>,
    keep_alive_peers: DashMap<EndpointId, ()>,
    cloud_relay_meter: CloudRelayMeter,
    cloud_relay_urls: RwLock<HashSet<String>>,
    peer_cloud_relay: DashMap<EndpointId, AtomicBool>,
    snapshots: DashMap<EndpointId, PeerSnap>,
    active_conns: AtomicU32,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
    packets_tx: AtomicU64,
    packets_rx: AtomicU64,
    dial_attempts: AtomicU64,
    dial_success: AtomicU64,
    dial_fail: AtomicU64,
    dials_suppressed: AtomicU64,
    queue_full: AtomicU64,
    stale_drops: AtomicU64,
    blocked_drops: AtomicU64,
    tun_write_drops: AtomicU64,
    send_errors: AtomicU64,
    too_large: AtomicU64,
    single_packets: AtomicU64,
    segmented_packets: AtomicU64,
    segments_tx: AtomicU64,
    segments_rx: AtomicU64,
    reassembly_malformed: AtomicU64,
    reassembly_expired: AtomicU64,
    reassembly_evicted: AtomicU64,
    tun_rx_packets: AtomicU64,
    tun_tx_packets: AtomicU64,
    tun_rx_bytes: AtomicU64,
    tun_tx_bytes: AtomicU64,
}

struct PeerSnap {
    state: String,
    keep_alive: bool,
    last_activity: Instant,
    live: bool,
    path: String,
    bytes_in: u64,
    bytes_out: u64,
}

impl TunnelMesh {
    pub fn new(cloud_relay_meter: CloudRelayMeter, keep_alive: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                keep_alive: AtomicBool::new(keep_alive),
                keep_alive_hosts: DashMap::new(),
                keep_alive_peers: DashMap::new(),
                cloud_relay_meter,
                cloud_relay_urls: RwLock::new(HashSet::new()),
                peer_cloud_relay: DashMap::new(),
                snapshots: DashMap::new(),
                active_conns: AtomicU32::new(0),
                bytes_tx: AtomicU64::new(0),
                bytes_rx: AtomicU64::new(0),
                packets_tx: AtomicU64::new(0),
                packets_rx: AtomicU64::new(0),
                dial_attempts: AtomicU64::new(0),
                dial_success: AtomicU64::new(0),
                dial_fail: AtomicU64::new(0),
                dials_suppressed: AtomicU64::new(0),
                queue_full: AtomicU64::new(0),
                stale_drops: AtomicU64::new(0),
                blocked_drops: AtomicU64::new(0),
                tun_write_drops: AtomicU64::new(0),
                send_errors: AtomicU64::new(0),
                too_large: AtomicU64::new(0),
                single_packets: AtomicU64::new(0),
                segmented_packets: AtomicU64::new(0),
                segments_tx: AtomicU64::new(0),
                segments_rx: AtomicU64::new(0),
                reassembly_malformed: AtomicU64::new(0),
                reassembly_expired: AtomicU64::new(0),
                reassembly_evicted: AtomicU64::new(0),
                tun_rx_packets: AtomicU64::new(0),
                tun_tx_packets: AtomicU64::new(0),
                tun_rx_bytes: AtomicU64::new(0),
                tun_tx_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub fn cloud_relay_meter(&self) -> CloudRelayMeter {
        self.inner.cloud_relay_meter.clone()
    }

    pub fn set_cloud_relay_urls(&self, urls: impl IntoIterator<Item = String>) {
        let normalized: HashSet<String> =
            urls.into_iter().map(|u| normalize_relay_url(&u)).collect();
        *self.inner.cloud_relay_urls.write() = normalized;
        self.inner.peer_cloud_relay.clear();
    }

    pub fn cloud_relay_urls(&self) -> HashSet<String> {
        self.inner.cloud_relay_urls.read().clone()
    }

    pub fn set_peer_cloud_relay(&self, peer: EndpointId, metered: bool) {
        self.inner
            .peer_cloud_relay
            .entry(peer)
            .or_insert_with(|| AtomicBool::new(false))
            .store(metered, Ordering::Relaxed);
    }

    pub fn clear_peer_cloud_relay(&self, peer: EndpointId) {
        self.inner.peer_cloud_relay.remove(&peer);
    }

    pub fn peer_is_cloud_relay(&self, peer: EndpointId) -> bool {
        self.inner
            .peer_cloud_relay
            .get(&peer)
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }

    pub fn set_keep_alive(&self, enabled: bool) {
        self.inner.keep_alive.store(enabled, Ordering::Relaxed);
    }

    pub fn keep_alive_global(&self) -> bool {
        self.inner.keep_alive.load(Ordering::Relaxed)
    }

    pub fn add_keep_alive_host(&self, hostname: &str) {
        self.inner
            .keep_alive_hosts
            .insert(hostname.to_ascii_lowercase(), ());
    }

    pub fn remove_keep_alive_host(&self, hostname: &str) {
        self.inner
            .keep_alive_hosts
            .remove(&hostname.to_ascii_lowercase());
    }

    pub fn set_peer_keep_alive(&self, peer: EndpointId, enabled: bool) {
        if enabled {
            self.inner.keep_alive_peers.insert(peer, ());
        } else {
            self.inner.keep_alive_peers.remove(&peer);
        }
    }

    pub fn keep_alive_for(&self, peer: EndpointId, hostname: Option<&str>) -> bool {
        if self.inner.keep_alive.load(Ordering::Relaxed) {
            return true;
        }
        if self.inner.keep_alive_peers.contains_key(&peer) {
            return true;
        }
        hostname.is_some_and(|h| {
            self.inner
                .keep_alive_hosts
                .contains_key(&h.to_ascii_lowercase())
        })
    }

    pub fn heartbeat_counters(&self) -> (u32, u64, u64) {
        (
            self.inner.active_conns.load(Ordering::Relaxed),
            self.inner.bytes_tx.load(Ordering::Relaxed),
            self.inner.bytes_rx.load(Ordering::Relaxed),
        )
    }

    pub fn on_demand_stats(&self) -> OnDemandStats {
        OnDemandStats {
            reconnect_attempts: self.inner.dial_attempts.load(Ordering::Relaxed),
            reconnect_success: self.inner.dial_success.load(Ordering::Relaxed),
            reconnect_fail: self.inner.dial_fail.load(Ordering::Relaxed),
            packets_buffered: 0,
            packets_dropped_timeout: self.inner.stale_drops.load(Ordering::Relaxed),
            packets_dropped_blocked: self.inner.blocked_drops.load(Ordering::Relaxed),
            dials_suppressed: self.inner.dials_suppressed.load(Ordering::Relaxed),
            reconnect_latency_avg_us: 0,
            reconnect_latency_max_us: 0,
        }
    }

    pub fn peer_bytes(&self, peer: EndpointId) -> (u64, u64) {
        self.inner
            .snapshots
            .get(&peer)
            .map(|s| (s.bytes_in, s.bytes_out))
            .unwrap_or((0, 0))
    }

    pub fn has_live(&self, peer: EndpointId) -> bool {
        self.inner.snapshots.get(&peer).is_some_and(|s| s.live)
    }

    pub fn peer_snapshot(&self, peer: EndpointId) -> PeerConnSnapshot {
        let keep_alive = self.keep_alive_for(peer, None);
        match self.inner.snapshots.get(&peer) {
            Some(s) => PeerConnSnapshot {
                state: s.state.clone(),
                keep_alive: keep_alive || s.keep_alive,
                last_activity_secs_ago: s.last_activity.elapsed().as_secs(),
                live: s.live,
                path: s.path.clone(),
            },
            None => PeerConnSnapshot {
                state: "idle".into(),
                keep_alive,
                last_activity_secs_ago: u64::MAX,
                live: false,
                path: "unknown".into(),
            },
        }
    }

    pub fn set_peer_state(
        &self,
        peer: EndpointId,
        state: &str,
        live: bool,
        path: &str,
        keep_alive: bool,
    ) {
        let prev_live = self.inner.snapshots.get(&peer).is_some_and(|s| s.live);
        match (prev_live, live) {
            (false, true) => {
                self.inner.active_conns.fetch_add(1, Ordering::Relaxed);
            }
            (true, false) => {
                self.inner.active_conns.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.inner
            .snapshots
            .entry(peer)
            .and_modify(|s| {
                s.state = state.into();
                s.live = live;
                s.path = path.into();
                s.keep_alive = keep_alive;
                s.last_activity = Instant::now();
            })
            .or_insert_with(|| PeerSnap {
                state: state.into(),
                keep_alive,
                last_activity: Instant::now(),
                live,
                path: path.into(),
                bytes_in: 0,
                bytes_out: 0,
            });
    }

    pub fn record_tx(&self, peer: EndpointId, bytes: u64) {
        self.inner.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.inner.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
        if let Some(mut s) = self.inner.snapshots.get_mut(&peer) {
            s.bytes_out += bytes;
            s.last_activity = Instant::now();
        }
        if self.peer_is_cloud_relay(peer) {
            self.inner.cloud_relay_meter.record(bytes);
        }
    }

    pub fn record_rx(&self, peer: EndpointId, bytes: u64) {
        self.inner.packets_rx.fetch_add(1, Ordering::Relaxed);
        self.inner.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
        if let Some(mut s) = self.inner.snapshots.get_mut(&peer) {
            s.bytes_in += bytes;
            s.last_activity = Instant::now();
        }
    }

    pub fn inc_dial_attempt(&self) {
        self.inner.dial_attempts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dial_success(&self) {
        self.inner.dial_success.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dial_fail(&self) {
        self.inner.dial_fail.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dials_suppressed(&self) {
        self.inner.dials_suppressed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_queue_full(&self) {
        self.inner.queue_full.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_stale(&self) {
        self.inner.stale_drops.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blocked(&self) {
        self.inner.blocked_drops.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_tun_write_drop(&self) {
        self.inner.tun_write_drops.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_send_error(&self) {
        self.inner.send_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_too_large(&self) {
        self.inner.too_large.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_single(&self) {
        self.inner.single_packets.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_segmented(&self) {
        self.inner.segmented_packets.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_segments_tx(&self, n: u64) {
        self.inner.segments_tx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_segments_rx(&self, n: u64) {
        self.inner.segments_rx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn inc_reassembly_malformed(&self) {
        self.inner
            .reassembly_malformed
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_reassembly_expired(&self) {
        self.inner
            .reassembly_expired
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_reassembly_evicted(&self) {
        self.inner
            .reassembly_evicted
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_tun_rx(&self, bytes: u64) {
        self.inner.tun_rx_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.tun_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn record_tun_tx(&self, bytes: u64) {
        self.inner.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.tun_tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn clear_peer(&self, peer: EndpointId) {
        if self
            .inner
            .snapshots
            .remove(&peer)
            .is_some_and(|(_, s)| s.live)
        {
            self.inner.active_conns.fetch_sub(1, Ordering::Relaxed);
        }
        self.inner.peer_cloud_relay.remove(&peer);
    }
}

pub fn normalize_relay_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_alive_peer_override() {
        let mesh = TunnelMesh::new(CloudRelayMeter::new(), false);
        let peer = iroh::SecretKey::generate().public();
        assert!(!mesh.keep_alive_for(peer, Some("host")));
        mesh.set_peer_keep_alive(peer, true);
        assert!(mesh.keep_alive_for(peer, Some("host")));
        mesh.add_keep_alive_host("other");
        assert!(mesh.keep_alive_for(peer, Some("other")));
    }

    #[test]
    fn live_connection_counter() {
        let mesh = TunnelMesh::new(CloudRelayMeter::new(), true);
        let peer = iroh::SecretKey::generate().public();
        mesh.set_peer_state(peer, "connected", true, "direct", true);
        assert_eq!(mesh.heartbeat_counters().0, 1);
        mesh.set_peer_state(peer, "idle", false, "unknown", true);
        assert_eq!(mesh.heartbeat_counters().0, 0);
    }
}
