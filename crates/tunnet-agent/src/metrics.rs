use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use metrics::{Counter, Gauge, counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Cached metric handles: registered once, incremented without per-packet
/// registry lookup. Hot packet/byte counters accumulate in shared atomics
/// (correct across peers — no per-peer gauge overwrite) and flush once a
/// second. Sojourn latency uses a bounded bucket histogram for p50/p95/p99
/// estimates without per-packet registry work. Drop reasons on hot paths
/// use pre-registered handles selected by a plain match.
#[derive(Clone)]
pub struct AgentMetrics {
    handle: PrometheusHandle,
    packets_out: Counter,
    packets_in: Counter,
    bytes_out: Counter,
    bytes_in: Counter,
    active_conns: Gauge,
    queue_packets: Gauge,
    queue_bytes: Gauge,
    queue_flows: Gauge,
    transport_full: Counter,
    frames: Counter,
    segments: Counter,
    pool_hits: Counter,
    pool_miss: Counter,
    drop_sched_stale: Counter,
    drop_sched_peer: Counter,
    drop_sched_flow: Counter,
    drop_sched_codel: Counter,
    drop_policy: Counter,
    drop_too_large: Counter,
    drop_no_conn: Counter,
    drop_other: Counter,
    sojourn_p50: Gauge,
    sojourn_p95: Gauge,
    sojourn_p99: Gauge,
    sojourn_avg: Gauge,
    hot: Arc<HotCounters>,
    sojourn: Arc<SojournHist>,
}

#[derive(Default)]
struct HotCounters {
    packets_out: AtomicU64,
    bytes_out: AtomicU64,
    packets_in: AtomicU64,
    bytes_in: AtomicU64,
    queue_packets: AtomicI64,
    queue_bytes: AtomicI64,
    queue_flows: AtomicI64,
}

/// Sojourn buckets (ms): [1, 5, 25, 100, 250, 1000, +inf). p50/p95/p99 are
/// estimated from cumulative counts — cheap and bounded.
const SOJOURN_BOUNDS_MS: [u64; 6] = [1, 5, 25, 100, 250, 1000];

struct SojournHist {
    buckets: [AtomicU64; 7],
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl SojournHist {
    fn observe(&self, d: Duration) {
        let ms = d.as_millis() as u64;
        let mut idx = 6;
        for (i, b) in SOJOURN_BOUNDS_MS.iter().enumerate() {
            if ms <= *b {
                idx = i;
                break;
            }
        }
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Estimate the q-quantile (0 < q <= 1) as a bucket upper bound in ms.
    fn quantile_ms(&self, q: f64) -> f64 {
        let total: u64 = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum();
        if total == 0 {
            return 0.0;
        }
        let mut cum = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            cum += b.load(Ordering::Relaxed);
            if cum as f64 >= q * total as f64 {
                return if i < SOJOURN_BOUNDS_MS.len() {
                    SOJOURN_BOUNDS_MS[i] as f64
                } else {
                    2000.0
                };
            }
        }
        2000.0
    }
}

impl Default for SojournHist {
    fn default() -> Self {
        Self {
            buckets: Default::default(),
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl AgentMetrics {
    /// Test handle without installing a global recorder (parallel tests).
    #[cfg(test)]
    pub fn for_tests() -> Self {
        let recorder = PrometheusBuilder::new()
            .with_recommended_naming(true)
            .build_recorder();
        Self::from_handle(recorder.handle())
    }

    #[allow(clippy::too_many_lines)]
    fn from_handle(handle: PrometheusHandle) -> Self {
        Self {
            handle,
            packets_out: counter!("tunnet_packets_total", "direction" => "out"),
            packets_in: counter!("tunnet_packets_total", "direction" => "in"),
            bytes_out: counter!("tunnet_bytes_total", "direction" => "out"),
            bytes_in: counter!("tunnet_bytes_total", "direction" => "in"),
            active_conns: gauge!("tunnet_active_connections"),
            queue_packets: gauge!("tunnet_sched_queue_packets"),
            queue_bytes: gauge!("tunnet_sched_queue_bytes"),
            queue_flows: gauge!("tunnet_sched_active_flows"),
            transport_full: counter!("tunnet_sched_transport_full_total"),
            frames: counter!("tunnet_frames_total"),
            segments: counter!("tunnet_segments_total"),
            pool_hits: counter!("tunnet_pool_hits_total"),
            pool_miss: counter!("tunnet_pool_miss_total"),
            drop_sched_stale: counter!("tunnet_sched_drops_total", "reason" => "sched_stale"),
            drop_sched_peer: counter!("tunnet_sched_drops_total", "reason" => "sched_peer"),
            drop_sched_flow: counter!("tunnet_sched_drops_total", "reason" => "sched_flow_cap"),
            drop_sched_codel: counter!("tunnet_sched_drops_total", "reason" => "sched_codel"),
            drop_policy: counter!("tunnet_dropped_packets_total", "reason" => "policy_deny"),
            drop_too_large: counter!("tunnet_dropped_packets_total", "reason" => "datagram_too_large"),
            drop_no_conn: counter!("tunnet_dropped_packets_total", "reason" => "no_connection"),
            drop_other: counter!("tunnet_dropped_packets_total", "reason" => "other"),
            sojourn_p50: gauge!("tunnet_sojourn_p50_ms"),
            sojourn_p95: gauge!("tunnet_sojourn_p95_ms"),
            sojourn_p99: gauge!("tunnet_sojourn_p99_ms"),
            sojourn_avg: gauge!("tunnet_sojourn_avg_ms"),
            hot: Arc::new(HotCounters::default()),
            sojourn: Arc::new(SojournHist::default()),
        }
    }

    pub fn new() -> anyhow::Result<Self> {
        let handle = PrometheusBuilder::new()
            .with_recommended_naming(true)
            .install_recorder()?;

        describe_counter!("tunnet_packets_total", "Packets processed by the tunnel");
        describe_counter!("tunnet_bytes_total", "Bytes processed by the tunnel");
        describe_counter!("tunnet_dropped_packets_total", "Packets dropped");
        describe_counter!(
            "tunnet_sched_transport_full_total",
            "Transport-full events (scheduler owns drop/retry)"
        );
        describe_counter!("tunnet_sched_drops_total", "Scheduler drops by reason");
        describe_counter!("tunnet_frames_total", "Overlay tunnel frames transmitted");
        describe_counter!(
            "tunnet_segments_total",
            "Overlay tunnel segments transmitted"
        );
        describe_counter!("tunnet_reassembly_total", "Reassembly outcomes by result");
        describe_counter!("tunnet_tun_syscalls_total", "TUN syscalls by operation");
        describe_counter!("tunnet_datagrams_total", "QUIC DATAGRAMs by direction");
        describe_counter!("tunnet_pool_hits_total", "Packet pool hits");
        describe_counter!("tunnet_pool_miss_total", "Packet pool misses");
        describe_gauge!("tunnet_active_connections", "Live peer connections");
        describe_gauge!(
            "tunnet_sched_queue_packets",
            "Queued logical packets across all peers"
        );
        describe_gauge!("tunnet_sched_queue_bytes", "Queued bytes across all peers");
        describe_gauge!("tunnet_sched_active_flows", "Active flows across all peers");
        describe_gauge!("tunnet_virtual_mtu_bytes", "Configured logical MTU");
        describe_gauge!("tunnet_sojourn_p50_ms", "Queue sojourn p50 estimate");
        describe_gauge!("tunnet_sojourn_p95_ms", "Queue sojourn p95 estimate");
        describe_gauge!("tunnet_sojourn_p99_ms", "Queue sojourn p99 estimate");
        describe_gauge!("tunnet_sojourn_avg_ms", "Queue sojourn mean");

        let m = Self::from_handle(handle.clone());
        // Periodic flush of hot counters + prometheus upkeep.
        let flush = m.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                flush.flush_hot();
                handle.run_upkeep();
            }
        });

        Ok(m)
    }

    fn flush_hot(&self) {
        let p_out = self.hot.packets_out.swap(0, Ordering::Relaxed);
        let b_out = self.hot.bytes_out.swap(0, Ordering::Relaxed);
        let p_in = self.hot.packets_in.swap(0, Ordering::Relaxed);
        let b_in = self.hot.bytes_in.swap(0, Ordering::Relaxed);
        if p_out > 0 {
            self.packets_out.increment(p_out);
        }
        if b_out > 0 {
            self.bytes_out.increment(b_out);
        }
        if p_in > 0 {
            self.packets_in.increment(p_in);
        }
        if b_in > 0 {
            self.bytes_in.increment(b_in);
        }
        self.queue_packets
            .set(self.hot.queue_packets.load(Ordering::Relaxed) as f64);
        self.queue_bytes
            .set(self.hot.queue_bytes.load(Ordering::Relaxed) as f64);
        self.queue_flows
            .set(self.hot.queue_flows.load(Ordering::Relaxed) as f64);
        self.sojourn_p50.set(self.sojourn.quantile_ms(0.50));
        self.sojourn_p95.set(self.sojourn.quantile_ms(0.95));
        self.sojourn_p99.set(self.sojourn.quantile_ms(0.99));
        let n = self.sojourn.count.load(Ordering::Relaxed);
        if n > 0 {
            self.sojourn_avg
                .set(self.sojourn.sum_us.load(Ordering::Relaxed) as f64 / 1000.0 / n as f64);
        }
    }

    pub fn packets_inc(&self, direction: &'static str) {
        match direction {
            "out" => self.hot.packets_out.fetch_add(1, Ordering::Relaxed),
            "in" => self.hot.packets_in.fetch_add(1, Ordering::Relaxed),
            _ => {
                counter!("tunnet_packets_total", "direction" => direction).increment(1);
                0
            }
        };
    }

    pub fn bytes_add(&self, direction: &'static str, n: u64) {
        match direction {
            "out" => self.hot.bytes_out.fetch_add(n, Ordering::Relaxed),
            "in" => self.hot.bytes_in.fetch_add(n, Ordering::Relaxed),
            _ => {
                counter!("tunnet_bytes_total", "direction" => direction).increment(n);
                0
            }
        };
    }

    /// Drop counter with pre-registered hot handles (no per-packet lookup).
    pub fn dropped_inc(&self, reason: &'static str) {
        match reason {
            "sched_stale" | "sched_emergency" => self.drop_sched_stale.increment(1),
            "sched_peer_bytes" | "sched_peer_packets" => self.drop_sched_peer.increment(1),
            "sched_flow_cap" => self.drop_sched_flow.increment(1),
            "sched_codel" => self.drop_sched_codel.increment(1),
            "policy_deny" | "policy_deny_in" => self.drop_policy.increment(1),
            "datagram_too_large" => self.drop_too_large.increment(1),
            "no_connection" => self.drop_no_conn.increment(1),
            _ => self.drop_other.increment(1),
        }
    }

    /// Scheduler drop (same cached handles; reason already scheduler-scoped).
    pub fn sched_drop_inc(&self, reason: &'static str) {
        self.dropped_inc(reason);
    }

    /// Report drained scheduler drop deltas (CoDel/emergency drops observed
    /// inside dequeue, which have no enqueue decision site to report them).
    pub fn sched_drops_add(&self, codel: u64, emergency: u64) {
        if codel > 0 {
            self.drop_sched_codel.increment(codel);
        }
        if emergency > 0 {
            self.drop_sched_stale.increment(emergency);
        }
    }

    /// Aggregate queue levels across all peers (signed deltas, never
    /// overwrites another peer's values).
    pub fn queue_add(&self, packets: i64, bytes: i64, flows: i64) {
        if packets != 0 {
            self.hot.queue_packets.fetch_add(packets, Ordering::Relaxed);
        }
        if bytes != 0 {
            self.hot.queue_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        if flows != 0 {
            self.hot.queue_flows.fetch_add(flows, Ordering::Relaxed);
        }
    }

    pub fn sched_transport_full_inc(&self) {
        self.transport_full.increment(1);
    }

    /// Phase 2 telemetry (all cached handles, no per-packet registry work).
    pub fn frame_sent_inc(&self, segments: u64) {
        self.frames.increment(1);
        if segments > 1 {
            self.segments.increment(segments);
        }
    }

    pub fn observe_sojourn(&self, d: Duration) {
        self.sojourn.observe(d);
    }

    pub fn reassembly_inc(&self, result: &'static str) {
        counter!("tunnet_reassembly_total", "result" => result).increment(1);
    }

    pub fn tun_syscall_inc(&self, op: &'static str) {
        counter!("tunnet_tun_syscalls_total", "op" => op).increment(1);
    }

    pub fn datagram_inc(&self, direction: &'static str) {
        counter!("tunnet_datagrams_total", "direction" => direction).increment(1);
    }

    pub fn pool_hit_miss(&self, hits: u64, misses: u64) {
        if hits > 0 {
            self.pool_hits.increment(hits);
        }
        if misses > 0 {
            self.pool_miss.increment(misses);
        }
    }

    pub fn mtu_set(&self, mtu: u64) {
        gauge!("tunnet_virtual_mtu_bytes").set(mtu as f64);
    }

    pub fn active_conns_inc(&self) {
        self.active_conns.increment(1.0);
    }

    pub fn active_conns_dec(&self) {
        self.active_conns.decrement(1.0);
    }

    pub fn render(&self) -> String {
        self.handle.render()
    }
}

pub fn metrics_port(bind: &str) -> &str {
    bind.rsplit(':').next().unwrap_or("9100")
}

/// Listen on localhost and the assigned overlay IP so peers can scrape via VPN.
pub fn spawn_listeners(metrics: AgentMetrics, metrics_bind: &str, overlay_ip: std::net::Ipv4Addr) {
    let port = metrics_port(metrics_bind);
    for bind in [
        format!("127.0.0.1:{}", port),
        format!("{}:{}", overlay_ip, port),
    ] {
        let m = metrics.clone();
        tokio::spawn(async move { serve_metrics(m, bind).await });
    }
}

pub async fn serve_metrics(metrics: AgentMetrics, bind: String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(?e, "failed to bind metrics endpoint");
            return;
        }
    };
    tracing::info!(%bind, "metrics endpoint listening");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let m = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // best-effort: read the request line
            let body = m.render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
