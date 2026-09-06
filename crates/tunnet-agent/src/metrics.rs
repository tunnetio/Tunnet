//! Metrics recorded at packet admission, transport submission, and OS delivery.
use metrics::{Counter, Gauge, counter, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
#[derive(Clone)]
pub struct AgentMetrics {
    handle: PrometheusHandle,
    packets_out: Counter,
    packets_in: Counter,
    bytes_out: Counter,
    bytes_in: Counter,
    active_conns: Gauge,
    interrupted: Counter,
    queue_packets: Gauge,
    queue_bytes: Gauge,
    overlay_tx_logical: Counter,
    overlay_tx_datagrams: Counter,
    overlay_rx_logical: Counter,
    tun_rx_packets: Counter,
    tun_rx_bytes: Counter,
    tun_tx_bytes: Counter,
    overlay_tx_bytes: Counter,
    overlay_rx_bytes: Counter,
    tun_write_queued: Counter,
    tun_write_packets: Counter,
    tun_write_queue_drop: Counter,
    pool_hits: Counter,
    pool_miss: Counter,
}
impl AgentMetrics {
    fn from_handle(handle: PrometheusHandle) -> Self {
        Self {
            handle,
            packets_out: counter!("tunnet_packets_total", "direction" => "out"),
            packets_in: counter!("tunnet_packets_total", "direction" => "in"),
            bytes_out: counter!("tunnet_bytes_total", "direction" => "out"),
            bytes_in: counter!("tunnet_bytes_total", "direction" => "in"),
            interrupted: counter!("tunnet_dropped_packets_total", "reason" => "connection_interrupted"),
            active_conns: gauge!("tunnet_active_connections"),
            queue_packets: gauge!("tunnet_queue_packets"),
            queue_bytes: gauge!("tunnet_queue_bytes"),
            overlay_tx_logical: counter!("tunnet_overlay_tx_logical_total"),
            overlay_tx_datagrams: counter!("tunnet_overlay_tx_datagrams_total"),
            overlay_rx_logical: counter!("tunnet_overlay_rx_logical_total"),
            tun_rx_bytes: counter!("tunnet_tun_rx_bytes_total"),
            tun_tx_bytes: counter!("tunnet_tun_tx_bytes_total"),
            overlay_tx_bytes: counter!("tunnet_overlay_tx_bytes_total"),
            overlay_rx_bytes: counter!("tunnet_overlay_rx_bytes_total"),
            tun_rx_packets: counter!("tunnet_tun_rx_packets_total"),
            tun_write_queued: counter!("tunnet_tun_write_queued_total"),
            tun_write_packets: counter!("tunnet_tun_write_packets_total"),
            tun_write_queue_drop: counter!("tunnet_tun_write_queue_drop_total"),
            pool_hits: counter!("tunnet_pool_hits_total"),
            pool_miss: counter!("tunnet_pool_miss_total"),
        }
    }
    #[cfg(test)]
    pub fn for_tests() -> Self {
        let recorder = PrometheusBuilder::new()
            .with_recommended_naming(true)
            .build_recorder();
        metrics::with_local_recorder(&recorder, || Self::from_handle(recorder.handle()))
    }
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::from_handle(
            PrometheusBuilder::new()
                .with_recommended_naming(true)
                .install_recorder()?,
        ))
    }
    pub fn interrupted_counter(&self) -> Counter {
        self.interrupted.clone()
    }
    pub fn packets_inc(&self, direction: &'static str) {
        if direction == "out" {
            self.packets_out.increment(1);
        } else {
            self.packets_in.increment(1);
        }
    }
    pub fn bytes_add(&self, direction: &'static str, n: u64) {
        if direction == "out" {
            self.bytes_out.increment(n);
        } else {
            self.bytes_in.increment(n);
        }
    }
    pub fn dropped_inc(&self, reason: &'static str) {
        self.dropped_add(reason, 1);
    }
    pub fn dropped_add(&self, reason: &'static str, n: u64) {
        if n > 0 {
            counter!("tunnet_dropped_packets_total", "reason" => reason).increment(n);
        }
    }
    pub fn queue_add(&self, packets: i64, bytes: i64) {
        self.queue_packets.increment(packets as f64);
        self.queue_bytes.increment(bytes as f64);
    }
    pub fn tun_rx_packets_inc(&self, bytes: usize) {
        self.tun_rx_bytes.increment(bytes as u64);
        self.tun_rx_packets.increment(1);
    }
    pub fn overlay_tx_logical_add(&self, n: u64) {
        self.overlay_tx_logical.increment(n);
    }
    pub fn overlay_tx_datagrams_add(&self, n: u64, bytes: usize) {
        self.overlay_tx_bytes.increment(bytes as u64);
        self.overlay_tx_datagrams.increment(n);
    }
    pub fn overlay_rx_logical_inc(&self) {
        self.overlay_rx_logical.increment(1);
    }
    pub fn tun_write_queued(&self) {
        self.tun_write_queued.increment(1);
    }
    pub fn tun_write_packets_add(&self, n: u64, bytes: usize) {
        self.tun_tx_bytes.increment(bytes as u64);
        self.tun_write_packets.increment(n);
    }
    pub fn tun_write_queue_drop(&self) {
        self.tun_write_queue_drop.increment(1);
    }
    pub fn tun_syscall_inc(&self, op: &'static str) {
        counter!("tunnet_tun_syscalls_total", "op" => op).increment(1);
    }
    pub fn datagram_inc(&self, direction: &'static str, bytes: usize) {
        self.overlay_rx_bytes.increment(bytes as u64);
        counter!("tunnet_datagrams_total", "direction" => direction).increment(1);
    }
    pub fn pool_hit_miss(&self, hits: u64, misses: u64) {
        self.pool_hits.increment(hits);
        self.pool_miss.increment(misses);
    }
    pub fn mtu_set(&self, mtu: u64) {
        gauge!("tunnet_virtual_mtu_bytes").set(mtu as f64);
    }
    pub fn dataplane_set(
        &self,
        up: bool,
        generation: u64,
        restart_count: u64,
        outbound_alive: bool,
        writer_alive: bool,
    ) {
        gauge!("tunnet_dataplane_up").set(if up { 1.0 } else { 0.0 });
        gauge!("tunnet_dataplane_generation").set(generation as f64);
        gauge!("tunnet_dataplane_restart_count").set(restart_count as f64);
        gauge!("tunnet_dataplane_outbound_alive").set(if outbound_alive { 1.0 } else { 0.0 });
        gauge!("tunnet_dataplane_writer_alive").set(if writer_alive { 1.0 } else { 0.0 });
    }
    pub fn active_conns_inc(&self) {
        self.active_conns.increment(1.0);
    }
    pub fn active_conns_dec(&self) {
        self.active_conns.decrement(1.0);
    }
    pub fn render(&self) -> String {
        self.handle.run_upkeep();
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
