use metrics::{counter, describe_counter, describe_gauge, gauge};

#[derive(Clone)]
#[cfg_attr(not(feature = "metrics-serve"), derive(Default))]
pub struct AgentMetrics {
    #[cfg(feature = "metrics-serve")]
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

impl AgentMetrics {
    /// Test handle without installing a global recorder (parallel tests).
    #[cfg(test)]
    pub fn for_tests() -> Self {
        #[cfg(feature = "metrics-serve")]
        {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new()
                .with_recommended_naming(true)
                .build_recorder();
            Self {
                handle: recorder.handle(),
            }
        }
        #[cfg(not(feature = "metrics-serve"))]
        Self::default()
    }

    pub fn new() -> anyhow::Result<Self> {
        #[cfg(feature = "metrics-serve")]
        {
            static RECORDER: parking_lot::Mutex<
                Option<metrics_exporter_prometheus::PrometheusHandle>,
            > = parking_lot::Mutex::new(None);
            let mut recorder = RECORDER.lock();
            if let Some(handle) = recorder.as_ref() {
                return Ok(Self {
                    handle: handle.clone(),
                });
            }
            let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
                .with_recommended_naming(true)
                .install_recorder()?;

            describe_counter!("tunnet_packets_total", "Packets processed by the tunnel");
            describe_counter!("tunnet_bytes_total", "Bytes processed by the tunnel");
            describe_counter!("tunnet_batches_total", "TUN/QUIC processing batches");
            describe_counter!(
                "tunnet_batch_packets_total",
                "Packets across processing batches"
            );
            describe_counter!("tunnet_dropped_packets_total", "Packets dropped");
            describe_gauge!("tunnet_active_connections", "Live peer connections");
            describe_gauge!(
                "tunnet_direct_network_conflicts",
                "Active Direct address-plan conflicts by category"
            );
            describe_gauge!(
                "tunnet_direct_network_healthy",
                "Direct network health (1 healthy, 0 degraded)"
            );

            *recorder = Some(handle.clone());
            Ok(Self { handle })
        }
        #[cfg(not(feature = "metrics-serve"))]
        {
            describe_counter!("tunnet_packets_total", "Packets processed by the tunnel");
            describe_counter!("tunnet_bytes_total", "Bytes processed by the tunnel");
            describe_counter!("tunnet_batches_total", "TUN/QUIC processing batches");
            describe_counter!(
                "tunnet_batch_packets_total",
                "Packets across processing batches"
            );
            describe_counter!("tunnet_dropped_packets_total", "Packets dropped");
            describe_gauge!("tunnet_active_connections", "Live peer connections");
            describe_gauge!(
                "tunnet_direct_network_conflicts",
                "Active Direct address-plan conflicts by category"
            );
            describe_gauge!(
                "tunnet_direct_network_healthy",
                "Direct network health (1 healthy, 0 degraded)"
            );
            Ok(Self::default())
        }
    }

    pub fn packets_add(&self, direction: &'static str, n: u64) {
        counter!("tunnet_packets_total", "direction" => direction).increment(n);
    }

    pub fn batch_observe(&self, direction: &'static str, n: u64) {
        counter!("tunnet_batch_packets_total", "direction" => direction).increment(n);
        counter!("tunnet_batches_total", "direction" => direction).increment(1);
    }

    pub fn bytes_add(&self, direction: &'static str, n: u64) {
        counter!("tunnet_bytes_total", "direction" => direction).increment(n);
    }

    pub fn dropped_add(&self, reason: &'static str, n: u64) {
        counter!("tunnet_dropped_packets_total", "reason" => reason).increment(n);
    }

    pub fn dropped_inc(&self, reason: &'static str) {
        self.dropped_add(reason, 1);
    }

    pub fn active_conns_inc(&self) {
        gauge!("tunnet_active_connections").increment(1.0);
    }

    pub fn active_conns_dec(&self) {
        gauge!("tunnet_active_connections").decrement(1.0);
    }

    pub fn direct_conflict(&self, category: &'static str, count: f64) {
        gauge!("tunnet_direct_network_conflicts", "category" => category).set(count);
    }

    pub fn direct_health(&self, healthy: bool) {
        gauge!("tunnet_direct_network_healthy").set(if healthy { 1.0 } else { 0.0 });
    }

    #[cfg(feature = "metrics-serve")]
    pub fn render(&self) -> String {
        self.handle.run_upkeep();
        self.handle.render()
    }
}

#[cfg(feature = "metrics-serve")]
pub fn metrics_port(bind: &str) -> &str {
    bind.rsplit(':').next().unwrap_or("9100")
}

/// Listen on localhost and the assigned overlay IP so peers can scrape via VPN.
#[cfg(feature = "metrics-serve")]
pub fn spawn_listeners(
    metrics: AgentMetrics,
    metrics_bind: &str,
    overlay_ip: std::net::Ipv4Addr,
) -> Vec<tokio::task::JoinHandle<()>> {
    let port = metrics_port(metrics_bind);
    let mut tasks = Vec::new();
    for bind in [
        format!("127.0.0.1:{}", port),
        format!("{}:{}", overlay_ip, port),
    ] {
        let m = metrics.clone();
        tasks.push(tokio::spawn(async move { serve_metrics(m, bind).await }));
    }
    tasks
}

#[cfg(feature = "metrics-serve")]
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
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept(), if connections.len() < 32 => accepted,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok((mut sock, _)) = accepted else {
            continue;
        };
        let m = metrics.clone();
        connections.spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // best-effort: read the request line
            let body = m.render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            }).await;
        });
    }
}
