//! Heartbeat + registration against the Tunnet control / management plane.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tunnet_common::{PortMapping, RedirectRule};

use crate::agent_accept::{AuthStore, TunnelAuth};
use crate::metrics::EdgeMetrics;
use crate::tcp::TcpMappingManager;
use crate::usage::UsageMeter;

#[derive(Clone)]
pub struct ControlClient {
    base: String,
    http: reqwest::Client,
    token: String,
    metrics: EdgeMetrics,
    /// True only for Tunnet Cloud hosted edges (control tells us at register).
    metering_enabled: Arc<AtomicBool>,
    usage: UsageMeter,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    endpoint_id: String,
    public_ip: Option<String>,
    agent_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub edge_id: String,
    pub name: String,
    pub domain: String,
    /// When true, this edge must batch-report splice bytes to the control plane.
    #[serde(default)]
    pub metering_enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatBody {
    endpoint_id: String,
    active_tunnels: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_valid_until: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatTunnelAuth {
    #[serde(default)]
    tunnel_id: String,
    subdomain: String,
    auth_token: String,
    #[serde(default)]
    local_port: u16,
    #[serde(default = "default_https")]
    protocol: String,
    #[serde(default)]
    basic_auth_user: Option<String>,
    #[serde(default)]
    basic_auth_password_hash: Option<String>,
    #[serde(default)]
    redirect_rules: Vec<RedirectRule>,
    #[serde(default)]
    port_mappings: Vec<PortMapping>,
}

fn default_https() -> String {
    "https".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeartbeatResponse {
    #[serde(default)]
    tunnels: Vec<HeartbeatTunnelAuth>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficLogLine {
    tunnel_id: String,
    method: String,
    path: String,
    status_code: i32,
    latency_ms: i32,
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficIngestBody {
    logs: Vec<TrafficLogLine>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageEntry {
    tunnel_id: String,
    bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageIngestBody {
    entries: Vec<UsageEntry>,
}

impl ControlClient {
    pub fn new(base: String, token: String, metrics: EdgeMetrics) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
            token,
            metrics,
            metering_enabled: Arc::new(AtomicBool::new(false)),
            usage: UsageMeter::new(),
        })
    }

    pub fn metering_enabled(&self) -> bool {
        self.metering_enabled.load(Ordering::Relaxed)
    }

    pub fn record_bytes(&self, tunnel_id: &str, bytes: u64) {
        if !self.metering_enabled() || bytes == 0 {
            return;
        }
        self.usage.record(tunnel_id, bytes);
    }

    pub async fn register(
        &self,
        endpoint_id: &str,
        public_ip: Option<String>,
    ) -> anyhow::Result<RegisterResponse> {
        let url = format!("{}/v1/edge/register", self.base);
        let resp = self
            .http
            .post(&url)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&RegisterBody {
                endpoint_id: endpoint_id.to_string(),
                public_ip,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            self.metrics.control_failure("register");
            anyhow::bail!("edge register failed: {status}: {text}");
        }
        let parsed: RegisterResponse = serde_json::from_str(&text)?;
        self.metering_enabled
            .store(parsed.metering_enabled, Ordering::Relaxed);
        if parsed.metering_enabled {
            tracing::info!("cloud hosted edge metering enabled");
        } else {
            tracing::info!("edge metering disabled (self-hosted or non-cloud control)");
        }
        Ok(parsed)
    }

    pub async fn heartbeat(
        &self,
        endpoint_id: &str,
        active_tunnels: u32,
        cert_valid_until: Option<&str>,
    ) -> anyhow::Result<HeartbeatResponse> {
        let url = format!("{}/v1/edge/heartbeat", self.base);
        let resp = self
            .http
            .post(&url)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&HeartbeatBody {
                endpoint_id: endpoint_id.to_string(),
                active_tunnels,
                cert_valid_until: cert_valid_until.map(str::to_string),
            })
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            self.metrics.control_failure("heartbeat");
            anyhow::bail!("edge heartbeat failed: {status}: {text}");
        }
        match serde_json::from_str(&text) {
            Ok(v) => Ok(v),
            Err(_) => Ok(HeartbeatResponse { tunnels: vec![] }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn_traffic_log(
        &self,
        tunnel_id: String,
        method: String,
        path: String,
        status_code: i32,
        latency_ms: i32,
        source_ip: Option<String>,
        bytes: Option<u64>,
    ) {
        // Request audit logs are fine for all edges; byte billing is separate.
        let client = self.clone();
        tokio::spawn(async move {
            if let Err(e) = client
                .post_traffic(vec![TrafficLogLine {
                    tunnel_id,
                    method,
                    path,
                    status_code,
                    latency_ms,
                    source_ip,
                    created_at: Some(jiff::Timestamp::now().to_string()),
                    bytes: bytes.map(|b| b as i64),
                }])
                .await
            {
                client.metrics.control_failure("traffic");
                tracing::debug!(?e, "traffic log post failed");
            }
        });
    }

    async fn post_traffic(&self, logs: Vec<TrafficLogLine>) -> anyhow::Result<()> {
        if logs.is_empty() {
            return Ok(());
        }
        let url = format!("{}/v1/edge/traffic", self.base);
        let resp = self
            .http
            .post(&url)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&TrafficIngestBody { logs })
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("traffic ingest failed: {status}: {text}");
        }
        Ok(())
    }

    async fn post_usage(&self, entries: Vec<UsageEntry>) -> anyhow::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let url = format!("{}/v1/edge/usage", self.base);
        let resp = self
            .http
            .post(&url)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&UsageIngestBody { entries })
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("usage ingest failed: {status}: {text}");
        }
        Ok(())
    }

    /// Flush accumulated splice bytes (cloud hosted edges only).
    pub async fn flush_usage(&self) -> anyhow::Result<()> {
        if !self.metering_enabled() {
            return Ok(());
        }
        let drained = self.usage.take_all();
        if drained.is_empty() {
            return Ok(());
        }
        let entries: Vec<UsageEntry> = drained
            .into_iter()
            .map(|(tunnel_id, bytes)| UsageEntry { tunnel_id, bytes })
            .collect();
        self.post_usage(entries).await
    }
}

pub fn spawn_heartbeat_loop(
    client: ControlClient,
    endpoint_id: String,
    registry: crate::registry::TunnelRegistry,
    auth: AuthStore,
    tcp_mgr: TcpMappingManager,
    cert_valid_until: Option<String>,
    metrics: EdgeMetrics,
) {
    let client = Arc::new(client);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let n = registry.active_count() as u32;
            metrics.set_active_tunnels(registry.active_count());

            // Batch cloud hosted traffic accounting with the heartbeat cadence.
            if let Err(e) = client.flush_usage().await {
                client.metrics.control_failure("usage");
                tracing::debug!(?e, "edge usage flush failed");
            }

            match client
                .heartbeat(&endpoint_id, n, cert_valid_until.as_deref())
                .await
            {
                Ok(resp) => {
                    metrics.heartbeat_ok(true);
                    let mut keep = Vec::with_capacity(resp.tunnels.len());
                    let mut mappings: Vec<(String, String, PortMapping)> = Vec::new();
                    for t in resp.tunnels {
                        keep.push(t.subdomain.clone());
                        let mut maps = t.port_mappings.clone();
                        if t.protocol == "tcp" && maps.is_empty() && t.local_port > 0 {
                            maps.push(PortMapping {
                                external_port: t.local_port,
                                target_port: t.local_port,
                                target_ipv4: None,
                            });
                        }
                        for m in &maps {
                            mappings.push((t.subdomain.clone(), t.tunnel_id.clone(), m.clone()));
                        }
                        auth.insert(
                            &t.subdomain,
                            TunnelAuth {
                                tunnel_id: t.tunnel_id,
                                auth_token: t.auth_token,
                                local_port: t.local_port,
                                protocol: t.protocol,
                                basic_auth_user: t.basic_auth_user,
                                basic_auth_password_hash: t.basic_auth_password_hash,
                                redirect_rules: t.redirect_rules,
                                port_mappings: maps,
                            },
                        );
                    }
                    auth.retain_subdomains(&keep);
                    tcp_mgr.reconcile(mappings, registry.clone(), metrics.clone());
                }
                Err(e) => {
                    metrics.heartbeat_ok(false);
                    tracing::warn!(?e, "edge heartbeat failed");
                }
            }
        }
    });
}
