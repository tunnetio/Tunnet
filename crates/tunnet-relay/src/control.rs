//! Optional registration + heartbeat + cloud metering against the Tunnet control plane.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ControlClient {
    base: String,
    http: reqwest::Client,
    token: String,
    metering_enabled: Arc<AtomicBool>,
    /// Per-organization bytes awaiting flush (cloud deployment relays only).
    pending: Arc<Mutex<HashMap<String, u64>>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    url: String,
    region: String,
    qad_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_url: Option<String>,
    access_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub relay_id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub metering_enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageEntry {
    organization_id: String,
    bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageBody {
    entries: Vec<UsageEntry>,
}

impl ControlClient {
    pub fn new(base: String, token: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
            token,
            metering_enabled: Arc::new(AtomicBool::new(false)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn metering_enabled(&self) -> bool {
        self.metering_enabled.load(Ordering::Relaxed)
    }

    pub async fn register(
        &self,
        url: &str,
        region: &str,
        qad_enabled: bool,
        metrics_url: Option<&str>,
        access_mode: &str,
    ) -> anyhow::Result<RegisterResponse> {
        let endpoint = format!("{}/v1/connectivity-relay/register", self.base);
        let resp = self
            .http
            .post(&endpoint)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&RegisterBody {
                url: url.to_string(),
                region: region.to_string(),
                qad_enabled,
                metrics_url: metrics_url.map(str::to_string),
                access_mode: access_mode.to_string(),
            })
            .send()
            .await
            .with_context(|| format!("POST {endpoint}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("connectivity-relay register failed: {status}: {text}");
        }
        let parsed: RegisterResponse = serde_json::from_str(&text)?;
        self.metering_enabled
            .store(parsed.metering_enabled, Ordering::Relaxed);
        if parsed.metering_enabled {
            tracing::info!("cloud deployment relay metering enabled");
        } else {
            tracing::info!("relay metering disabled (org self-hosted relay or non-cloud control)");
        }
        Ok(parsed)
    }

    pub async fn heartbeat(
        &self,
        status: Option<&str>,
        metrics: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let endpoint = format!("{}/v1/connectivity-relay/heartbeat", self.base);
        let resp = self
            .http
            .post(&endpoint)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&HeartbeatBody {
                status: status.map(str::to_string),
                metrics,
            })
            .send()
            .await
            .with_context(|| format!("POST {endpoint}"))?;
        let status_code = resp.status();
        if !status_code.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("connectivity-relay heartbeat failed: {status_code}: {text}");
        }
        Ok(())
    }

    async fn flush_usage(&self) -> anyhow::Result<()> {
        if !self.metering_enabled() {
            return Ok(());
        }
        let drained: Vec<(String, u64)> = {
            let mut guard = self.pending.lock().expect("usage meter poisoned");
            guard.drain().filter(|(_, n)| *n > 0).collect()
        };
        if drained.is_empty() {
            return Ok(());
        }
        let entries: Vec<UsageEntry> = drained
            .into_iter()
            .map(|(organization_id, bytes)| UsageEntry {
                organization_id,
                bytes,
            })
            .collect();
        let endpoint = format!("{}/v1/connectivity-relay/usage", self.base);
        let resp = self
            .http
            .post(&endpoint)
            .header("authorization", format!("Bearer {}", self.token))
            .json(&UsageBody { entries })
            .send()
            .await
            .with_context(|| format!("POST {endpoint}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("connectivity-relay usage failed: {status}: {text}");
        }
        Ok(())
    }

    pub fn spawn_heartbeat_loop(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(e) = self.flush_usage().await {
                    tracing::debug!(?e, "relay usage flush failed");
                }
                if let Err(e) = self
                    .heartbeat(Some("healthy"), Some(serde_json::json!({ "ok": true })))
                    .await
                {
                    tracing::warn!(?e, "relay heartbeat failed");
                }
            }
        })
    }
}
