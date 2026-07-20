use std::time::Duration;

use async_trait::async_trait;
use rand::RngExt;

use crate::event::AuditEvent;

#[async_trait]
pub trait AuditStream: Send + Sync {
    fn name(&self) -> &str;
    async fn send_batch(&self, events: &[AuditEvent]) -> anyhow::Result<()>;
    fn clone_box(&self) -> Box<dyn AuditStream>;

    async fn send_with_retry(&self, events: &[AuditEvent], max_retries: u32) {
        let mut attempt = 0u32;
        let mut delay = Duration::from_secs(30);

        loop {
            match self.send_batch(events).await {
                Ok(()) => return,
                Err(e) if attempt < max_retries => {
                    attempt += 1;
                    let jitter = rand::rng().random_range(0..delay.as_millis().max(1) as u64 / 4);
                    tracing::warn!(
                        stream = self.name(),
                        attempt,
                        ?e,
                        "audit stream delivery failed, retrying"
                    );
                    tokio::time::sleep(delay + Duration::from_millis(jitter)).await;
                    delay = (delay * 2).min(Duration::from_secs(240));
                }
                Err(e) => {
                    tracing::error!(
                        stream = self.name(),
                        attempt,
                        ?e,
                        events_dropped = events.len(),
                        "audit stream delivery failed permanently"
                    );
                    return;
                }
            }
        }
    }
}

/// Community-tier generic webhook stream.
pub struct WebhookStream {
    url: String,
    headers: Vec<(String, String)>,
    client: reqwest::Client,
}

impl WebhookStream {
    pub fn new(url: String, headers: Vec<(String, String)>) -> Self {
        Self {
            url,
            headers,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AuditStream for WebhookStream {
    fn name(&self) -> &str {
        "webhook"
    }

    fn clone_box(&self) -> Box<dyn AuditStream> {
        Box::new(Self {
            url: self.url.clone(),
            headers: self.headers.clone(),
            client: self.client.clone(),
        })
    }

    async fn send_batch(&self, events: &[AuditEvent]) -> anyhow::Result<()> {
        // Cap at 500 events / ~1MB per Infisical-style delivery.
        for chunk in events.chunks(500) {
            let mut req = self.client.post(&self.url).json(chunk);
            for (k, v) in &self.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("webhook returned {}", resp.status());
            }
        }
        Ok(())
    }
}
