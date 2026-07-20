use std::time::Duration;

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub hmac_key: Vec<u8>,
    pub buffer_capacity: usize,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub webhook_url: Option<String>,
    pub webhook_headers: Vec<(String, String)>,
}

impl AuditConfig {
    /// Load from environment. Returns `None` if `TUNNET_AUDIT_HMAC_KEY` is missing.
    pub fn from_env() -> anyhow::Result<Self> {
        let hmac_key = std::env::var("TUNNET_AUDIT_HMAC_KEY")
            .map_err(|_| anyhow::anyhow!("TUNNET_AUDIT_HMAC_KEY is required"))?;
        if hmac_key.len() < 32 {
            anyhow::bail!("TUNNET_AUDIT_HMAC_KEY must be at least 32 characters");
        }

        let buffer_capacity = std::env::var("TUNNET_AUDIT_BUFFER_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8192);
        let batch_size = std::env::var("TUNNET_AUDIT_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let flush_ms = std::env::var("TUNNET_AUDIT_FLUSH_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000u64);

        let webhook_url = std::env::var("TUNNET_AUDIT_STREAM_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let webhook_headers = std::env::var("TUNNET_AUDIT_STREAM_WEBHOOK_HEADERS")
            .ok()
            .map(|s| parse_headers(&s))
            .unwrap_or_default();

        Ok(Self {
            hmac_key: hmac_key.into_bytes(),
            buffer_capacity,
            batch_size,
            flush_interval: Duration::from_millis(flush_ms),
            webhook_url,
            webhook_headers,
        })
    }
}

fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            let (k, v) = pair.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
