//! In-memory ring buffer of captured HTTP exchanges.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use uuid::Uuid;

/// Max bytes of each body kept in the inspector.
pub const BODY_CAP: usize = 1024 * 1024;
/// Max exchanges retained (oldest dropped).
pub const RING_CAP: usize = 100;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedExchange {
    pub id: String,
    pub tunnel_id: String,
    pub started_at: String,
    pub method: String,
    pub path: String,
    pub request_headers: Vec<(String, String)>,
    #[serde(serialize_with = "ser_body")]
    pub request_body: Vec<u8>,
    pub request_body_truncated: bool,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    #[serde(serialize_with = "ser_body")]
    pub response_body: Vec<u8>,
    pub response_body_truncated: bool,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayed_from: Option<String>,
}

fn ser_body<S: serde::Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    // Prefer UTF-8 text; fall back to base64 for binary.
    match std::str::from_utf8(bytes) {
        Ok(text) => s.serialize_str(text),
        Err(_) => s.serialize_str(&format!(
            "base64:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes,)
        )),
    }
}

#[derive(Clone, Default)]
pub struct ExchangeStore {
    inner: Arc<Mutex<VecDeque<CapturedExchange>>>,
}

impl ExchangeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, exchange: CapturedExchange) {
        let mut guard = self.inner.lock();
        if guard.len() >= RING_CAP {
            guard.pop_front();
        }
        guard.push_back(exchange);
    }

    pub fn list(&self) -> Vec<CapturedExchange> {
        self.inner.lock().iter().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<CapturedExchange> {
        self.inner.lock().iter().find(|e| e.id == id).cloned()
    }

    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    pub fn new_id() -> String {
        Uuid::new_v4().to_string()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeSummary {
    pub id: String,
    pub tunnel_id: String,
    pub started_at: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub request_body_truncated: bool,
    pub response_body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayed_from: Option<String>,
}

impl From<&CapturedExchange> for ExchangeSummary {
    fn from(e: &CapturedExchange) -> Self {
        Self {
            id: e.id.clone(),
            tunnel_id: e.tunnel_id.clone(),
            started_at: e.started_at.clone(),
            method: e.method.clone(),
            path: e.path.clone(),
            status: e.status,
            latency_ms: e.latency_ms,
            request_body_truncated: e.request_body_truncated,
            response_body_truncated: e.response_body_truncated,
            replayed_from: e.replayed_from.clone(),
        }
    }
}
