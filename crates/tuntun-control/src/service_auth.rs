//! HMAC authentication for management → control-plane internal API.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

const HDR_TIMESTAMP: &str = "x-tuntun-timestamp";
const HDR_NONCE: &str = "x-tuntun-nonce";
const HDR_SIGNATURE: &str = "x-tuntun-signature";
const MAX_SKEW_SECS: i64 = 60;
const NONCE_TTL_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct ServiceAuth {
    secret: Vec<u8>,
    seen_nonces: DashMap<String, i64>,
}

impl ServiceAuth {
    pub fn new(secret: &str) -> anyhow::Result<Self> {
        if secret.len() < 32 {
            anyhow::bail!("TUNTUN_SERVICE_SECRET must be at least 32 characters");
        }
        Ok(Self {
            secret: secret.as_bytes().to_vec(),
            seen_nonces: DashMap::new(),
        })
    }

    pub async fn verify(
        &self,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Result<(), ServiceAuthError> {
        let timestamp = headers
            .get(HDR_TIMESTAMP)
            .and_then(|v| v.to_str().ok())
            .ok_or(ServiceAuthError::MissingHeader)?;
        let nonce = headers
            .get(HDR_NONCE)
            .and_then(|v| v.to_str().ok())
            .ok_or(ServiceAuthError::MissingHeader)?;
        let signature = headers
            .get(HDR_SIGNATURE)
            .and_then(|v| v.to_str().ok())
            .ok_or(ServiceAuthError::MissingHeader)?;

        let ts: i64 = timestamp
            .parse()
            .map_err(|_| ServiceAuthError::InvalidTimestamp)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if (now - ts).abs() > MAX_SKEW_SECS {
            return Err(ServiceAuthError::StaleTimestamp);
        }

        self.prune_nonces(now);
        if self.seen_nonces.insert(nonce.to_string(), now).is_some() {
            return Err(ServiceAuthError::Replay);
        }

        let mut hasher = Sha256::new();
        hasher.update(body);
        let body_hash = hex::encode(hasher.finalize());
        let canonical = format!("{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}");

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| ServiceAuthError::BadSignature)?;
        mac.update(canonical.as_bytes());
        let expected = mac.finalize().into_bytes();

        let provided = hex::decode(signature).map_err(|_| ServiceAuthError::BadSignature)?;
        if provided.len() != expected.len() || !subtle_eq(&provided, expected.as_slice()) {
            return Err(ServiceAuthError::BadSignature);
        }

        Ok(())
    }

    fn prune_nonces(&self, now: i64) {
        self.seen_nonces
            .retain(|_, ts| now.saturating_sub(*ts) <= NONCE_TTL_SECS);
    }
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[derive(Debug)]
pub enum ServiceAuthError {
    MissingHeader,
    InvalidTimestamp,
    StaleTimestamp,
    Replay,
    BadSignature,
}

impl IntoResponse for ServiceAuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::MissingHeader => (StatusCode::UNAUTHORIZED, "missing service auth headers"),
            Self::InvalidTimestamp | Self::StaleTimestamp => {
                (StatusCode::UNAUTHORIZED, "stale timestamp")
            }
            Self::Replay => (StatusCode::UNAUTHORIZED, "replay detected"),
            Self::BadSignature => (StatusCode::UNAUTHORIZED, "bad signature"),
        };
        (status, msg).into_response()
    }
}
