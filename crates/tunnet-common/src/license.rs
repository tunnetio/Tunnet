//! Ed25519 license certificate verification (mirrors `@tunnet/entitlements/license`).

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
const LICENSE_PUBLIC_KEY_RAW: [u8; 32] = [
    0x54, 0x54, 0x4b, 0xc6, 0x25, 0x1b, 0x80, 0x76, 0xe7, 0xcd, 0xce, 0xff, 0x6b, 0x74, 0x1d, 0x25,
    0x8b, 0x37, 0xa6, 0xa9, 0x30, 0x20, 0xa0, 0x3a, 0x25, 0x1f, 0xe2, 0x09, 0xb3, 0x25, 0xeb, 0xbd,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Community,
    Cloud,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlements {
    pub tier: LicenseTier,
    pub multi_organization: bool,
    pub cloud_landing: bool,
    pub open_sign_up: bool,
    pub clickhouse_audit: bool,
    pub audit_enterprise_streams: bool,
    pub compliance_export: bool,
    pub license_expires_at: Option<i64>,
}

impl Entitlements {
    pub fn community() -> Self {
        Self {
            tier: LicenseTier::Community,
            multi_organization: false,
            cloud_landing: false,
            open_sign_up: false,
            clickhouse_audit: false,
            audit_enterprise_streams: false,
            compliance_export: false,
            license_expires_at: None,
        }
    }

    pub fn for_tier(tier: LicenseTier, exp: Option<i64>) -> Self {
        match tier {
            LicenseTier::Community => Self::community(),
            LicenseTier::Cloud => Self {
                tier: LicenseTier::Cloud,
                multi_organization: true,
                cloud_landing: true,
                open_sign_up: true,
                clickhouse_audit: true,
                audit_enterprise_streams: true,
                compliance_export: true,
                license_expires_at: exp,
            },
            LicenseTier::Enterprise => Self {
                tier: LicenseTier::Enterprise,
                multi_organization: false,
                cloud_landing: false,
                open_sign_up: false,
                clickhouse_audit: true,
                audit_enterprise_streams: true,
                compliance_export: true,
                license_expires_at: exp,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct LicensePayload {
    v: u32,
    tier: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    sub: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LicenseCertificate {
    alg: String,
    payload: LicensePayload,
    signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid license JSON")]
    InvalidJson,
    #[error("invalid license structure")]
    InvalidStructure,
    #[error("invalid license signature")]
    BadSignature,
    #[error("license expired")]
    Expired,
    #[error("unsupported license version")]
    UnsupportedVersion,
}

fn canonical_bytes(payload: &LicensePayload) -> Vec<u8> {
    // Match TS: JSON object with fixed key order v, tier, exp, iat, optional sub.
    let mut map = serde_json::Map::new();
    map.insert("v".into(), serde_json::json!(payload.v));
    map.insert("tier".into(), serde_json::json!(payload.tier));
    map.insert("exp".into(), serde_json::json!(payload.exp));
    map.insert("iat".into(), serde_json::json!(payload.iat));
    if let Some(ref sub) = payload.sub {
        map.insert("sub".into(), serde_json::json!(sub));
    }
    serde_json::to_vec(&serde_json::Value::Object(map)).expect("license canonical json")
}

fn from_base64_url(value: &str) -> Option<Vec<u8>> {
    let padded = value.replace('-', "+").replace('_', "/");
    let pad = match padded.len() % 4 {
        0 => "",
        n => &"===="[..4 - n],
    };
    base64::engine::general_purpose::STANDARD
        .decode(format!("{padded}{pad}"))
        .ok()
}

/// Verify a license certificate JSON string. Returns community entitlements on soft failure
/// only when callers choose to; this function returns Err for invalid/expired.
pub fn verify_license(input: &str, now_sec: i64) -> Result<Entitlements, LicenseError> {
    let cert: LicenseCertificate =
        serde_json::from_str(input).map_err(|_| LicenseError::InvalidJson)?;

    if cert.alg != "Ed25519" {
        return Err(LicenseError::InvalidStructure);
    }
    if cert.payload.v != 1 {
        return Err(LicenseError::UnsupportedVersion);
    }

    let tier = match cert.payload.tier.as_str() {
        "cloud" => LicenseTier::Cloud,
        "enterprise" => LicenseTier::Enterprise,
        _ => return Err(LicenseError::InvalidStructure),
    };

    let sig_bytes = from_base64_url(&cert.signature).ok_or(LicenseError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LicenseError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_arr);

    let vk = VerifyingKey::from_bytes(&LICENSE_PUBLIC_KEY_RAW)
        .map_err(|_| LicenseError::BadSignature)?;

    let msg = canonical_bytes(&cert.payload);
    vk.verify(&msg, &signature)
        .map_err(|_| LicenseError::BadSignature)?;

    if cert.payload.exp <= now_sec {
        return Err(LicenseError::Expired);
    }

    Ok(Entitlements::for_tier(tier, Some(cert.payload.exp)))
}

/// Load license text from `TUNNET_LICENSE` (inline JSON, file path, or http URL).
pub async fn load_license_text(raw: Option<&str>) -> Option<String> {
    let ref_ = raw?.trim();
    if ref_.is_empty() {
        return None;
    }
    if ref_.starts_with('{') {
        return Some(ref_.to_string());
    }
    if ref_.starts_with("http://") || ref_.starts_with("https://") {
        match reqwest::get(ref_).await {
            Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "TUNNET_LICENSE fetch failed");
                None
            }
            Err(e) => {
                tracing::warn!(?e, "TUNNET_LICENSE fetch failed");
                None
            }
        }
    } else {
        match std::fs::read_to_string(ref_) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(?e, path = %ref_, "TUNNET_LICENSE file not found");
                None
            }
        }
    }
}

/// Resolve entitlements from env, defaulting to community.
pub async fn resolve_entitlements_from_env() -> Entitlements {
    let raw = std::env::var("TUNNET_LICENSE").ok();
    let Some(text) = load_license_text(raw.as_deref()).await else {
        return Entitlements::community();
    };
    let now = chrono::Utc::now().timestamp();
    match verify_license(&text, now) {
        Ok(e) => e,
        Err(LicenseError::Expired) => {
            tracing::warn!("TUNNET_LICENSE expired; using community entitlements");
            Entitlements::community()
        }
        Err(e) => {
            tracing::warn!(?e, "TUNNET_LICENSE invalid; using community entitlements");
            Entitlements::community()
        }
    }
}
