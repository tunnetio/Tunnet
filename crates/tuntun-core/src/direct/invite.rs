//! Invite codes for Direct mode admission.

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// Topic hash (hex).
    pub topic: String,
    /// Network secret (hex).
    pub secret: String,
    /// Network display name.
    pub network_name: String,
    /// Coordinator endpoint id (hex).
    pub coordinator: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub reusable: bool,
    /// Opaque invite id for one-time tracking.
    pub invite_id: String,
}

/// Encode invite as URL-safe base64 JSON (no padding).
pub fn encode_invite(invite: &InviteCode) -> anyhow::Result<String> {
    let json = serde_json::to_vec(invite)?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        json,
    ))
}

pub fn decode_invite(code: &str) -> anyhow::Result<InviteCode> {
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        code.trim(),
    )
    .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, code.trim()))
    .context("invalid invite code encoding")?;
    let invite: InviteCode = serde_json::from_slice(&raw).context("invalid invite payload")?;
    if invite.expires_at < Utc::now() {
        anyhow::bail!("invite code expired at {}", invite.expires_at);
    }
    Ok(invite)
}

impl InviteCode {
    pub fn new(
        topic: String,
        secret: String,
        network_name: String,
        coordinator: String,
        expires: Duration,
        reusable: bool,
    ) -> Self {
        Self {
            topic,
            secret,
            network_name,
            coordinator,
            expires_at: Utc::now() + expires,
            reusable,
            invite_id: hex::encode(rand::random::<[u8; 16]>()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let inv = InviteCode::new(
            "aa".repeat(32),
            "bb".repeat(32),
            "home".into(),
            "cc".repeat(32),
            Duration::hours(24),
            false,
        );
        let code = encode_invite(&inv).unwrap();
        let decoded = decode_invite(&code).unwrap();
        assert_eq!(decoded.network_name, "home");
        assert_eq!(decoded.invite_id, inv.invite_id);
    }
}
