//! Coordinator-issued Direct join capabilities.
//!
//! An invite is a bearer secret plus the signed [`Genesis`]. Policy (expiry,
//! reusable/one-time, revocation, claim) lives on the coordinator and is not
//! taken from the joining client.

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::grants::{Genesis, verify_genesis, verifying_key_from_hex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// Signed network genesis. Verify before contacting the coordinator.
    pub genesis: Genesis,
    /// Unique per-invite secret (hex). Admission capability; not a network-wide secret.
    pub invite_secret: String,
    /// Issuance snapshot for client-side early expiry. Coordinator is authoritative.
    pub expires_at: jiff::Timestamp,
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
    let vk = verifying_key_from_hex(&invite.genesis.coordinator_verifying_key)
        .context("invalid coordinator key in invite")?;
    verify_genesis(&vk, &invite.genesis).context("invite genesis signature invalid")?;
    if invite.genesis.coordinator_verifying_key.is_empty()
        || invite.genesis.coordinator_endpoint_id.is_empty()
    {
        anyhow::bail!("invite genesis missing coordinator identity");
    }
    if hex::decode(invite.invite_secret.trim())
        .unwrap_or_default()
        .len()
        < 16
    {
        anyhow::bail!("invite secret too short");
    }
    if invite.expires_at < jiff::Timestamp::now() {
        anyhow::bail!("invite code expired at {}", invite.expires_at);
    }
    Ok(invite)
}

pub fn invite_secret_hash(secret_hex: &str) -> String {
    hex::encode(blake3::hash(secret_hex.trim().as_bytes()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct::addrplan::select_peer_cidr;
    use crate::direct::grants::{
        GENESIS_SCHEMA_VERSION, generate_coordinator_keypair, sign_genesis,
    };

    fn signed_genesis() -> (InviteCode, ed25519_dalek::VerifyingKey) {
        let (sk, vk) = generate_coordinator_keypair();
        let cidr = select_peer_cidr(&[], &[]).unwrap();
        let genesis = sign_genesis(
            &sk,
            Genesis {
                schema_version: GENESIS_SCHEMA_VERSION,
                network_id: uuid::Uuid::nil(),
                network_name: "home".into(),
                coordinator_endpoint_id: "cc".repeat(32),
                coordinator_verifying_key: hex::encode(vk.to_bytes()),
                address_plan: cidr,
                created_at: jiff::Timestamp::now(),
                sig: String::new(),
            },
        )
        .unwrap();
        let inv = InviteCode {
            genesis,
            invite_secret: hex::encode([7u8; 32]),
            expires_at: jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24),
        };
        (inv, vk)
    }

    #[test]
    fn roundtrip() {
        let (inv, _) = signed_genesis();
        let code = encode_invite(&inv).unwrap();
        let decoded = decode_invite(&code).unwrap();
        assert_eq!(decoded.genesis.network_name, "home");
        assert_eq!(decoded.invite_secret, inv.invite_secret);
    }
}
