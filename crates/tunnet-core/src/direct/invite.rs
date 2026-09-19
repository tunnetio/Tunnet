//! Coordinator-issued Direct join capabilities.
//!
//! An invite is a bearer secret plus the signed [`Genesis`]. The coordinator
//! enforces [`InviteAdmission`]; the copy in the token is informational.

use anyhow::Context;
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};

use super::connectivity::strip_overlay_addrs;
use super::grants::{Genesis, verify_genesis, verifying_key_from_hex};

/// How redeeming this invite admits an endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteAdmission {
    /// Single-use capability: valid redemption admits immediately.
    #[default]
    Immediate,
    /// Redemption creates a pending request bound to the presenting EndpointId.
    ApprovalRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// Signed network genesis. Verify before contacting the coordinator.
    pub genesis: Genesis,
    /// Unique per-invite secret (hex). Admission capability; not a network-wide secret.
    pub invite_secret: String,
    /// Issuance snapshot for client-side early expiry. Coordinator is authoritative.
    pub expires_at: jiff::Timestamp,
    /// Coordinator [`EndpointAddr`] at issue time. Bootstrap hints, not transport policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_addr: Option<EndpointAddr>,
    /// Informational copy of coordinator admission policy.
    #[serde(default)]
    pub admission: InviteAdmission,
}

/// Address used to open JOIN_ALPN.
///
/// Trust is the genesis coordinator [`EndpointId`]. Overlay/TUN IPs are never
/// dialed. When the snapshot includes a relay, IP candidates are omitted from
/// this handshake address: iroh 1.2 treats IP as primary and relay as backup,
/// then `SendDatagram` uses only `selected_path`, so an unreachable IP starves
/// a working relay for the rest of the QUIC handshake. The invite still stores
/// the full snapshot. After join, the mesh endpoint discovers current paths.
pub fn join_dial_addr(invite: &InviteCode) -> anyhow::Result<EndpointAddr> {
    let id: EndpointId = invite
        .genesis
        .coordinator_endpoint_id
        .parse()
        .context("invalid coordinator endpoint id in invite")?;
    let overlay = [invite.genesis.address_plan.peer_cidr];
    let addr = match &invite.coordinator_addr {
        Some(addr) if addr.id == id => strip_overlay_addrs(addr.clone(), &overlay),
        Some(addr) => anyhow::bail!(
            "invite coordinator_addr id {addr_id} does not match genesis {id}",
            addr_id = addr.id
        ),
        None => EndpointAddr::new(id),
    };
    Ok(join_handshake_addr(addr))
}

/// Drop IP candidates when a relay is present so the handshake can use it.
pub fn join_handshake_addr(mut addr: EndpointAddr) -> EndpointAddr {
    if addr.relay_urls().next().is_some() {
        addr.addrs.retain(|a| !a.is_ip());
    }
    addr
}

/// Stamp the coordinator's current iroh address onto a newly issued invite.
pub fn stamp_coordinator_addr(invite: &mut InviteCode, endpoint: &iroh::Endpoint) {
    let overlay = [invite.genesis.address_plan.peer_cidr];
    let mut addr = endpoint.addr();
    if addr.id.to_string() != invite.genesis.coordinator_endpoint_id {
        tracing::warn!(
            genesis = %invite.genesis.coordinator_endpoint_id,
            endpoint = %addr.id,
            "invite genesis coordinator id differs from local endpoint; stamping genesis id"
        );
        addr.id = invite
            .genesis
            .coordinator_endpoint_id
            .parse()
            .unwrap_or(addr.id);
    }
    invite.coordinator_addr = Some(strip_overlay_addrs(addr, &overlay));
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
    use std::net::SocketAddr;

    fn signed_invite(coord_id: Option<EndpointId>) -> InviteCode {
        let (sk, vk) = generate_coordinator_keypair();
        let cidr = select_peer_cidr(&[], &[]).unwrap();
        let id = coord_id.unwrap_or_else(|| iroh::SecretKey::generate().public());
        let genesis = sign_genesis(
            &sk,
            Genesis {
                schema_version: GENESIS_SCHEMA_VERSION,
                network_id: uuid::Uuid::nil(),
                network_name: "home".into(),
                coordinator_endpoint_id: id.to_string(),
                coordinator_verifying_key: hex::encode(vk.to_bytes()),
                address_plan: cidr,
                created_at: jiff::Timestamp::now(),
                sig: String::new(),
            },
        )
        .unwrap();
        InviteCode {
            genesis,
            invite_secret: hex::encode([7u8; 32]),
            expires_at: jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24),
            coordinator_addr: None,
            admission: InviteAdmission::Immediate,
        }
    }

    #[test]
    fn roundtrip() {
        let id = iroh::SecretKey::generate().public();
        let relay: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link.".parse().unwrap();
        let mut inv = signed_invite(Some(id));
        inv.coordinator_addr = Some(
            EndpointAddr::new(id)
                .with_relay_url(relay)
                .with_ip_addr("192.168.1.20:11204".parse().unwrap()),
        );
        let code = encode_invite(&inv).unwrap();
        let decoded = decode_invite(&code).unwrap();
        assert_eq!(decoded.genesis.network_name, "home");
        assert_eq!(decoded.invite_secret, inv.invite_secret);
        assert_eq!(decoded.coordinator_addr, inv.coordinator_addr);
    }

    #[test]
    fn missing_addr_field_decodes() {
        let inv = signed_invite(None);
        let mut value = serde_json::to_value(&inv).unwrap();
        value.as_object_mut().unwrap().remove("coordinator_addr");
        let decoded: InviteCode = serde_json::from_value(value).unwrap();
        assert!(decoded.coordinator_addr.is_none());
    }

    #[test]
    fn join_dial_with_relay_omits_ips() {
        let id = iroh::SecretKey::generate().public();
        let relay: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link.".parse().unwrap();
        let mut inv = signed_invite(Some(id));
        inv.coordinator_addr = Some(
            EndpointAddr::new(id)
                .with_relay_url(relay.clone())
                .with_ip_addr("192.168.1.20:11204".parse().unwrap())
                .with_ip_addr("[2001:db8::1]:11204".parse().unwrap()),
        );
        let addr = join_dial_addr(&inv).unwrap();
        assert_eq!(addr.id, id);
        assert!(addr.relay_urls().any(|u| u == &relay));
        assert_eq!(addr.ip_addrs().count(), 0);
        assert!(
            inv.coordinator_addr
                .as_ref()
                .unwrap()
                .ip_addrs()
                .next()
                .is_some()
        );
    }

    #[test]
    fn join_dial_without_relay_keeps_lan_ips() {
        let id = iroh::SecretKey::generate().public();
        let lan: SocketAddr = "192.168.1.20:11204".parse().unwrap();
        let mut inv = signed_invite(Some(id));
        inv.coordinator_addr = Some(EndpointAddr::new(id).with_ip_addr(lan));
        let addr = join_dial_addr(&inv).unwrap();
        assert!(addr.ip_addrs().any(|a| *a == lan));
        assert_eq!(addr.relay_urls().count(), 0);
    }

    #[test]
    fn join_dial_without_snapshot_is_id_only() {
        let inv = signed_invite(None);
        let addr = join_dial_addr(&inv).unwrap();
        assert!(addr.addrs.is_empty());
        assert_eq!(addr.id.to_string(), inv.genesis.coordinator_endpoint_id);
    }

    #[test]
    fn join_dial_rejects_id_mismatch() {
        let mut inv = signed_invite(None);
        let other = iroh::SecretKey::generate().public();
        inv.coordinator_addr = Some(EndpointAddr::new(other));
        let err = join_dial_addr(&inv).unwrap_err();
        assert!(err.to_string().contains("does not match genesis"));
    }

    #[test]
    fn join_dial_strips_overlay_ips() {
        let id = iroh::SecretKey::generate().public();
        let mut inv = signed_invite(Some(id));
        let overlay_ip = inv.genesis.address_plan.peer_cidr.network();
        let overlay: SocketAddr = (overlay_ip, 11204).into();
        let lan: SocketAddr = "192.168.1.20:11204".parse().unwrap();
        let relay: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link.".parse().unwrap();
        inv.coordinator_addr = Some(
            EndpointAddr::new(id)
                .with_relay_url(relay)
                .with_ip_addr(overlay)
                .with_ip_addr(lan),
        );
        let addr = join_dial_addr(&inv).unwrap();
        assert_eq!(addr.ip_addrs().count(), 0);
        assert_eq!(addr.relay_urls().count(), 1);
        let _ = overlay;
        let _ = lan;
    }
}
