//! Ed25519 network grants, member records, genesis, epochs, and content encryption.

use std::net::Ipv4Addr;

use aes_gcm::aead::{Aead, Generate};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, bail};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Coordinator,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGrant {
    pub network_id: Uuid,
    pub endpoint_id: String,
    pub role: MemberRole,
    pub network_epoch: u64,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub content_key: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMemberRecord {
    pub schema_version: u16,
    pub network_id: Uuid,
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: Ipv4Addr,
    pub tags: Vec<String>,
    pub status: String,
    pub ssh_host_key: Option<String>,
    pub sequence: u64,
    pub joined_at: Timestamp,
    pub grant: NetworkGrant,
    pub endpoint_sig: String,
    pub coordinator: bool,
}

pub const MEMBER_SCHEMA_VERSION: u16 = 2;
pub const GENESIS_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    pub schema_version: u16,
    pub network_id: Uuid,
    pub network_name: String,
    pub coordinator_endpoint_id: String,
    pub coordinator_verifying_key: String,
    pub address_plan: crate::direct::addrplan::AddressPlan,
    pub created_at: Timestamp,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRecord {
    pub network_epoch: u64,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub endpoint_id: String,
    pub network_epoch: u64,
    pub reason: String,
    pub sig: String,
}

pub fn generate_coordinator_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut rand::rng());
    let vk = sk.verifying_key();
    (sk, vk)
}

pub fn signing_key_from_hex(hex_key: &str) -> anyhow::Result<SigningKey> {
    let bytes = hex::decode(hex_key.trim()).context("invalid signing key hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key_from_hex(hex_key: &str) -> anyhow::Result<VerifyingKey> {
    let bytes = hex::decode(hex_key.trim()).context("invalid verifying key hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).context("invalid ed25519 verifying key")
}

fn sign_bytes(sk: &SigningKey, payload: &[u8]) -> String {
    hex::encode(sk.sign(payload).to_bytes())
}

fn verify_sig(vk: &VerifyingKey, payload: &[u8], sig_hex: &str) -> anyhow::Result<()> {
    let sig_bytes = hex::decode(sig_hex.trim()).context("invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(payload, &sig)
        .map_err(|_| anyhow::anyhow!("invalid signature"))
}

#[derive(Serialize)]
struct GrantSignPayload<'a> {
    network_id: Uuid,
    endpoint_id: &'a str,
    role: MemberRole,
    network_epoch: u64,
    issued_at: Timestamp,
    expires_at: Timestamp,
    content_key: &'a str,
}

fn grant_sign_payload(grant: &NetworkGrant) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&GrantSignPayload {
        network_id: grant.network_id,
        endpoint_id: &grant.endpoint_id,
        role: grant.role,
        network_epoch: grant.network_epoch,
        issued_at: grant.issued_at,
        expires_at: grant.expires_at,
        content_key: &grant.content_key,
    })?)
}

/// Fixed lifetime for coordinator-issued grants: ten years.
pub const GRANT_LIFETIME: SignedDuration = SignedDuration::from_hours(3650 * 24);

/// When a grant issued at `issued_at` expires.
pub fn grant_expiry(issued_at: Timestamp) -> anyhow::Result<Timestamp> {
    issued_at
        .checked_add(GRANT_LIFETIME)
        .context("grant expiry is outside the representable timestamp range")
}

pub fn sign_grant(sk: &SigningKey, mut grant: NetworkGrant) -> anyhow::Result<NetworkGrant> {
    let payload = grant_sign_payload(&grant)?;
    grant.sig = sign_bytes(sk, &payload);
    Ok(grant)
}

pub fn verify_grant(vk: &VerifyingKey, grant: &NetworkGrant, min_epoch: u64) -> anyhow::Result<()> {
    if grant.network_epoch < min_epoch {
        bail!(
            "grant epoch {} below minimum {}",
            grant.network_epoch,
            min_epoch
        );
    }
    if grant.expires_at <= Timestamp::now() {
        bail!("grant expired at {}", grant.expires_at);
    }
    let payload = grant_sign_payload(grant)?;
    verify_sig(vk, &payload, &grant.sig)
}

#[derive(Serialize)]
struct MemberRecordSignPayload<'a> {
    schema_version: u16,
    network_id: Uuid,
    endpoint_id: &'a str,
    hostname: &'a str,
    ipv4: Ipv4Addr,
    tags: &'a [String],
    status: &'a str,
    ssh_host_key: &'a Option<String>,
    sequence: u64,
    joined_at: Timestamp,
    grant: &'a NetworkGrant,
    coordinator: bool,
}

fn member_record_sign_payload(record: &SignedMemberRecord) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&MemberRecordSignPayload {
        schema_version: record.schema_version,
        network_id: record.network_id,
        endpoint_id: &record.endpoint_id,
        hostname: &record.hostname,
        ipv4: record.ipv4,
        tags: &record.tags,
        status: &record.status,
        ssh_host_key: &record.ssh_host_key,
        sequence: record.sequence,
        joined_at: record.joined_at,
        grant: &record.grant,
        coordinator: record.coordinator,
    })?)
}

/// Coordinator attestation over the member record (including embedded grant).
pub fn sign_member_record(
    coord_sk: &SigningKey,
    mut record: SignedMemberRecord,
) -> anyhow::Result<SignedMemberRecord> {
    let payload = member_record_sign_payload(&record)?;
    record.endpoint_sig = sign_bytes(coord_sk, &payload);
    Ok(record)
}

pub fn verify_member_record(
    coord_vk: &VerifyingKey,
    record: &SignedMemberRecord,
    min_epoch: u64,
) -> anyhow::Result<()> {
    if record.schema_version != MEMBER_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported member record schema {}; recreate the network with `tunnet create`",
            record.schema_version
        );
    }
    verify_grant(coord_vk, &record.grant, min_epoch)?;
    let payload = member_record_sign_payload(record)?;
    verify_sig(coord_vk, &payload, &record.endpoint_sig)
}

#[derive(Serialize)]
struct GenesisSignPayload<'a> {
    schema_version: u16,
    network_id: Uuid,
    network_name: &'a str,
    coordinator_endpoint_id: &'a str,
    coordinator_verifying_key: &'a str,
    peer_cidr: String,
    created_at: Timestamp,
}

fn genesis_sign_payload(genesis: &Genesis) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&GenesisSignPayload {
        schema_version: genesis.schema_version,
        network_id: genesis.network_id,
        network_name: &genesis.network_name,
        coordinator_endpoint_id: &genesis.coordinator_endpoint_id,
        coordinator_verifying_key: &genesis.coordinator_verifying_key,
        peer_cidr: genesis.address_plan.peer_cidr.to_string(),
        created_at: genesis.created_at,
    })?)
}

pub fn sign_genesis(sk: &SigningKey, mut genesis: Genesis) -> anyhow::Result<Genesis> {
    let payload = genesis_sign_payload(&genesis)?;
    genesis.sig = sign_bytes(sk, &payload);
    Ok(genesis)
}

pub fn verify_genesis(vk: &VerifyingKey, genesis: &Genesis) -> anyhow::Result<()> {
    if genesis.schema_version != GENESIS_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported genesis schema {}; recreate the network with `tunnet create`",
            genesis.schema_version
        );
    }
    let payload = genesis_sign_payload(genesis)?;
    verify_sig(vk, &payload, &genesis.sig)
}

pub fn validate_member_against_genesis(
    genesis: &Genesis,
    record: &SignedMemberRecord,
) -> anyhow::Result<()> {
    if record.network_id != genesis.network_id {
        anyhow::bail!("member network mismatch");
    }
    if record.grant.network_id != genesis.network_id {
        anyhow::bail!("grant network mismatch");
    }
    crate::direct::addrplan::validate_member_ip(&genesis.address_plan, &record.ipv4)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn validate_membership_set(
    genesis: &Genesis,
    records: &[SignedMemberRecord],
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for r in records {
        validate_member_against_genesis(genesis, r)?;
        if !seen.insert(r.ipv4) {
            anyhow::bail!("duplicate member address {}", r.ipv4);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct EpochSignPayload {
    network_epoch: u64,
}

fn epoch_sign_payload(epoch: &EpochRecord) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&EpochSignPayload {
        network_epoch: epoch.network_epoch,
    })?)
}

pub fn sign_epoch(sk: &SigningKey, mut epoch: EpochRecord) -> anyhow::Result<EpochRecord> {
    let payload = epoch_sign_payload(&epoch)?;
    epoch.sig = sign_bytes(sk, &payload);
    Ok(epoch)
}

pub fn verify_epoch(vk: &VerifyingKey, epoch: &EpochRecord) -> anyhow::Result<()> {
    let payload = epoch_sign_payload(epoch)?;
    verify_sig(vk, &payload, &epoch.sig)
}

#[derive(Serialize)]
struct RevocationSignPayload<'a> {
    endpoint_id: &'a str,
    network_epoch: u64,
    reason: &'a str,
}

fn revocation_sign_payload(revocation: &Revocation) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&RevocationSignPayload {
        endpoint_id: &revocation.endpoint_id,
        network_epoch: revocation.network_epoch,
        reason: &revocation.reason,
    })?)
}

pub fn sign_revocation(sk: &SigningKey, mut revocation: Revocation) -> anyhow::Result<Revocation> {
    let payload = revocation_sign_payload(&revocation)?;
    revocation.sig = sign_bytes(sk, &payload);
    Ok(revocation)
}

pub fn verify_revocation(vk: &VerifyingKey, revocation: &Revocation) -> anyhow::Result<()> {
    let payload = revocation_sign_payload(revocation)?;
    verify_sig(vk, &payload, &revocation.sig)
}

pub fn encrypt_content(content_key_hex: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key_bytes = hex::decode(content_key_hex.trim()).context("invalid content key hex")?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("content key must be 32 bytes"))?;
    let cipher =
        Aes256Gcm::new_from_slice(&key_arr).map_err(|_| anyhow::anyhow!("aes key init"))?;
    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;
    let mut out = nonce.as_slice().to_vec();
    out.extend(ciphertext);
    Ok(out)
}

pub fn decrypt_content(content_key_hex: &str, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        bail!("ciphertext too short");
    }
    let key_bytes = hex::decode(content_key_hex.trim()).context("invalid content key hex")?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("content key must be 32 bytes"))?;
    let cipher =
        Aes256Gcm::new_from_slice(&key_arr).map_err(|_| anyhow::anyhow!("aes key init"))?;
    let (nonce_bytes, enc) = ciphertext.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes.try_into().unwrap();
    let nonce = Nonce::from(nonce_arr);
    cipher
        .decrypt(&nonce, enc)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_expiry_uses_fixed_lifetime() {
        let now = Timestamp::now();
        let expires = grant_expiry(now).expect("ten-year grant expiry must be computable");

        assert_eq!(now.duration_until(expires), GRANT_LIFETIME);
    }

    fn sample_grant(network_id: Uuid, endpoint_id: &str, role: MemberRole) -> NetworkGrant {
        let now = Timestamp::now();
        NetworkGrant {
            network_id,
            endpoint_id: endpoint_id.into(),
            role,
            network_epoch: 1,
            issued_at: now,
            expires_at: now.checked_add(SignedDuration::from_hours(24)).unwrap(),
            content_key: hex::encode([0xAB; 32]),
            sig: String::new(),
        }
    }

    #[test]
    fn keypair_roundtrip() {
        let (sk, vk) = generate_coordinator_keypair();
        let sk2 = signing_key_from_hex(&hex::encode(sk.to_bytes())).unwrap();
        let vk2 = verifying_key_from_hex(&hex::encode(vk.to_bytes())).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn grant_sign_verify_roundtrip() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let network_id = Uuid::new_v4();
        let grant = sign_grant(
            &coord_sk,
            sample_grant(network_id, "aa".repeat(32).as_str(), MemberRole::Member),
        )
        .unwrap();
        verify_grant(&coord_vk, &grant, 1).unwrap();
    }

    #[test]
    fn grant_rejects_forged_sig() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let (_, other_vk) = generate_coordinator_keypair();
        let network_id = Uuid::new_v4();
        let mut grant = sign_grant(
            &coord_sk,
            sample_grant(network_id, "bb".repeat(32).as_str(), MemberRole::Member),
        )
        .unwrap();
        grant.sig = hex::encode([0u8; 64]);
        assert!(verify_grant(&coord_vk, &grant, 1).is_err());
        assert!(verify_grant(&other_vk, &grant, 1).is_err());
    }

    #[test]
    fn grant_rejects_low_epoch() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let network_id = Uuid::new_v4();
        let grant = sign_grant(
            &coord_sk,
            sample_grant(network_id, "cc".repeat(32).as_str(), MemberRole::Member),
        )
        .unwrap();
        assert!(verify_grant(&coord_vk, &grant, 2).is_err());
    }

    #[test]
    fn member_record_roundtrip() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let endpoint_vk = SigningKey::generate(&mut rand::rng()).verifying_key();
        let network_id = Uuid::new_v4();
        let grant = sign_grant(
            &coord_sk,
            sample_grant(
                network_id,
                &hex::encode(endpoint_vk.to_bytes()),
                MemberRole::Member,
            ),
        )
        .unwrap();
        let record = SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id,
            endpoint_id: hex::encode(endpoint_vk.to_bytes()),
            hostname: "alice".into(),
            ipv4: "10.21.0.7".parse().unwrap(),
            tags: vec!["tag".into()],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: Timestamp::now(),
            grant,
            endpoint_sig: String::new(),
            coordinator: false,
        };
        let signed = sign_member_record(&coord_sk, record).unwrap();
        verify_member_record(&coord_vk, &signed, 1).unwrap();
    }

    #[test]
    fn member_record_rejects_tampered_grant() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let endpoint_vk = SigningKey::generate(&mut rand::rng()).verifying_key();
        let network_id = Uuid::new_v4();
        let grant = sign_grant(
            &coord_sk,
            sample_grant(
                network_id,
                &hex::encode(endpoint_vk.to_bytes()),
                MemberRole::Member,
            ),
        )
        .unwrap();
        let mut record = SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id,
            endpoint_id: hex::encode(endpoint_vk.to_bytes()),
            hostname: "bob".into(),
            ipv4: "10.21.0.8".parse().unwrap(),
            tags: vec![],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: Timestamp::now(),
            grant,
            endpoint_sig: String::new(),
            coordinator: false,
        };
        let signed = sign_member_record(&coord_sk, record.clone()).unwrap();
        record.grant.network_epoch = 99;
        assert!(verify_member_record(&coord_vk, &signed, 1).is_ok());
        assert!(verify_member_record(&coord_vk, &record, 1).is_err());
    }

    #[test]
    fn member_record_rejects_legacy_schema() {
        let (coord_sk, coord_vk) = generate_coordinator_keypair();
        let network_id = Uuid::new_v4();
        let grant = sign_grant(
            &coord_sk,
            sample_grant(network_id, &"aa".repeat(32), MemberRole::Member),
        )
        .unwrap();
        let record = SignedMemberRecord {
            schema_version: 1,
            network_id,
            endpoint_id: "aa".repeat(32),
            hostname: "legacy".into(),
            ipv4: "10.21.0.9".parse().unwrap(),
            tags: vec![],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: Timestamp::now(),
            grant,
            endpoint_sig: String::new(),
            coordinator: false,
        };
        let signed = sign_member_record(&coord_sk, record).unwrap();
        assert!(verify_member_record(&coord_vk, &signed, 1).is_err());
    }

    #[test]
    fn genesis_roundtrip() {
        let (sk, vk) = generate_coordinator_keypair();
        let genesis = Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: Uuid::new_v4(),
            network_name: "home".into(),
            coordinator_endpoint_id: "dd".repeat(32),
            coordinator_verifying_key: hex::encode(vk.to_bytes()),
            address_plan: crate::direct::addrplan::AddressPlan {
                peer_cidr: "10.31.0.0/24".parse().unwrap(),
            },
            created_at: Timestamp::now(),
            sig: String::new(),
        };
        let signed = sign_genesis(&sk, genesis).unwrap();
        verify_genesis(&vk, &signed).unwrap();
    }

    #[test]
    fn genesis_signature_covers_peer_cidr() {
        let (sk, vk) = generate_coordinator_keypair();
        let genesis = Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: Uuid::new_v4(),
            network_name: "home".into(),
            coordinator_endpoint_id: "dd".repeat(32),
            coordinator_verifying_key: hex::encode(vk.to_bytes()),
            address_plan: crate::direct::addrplan::AddressPlan {
                peer_cidr: "10.31.0.0/24".parse().unwrap(),
            },
            created_at: Timestamp::now(),
            sig: String::new(),
        };
        let mut signed = sign_genesis(&sk, genesis).unwrap();
        verify_genesis(&vk, &signed).unwrap();
        signed.address_plan.peer_cidr = "10.32.0.0/24".parse().unwrap();
        assert!(verify_genesis(&vk, &signed).is_err());
    }

    #[test]
    fn genesis_rejects_legacy_schema() {
        let (sk, vk) = generate_coordinator_keypair();
        let genesis = Genesis {
            schema_version: 1,
            network_id: Uuid::new_v4(),
            network_name: "home".into(),
            coordinator_endpoint_id: "dd".repeat(32),
            coordinator_verifying_key: hex::encode(vk.to_bytes()),
            address_plan: crate::direct::addrplan::AddressPlan {
                peer_cidr: "10.31.0.0/24".parse().unwrap(),
            },
            created_at: Timestamp::now(),
            sig: String::new(),
        };
        let signed = sign_genesis(&sk, genesis).unwrap();
        assert!(verify_genesis(&vk, &signed).is_err());
    }

    #[test]
    fn member_outside_plan_rejected() {
        let genesis = Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: Uuid::new_v4(),
            network_name: "home".into(),
            coordinator_endpoint_id: "dd".repeat(32),
            coordinator_verifying_key: String::new(),
            address_plan: crate::direct::addrplan::AddressPlan {
                peer_cidr: "10.40.0.0/24".parse().unwrap(),
            },
            created_at: Timestamp::now(),
            sig: String::new(),
        };
        let record = SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id: genesis.network_id,
            endpoint_id: "aa".repeat(32),
            hostname: "x".into(),
            ipv4: "192.168.1.5".parse().unwrap(),
            tags: vec![],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: Timestamp::now(),
            grant: sample_grant(genesis.network_id, &"aa".repeat(32), MemberRole::Member),
            endpoint_sig: String::new(),
            coordinator: false,
        };
        assert!(validate_member_against_genesis(&genesis, &record).is_err());
    }

    #[test]
    fn epoch_roundtrip() {
        let (sk, vk) = generate_coordinator_keypair();
        let epoch = EpochRecord {
            network_epoch: 2,
            sig: String::new(),
        };
        let signed = sign_epoch(&sk, epoch).unwrap();
        verify_epoch(&vk, &signed).unwrap();
    }

    #[test]
    fn revocation_roundtrip() {
        let (sk, vk) = generate_coordinator_keypair();
        let revocation = Revocation {
            endpoint_id: "ee".repeat(32),
            network_epoch: 2,
            reason: "kicked".into(),
            sig: String::new(),
        };
        let signed = sign_revocation(&sk, revocation).unwrap();
        verify_revocation(&vk, &signed).unwrap();
    }

    #[test]
    fn content_encrypt_roundtrip() {
        let key = hex::encode([0x42; 32]);
        let plaintext = b"hello tunnet direct";
        let enc = encrypt_content(&key, plaintext).unwrap();
        let dec = decrypt_content(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn content_decrypt_rejects_wrong_key() {
        let key = hex::encode([0x42; 32]);
        let wrong = hex::encode([0x43; 32]);
        let enc = encrypt_content(&key, b"secret").unwrap();
        assert!(decrypt_content(&wrong, &enc).is_err());
    }
}
