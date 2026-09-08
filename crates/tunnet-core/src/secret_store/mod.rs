//! Tiered encryption at rest for agent secrets (identity, network PSK, tickets, auth).
//!
//! Layout:
//! - `state.enc` - AES-256-GCM ciphertext of [`SensitivePayload`]
//! - `state.enc.meta` - seal tier + wrapped DEK / salt
//!
//! Tiers (best available wins unless plaintext forced):
//! 1. `tpm` - Windows DPAPI (TPM-backed when present); Linux falls through today
//! 2. `keychain` - macOS System/login Keychain
//! 3. `derived` - HKDF from machine-id + boot-id + salt (offline-copy protection)
//! 4. `plaintext` - explicit `--no-encrypt-state` / `TUNNET_NO_ENCRYPT_STATE`

mod derived;
mod persist;
mod platform;

pub use persist::{load_agent, persist_agent};

use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::identity::AgentIdentity;
use crate::state::{CliAuthTokens, StatePaths};

const PAYLOAD_VERSION: u32 = 2;
const META_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SealTier {
    Tpm,
    Keychain,
    Derived,
    Plaintext,
}

impl SealTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::Keychain => "keychain",
            Self::Derived => "derived",
            Self::Plaintext => "plaintext",
        }
    }
}

/// Per-network sealed fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkSecrets {
    /// Join/bootstrap secret (hex). Not used for ongoing transport auth.
    pub join_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_ticket: Option<String>,
    /// Coordinator ed25519 signing key seed (hex). Present only on coordinator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_signing_key: Option<String>,
    /// Serialized [`crate::direct::NetworkGrant`] JSON for this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_grant: Option<String>,
    /// Network content encryption key (32-byte hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_key: Option<String>,
}

/// In-memory secrets held after unlock.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AgentSecrets {
    pub identity_seed: [u8; 32],
    #[zeroize(skip)]
    pub networks: BTreeMap<Uuid, NetworkSecrets>,
    #[zeroize(skip)]
    pub auth: Option<CliAuthTokens>,
    /// Custom Direct relay auth tokens keyed by relay URL. Never written to
    /// `tunnet.toml` or `state.json`.
    #[zeroize(skip)]
    pub relay_auth: BTreeMap<String, String>,
}

impl AgentSecrets {
    pub fn identity(&self) -> AgentIdentity {
        AgentIdentity::from_bytes(self.identity_seed)
    }

    pub fn from_identity(identity: &AgentIdentity) -> Self {
        Self {
            identity_seed: identity.secret_bytes,
            networks: BTreeMap::new(),
            auth: None,
            relay_auth: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SensitivePayload {
    version: u32,
    identity_seed_hex: String,
    #[serde(default)]
    networks: BTreeMap<Uuid, NetworkSecrets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<CliAuthTokens>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    relay_auth: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct SealMeta {
    version: u32,
    tier: SealTier,
    /// Hex salt for derived tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt_hex: Option<String>,
    /// Wrapped DEK (hex). Absent for keychain (DEK lives in Keychain) and plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_dek_hex: Option<String>,
    /// Plaintext DEK hex - only for tier `plaintext`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dek_hex: Option<String>,
}

/// Policy for selecting a seal tier when writing.
#[derive(Debug, Clone, Copy)]
pub struct SealPolicy {
    pub allow_encrypt: bool,
}

impl SealPolicy {
    pub fn from_env_and_flag(no_encrypt: bool) -> Self {
        let env_off = std::env::var("TUNNET_NO_ENCRYPT_STATE")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
        Self {
            allow_encrypt: !(no_encrypt || env_off),
        }
    }

    pub fn pick_tier(self) -> SealTier {
        if !self.allow_encrypt {
            return SealTier::Plaintext;
        }
        platform::best_tier()
    }
}

pub fn secrets_exist(paths: &StatePaths) -> bool {
    paths.secrets_file().exists()
}

/// Save secrets using the best available tier (or plaintext if policy says so).
pub fn save_secrets(
    paths: &StatePaths,
    secrets: &AgentSecrets,
    policy: SealPolicy,
) -> anyhow::Result<SealTier> {
    paths.ensure()?;
    let tier = policy.pick_tier();
    let payload = SensitivePayload {
        version: PAYLOAD_VERSION,
        identity_seed_hex: hex::encode(secrets.identity_seed),
        networks: secrets.networks.clone(),
        auth: secrets.auth.clone(),
        relay_auth: secrets.relay_auth.clone(),
    };
    let plain = serde_json::to_vec(&payload).context("serialize sensitive payload")?;

    let mut dek = Key::<Aes256Gcm>::generate();
    let cipher = Aes256Gcm::new(&dek);
    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;

    // state.enc = nonce(12) || ciphertext+tag
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    std::fs::write(paths.secrets_file(), &blob)
        .with_context(|| format!("write {}", paths.secrets_file().display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(paths.secrets_file(), std::fs::Permissions::from_mode(0o600));
    }

    let meta = match tier {
        SealTier::Plaintext => SealMeta {
            version: META_VERSION,
            tier,
            salt_hex: None,
            wrapped_dek_hex: None,
            dek_hex: Some(hex::encode(dek.as_slice())),
        },
        SealTier::Derived => {
            let salt = random_salt();
            let wrap_key = derived::derive_wrap_key(&salt)?;
            let wrapped = wrap_dek(&wrap_key, dek.as_slice())?;
            SealMeta {
                version: META_VERSION,
                tier,
                salt_hex: Some(hex::encode(salt)),
                wrapped_dek_hex: Some(hex::encode(wrapped)),
                dek_hex: None,
            }
        }
        SealTier::Keychain => {
            platform::store_dek_keychain(dek.as_slice())?;
            SealMeta {
                version: META_VERSION,
                tier,
                salt_hex: None,
                wrapped_dek_hex: None,
                dek_hex: None,
            }
        }
        SealTier::Tpm => {
            let wrapped = platform::wrap_dek_tpm(dek.as_slice())?;
            SealMeta {
                version: META_VERSION,
                tier,
                salt_hex: None,
                wrapped_dek_hex: Some(hex::encode(wrapped)),
                dek_hex: None,
            }
        }
    };

    let meta_json = serde_json::to_vec_pretty(&meta).context("serialize seal meta")?;
    std::fs::write(paths.secrets_meta_file(), meta_json)
        .with_context(|| format!("write {}", paths.secrets_meta_file().display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            paths.secrets_meta_file(),
            std::fs::Permissions::from_mode(0o600),
        );
    }

    dek.zeroize();
    tracing::info!(tier = %tier.as_str(), "agent secrets sealed");
    Ok(tier)
}

/// Load and decrypt secrets from `state.enc`.
pub fn load_secrets(paths: &StatePaths) -> anyhow::Result<(AgentSecrets, SealTier)> {
    let meta_bytes = std::fs::read(paths.secrets_meta_file())
        .with_context(|| format!("read {}", paths.secrets_meta_file().display()))?;
    let meta: SealMeta = serde_json::from_slice(&meta_bytes).context("parse state.enc.meta")?;
    let blob = std::fs::read(paths.secrets_file())
        .with_context(|| format!("read {}", paths.secrets_file().display()))?;
    if blob.len() < 12 + 16 {
        bail!("state.enc too short");
    }

    let mut dek = resolve_dek(&meta)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| anyhow::anyhow!("invalid DEK"))?;
    let nonce = nonce_from_bytes(&blob[..12])?;
    let plain = cipher
        .decrypt(&nonce, &blob[12..])
        .map_err(|_| anyhow::anyhow!("failed to decrypt state.enc (wrong machine or corrupt?)"))?;
    dek.zeroize();

    let payload: SensitivePayload =
        serde_json::from_slice(&plain).context("parse decrypted sensitive payload")?;
    if payload.version != PAYLOAD_VERSION {
        bail!("unsupported sensitive payload version {}", payload.version);
    }
    let seed = hex::decode(&payload.identity_seed_hex).context("identity seed hex")?;
    if seed.len() != 32 {
        bail!("identity seed must be 32 bytes");
    }
    let identity_seed = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity seed must be 32 bytes"))?;

    Ok((
        AgentSecrets {
            identity_seed,
            networks: payload.networks,
            auth: payload.auth,
            relay_auth: payload.relay_auth,
        },
        meta.tier,
    ))
}

fn resolve_dek(meta: &SealMeta) -> anyhow::Result<[u8; 32]> {
    match meta.tier {
        SealTier::Plaintext => {
            let hex = meta
                .dek_hex
                .as_deref()
                .context("plaintext tier missing dek_hex")?;
            decode_dek32(hex)
        }
        SealTier::Derived => {
            let salt_hex = meta
                .salt_hex
                .as_deref()
                .context("derived tier missing salt")?;
            let salt = hex::decode(salt_hex).context("salt hex")?;
            let wrapped_hex = meta
                .wrapped_dek_hex
                .as_deref()
                .context("derived tier missing wrapped_dek")?;
            let wrapped = hex::decode(wrapped_hex).context("wrapped dek hex")?;
            let wrap_key = derived::derive_wrap_key(&salt)?;
            unwrap_dek(&wrap_key, &wrapped)
        }
        SealTier::Keychain => platform::load_dek_keychain(),
        SealTier::Tpm => {
            let wrapped_hex = meta
                .wrapped_dek_hex
                .as_deref()
                .context("tpm tier missing wrapped_dek")?;
            let wrapped = hex::decode(wrapped_hex).context("wrapped dek hex")?;
            platform::unwrap_dek_tpm(&wrapped)
        }
    }
}

fn decode_dek32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let v = hex::decode(hex_str).context("dek hex")?;
    if v.len() != 32 {
        bail!("dek must be 32 bytes");
    }
    v.try_into()
        .map_err(|_| anyhow::anyhow!("dek must be 32 bytes"))
}

fn wrap_dek(wrap_key: &[u8; 32], dek: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(wrap_key).map_err(|_| anyhow::anyhow!("invalid wrap key"))?;
    let nonce = Nonce::generate();
    let ct = cipher
        .encrypt(&nonce, dek)
        .map_err(|_| anyhow::anyhow!("wrap DEK failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_dek(wrap_key: &[u8; 32], wrapped: &[u8]) -> anyhow::Result<[u8; 32]> {
    if wrapped.len() < 12 + 16 {
        bail!("wrapped DEK too short");
    }
    let cipher =
        Aes256Gcm::new_from_slice(wrap_key).map_err(|_| anyhow::anyhow!("invalid wrap key"))?;
    let nonce = nonce_from_bytes(&wrapped[..12])?;
    let plain = cipher
        .decrypt(&nonce, &wrapped[12..])
        .map_err(|_| anyhow::anyhow!("unwrap DEK failed"))?;
    if plain.len() != 32 {
        bail!("unwrapped DEK wrong length");
    }
    plain
        .try_into()
        .map_err(|_| anyhow::anyhow!("unwrapped DEK wrong length"))
}

fn random_salt() -> [u8; 16] {
    rand::random()
}

fn nonce_from_bytes(bytes: &[u8]) -> anyhow::Result<Nonce<aes_gcm::aead::consts::U12>> {
    let arr: [u8; 12] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be 12 bytes"))?;
    Ok(Nonce::from(arr))
}

/// Delete sealed secret files.
pub fn clear_secrets(paths: &StatePaths) -> anyhow::Result<()> {
    for p in [paths.secrets_file(), paths.secrets_meta_file()] {
        if p.exists() {
            std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
        }
    }
    let _ = platform::delete_dek_keychain();
    Ok(())
}

pub fn load_or_create_secrets(
    paths: &StatePaths,
    policy: SealPolicy,
) -> anyhow::Result<(AgentSecrets, SealTier)> {
    if secrets_exist(paths) {
        return load_secrets(paths);
    }
    let identity = AgentIdentity::generate();
    let secrets = AgentSecrets::from_identity(&identity);
    let tier = save_secrets(paths, &secrets, policy)?;
    Ok((secrets, tier))
}

/// Store management OAuth tokens in `state.enc`.
pub fn store_auth(paths: &StatePaths, auth: CliAuthTokens) -> anyhow::Result<()> {
    let policy = SealPolicy::from_env_and_flag(false);
    let (mut secrets, _) = if secrets_exist(paths) {
        load_secrets(paths)?
    } else {
        load_or_create_secrets(paths, policy)?
    };
    secrets.auth = Some(auth);
    save_secrets(paths, &secrets, policy)?;
    Ok(())
}

pub fn load_auth(paths: &StatePaths) -> anyhow::Result<Option<CliAuthTokens>> {
    if !secrets_exist(paths) {
        return Ok(None);
    }
    let (secrets, _) = load_secrets(paths)?;
    Ok(secrets.auth.clone())
}

pub fn clear_auth(paths: &StatePaths) -> anyhow::Result<()> {
    if !secrets_exist(paths) {
        return Ok(());
    }
    let policy = SealPolicy::from_env_and_flag(false);
    let (mut secrets, _) = load_secrets(paths)?;
    secrets.auth = None;
    save_secrets(paths, &secrets, policy)?;
    Ok(())
}

pub fn load_relay_auth(paths: &StatePaths) -> anyhow::Result<BTreeMap<String, String>> {
    if !secrets_exist(paths) {
        return Ok(BTreeMap::new());
    }
    let (secrets, _) = load_secrets(paths)?;
    Ok(secrets.relay_auth.clone())
}

/// Persist a Direct custom-relay auth token in `state.enc`, keyed by URL.
pub fn store_relay_auth(paths: &StatePaths, url: &str, token: &str) -> anyhow::Result<()> {
    let policy = SealPolicy::from_env_and_flag(false);
    let (mut secrets, _) = if secrets_exist(paths) {
        load_secrets(paths)?
    } else {
        load_or_create_secrets(paths, policy)?
    };
    if token.is_empty() {
        secrets.relay_auth.remove(url);
    } else {
        secrets
            .relay_auth
            .insert(url.to_string(), token.to_string());
    }
    save_secrets(paths, &secrets, policy)?;
    Ok(())
}

pub fn clear_relay_auth(paths: &StatePaths) -> anyhow::Result<()> {
    if !secrets_exist(paths) {
        return Ok(());
    }
    let policy = SealPolicy::from_env_and_flag(false);
    let (mut secrets, _) = load_secrets(paths)?;
    secrets.relay_auth.clear();
    save_secrets(paths, &secrets, policy)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_paths() -> (TempDir, StatePaths) {
        let dir = TempDir::new().unwrap();
        let paths = StatePaths::from_dir(dir.path().to_path_buf());
        (dir, paths)
    }

    #[test]
    fn roundtrip_derived() {
        let (_tmp, paths) = test_paths();
        paths.ensure().unwrap();
        let id = AgentIdentity::generate();
        let nid = Uuid::from_u128(42);
        let secrets = AgentSecrets {
            identity_seed: id.secret_bytes,
            networks: BTreeMap::from([(
                nid,
                NetworkSecrets {
                    join_secret: "deadbeef".into(),
                    doc_ticket: Some("ticket".into()),
                    coordinator_signing_key: None,
                    network_grant: None,
                    content_key: None,
                },
            )]),
            auth: None,
            relay_auth: BTreeMap::from([(
                "https://relay.example.com".into(),
                "relay-secret".into(),
            )]),
        };
        let policy = SealPolicy {
            allow_encrypt: true,
        };
        let tier = save_secrets(
            &paths,
            &secrets,
            SealPolicy {
                allow_encrypt: false,
            },
        )
        .unwrap();
        assert_eq!(tier, SealTier::Plaintext);
        let (loaded, t) = load_secrets(&paths).unwrap();
        assert_eq!(t, SealTier::Plaintext);
        assert_eq!(loaded.identity_seed, secrets.identity_seed);
        let ns = loaded.networks.get(&nid).unwrap();
        assert_eq!(ns.join_secret, "deadbeef");
        assert_eq!(ns.doc_ticket.as_deref(), Some("ticket"));
        assert_eq!(
            loaded
                .relay_auth
                .get("https://relay.example.com")
                .map(String::as_str),
            Some("relay-secret")
        );
        let public = std::fs::read_to_string(paths.state_file())
            .ok()
            .unwrap_or_default();
        assert!(!public.contains("relay-secret"));
        let toml_path = paths.config_toml_file();
        if toml_path.exists() {
            let toml = std::fs::read_to_string(toml_path).unwrap();
            assert!(!toml.contains("relay-secret"));
        }
        let _ = policy;
    }

    #[test]
    fn derived_wrap_roundtrip() {
        let salt = random_salt();
        let key = derived::derive_wrap_key(&salt).unwrap();
        let dek = Key::<Aes256Gcm>::generate();
        let wrapped = wrap_dek(&key, dek.as_slice()).unwrap();
        let out = unwrap_dek(&key, &wrapped).unwrap();
        assert_eq!(out.as_slice(), dek.as_slice());
    }
}
