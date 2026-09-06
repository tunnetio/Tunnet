use std::path::PathBuf;

use anyhow::Context;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct StatePaths {
    pub dir: PathBuf,
}

impl StatePaths {
    pub fn system_dir() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/var/lib/tunnet")
        }
        #[cfg(windows)]
        {
            let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
            PathBuf::from(base).join("tunnet")
        }
        #[cfg(not(any(unix, windows)))]
        {
            PathBuf::from("./tunnet-state")
        }
    }

    pub fn resolve(explicit: Option<&str>) -> Self {
        if let Some(p) = explicit {
            return Self {
                dir: PathBuf::from(p),
            };
        }
        if let Ok(p) = std::env::var("TUNNET_STATE_DIR")
            && !p.is_empty()
        {
            return Self {
                dir: PathBuf::from(p),
            };
        }
        Self {
            dir: Self::system_dir(),
        }
    }

    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    pub fn cache_file(&self) -> PathBuf {
        self.dir.join("routing_cache.json")
    }
    /// Unified agent configuration (TOML)
    pub fn config_toml_file(&self) -> PathBuf {
        self.dir.join("tunnet.toml")
    }
    /// Encrypted secrets (identity, network PSK, tickets, auth).
    pub fn secrets_file(&self) -> PathBuf {
        self.dir.join("state.enc")
    }
    /// Seal metadata for `state.enc` (tier, wrapped DEK / salt).
    pub fn secrets_meta_file(&self) -> PathBuf {
        self.dir.join("state.enc.meta")
    }
    /// Core update staging, pending marker, and rollback of the Core unit.
    pub fn update_dir(&self) -> PathBuf {
        self.dir.join("update")
    }
    pub fn update_pending_file(&self) -> PathBuf {
        self.update_dir().join("pending.json")
    }
    pub fn update_previous_bin(&self) -> PathBuf {
        self.update_dir().join("tunnet.prev")
    }
    pub fn update_previous_dir(&self) -> PathBuf {
        self.update_dir().join("previous")
    }
    pub fn update_staging_dir(&self) -> PathBuf {
        self.update_dir().join("staged")
    }
    /// Per-network iroh-docs store root.
    pub fn docs_dir(&self, network_id: Uuid) -> PathBuf {
        self.dir.join("docs").join(network_id.to_string())
    }
    /// Pending coordinator firewall suggestion for a network.
    pub fn firewall_pending_file(&self, network_id: Uuid) -> PathBuf {
        self.dir
            .join("firewall_pending")
            .join(format!("{network_id}.json"))
    }
    pub fn invites_file(&self, network_id: Uuid) -> PathBuf {
        self.dir
            .join("direct_invites")
            .join(format!("{network_id}.json"))
    }
    pub fn pending_file(&self, network_id: Uuid) -> PathBuf {
        self.dir
            .join("direct_pending")
            .join(format!("{network_id}.json"))
    }

    pub fn ensure(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("mkdir {}", self.dir.display()))?;
        Ok(())
    }

    pub fn ensure_network_dirs(&self, network_id: Uuid) -> anyhow::Result<()> {
        self.ensure()?;
        for sub in [
            self.docs_dir(network_id),
            self.dir.join("firewall_pending"),
            self.dir.join("direct_invites"),
            self.dir.join("direct_pending"),
        ] {
            std::fs::create_dir_all(&sub).with_context(|| format!("mkdir {}", sub.display()))?;
        }
        Ok(())
    }

    pub fn clone_paths(&self) -> StatePaths {
        StatePaths {
            dir: self.dir.clone(),
        }
    }
}

/// Operating mode of this agent for the persisted network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    Managed,
    Direct,
}

/// Managed-mode enrollment state (control plane).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedState {
    pub control_url: String,
    pub network_name: String,
    pub network_id: Uuid,
    pub organization_id: String,
    pub enrolled_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
    #[serde(default)]
    pub local_ui: tunnet_common::local_api::LocalUiPolicy,
}

/// Direct-mode P2P network state (no control plane).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectState {
    pub network_name: String,
    /// Hex join/bootstrap secret. In-memory only - sealed in `state.enc`.
    #[serde(skip)]
    pub join_secret: String,
    /// Hex topic id = blake3(network_name || join_secret).
    pub topic_hash: String,
    /// Deterministic UUID derived from topic_hash (for IPC / gossip topic helpers).
    pub network_id: Uuid,
    pub coordinator: bool,
    /// Auto-admit valid invite codes without manual approval.
    #[serde(default)]
    pub open: bool,
    pub hostname: String,
    /// Optional coordinator endpoint id (hex) known at join time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_endpoint_id: Option<String>,
    /// Coordinator ed25519 verifying key (hex). Public; also in invite + genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_verifying_key: Option<String>,
    /// Current network epoch (revocation watermark).
    #[serde(default)]
    pub network_epoch: u64,
    /// Signed network authority. Entire address plan is covered by the signature.
    pub genesis: crate::direct::Genesis,
    /// Local node's signed member record. Authoritative self address.
    pub self_record: crate::direct::SignedMemberRecord,
    /// iroh-docs ticket. In-memory only - sealed in `state.enc`.
    #[serde(skip)]
    pub doc_ticket: Option<String>,
    /// iroh-docs namespace id (hex). Network document identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_id: Option<String>,
    /// Coordinator signing key seed (hex). In-memory only - sealed.
    #[serde(skip)]
    pub coordinator_signing_key: Option<String>,
    /// Serialized NetworkGrant JSON for this endpoint. In-memory only - sealed.
    #[serde(skip)]
    pub network_grant: Option<String>,
    /// Network content key (hex). In-memory only - sealed.
    #[serde(skip)]
    pub content_key: Option<String>,
    /// Auto-accept coordinator firewall policy suggestions.
    #[serde(default)]
    pub auto_accept_firewall: bool,
    pub created_at: Timestamp,
}

impl DirectState {
    pub fn self_ipv4(&self) -> std::net::Ipv4Addr {
        self.self_record.ipv4
    }

    pub fn address_plan(&self) -> crate::direct::AddressPlan {
        self.genesis.address_plan
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum PersistedState {
    Managed(ManagedState),
    Direct {
        /// Join order = vec order (first = outbound winner on IP clash).
        networks: Vec<DirectState>,
    },
}

impl PersistedState {
    /// Write public (non-secret) fields to `state.json`.
    pub fn save_public(&self, paths: &StatePaths) -> anyhow::Result<()> {
        paths.ensure()?;
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(paths.state_file(), json)?;
        Ok(())
    }

    /// Alias: public state only. Secrets go through [`crate::secret_store`].
    pub fn save(&self, paths: &StatePaths) -> anyhow::Result<()> {
        self.save_public(paths)
    }

    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        let s = std::fs::read(paths.state_file())
            .with_context(|| format!("read {}", paths.state_file().display()))?;
        serde_json::from_slice(&s).context("parse state.json")
    }

    /// Load state if present; `Ok(None)` when no state file exists yet.
    pub fn try_load(paths: &StatePaths) -> anyhow::Result<Option<Self>> {
        if !paths.state_file().exists() {
            return Ok(None);
        }
        Ok(Some(Self::load(paths)?))
    }

    /// Merge secrets from `state.enc` into this in-memory state.
    pub fn apply_secrets(&mut self, secrets: &crate::secret_store::AgentSecrets) {
        if let PersistedState::Direct { networks } = self {
            for d in networks.iter_mut() {
                if let Some(ns) = secrets.networks.get(&d.network_id) {
                    d.join_secret = ns.join_secret.clone();
                    d.doc_ticket = ns.doc_ticket.clone();
                    d.coordinator_signing_key = ns.coordinator_signing_key.clone();
                    d.network_grant = ns.network_grant.clone();
                    d.content_key = ns.content_key.clone();
                }
            }
        }
    }

    pub fn mode(&self) -> NodeMode {
        match self {
            PersistedState::Managed(_) => NodeMode::Managed,
            PersistedState::Direct { .. } => NodeMode::Direct,
        }
    }

    pub fn is_managed(&self) -> bool {
        matches!(self, PersistedState::Managed(_))
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, PersistedState::Direct { .. })
    }

    pub fn as_managed(&self) -> Option<&ManagedState> {
        match self {
            PersistedState::Managed(m) => Some(m),
            _ => None,
        }
    }

    pub fn direct_networks(&self) -> &[DirectState] {
        match self {
            PersistedState::Direct { networks } => networks,
            _ => &[],
        }
    }

    pub fn direct_networks_mut(&mut self) -> Option<&mut Vec<DirectState>> {
        match self {
            PersistedState::Direct { networks } => Some(networks),
            _ => None,
        }
    }

    pub fn direct_by_name(&self, name: &str) -> Option<&DirectState> {
        self.direct_networks()
            .iter()
            .find(|d| d.network_name.eq_ignore_ascii_case(name))
    }

    pub fn direct_by_id(&self, id: Uuid) -> Option<&DirectState> {
        self.direct_networks().iter().find(|d| d.network_id == id)
    }

    /// Resolve a Direct network by optional name. If `name` is `None` and exactly
    /// one network is joined, returns that network.
    pub fn require_direct_network_id(&self, id: Uuid) -> anyhow::Result<&DirectState> {
        match self {
            PersistedState::Direct { networks } => networks
                .iter()
                .find(|d| d.network_id == id)
                .with_context(|| format!("Direct network '{id}' not found")),
            PersistedState::Managed(_) => anyhow::bail!(
                "this command requires Direct mode; this agent is in Managed mode \
                 (run `tunnet reset --yes` to switch)"
            ),
        }
    }

    pub fn require_direct_network(&self, name: Option<&str>) -> anyhow::Result<&DirectState> {
        let networks = match self {
            PersistedState::Direct { networks } => networks,
            PersistedState::Managed(_) => anyhow::bail!(
                "this command requires Direct mode; this agent is in Managed mode \
                 (run `tunnet reset --yes` to switch)"
            ),
        };
        if networks.is_empty() {
            anyhow::bail!("no Direct networks joined");
        }
        match name {
            Some(n) => self
                .direct_by_name(n)
                .with_context(|| format!("Direct network '{n}' not found")),
            None if networks.len() == 1 => Ok(&networks[0]),
            None => anyhow::bail!(
                "multiple Direct networks joined; pass --network <name> \
                 (joined: {})",
                networks
                    .iter()
                    .map(|d| d.network_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    pub fn require_managed(&self) -> anyhow::Result<&ManagedState> {
        self.as_managed().context(
            "this command requires Managed mode; this agent is in Direct mode \
             (run `tunnet reset --yes` to switch)",
        )
    }

    /// Managed network id, or first Direct network id (status / display helpers).
    pub fn primary_network_id(&self) -> Option<Uuid> {
        match self {
            PersistedState::Managed(m) => Some(m.network_id),
            PersistedState::Direct { networks } => networks.first().map(|d| d.network_id),
        }
    }

    pub fn primary_network_name(&self) -> Option<&str> {
        match self {
            PersistedState::Managed(m) => Some(&m.network_name),
            PersistedState::Direct { networks } => {
                networks.first().map(|d| d.network_name.as_str())
            }
        }
    }
}

/// Tokens from `tunnet login` (OAuth PKCE against management).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliAuthTokens {
    pub management_url: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub scope: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub obtained_at: Timestamp,
}

impl CliAuthTokens {
    /// Persist auth tokens into `state.enc` (creates a sealed vault if needed).
    pub fn save(&self, paths: &StatePaths) -> anyhow::Result<()> {
        crate::secret_store::store_auth(paths, self.clone())
    }

    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        crate::secret_store::load_auth(paths)?.context("no auth tokens in state.enc")
    }

    pub fn clear(paths: &StatePaths) -> anyhow::Result<()> {
        crate::secret_store::clear_auth(paths)
    }

    pub fn access_token_valid(&self) -> bool {
        match self.expires_at {
            Some(exp) => exp > Timestamp::now() + SignedDuration::from_secs(30),
            None => true,
        }
    }
}

pub fn save_snapshot_cache(
    paths: &StatePaths,
    snap: &tunnet_common::EndpointSnapshot,
) -> anyhow::Result<()> {
    paths.ensure()?;
    let json = serde_json::to_vec(snap)?;
    std::fs::write(paths.cache_file(), json)?;
    Ok(())
}

pub fn load_snapshot_cache(paths: &StatePaths) -> Option<tunnet_common::EndpointSnapshot> {
    let s = std::fs::read(paths.cache_file()).ok()?;
    serde_json::from_slice(&s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct::{GENESIS_SCHEMA_VERSION, MEMBER_SCHEMA_VERSION, MemberRole, NetworkGrant};

    fn test_genesis(network_id: Uuid, cidr: &str) -> crate::direct::Genesis {
        crate::direct::Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id,
            network_name: "home".into(),
            coordinator_endpoint_id: "aa".repeat(32),
            coordinator_verifying_key: "bb".repeat(32),
            address_plan: crate::direct::AddressPlan {
                peer_cidr: cidr.parse().unwrap(),
            },
            created_at: Timestamp::now(),
            sig: String::new(),
        }
    }

    fn test_record(network_id: Uuid, ip: &str) -> crate::direct::SignedMemberRecord {
        let now = Timestamp::now();
        crate::direct::SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id,
            endpoint_id: "aa".repeat(32),
            hostname: "laptop".into(),
            ipv4: ip.parse().unwrap(),
            tags: vec![],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: now,
            grant: NetworkGrant {
                network_id,
                endpoint_id: "aa".repeat(32),
                role: MemberRole::Coordinator,
                network_epoch: 0,
                issued_at: now,
                expires_at: now,
                content_key: hex::encode([0u8; 32]),
                sig: String::new(),
            },
            endpoint_sig: String::new(),
            coordinator: true,
        }
    }

    fn test_direct(name: &str, id: Uuid, cidr: &str, ip: &str) -> DirectState {
        DirectState {
            network_name: name.into(),
            join_secret: String::new(),
            topic_hash: "bb".repeat(32),
            network_id: id,
            coordinator: true,
            open: true,
            hostname: "laptop".into(),
            coordinator_endpoint_id: None,
            coordinator_verifying_key: None,
            network_epoch: 0,
            genesis: test_genesis(id, cidr),
            self_record: test_record(id, ip),
            doc_ticket: None,
            namespace_id: None,
            coordinator_signing_key: None,
            network_grant: None,
            content_key: None,
            auto_accept_firewall: false,
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn tagged_direct_roundtrip() {
        let id = Uuid::nil();
        let s = PersistedState::Direct {
            networks: vec![test_direct("home", id, "10.21.0.0/24", "10.21.0.1")],
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let loaded: PersistedState = serde_json::from_slice(&bytes).unwrap();
        assert!(loaded.is_direct());
        let d = loaded.require_direct_network(None).unwrap();
        assert!(
            d.join_secret.is_empty(),
            "secrets must not live in state.json"
        );
        assert!(d.doc_ticket.is_none());
    }

    #[test]
    fn tagged_managed_roundtrip() {
        let s = PersistedState::Managed(ManagedState {
            control_url: "http://localhost:8080".into(),
            network_name: "default".into(),
            network_id: Uuid::nil(),
            organization_id: "org".into(),
            enrolled_at: Timestamp::now(),
            management_url: None,
            dashboard_url: None,
            local_ui: tunnet_common::local_api::LocalUiPolicy::default(),
        });
        let bytes = serde_json::to_vec(&s).unwrap();
        let loaded: PersistedState = serde_json::from_slice(&bytes).unwrap();
        assert!(loaded.is_managed());
        assert_eq!(loaded.primary_network_name(), Some("default"));
    }

    #[test]
    fn require_direct_network_multi() {
        let s = PersistedState::Direct {
            networks: vec![
                test_direct("gaming", Uuid::from_u128(1), "10.31.0.0/24", "10.31.0.1"),
                test_direct("homelab", Uuid::from_u128(2), "10.32.0.0/24", "10.32.0.1"),
            ],
        };
        assert!(s.require_direct_network(None).is_err());
        assert_eq!(
            s.require_direct_network(Some("homelab"))
                .unwrap()
                .network_name,
            "homelab"
        );
    }
}
