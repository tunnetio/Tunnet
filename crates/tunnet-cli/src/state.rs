//! Minimal read-only view of `state.json` for offline `tunnet status`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tunnet_service::system_state_dir;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StatePaths {
    pub dir: PathBuf,
}

impl StatePaths {
    pub fn resolve(state_dir: Option<&str>) -> Self {
        Self {
            dir: if let Some(s) = state_dir {
                PathBuf::from(s)
            } else if let Ok(s) = std::env::var("TUNNET_STATE_DIR") {
                PathBuf::from(s)
            } else {
                system_state_dir()
            },
        }
    }

    pub fn system_dir() -> PathBuf {
        system_state_dir()
    }

    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }
}

/// Mirrors `tunnet_core::PersistedState` wire shape (`{"mode":"managed"|\"direct\", ...}`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum PersistedState {
    Managed(ManagedState),
    Direct { networks: Vec<DirectState> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedState {
    pub network_name: String,
    pub network_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectState {
    pub network_name: String,
    pub network_id: Uuid,
    pub hostname: String,
    pub self_record: DirectMemberRecord,
    #[serde(default)]
    #[allow(dead_code)]
    pub genesis: Option<DirectGenesis>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectMemberRecord {
    pub ipv4: Ipv4Addr,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct DirectGenesis {
    pub address_plan: DirectAddressPlan,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct DirectAddressPlan {
    pub peer_cidr: String,
}

impl DirectState {
    pub fn assigned_ipv4(&self) -> Ipv4Addr {
        self.self_record.ipv4
    }
}

impl PersistedState {
    pub fn try_load(paths: &StatePaths) -> anyhow::Result<Option<Self>> {
        let path = paths.state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn mode(&self) -> &'static str {
        match self {
            PersistedState::Managed(_) => "Managed",
            PersistedState::Direct { .. } => "Direct",
        }
    }
}

pub fn known_hosts_path(state_dir: &Path) -> PathBuf {
    state_dir.join("known_hosts")
}
