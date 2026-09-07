//! Disk-backed Direct admin helpers (pending joins, invite ids).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::StatePaths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJoin {
    pub endpoint_id: String,
    pub hostname: String,
}

pub fn load_pending(paths: &StatePaths, network_id: Uuid) -> anyhow::Result<Vec<PendingJoin>> {
    let p = paths.pending_file(network_id);
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}

pub fn save_pending(
    paths: &StatePaths,
    network_id: Uuid,
    list: &[PendingJoin],
) -> anyhow::Result<()> {
    paths.ensure_network_dirs(network_id)?;
    std::fs::write(
        paths.pending_file(network_id),
        serde_json::to_vec_pretty(list)?,
    )?;
    Ok(())
}

pub fn push_pending(paths: &StatePaths, network_id: Uuid, p: &PendingJoin) -> anyhow::Result<()> {
    let mut list = load_pending(paths, network_id)?;
    list.retain(|x| x.endpoint_id != p.endpoint_id);
    list.push(p.clone());
    save_pending(paths, network_id, &list)
}

pub fn load_invite_ids(paths: &StatePaths, network_id: Uuid) -> anyhow::Result<HashSet<String>> {
    if !paths.invites_file(network_id).exists() {
        return Ok(HashSet::new());
    }
    Ok(serde_json::from_slice(&std::fs::read(
        paths.invites_file(network_id),
    )?)?)
}

pub fn save_invite_ids(
    paths: &StatePaths,
    network_id: Uuid,
    set: &HashSet<String>,
) -> anyhow::Result<()> {
    paths.ensure_network_dirs(network_id)?;
    std::fs::write(
        paths.invites_file(network_id),
        serde_json::to_vec_pretty(set)?,
    )?;
    Ok(())
}

pub fn queue_kick(paths: &StatePaths, network_id: Uuid, peer_id: &str) -> anyhow::Result<()> {
    paths.ensure_network_dirs(network_id)?;
    let kick_path = paths
        .dir
        .join("direct_pending_kick")
        .join(format!("{network_id}.json"));
    if let Some(parent) = kick_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut kicks: Vec<String> = if kick_path.exists() {
        serde_json::from_slice(&std::fs::read(&kick_path)?)?
    } else {
        vec![]
    };
    if !kicks.iter().any(|id| id == peer_id) {
        kicks.push(peer_id.to_string());
    }
    std::fs::write(&kick_path, serde_json::to_vec_pretty(&kicks)?)?;
    Ok(())
}

pub fn pending_path(paths: &StatePaths, network_id: Uuid) -> std::path::PathBuf {
    paths.pending_file(network_id)
}
