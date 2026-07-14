//! Disk-backed Direct admin helpers (pending joins, invite ids).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::state::StatePaths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJoin {
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: Ipv4Addr,
    pub collision_index: u8,
}

pub fn load_pending(paths: &StatePaths) -> anyhow::Result<Vec<PendingJoin>> {
    let p = paths.pending_file();
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}

pub fn save_pending(paths: &StatePaths, list: &[PendingJoin]) -> anyhow::Result<()> {
    paths.ensure()?;
    std::fs::write(paths.pending_file(), serde_json::to_vec_pretty(list)?)?;
    Ok(())
}

pub fn push_pending(paths: &StatePaths, p: &PendingJoin) -> anyhow::Result<()> {
    let mut list = load_pending(paths)?;
    list.retain(|x| x.endpoint_id != p.endpoint_id);
    list.push(p.clone());
    save_pending(paths, &list)
}

pub fn load_invite_ids(paths: &StatePaths) -> anyhow::Result<HashSet<String>> {
    if !paths.invites_file().exists() {
        return Ok(HashSet::new());
    }
    Ok(serde_json::from_slice(&std::fs::read(
        paths.invites_file(),
    )?)?)
}

pub fn save_invite_ids(paths: &StatePaths, set: &HashSet<String>) -> anyhow::Result<()> {
    paths.ensure()?;
    std::fs::write(paths.invites_file(), serde_json::to_vec_pretty(set)?)?;
    Ok(())
}

pub fn parse_expires(s: &str) -> anyhow::Result<chrono::Duration> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        let n: i64 = h.parse()?;
        return Ok(chrono::Duration::hours(n));
    }
    if let Some(d) = s.strip_suffix('d') {
        let n: i64 = d.parse()?;
        return Ok(chrono::Duration::days(n));
    }
    if let Some(m) = s.strip_suffix('m') {
        let n: i64 = m.parse()?;
        return Ok(chrono::Duration::minutes(n));
    }
    let secs: i64 = s.parse()?;
    Ok(chrono::Duration::seconds(secs))
}

pub fn queue_kick(paths: &StatePaths, peer_id: &str) -> anyhow::Result<()> {
    let kick_path = paths.dir.join("direct_pending_kick.json");
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

pub fn pending_path(paths: &StatePaths) -> PathBuf {
    paths.pending_file()
}
