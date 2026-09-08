//! Disk-backed Direct kick queue (applied when docs membership is ready).

use crate::state::StatePaths;
use uuid::Uuid;

pub fn queue_kick(paths: &StatePaths, network_id: Uuid, peer_id: &str) -> anyhow::Result<()> {
    paths.ensure_network_dirs(network_id)?;
    let kick_path = paths.pending_kick_file(network_id);
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
