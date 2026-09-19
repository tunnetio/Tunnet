//! Map [`AgentSnapshot`] onto Local API status types.

use tunnet_common::local_api::{NodeModeApi, PeerSummary};
use tunnet_core::local_api::{MeshObservation, ObservedNetwork};

use super::snapshot::{AgentMode, AgentSnapshot, DataPlaneState};

pub(crate) fn from_snapshot(snap: &AgentSnapshot) -> MeshObservation {
    MeshObservation {
        endpoint_id: snap.endpoint_id.clone(),
        hostname: snap.hostname.clone(),
        mode: match snap.mode {
            AgentMode::Idle => NodeModeApi::Idle,
            AgentMode::Direct => NodeModeApi::Direct,
            AgentMode::Managed => NodeModeApi::Managed,
        },
        data_plane_up: snap.data_plane == DataPlaneState::Up,
        uptime_secs: snap.uptime_secs,
        networks: snap
            .networks
            .iter()
            .map(|n| ObservedNetwork {
                network_id: n.network_id.clone(),
                network_name: n.network_name.clone(),
                ip: n.ip.clone(),
                mode: match n.mode {
                    AgentMode::Managed => "managed".into(),
                    _ => "direct".into(),
                },
                role: n.role.as_str().into(),
                peers_total: n.peers_total,
                peers_online: n.peers_online,
            })
            .collect(),
        peers: snap
            .peers
            .iter()
            .map(|p| PeerSummary {
                network_id: p.network_id.clone(),
                ip: p.ip.clone(),
                hostname: p.hostname.clone(),
                endpoint_id: p.endpoint_id.clone(),
                tags: p.tags.clone(),
                online: p.online,
                latency_ms: p.latency_ms,
                os: None,
                conn_state: p.conn_state.map(|c| c.as_str().to_string()),
                path: p.path.map(|path| match path {
                    super::snapshot::PeerPath::Direct => "direct".into(),
                    super::snapshot::PeerPath::Relay => "relay".into(),
                }),
                bytes_in: p.bytes_in,
                bytes_out: p.bytes_out,
                last_seen_secs_ago: p.last_seen_secs_ago,
                keep_alive: p.keep_alive,
                ssh_host_key: p.ssh_host_key.clone(),
            })
            .collect(),
    }
}
