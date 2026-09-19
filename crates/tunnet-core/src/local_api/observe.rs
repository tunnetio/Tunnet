//! Runtime mesh observation consumed by Local API status GETs.

use tunnet_common::local_api::{NodeModeApi, PeerSummary};

/// Point-in-time mesh facts produced by the agent runtime.
#[derive(Debug, Clone)]
pub struct MeshObservation {
    pub endpoint_id: String,
    pub hostname: String,
    pub mode: NodeModeApi,
    pub data_plane_up: bool,
    pub uptime_secs: u64,
    pub networks: Vec<ObservedNetwork>,
    pub peers: Vec<PeerSummary>,
}

#[derive(Debug, Clone)]
pub struct ObservedNetwork {
    pub network_id: String,
    pub network_name: String,
    pub ip: String,
    pub mode: String,
    pub role: String,
    pub peers_total: usize,
    pub peers_online: usize,
}
