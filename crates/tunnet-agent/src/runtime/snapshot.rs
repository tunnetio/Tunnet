//! Authoritative in-process view of the agent.
//!
//! Hosts (Android, Local API, future subscribers) read this type. They do not
//! reconstruct lifecycle from flags, peer lists, or error text.

use std::time::Instant;

use serde::Serialize;
use tunnet_core::{CoreNode, PersistedState};
use uuid::Uuid;

/// Kind of failure a host can branch on without parsing message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorKind {
    NotJoined,
    AlreadyJoined,
    InvalidRequest,
    JoinFailed,
    ActivateFailed,
    DataPlane,
    Busy,
    Stopped,
    Failed,
    Internal,
}

/// Structured runtime error. `message` is diagnostic; `kind` is the API.
#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct AgentError {
    pub kind: AgentErrorKind,
    pub message: String,
}

impl AgentError {
    pub fn new(kind: AgentErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn info(&self) -> AgentErrorInfo {
        AgentErrorInfo {
            kind: self.kind,
            message: self.message.clone(),
        }
    }
}

impl From<anyhow::Error> for AgentError {
    fn from(err: anyhow::Error) -> Self {
        Self::new(AgentErrorKind::Internal, format!("{err:#}"))
    }
}

/// Serializable error carried on a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentErrorInfo {
    pub kind: AgentErrorKind,
    pub message: String,
}

/// Where the runtime is in its own lifecycle.
///
/// Permission and VPN-consent state stay on the host. These variants are only
/// states the agent itself can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    Idle,
    Joining,
    PendingApproval,
    Activating,
    Running,
    Stopping,
    Failed,
    Stopped,
}

/// Membership mode of the current snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    Idle,
    Direct,
    Managed,
}

/// Data plane as a single explicit state, not a boolean beside lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneState {
    Down,
    Up,
}

/// Role of this node on one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Coordinator,
    Member,
    Managed,
}

impl AgentRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Member => "member",
            Self::Managed => "managed",
        }
    }
}

/// How this node is connected to a peer, when the transport reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerPath {
    Direct,
    Relay,
}

/// On-demand connection state for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConnKind {
    Connected,
    Dialing,
    Idle,
    Backoff,
    Blocked,
    Rejected,
}

impl PeerConnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Dialing => "dialing",
            Self::Idle => "idle",
            Self::Backoff => "backoff",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

/// One joined network as the runtime currently knows it.
#[derive(Debug, Clone, Serialize)]
pub struct AgentNetwork {
    pub network_id: String,
    pub network_name: String,
    pub ip: String,
    pub mode: AgentMode,
    pub role: AgentRole,
    pub peers_total: usize,
    pub peers_online: usize,
}

/// One mesh peer as the runtime currently knows it.
#[derive(Debug, Clone, Serialize)]
pub struct AgentPeer {
    pub network_id: String,
    pub ip: String,
    pub hostname: String,
    pub endpoint_id: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_state: Option<PeerConnKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PeerPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_secs_ago: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
}

/// Authoritative in-process view of the agent.
///
/// Cheap to clone for host UIs and for a future watch subscriber. Live peer
/// fields are composed on each read while the mesh is running; phase changes
/// publish a new snapshot immediately.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSnapshot {
    pub lifecycle: AgentLifecycle,
    pub mode: AgentMode,
    pub endpoint_id: String,
    pub hostname: String,
    pub data_plane: DataPlaneState,
    pub uptime_secs: u64,
    pub networks: Vec<AgentNetwork>,
    pub peers: Vec<AgentPeer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentErrorInfo>,
}

impl AgentSnapshot {
    pub fn data_plane_up(&self) -> bool {
        self.data_plane == DataPlaneState::Up
    }

    pub fn peers_for_network(&self, network_id: &str) -> Vec<AgentPeer> {
        self.peers
            .iter()
            .filter(|p| p.network_id == network_id)
            .cloned()
            .collect()
    }
}

pub(crate) fn empty_snapshot(
    hostname: String,
    uptime_secs: u64,
    lifecycle: AgentLifecycle,
) -> AgentSnapshot {
    AgentSnapshot {
        lifecycle,
        mode: AgentMode::Idle,
        endpoint_id: String::new(),
        hostname,
        data_plane: DataPlaneState::Down,
        uptime_secs,
        networks: Vec::new(),
        peers: Vec::new(),
        error: None,
    }
}

pub(crate) fn with_error(mut snap: AgentSnapshot, err: &AgentError) -> AgentSnapshot {
    snap.lifecycle = AgentLifecycle::Failed;
    snap.data_plane = DataPlaneState::Down;
    snap.peers.clear();
    for net in &mut snap.networks {
        net.peers_online = 0;
    }
    snap.error = Some(err.info());
    snap
}

pub(crate) fn membership_from_persisted(
    persisted: &PersistedState,
    self_ipv4: Option<std::net::Ipv4Addr>,
    peers: &[AgentPeer],
) -> (AgentMode, Vec<AgentNetwork>) {
    match persisted {
        PersistedState::Managed(m) => {
            let (total, online) = peer_counts(peers, &m.network_id.to_string());
            (
                AgentMode::Managed,
                vec![AgentNetwork {
                    network_id: m.network_id.to_string(),
                    network_name: m.network_name.clone(),
                    ip: self_ipv4.map(|ip| ip.to_string()).unwrap_or_default(),
                    mode: AgentMode::Managed,
                    role: AgentRole::Managed,
                    peers_total: total,
                    peers_online: online,
                }],
            )
        }
        PersistedState::Direct { networks } => (
            AgentMode::Direct,
            networks
                .iter()
                .map(|d| {
                    let id = d.network_id.to_string();
                    let (total, online) = peer_counts(peers, &id);
                    AgentNetwork {
                        network_id: id,
                        network_name: d.network_name.clone(),
                        ip: d.self_record.ipv4.to_string(),
                        mode: AgentMode::Direct,
                        role: if d.coordinator {
                            AgentRole::Coordinator
                        } else {
                            AgentRole::Member
                        },
                        peers_total: total,
                        peers_online: online,
                    }
                })
                .collect(),
        ),
    }
}

fn peer_counts(peers: &[AgentPeer], network_id: &str) -> (usize, usize) {
    let of_net: Vec<_> = peers
        .iter()
        .filter(|p| p.network_id == network_id)
        .collect();
    let online = of_net.iter().filter(|p| p.online == Some(true)).count();
    (of_net.len(), online)
}

pub(crate) fn peers_from_node(
    node: &CoreNode,
    peer_rtt: &dashmap::DashMap<String, f64>,
    network_id: Option<Uuid>,
) -> Vec<AgentPeer> {
    let pool = &node.tunnel_pool;
    let self_id = node.endpoint_id_hex();
    node.routes
        .peers()
        .into_iter()
        .filter(|p| p.endpoint_hex != self_id)
        .filter(|p| network_id.is_none_or(|nid| p.network_id == nid))
        .map(|p| {
            let snap = pool.peer_snapshot(p.endpoint);
            let (bytes_in, bytes_out) = pool.peer_bytes(p.endpoint);
            let presence_online = node.peer_presence_online(&p.endpoint_hex);
            let presence_last_seen = node.peer_presence_last_seen(&p.endpoint_hex);
            let last_seen = if snap.last_activity_secs_ago == u64::MAX {
                presence_last_seen
            } else {
                Some(snap.last_activity_secs_ago)
            };
            let pool_online = snap.live || pool.has_live(p.endpoint);
            let online = if pool_online {
                Some(true)
            } else {
                presence_online
            };
            let latency_ms = peer_rtt.get(&p.endpoint_hex).map(|v| *v);
            AgentPeer {
                network_id: p.network_id.to_string(),
                ip: p.ip.to_string(),
                hostname: p.hostname.clone(),
                endpoint_id: p.endpoint_hex.clone(),
                tags: p.tags.clone(),
                online,
                latency_ms,
                conn_state: conn_kind(&snap.state),
                path: peer_path(&snap.path),
                bytes_in: Some(bytes_in),
                bytes_out: Some(bytes_out),
                last_seen_secs_ago: last_seen,
                keep_alive: Some(snap.keep_alive),
                ssh_host_key: p.ssh_host_key.clone(),
            }
        })
        .collect()
}

pub(crate) fn snapshot_from_node(
    node: &CoreNode,
    hostname: &str,
    dataplane_up: bool,
    peer_rtt: &dashmap::DashMap<String, f64>,
    started_at: Instant,
) -> AgentSnapshot {
    let peers = peers_from_node(node, peer_rtt, None);
    let (mode, networks) = membership_from_persisted(&node.persisted, Some(node.self_ipv4), &peers);
    AgentSnapshot {
        lifecycle: AgentLifecycle::Running,
        mode,
        endpoint_id: node.endpoint_id_hex(),
        hostname: hostname.to_string(),
        data_plane: if dataplane_up {
            DataPlaneState::Up
        } else {
            DataPlaneState::Down
        },
        uptime_secs: started_at.elapsed().as_secs(),
        networks,
        peers,
        error: None,
    }
}

fn conn_kind(state: &str) -> Option<PeerConnKind> {
    Some(match state {
        "connected" => PeerConnKind::Connected,
        "dialing" => PeerConnKind::Dialing,
        "idle" => PeerConnKind::Idle,
        "backoff" => PeerConnKind::Backoff,
        "blocked" => PeerConnKind::Blocked,
        "rejected" => PeerConnKind::Rejected,
        _ => return None,
    })
}

fn peer_path(path: &str) -> Option<PeerPath> {
    match path {
        "direct" => Some(PeerPath::Direct),
        "relay" | "relayed" => Some(PeerPath::Relay),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_and_down_are_distinct_from_failed() {
        let running = AgentSnapshot {
            lifecycle: AgentLifecycle::Running,
            mode: AgentMode::Direct,
            endpoint_id: "aa".into(),
            hostname: "phone".into(),
            data_plane: DataPlaneState::Down,
            uptime_secs: 1,
            networks: vec![AgentNetwork {
                network_id: "n1".into(),
                network_name: "lab".into(),
                ip: "10.0.0.1".into(),
                mode: AgentMode::Direct,
                role: AgentRole::Member,
                peers_total: 0,
                peers_online: 0,
            }],
            peers: Vec::new(),
            error: None,
        };
        assert!(!running.data_plane_up());
        assert_eq!(running.lifecycle, AgentLifecycle::Running);

        let err = AgentError::new(AgentErrorKind::Failed, "supervisor stopped");
        let failed = with_error(running.clone(), &err);
        assert_eq!(failed.lifecycle, AgentLifecycle::Failed);
        assert_eq!(failed.data_plane, DataPlaneState::Down);
        assert_eq!(failed.error.as_ref().unwrap().kind, AgentErrorKind::Failed);
        assert!(!failed.networks.is_empty());
        assert!(failed.peers.is_empty());
    }

    #[test]
    fn peers_are_not_collapsed_to_a_single_network() {
        let snap = AgentSnapshot {
            lifecycle: AgentLifecycle::Running,
            mode: AgentMode::Direct,
            endpoint_id: "aa".into(),
            hostname: "phone".into(),
            data_plane: DataPlaneState::Up,
            uptime_secs: 1,
            networks: vec![
                AgentNetwork {
                    network_id: "n1".into(),
                    network_name: "one".into(),
                    ip: "10.0.0.1".into(),
                    mode: AgentMode::Direct,
                    role: AgentRole::Member,
                    peers_total: 1,
                    peers_online: 1,
                },
                AgentNetwork {
                    network_id: "n2".into(),
                    network_name: "two".into(),
                    ip: "10.1.0.1".into(),
                    mode: AgentMode::Direct,
                    role: AgentRole::Coordinator,
                    peers_total: 1,
                    peers_online: 0,
                },
            ],
            peers: vec![
                AgentPeer {
                    network_id: "n1".into(),
                    ip: "10.0.0.2".into(),
                    hostname: "a".into(),
                    endpoint_id: "e1".into(),
                    tags: vec![],
                    online: Some(true),
                    latency_ms: Some(12.0),
                    conn_state: Some(PeerConnKind::Connected),
                    path: Some(PeerPath::Direct),
                    bytes_in: None,
                    bytes_out: None,
                    last_seen_secs_ago: None,
                    keep_alive: None,
                    ssh_host_key: None,
                },
                AgentPeer {
                    network_id: "n2".into(),
                    ip: "10.1.0.2".into(),
                    hostname: "b".into(),
                    endpoint_id: "e2".into(),
                    tags: vec![],
                    online: Some(false),
                    latency_ms: None,
                    conn_state: Some(PeerConnKind::Idle),
                    path: None,
                    bytes_in: None,
                    bytes_out: None,
                    last_seen_secs_ago: None,
                    keep_alive: None,
                    ssh_host_key: None,
                },
            ],
            error: None,
        };
        assert_eq!(snap.peers_for_network("n1").len(), 1);
        assert_eq!(snap.peers_for_network("n2")[0].hostname, "b");
        assert_eq!(snap.networks.len(), 2);
    }
}
