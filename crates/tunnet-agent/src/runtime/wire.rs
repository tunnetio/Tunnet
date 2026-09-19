//! Protobuf encoding of [`super::AgentSnapshot`] for host FFIs.
//!
//! Types are generated from `proto/tunnet/agent.proto`. Field numbers in that
//! file are the compatibility contract.

use prost::Message;

use super::snapshot::{
    AgentErrorInfo, AgentErrorKind, AgentLifecycle, AgentMode, AgentNetwork, AgentPeer, AgentRole,
    AgentSnapshot, DataPlaneState, PeerConnKind, PeerPath,
};

mod pb {
    include!(concat!(env!("OUT_DIR"), "/tunnet.agent.rs"));
}

pub use pb::{
    DataPlane, ErrorKind, Lifecycle, Mode, NativeResult, Network, Peer, Role, Snapshot,
    SnapshotError,
};
pub use pb::{PeerConn, PeerPath as WirePeerPath};

impl NativeResult {
    pub fn ok() -> Self {
        Self {
            ok: true,
            kind: ErrorKind::Unspecified as i32,
            message: String::new(),
        }
    }

    pub fn err(kind: AgentErrorKind, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            kind: error_kind(kind) as i32,
            message: message.into(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        Message::encode_to_vec(self)
    }
}

pub fn encode_snapshot(snap: &AgentSnapshot) -> Vec<u8> {
    Snapshot::from(snap).encode_to_vec()
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, prost::DecodeError> {
    Snapshot::decode(bytes)
}

impl From<&AgentSnapshot> for Snapshot {
    fn from(snap: &AgentSnapshot) -> Self {
        Self {
            lifecycle: lifecycle(snap.lifecycle) as i32,
            mode: mode(snap.mode) as i32,
            endpoint_id: snap.endpoint_id.clone(),
            hostname: snap.hostname.clone(),
            data_plane: match snap.data_plane {
                DataPlaneState::Down => DataPlane::Down as i32,
                DataPlaneState::Up => DataPlane::Up as i32,
            },
            uptime_secs: snap.uptime_secs,
            networks: snap.networks.iter().map(Network::from).collect(),
            peers: snap.peers.iter().map(Peer::from).collect(),
            error: snap.error.as_ref().map(SnapshotError::from),
        }
    }
}

impl From<&AgentNetwork> for Network {
    fn from(n: &AgentNetwork) -> Self {
        Self {
            network_id: n.network_id.clone(),
            network_name: n.network_name.clone(),
            ip: n.ip.clone(),
            mode: mode(n.mode) as i32,
            role: match n.role {
                AgentRole::Coordinator => Role::Coordinator as i32,
                AgentRole::Member => Role::Member as i32,
                AgentRole::Managed => Role::Managed as i32,
            },
            peers_total: n.peers_total as u32,
            peers_online: n.peers_online as u32,
        }
    }
}

impl From<&AgentPeer> for Peer {
    fn from(p: &AgentPeer) -> Self {
        Self {
            network_id: p.network_id.clone(),
            ip: p.ip.clone(),
            hostname: p.hostname.clone(),
            endpoint_id: p.endpoint_id.clone(),
            tags: p.tags.clone(),
            online: p.online,
            latency_ms: p.latency_ms,
            conn_state: p.conn_state.map(|c| match c {
                PeerConnKind::Connected => PeerConn::Connected as i32,
                PeerConnKind::Dialing => PeerConn::Dialing as i32,
                PeerConnKind::Idle => PeerConn::Idle as i32,
                PeerConnKind::Backoff => PeerConn::Backoff as i32,
                PeerConnKind::Blocked => PeerConn::Blocked as i32,
                PeerConnKind::Rejected => PeerConn::Rejected as i32,
            }),
            path: p.path.map(|path| match path {
                PeerPath::Direct => WirePeerPath::Direct as i32,
                PeerPath::Relay => WirePeerPath::Relay as i32,
            }),
            bytes_in: p.bytes_in,
            bytes_out: p.bytes_out,
            last_seen_secs_ago: p.last_seen_secs_ago,
            keep_alive: p.keep_alive,
            ssh_host_key: p.ssh_host_key.clone(),
        }
    }
}

impl From<&AgentErrorInfo> for SnapshotError {
    fn from(e: &AgentErrorInfo) -> Self {
        Self {
            kind: error_kind(e.kind) as i32,
            message: e.message.clone(),
        }
    }
}

fn lifecycle(value: AgentLifecycle) -> Lifecycle {
    match value {
        AgentLifecycle::Idle => Lifecycle::Idle,
        AgentLifecycle::Joining => Lifecycle::Joining,
        AgentLifecycle::PendingApproval => Lifecycle::PendingApproval,
        AgentLifecycle::Activating => Lifecycle::Activating,
        AgentLifecycle::Running => Lifecycle::Running,
        AgentLifecycle::Stopping => Lifecycle::Stopping,
        AgentLifecycle::Failed => Lifecycle::Failed,
        AgentLifecycle::Stopped => Lifecycle::Stopped,
    }
}

fn mode(value: AgentMode) -> Mode {
    match value {
        AgentMode::Idle => Mode::Idle,
        AgentMode::Direct => Mode::Direct,
        AgentMode::Managed => Mode::Managed,
    }
}

fn error_kind(value: AgentErrorKind) -> ErrorKind {
    match value {
        AgentErrorKind::NotJoined => ErrorKind::NotJoined,
        AgentErrorKind::AlreadyJoined => ErrorKind::AlreadyJoined,
        AgentErrorKind::InvalidRequest => ErrorKind::InvalidRequest,
        AgentErrorKind::JoinFailed => ErrorKind::JoinFailed,
        AgentErrorKind::ActivateFailed => ErrorKind::ActivateFailed,
        AgentErrorKind::DataPlane => ErrorKind::DataPlane,
        AgentErrorKind::Busy => ErrorKind::Busy,
        AgentErrorKind::Stopped => ErrorKind::Stopped,
        AgentErrorKind::Failed => ErrorKind::Failed,
        AgentErrorKind::Internal => ErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::snapshot::empty_snapshot;

    #[test]
    fn snapshot_roundtrips_through_protobuf() {
        let mut snap = empty_snapshot("phone".into(), 9, AgentLifecycle::Running);
        snap.mode = AgentMode::Direct;
        snap.endpoint_id = "aa".into();
        snap.networks.push(AgentNetwork {
            network_id: "n1".into(),
            network_name: "lab".into(),
            ip: "10.0.0.1".into(),
            mode: AgentMode::Direct,
            role: AgentRole::Member,
            peers_total: 1,
            peers_online: 1,
        });
        snap.peers.push(AgentPeer {
            network_id: "n1".into(),
            ip: "10.0.0.2".into(),
            hostname: "peer".into(),
            endpoint_id: "bb".into(),
            tags: vec!["tag:a".into()],
            online: Some(true),
            latency_ms: Some(12.5),
            conn_state: Some(PeerConnKind::Connected),
            path: Some(PeerPath::Direct),
            bytes_in: Some(1),
            bytes_out: Some(2),
            last_seen_secs_ago: Some(3),
            keep_alive: Some(true),
            ssh_host_key: None,
        });
        let bytes = encode_snapshot(&snap);
        let decoded = decode_snapshot(&bytes).expect("decode");
        assert_eq!(decoded.lifecycle, Lifecycle::Running as i32);
        assert_eq!(decoded.hostname, "phone");
        assert_eq!(decoded.networks.len(), 1);
        assert_eq!(decoded.peers[0].hostname, "peer");
        assert_eq!(decoded.peers[0].path, Some(WirePeerPath::Direct as i32));
        assert_eq!(decoded.mode, Mode::Direct as i32);
        assert_eq!(decoded.networks[0].role, Role::Member as i32);
    }

    #[test]
    fn unknown_lifecycle_value_is_preserved() {
        let mut buf = Vec::new();
        prost::encoding::int32::encode(1, &99i32, &mut buf);
        let decoded = decode_snapshot(&buf).expect("decode");
        assert_eq!(decoded.lifecycle, 99);
        assert!(Lifecycle::try_from(decoded.lifecycle).is_err());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let snap = empty_snapshot("phone".into(), 1, AgentLifecycle::Idle);
        let mut buf = encode_snapshot(&snap);
        prost::encoding::bytes::encode(15, &b"future".to_vec(), &mut buf);
        let decoded = decode_snapshot(&buf).expect("decode");
        assert_eq!(decoded.hostname, "phone");
        assert_eq!(decoded.lifecycle, Lifecycle::Idle as i32);
    }

    #[test]
    fn native_result_ok_does_not_set_an_error_kind() {
        let decoded = NativeResult::decode(&NativeResult::ok().to_vec()[..]).expect("decode");
        assert!(decoded.ok);
        assert_eq!(decoded.kind, ErrorKind::Unspecified as i32);
        assert!(decoded.message.is_empty());
    }

    #[test]
    fn native_result_err_carries_kind_not_just_text() {
        let bytes =
            NativeResult::err(AgentErrorKind::InvalidRequest, "invite code is empty").to_vec();
        let decoded = NativeResult::decode(&bytes[..]).expect("decode");
        assert!(!decoded.ok);
        assert_eq!(decoded.kind, ErrorKind::InvalidRequest as i32);
        assert_eq!(decoded.message, "invite code is empty");
    }

    #[test]
    fn native_result_unknown_kind_is_preserved() {
        let encoded = NativeResult {
            ok: false,
            kind: 99,
            message: "display only".into(),
        }
        .to_vec();
        let decoded = NativeResult::decode(&encoded[..]).expect("decode");
        assert_eq!(decoded.kind, 99);
        assert!(ErrorKind::try_from(decoded.kind).is_err());
    }
}
