use serde::{Deserialize, Serialize};

use crate::{
    EffectiveAgentConfig, EndpointIdHex, EndpointSnapshot, NetworkMembershipSnapshot, RedirectRule,
    RemoteAgentPolicy, SnapshotDelta,
    policy::PolicyBundle,
    posture::{CustomScriptConfig, PostureEvalResult},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Snapshot(Box<EndpointSnapshot>),
    Delta(SnapshotDelta),
    Policy(PolicyBundle),
    ForceReenroll {
        reason: String,
    },
    Ping {
        nonce: u64,
    },

    /// Dashboard / CP tells agent to start an internal serve.
    StartServe {
        serve_id: String,
        port: u16,
        protocol: String,
        internal_hostname: String,
        /// PEM leaf cert (optional for tcp).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        certificate_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key_pem: Option<String>,
        #[serde(default = "default_all_peers")]
        access_mode: String,
        #[serde(default)]
        allowed_tags: Vec<String>,
        #[serde(default)]
        allowed_endpoint_ids: Vec<String>,
        /// Optional upstream `host:port` (defaults to `127.0.0.1:{port}`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_addr: Option<String>,
    },
    /// Desired set of dashboard-managed serve ids. Agent stops managed serves not listed.
    ReconcileServes {
        #[serde(default)]
        serve_ids: Vec<String>,
    },
    StopServe {
        serve_id: String,
    },

    /// Dashboard / CP tells agent to open a reverse tunnel to a relay.
    OpenTunnel {
        tunnel_id: String,
        /// iroh endpoint id hex of the relay.
        relay_addr: String,
        subdomain: String,
        public_hostname: String,
        local_port: u16,
        protocol: String,
        auth_token: String,
        #[serde(default)]
        redirect_rules: Vec<RedirectRule>,
        /// Optional default upstream `host:port` (defaults to `127.0.0.1:{local_port}`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_addr: Option<String>,
    },
    StopTunnel {
        tunnel_id: String,
    },

    /// Dashboard / CP tells destination agent to force-close an SSH session.
    KillSshSession {
        session_id: String,
    },

    /// Dashboard / CP asks sender agent to publish and offer a local file.
    SendFile {
        transfer_id: String,
        path: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Dashboard / CP accepts a pending inbound offer on the receiver agent.
    AcceptTransfer {
        transfer_id: String,
    },
    /// Dashboard / CP rejects a pending inbound offer on the receiver agent.
    RejectTransfer {
        transfer_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Push per-machine send consent / inbox settings.
    SetSendConsent {
        mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inbox_path: Option<String>,
        #[serde(default)]
        pin_blobs: bool,
    },

    /// Control plane requests an immediate posture re-collection.
    PostureRecheck,
    /// Push updated posture collector configuration to the agent.
    PostureConfigUpdate {
        interval_secs: u64,
        enabled_collectors: Vec<String>,
        #[serde(default)]
        custom_scripts: Vec<CustomScriptConfig>,
    },
    /// Hot-push org remote agent policy (without a full snapshot).
    AgentConfigUpdate {
        policy: RemoteAgentPolicy,
    },
    /// Evaluation results and enforcement state for this device.
    PostureStatus {
        postures: Vec<PostureEvalResult>,
        enforcement_action: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace_period_remaining_secs: Option<u64>,
        #[serde(default)]
        remediation_messages: Vec<String>,
    },
}

fn default_all_peers() -> String {
    "all_peers".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello {
        endpoint_id: EndpointIdHex,
        agent_version: String,
        known_version: u64,
    },
    Heartbeat {
        active_conns: u32,
        bytes_tx: u64,
        bytes_rx: u64,
    },
    Pong {
        nonce: u64,
    },

    ServeReady {
        serve_id: String,
    },
    ServeStopped {
        serve_id: String,
    },
    ServeFailed {
        serve_id: String,
        error: String,
    },
    /// A peer connected to an active serve.
    ServePeerJoined {
        serve_id: String,
        peer_endpoint_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_hostname: Option<String>,
    },
    /// A peer disconnected from a serve (includes final byte counters).
    ServePeerLeft {
        serve_id: String,
        peer_endpoint_id: String,
        bytes_in: u64,
        bytes_out: u64,
    },

    TunnelReady {
        tunnel_id: String,
    },
    TunnelStopped {
        tunnel_id: String,
    },
    TunnelFailed {
        tunnel_id: String,
        error: String,
    },

    /// Destination agent: an SSH session started.
    SshSessionStarted {
        session_id: String,
        src_endpoint_id: EndpointIdHex,
        target_user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        src_hostname: Option<String>,
        recorded: bool,
    },
    /// Destination agent: an SSH session ended.
    SshSessionEnded {
        session_id: String,
        #[serde(default)]
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },

    /// Recorder node: a session recording was saved locally (and cast uploaded separately).
    SshRecordingSaved {
        session_id: String,
        recorder_endpoint_id: EndpointIdHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default)]
        byte_size: u64,
        #[serde(default)]
        content_sha256: String,
    },

    /// Agent notified CP that a transfer offer was sent (or received pending).
    TransferOffer {
        transfer_id: String,
        sender_endpoint_id: EndpointIdHex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver_endpoint_id: Option<EndpointIdHex>,
        file_name: String,
        size: u64,
        blake3_hash: String,
        #[serde(default)]
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Progress update while downloading / uploading.
    TransferProgress {
        transfer_id: String,
        percent: f32,
        bytes_transferred: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes_total: Option<u64>,
    },
    /// Transfer finished successfully.
    TransferComplete {
        transfer_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inbox_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
    /// Transfer failed or was rejected.
    TransferFailed {
        transfer_id: String,
        error: String,
        #[serde(default)]
        rejected: bool,
    },

    /// Agent posture attribute report (full snapshot or delta).
    PostureReport {
        full: bool,
        attributes: std::collections::HashMap<String, serde_json::Value>,
        collected_at: chrono::DateTime<chrono::Utc>,
    },

    /// Effective merged config (local ∪ remote ∪ defaults) for dashboard display.
    EffectiveConfigReport {
        config: EffectiveAgentConfig,
        reported_at: chrono::DateTime<chrono::Utc>,
    },
}

// Silence unused import when building with certain feature combos.
#[allow(dead_code)]
fn _touch(_: NetworkMembershipSnapshot) {}
