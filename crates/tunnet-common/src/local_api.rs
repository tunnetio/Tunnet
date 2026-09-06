//! Local Management API (`/v1`) JSON types shared by `tunnetd` and `tunnet-client`.
//!
//! These structs describe the HTTP JSON contract for controlling a running Tunnet
//! daemon over a machine-local Unix socket or named pipe. They replace the legacy
//! newline-delimited IPC protocol and are consumed by the `tunnet-client` crate,
//! the `tunnet` CLI, and future desktop integrations.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Local Management API major version (URL prefix `/v1/`).
pub const API_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Permissions (capability strings for auth)
// ---------------------------------------------------------------------------

pub mod permissions {
    pub const STATUS_READ: &str = "status.read";
    pub const EVENTS_READ: &str = "events.read";
    pub const DNS_READ: &str = "dns.read";
    pub const ROUTES_READ: &str = "routes.read";
    pub const DIAG_READ: &str = "diag.read";
    pub const DATA_PLANE_WRITE: &str = "data_plane.write";
    pub const SEND: &str = "send";
    pub const SSH: &str = "ssh";
    pub const SERVE: &str = "serve";
    pub const TUNNEL: &str = "tunnel";
    pub const NETWORK_INVITE: &str = "network.invite";
    pub const NETWORK_ADMIT: &str = "network.admit";
    pub const FIREWALL_WRITE: &str = "firewall.write";
    pub const POLICY_WRITE: &str = "policy.write";
    pub const LIFECYCLE: &str = "lifecycle";
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Structured error codes for actionable CLI and client messaging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// Client-side only: Local API socket unreachable (`tunnetd` not running).
    DaemonNotRunning,
    DataPlaneDown,
    NotEnrolled,
    NotFound,
    Denied,
    InvalidRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
}

/// Format a Local API error for CLI display.
pub fn format_api_error(code: &ApiErrorCode, message: &str) -> String {
    match code {
        ApiErrorCode::DaemonNotRunning => {
            "tunnetd is not running (start with `tunnet service start` or run `tunnetd`)".into()
        }
        ApiErrorCode::DataPlaneDown => {
            format!("{message} (bring data plane up with `tunnet up`)")
        }
        ApiErrorCode::NotEnrolled => {
            format!("{message} (enroll or join a network first)")
        }
        ApiErrorCode::NotFound => message.to_string(),
        ApiErrorCode::Denied => message.to_string(),
        ApiErrorCode::InvalidRequest => message.to_string(),
        ApiErrorCode::Internal => message.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OkResponse {
    pub message: String,
}

// ---------------------------------------------------------------------------
// Local UI policy (managed-mode desktop / tray restrictions)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalUiPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_disconnect: bool,
    #[serde(default = "default_true")]
    pub allow_serve: bool,
    #[serde(default = "default_true")]
    pub allow_tunnel: bool,
    #[serde(default = "default_true")]
    pub allow_self_tags: bool,
}

impl Default for LocalUiPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_disconnect: true,
            allow_serve: true,
            allow_tunnel: true,
            allow_self_tags: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Node / network summary (status model)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeModeApi {
    Idle,
    Direct,
    Managed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PeerSummary {
    pub network_id: String,
    pub ip: String,
    pub hostname: String,
    pub endpoint_id: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// connected | suspended | reconnecting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_state: Option<String>,
    /// direct | relay | unknown
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_secs_ago: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkSummary {
    pub network_id: String,
    pub network_name: String,
    /// direct | managed
    pub mode: String,
    pub ip: String,
    /// coordinator | member | managed
    pub role: String,
    pub peers_total: usize,
    pub peers_online: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conntrack_entries: Option<usize>,
    pub relay_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlPlaneStatusInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeSummary {
    pub endpoint_id: String,
    pub hostname: String,
    pub mode: NodeModeApi,
    pub daemon_version: String,
    pub api_version: u32,
    pub data_plane_up: bool,
    pub uptime_secs: u64,
    pub snapshot_version: u64,
    pub networks: Vec<NetworkSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand: Option<OnDemandStatusInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlPlaneStatusInfo>,
    /// Short git hash the DAEMON binary was built from ("unknown" when
    /// unavailable). Compared against the CLI's own hash to catch
    /// stale-daemon traps (fresh CLI, old service binary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_git: Option<String>,
    /// Tunnel ALPN the daemon speaks (e.g. `tunnet/tunnel/3`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_alpn: Option<String>,
    /// Dataplane health detail (never "up" with a dead packet worker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane: Option<DataPlaneInfo>,
}

/// Dataplane health detail for `tunnet status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DataPlaneInfo {
    /// `up` | `degraded` | `restarting` | `down`.
    pub state: String,
    pub outbound_alive: bool,
    pub restart_count: u64,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MetaInfo {
    pub api_version: u32,
    pub daemon_version: String,
    pub mode: NodeModeApi,
    pub features: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworksResponse {
    pub networks: Vec<NetworkSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PeersResponse {
    pub peers: Vec<PeerSummary>,
}

/// Server-sent events emitted on `GET /v1/events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalEvent {
    DaemonReady,
    DaemonModeChanged {
        mode: NodeModeApi,
    },
    DataPlaneChanged {
        up: bool,
    },
    NetworkAdded {
        network_id: String,
    },
    NetworkRemoved {
        network_id: String,
    },
    PeerOnline {
        network_id: String,
        endpoint_id: String,
    },
    PeerOffline {
        network_id: String,
        endpoint_id: String,
    },
    PeerPathChanged {
        network_id: String,
        endpoint_id: String,
        path: String,
    },
    PeerMetrics {
        network_id: String,
        endpoint_id: String,
        latency_ms: f64,
    },
    DirectJoinRequested {
        network_id: String,
        peer_id: String,
    },
    TransferCreated {
        id: String,
    },
    TransferProgress {
        id: String,
        bytes: u64,
    },
    TransferCompleted {
        id: String,
    },
    ControlConnected,
    ControlDisconnected,
    UpdateAvailable {
        version: String,
    },
    CoreUpdateChanged {
        status: CoreUpdateStatus,
    },
}

// ---------------------------------------------------------------------------
// SSE events (ping)
// ---------------------------------------------------------------------------

/// Server-sent events emitted by `GET /v1/ping` (one probe per round, then summary).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PingEvent {
    Probe(PingProbe),
    Summary(PingSummary),
}

// ---------------------------------------------------------------------------
// Query / path parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PingParams {
    pub peer: String,
    #[serde(default = "default_ping_count")]
    pub count: u32,
    #[serde(default = "default_ping_interval_ms")]
    pub interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshSessionsParams {
    #[serde(default = "default_ssh_list_limit")]
    pub limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshRecordingsParams {
    #[serde(default = "default_ssh_list_limit")]
    pub limit: u32,
}

// ---------------------------------------------------------------------------
// Bootstrap / lifecycle request bodies
// ---------------------------------------------------------------------------

/// Enroll this machine into a Managed network via the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalEnrollRequest {
    pub control_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default = "default_enroll_wait_secs")]
    pub wait_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
    #[serde(default)]
    pub no_encrypt_state: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkCreateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default)]
    pub open: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default)]
    pub no_encrypt_state: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkJoinRequest {
    pub invite_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default)]
    pub auto_accept_firewall: bool,
    #[serde(default)]
    pub no_encrypt_state: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkLeaveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkUpgradeRequest {
    pub control_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResetRequest {
    #[serde(default)]
    pub yes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PostureCheckRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definitions_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyOpRequest {
    /// validate | test | simulate | fmt | export | diff | apply | drift | history | rollback
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_contents: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    #[serde(default)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JsonPayload {
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidateConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthLoginRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateRequest {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub restart: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoreUpdatePhase {
    Idle,
    Checking,
    Available,
    Downloading,
    Verifying,
    Staged,
    Activating,
    HealthCheck,
    Complete,
    Error,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CoreUpdateStatus {
    pub phase: CoreUpdatePhase,
    pub current_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_version: Option<String>,
    pub api_version: u32,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Device / machine request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceLabelRequest {
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceLabelPatchRequest {
    /// `None` value deletes the label key.
    pub labels: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceLabelDeleteRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceTagAddRequest {
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceTagRemoveRequest {
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceExpiryRequest {
    pub duration: String,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteAddRequest {
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Serve / tunnel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServeStartRequest {
    pub port: u16,
    #[serde(default = "default_https")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_endpoint_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServeOffRequest {
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TunnelStartRequest {
    pub port: u16,
    #[serde(default = "default_https")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(default)]
    pub inspect: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspect_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TunnelOffRequest {
    pub port: u16,
}

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshAuthPollRequest {
    pub challenge_token: String,
}

// ---------------------------------------------------------------------------
// File transfer (send)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendFileRequest {
    pub path: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendAcceptRequest {
    pub transfer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendRejectRequest {
    pub transfer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendSetConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_blobs: Option<bool>,
}

// ---------------------------------------------------------------------------
// Direct mode request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectNetworkRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPeerRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectInviteRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default)]
    pub reusable: bool,
    #[serde(default = "default_invite_expires")]
    pub expires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectFirewallAddRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub direction: String,
    pub action: String,
    #[serde(default = "default_fw_protocol")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectFirewallRemoveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPolicySetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// TOML contents of a policy file (global rules + optional per-hostname).
    pub toml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectKeepAliveRequest {
    pub hostname: String,
    #[serde(default = "default_true")]
    pub enable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectOverrideIpRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub peer: String,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectConnectRequest {
    pub contact_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectConnectContactRequest {
    pub contact_id: String,
}

// ---------------------------------------------------------------------------
// Response wrappers (resource-oriented; formerly inline IPC variants)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteAddedResponse {
    pub cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DataPlaneStatus {
    pub up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServesResponse {
    pub serves: Vec<ServeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TunnelsResponse {
    pub tunnels: Vec<TunnelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransfersResponse {
    pub transfers: Vec<TransferInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshSessionsResponse {
    pub sessions: Vec<SshSessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshRecordingsResponse {
    pub recordings: Vec<SshRecordingInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshCastResponse {
    pub session_id: String,
    pub cast_text: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshAuthPollResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectInviteResponse {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPendingResponse {
    pub requests: Vec<DirectPendingInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectFirewallResponse {
    pub enabled: bool,
    pub rules: Vec<DirectFirewallRuleInfo>,
    #[serde(default)]
    pub conntrack_entries: usize,
    #[serde(default)]
    pub packets_allowed: u64,
    #[serde(default)]
    pub packets_denied: u64,
    #[serde(default)]
    pub packets_rejected: u64,
    #[serde(default)]
    pub suggested_rules: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectFirewallPendingResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPolicyResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectConnectPendingResponse {
    pub requests: Vec<DirectConnectPendingInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectContactResponse {
    pub contact_id: String,
}

// ---------------------------------------------------------------------------
// Info / response structs (carried over from IPC protocol)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectConnectPendingInfo {
    pub contact_id: String,
    pub endpoint_id: String,
    pub hostname: String,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPendingInfo {
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: String,
    pub collision_index: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectFirewallRuleInfo {
    pub index: usize,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshSessionInfo {
    pub id: String,
    pub src_endpoint_id: String,
    pub dst_endpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_hostname: Option<String>,
    pub target_user: String,
    pub status: String,
    pub recorded: bool,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SshRecordingInfo {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    pub byte_size: u64,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
}

/// Control-plane WebSocket connectivity for Managed agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ControlPlaneStatusInfo {
    pub url: String,
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_for_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_change_secs_ago: Option<u64>,
    pub reconnects: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OnDemandStatusInfo {
    pub reconnect_attempts: u64,
    pub reconnect_success: u64,
    pub reconnect_fail: u64,
    pub packets_buffered: u64,
    pub packets_dropped_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsStatusInfo {
    pub suffix: String,
    pub upstream: Vec<String>,
    pub dnssec: bool,
    pub peer_dns_active: bool,
    pub cached_entries: usize,
    pub synthetic_base: String,
    pub magic_ip: String,
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoutesInfo {
    pub subnet_routes: Vec<SubnetRouteInfo>,
    pub hostname_routes: Vec<HostnameRouteInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<ExitNodeRouteInfo>,
    pub split_tunnel_mode: String,
    pub split_tunnel_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubnetRouteInfo {
    pub cidr: String,
    pub via_hostname: String,
    pub via_ip: String,
    pub via_endpoint_id: String,
    pub advertised_by_self: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HostnameRouteInfo {
    pub hostname: String,
    pub is_wildcard: bool,
    pub via_hostname: String,
    pub via_ip: String,
    pub via_endpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExitNodeRouteInfo {
    pub hostname: String,
    pub via_ip: String,
    pub endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PingProbe {
    pub seq: u32,
    pub peer: String,
    pub peer_ip: String,
    pub latency_ms: f64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PingSummary {
    pub peer: String,
    pub peer_ip: String,
    pub transmitted: u32,
    pub received: u32,
    pub loss_pct: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DiagInfo {
    pub nat_type: String,
    pub endpoint_id: String,
    pub endpoint_online: bool,
    pub relay_reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_rtt_ms: Option<f64>,
    pub direct_peers: usize,
    pub relayed_peers: usize,
    pub total_peers: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetcheckInfo {
    pub ok: bool,
    pub checks: Vec<NetcheckItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetcheckItem {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServeInfo {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub url: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TunnelInfo {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub public_url: String,
    pub relay: String,
    pub status: String,
    /// Local inspector URL when `--inspect` is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspector_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TransferInfo {
    pub transfer_id: String,
    pub direction: String,
    pub peer_endpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_hostname: Option<String>,
    pub file_name: String,
    pub size: u64,
    pub hash: String,
    pub status: String,
    pub percent: f32,
    pub bytes_transferred: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_path: Option<String>,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendConfigInfo {
    pub consent: String,
    pub inbox_path: String,
    pub pin_blobs: bool,
}

/// Convenience: self IPv4 as string for status.
pub fn ip_str(ip: Ipv4Addr) -> String {
    ip.to_string()
}

fn default_invite_expires() -> String {
    "24h".into()
}

fn default_ssh_list_limit() -> u32 {
    50
}

fn default_ping_count() -> u32 {
    4
}

fn default_ping_interval_ms() -> u64 {
    1000
}

fn default_https() -> String {
    "https".into()
}

fn default_fw_protocol() -> String {
    "tcp".into()
}

fn default_true() -> bool {
    true
}

fn default_enroll_wait_secs() -> u64 {
    600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_not_running_error_names_supported_start_commands() {
        let msg = format_api_error(&ApiErrorCode::DaemonNotRunning, "ignored");
        assert_eq!(
            msg,
            "tunnetd is not running (start with `tunnet service start` or run `tunnetd`)"
        );
    }

    #[test]
    fn ping_event_serde_roundtrip() {
        let probe = PingEvent::Probe(PingProbe {
            seq: 1,
            peer: "db".into(),
            peer_ip: "100.64.0.2".into(),
            latency_ms: 12.5,
            path: "direct".into(),
        });
        let json = serde_json::to_string(&probe).unwrap();
        assert!(json.contains("\"type\":\"probe\""));
        let back: PingEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, PingEvent::Probe(_)));
    }
}
