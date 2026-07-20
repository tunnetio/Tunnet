//! Agent IPC v3 - newline-delimited JSON request/response over a local socket.
//!
//! Every `tunnet <subcommand>` that is not bootstrap (`enroll` / `reset`) talks
//! to the running agent through this protocol. The agent owns CoreNode; the CLI
//! process stays unprivileged and finishes in milliseconds.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Wire protocol version - bump when breaking request/response shapes.
pub const IPC_VERSION: u32 = 3;

/// Structured IPC error codes for actionable CLI messaging.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    /// Client-side only: agent IPC socket unreachable.
    AgentNotRunning,
    DataPlaneDown,
    NotEnrolled,
    NotFound,
    Denied,
    InvalidRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Agent + network health summary. When `peers` is true, include peer table.
    Status {
        #[serde(default)]
        peers: bool,
    },
    DnsStatus,
    RouteList,
    RouteAdd {
        cidr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    Ping {
        peer: String,
        #[serde(default = "default_ping_count")]
        count: u32,
        #[serde(default = "default_ping_interval_ms")]
        interval_ms: u64,
    },
    Diag,
    Netcheck,

    ServeStart {
        port: u16,
        #[serde(default = "default_https")]
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        certificate_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        internal_hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        serve_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_endpoint_ids: Vec<String>,
    },
    ServeStatus,
    ServeOff {
        port: u16,
    },

    TunnelStart {
        port: u16,
        #[serde(default = "default_https")]
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subdomain: Option<String>,
        /// Capture HTTP traffic and serve a local inspector UI.
        #[serde(default)]
        inspect: bool,
        /// Bind address for the inspector (default `127.0.0.1:4040`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inspect_addr: Option<String>,
    },
    TunnelStatus,
    TunnelOff {
        port: u16,
    },

    /// List SSH sessions from the control plane.
    SshSessions {
        #[serde(default = "default_ssh_list_limit")]
        limit: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    /// List SSH recordings from the control plane.
    SshRecordings {
        #[serde(default = "default_ssh_list_limit")]
        limit: u32,
    },
    /// Fetch a recording cast by session id.
    SshPlay {
        session_id: String,
    },

    /// Poll a check-mode re-auth challenge for a proof token.
    SshAuthPoll {
        challenge_token: String,
    },

    /// Send a file or directory to a peer (hostname / IP / endpoint id / `tag:name`).
    SendFile {
        path: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    SendAccept {
        transfer_id: String,
    },
    SendReject {
        transfer_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    SendList,
    SendHistory,
    SendConfig,
    SendSetConfig {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inbox_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin_blobs: Option<bool>,
    },

    /// Whether TUN + system DNS/routes are active.
    DataPlaneStatus,
    /// Bring TUN + DNS + routes up (daemon must already be running).
    DataPlaneUp,
    /// Tear down TUN + DNS + routes; keep mesh/docs/IPC alive.
    DataPlaneDown,

    /// Direct: create invite code (coordinator).
    DirectInvite {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default)]
        reusable: bool,
        #[serde(default = "default_invite_expires")]
        expires: String,
    },
    DirectRequests {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectAccept {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        peer_id: String,
    },
    DirectDeny {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        peer_id: String,
    },
    DirectKick {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        peer_id: String,
    },
    DirectFirewallShow {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallOff {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallAdd {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        direction: String,
        action: String,
        #[serde(default = "default_fw_protocol")]
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
    },
    DirectFirewallRemove {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        index: usize,
    },
    DirectFirewallReset {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallFlushConntrack {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallAcceptSuggestion {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectFirewallRejectSuggestion {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectPolicyShow {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectPolicySet {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        /// TOML contents of a policy file (global rules + optional per-hostname).
        toml: String,
    },
    DirectPolicyClear {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
    },
    DirectKeepAlive {
        hostname: String,
        #[serde(default = "default_true")]
        enable: bool,
    },
    /// Manual IP override for birthday collisions.
    DirectOverrideIp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        peer: String,
        ip: String,
    },
    DirectConnect {
        contact_id: String,
    },
    DirectConnectAllow {
        contact_id: String,
    },
    DirectConnectPending,
    DirectConnectAccept {
        contact_id: String,
    },
    DirectConnectDeny {
        contact_id: String,
    },
    DirectConnectRotate,

    /// Reload firewall / DNS / logging / keep-alive from tunnet.toml without dropping connections.
    Reload,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum IpcResponse {
    Ready,
    Status(StatusInfo),
    DnsStatus(DnsStatusInfo),
    Routes(RoutesInfo),
    RouteAdded {
        cidr: String,
    },
    /// Streaming-style: one PingProbe per round, then PingSummary.
    PingProbe(PingProbe),
    PingSummary(PingSummary),
    Diag(DiagInfo),
    Netcheck(NetcheckInfo),
    Serve(ServeInfo),
    Serves {
        serves: Vec<ServeInfo>,
    },
    Tunnel(TunnelInfo),
    Tunnels {
        tunnels: Vec<TunnelInfo>,
    },
    SshSessions {
        sessions: Vec<SshSessionInfo>,
    },
    SshRecordings {
        recordings: Vec<SshRecordingInfo>,
    },
    SshCast {
        session_id: String,
        cast_text: String,
        content_sha256: String,
    },
    SshAuthPoll {
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof_token: Option<String>,
    },
    Transfer(TransferInfo),
    Transfers {
        transfers: Vec<TransferInfo>,
    },
    SendConfig(SendConfigInfo),
    DataPlane {
        up: bool,
    },
    DirectInvite {
        code: String,
    },
    DirectPending {
        requests: Vec<DirectPendingInfo>,
    },
    DirectFirewall {
        enabled: bool,
        rules: Vec<DirectFirewallRuleInfo>,
        #[serde(default)]
        conntrack_entries: usize,
        #[serde(default)]
        packets_allowed: u64,
        #[serde(default)]
        packets_denied: u64,
        #[serde(default)]
        packets_rejected: u64,
        #[serde(default)]
        suggested_rules: usize,
    },
    DirectFirewallPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pending: Option<String>,
    },
    DirectPolicy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json: Option<String>,
    },
    DirectConnectPending {
        requests: Vec<DirectConnectPendingInfo>,
    },
    DirectContact {
        contact_id: String,
    },
    Ok {
        message: String,
    },
    Error {
        code: IpcErrorCode,
        message: String,
    },
}

/// Format an IPC error for CLI display.
pub fn format_ipc_error(code: &IpcErrorCode, message: &str) -> String {
    match code {
        IpcErrorCode::AgentNotRunning => {
            "agent is not running (start with `tunnet up` / service)".into()
        }
        IpcErrorCode::DataPlaneDown => {
            format!("{message} (bring data plane up with `tunnet up`)")
        }
        IpcErrorCode::NotEnrolled => {
            format!("{message} (enroll or join a network first)")
        }
        IpcErrorCode::NotFound => message.to_string(),
        IpcErrorCode::Denied => message.to_string(),
        IpcErrorCode::InvalidRequest => message.to_string(),
        IpcErrorCode::Internal => message.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConnectPendingInfo {
    pub contact_id: String,
    pub endpoint_id: String,
    pub hostname: String,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPendingInfo {
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: String,
    pub collision_index: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLite {
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
    /// OpenSSH public host key line when advertised by the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub ip: String,
    pub hostname: String,
    pub network_name: String,
    pub network_id: String,
    pub organization_id: String,
    pub endpoint_id: String,
    pub peers_total: usize,
    pub peers_online: usize,
    pub relay_status: String,
    pub uptime_secs: u64,
    pub agent_version: String,
    pub snapshot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerLite>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane_up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conntrack_entries: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand: Option<OnDemandStatusInfo>,
    /// RFC3339 timestamp when this machine is deleted after inactivity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Seconds until `expires_at`, when auto-expiry is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    /// Control plane base URL (Managed). Loopback here on a VM means enroll is broken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    /// Live WebSocket link to the control plane (Managed only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<ControlPlaneStatusInfo>,
}

/// Control-plane WebSocket connectivity for Managed agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct OnDemandStatusInfo {
    pub reconnect_attempts: u64,
    pub reconnect_success: u64,
    pub reconnect_fail: u64,
    pub packets_buffered: u64,
    pub packets_dropped_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatusInfo {
    pub suffix: String,
    pub upstream: Vec<String>,
    pub peer_dns_active: bool,
    pub cached_entries: usize,
    pub synthetic_base: String,
    pub magic_ip: String,
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesInfo {
    pub subnet_routes: Vec<SubnetRouteInfo>,
    pub hostname_routes: Vec<HostnameRouteInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<ExitNodeRouteInfo>,
    pub split_tunnel_mode: String,
    pub split_tunnel_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRouteInfo {
    pub cidr: String,
    pub via_hostname: String,
    pub via_ip: String,
    pub via_endpoint_id: String,
    pub advertised_by_self: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ExitNodeRouteInfo {
    pub hostname: String,
    pub via_ip: String,
    pub endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingProbe {
    pub seq: u32,
    pub peer: String,
    pub peer_ip: String,
    pub latency_ms: f64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct NetcheckInfo {
    pub ok: bool,
    pub checks: Vec<NetcheckItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetcheckItem {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServeInfo {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub url: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct SendConfigInfo {
    pub consent: String,
    pub inbox_path: String,
    pub pin_blobs: bool,
}

/// Convenience: self IPv4 as string for status.
pub fn ip_str(ip: Ipv4Addr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_agent_not_running() {
        let msg = format_ipc_error(&IpcErrorCode::AgentNotRunning, "ignored");
        assert!(msg.contains("agent is not running"));
        assert!(msg.contains("tunnet up"));
    }
}
