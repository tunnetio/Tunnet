//! Agent IPC v2 - newline-delimited JSON request/response over a local socket.
//!
//! Every `tuntun <subcommand>` that is not bootstrap (`enroll` / `reset`) talks
//! to the running agent through this protocol. The agent owns CoreNode; the CLI
//! process stays unprivileged and finishes in milliseconds.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Wire protocol version - bump when breaking request/response shapes.
pub const IPC_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Legacy: open a bidirectional byte stream to a peer:port (FD handoff).
    OpenStream {
        host: String,
        port: u16,
    },
    /// Legacy: list mesh peers.
    ListPeers,

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
    },
    TunnelStatus,
    TunnelOff {
        port: u16,
    },

    /// Open a mesh SSH session. After `Ready`, the connection becomes a raw
    /// bidirectional byte pipe (with in-band resize frames).
    Ssh {
        target: String,
        user: String,
        local_user: String,
        term_type: String,
        width: u16,
        height: u16,
        #[serde(default)]
        env_vars: Vec<(String, String)>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
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
        #[serde(default)]
        reusable: bool,
        #[serde(default = "default_invite_expires")]
        expires: String,
    },
    DirectRequests,
    DirectAccept {
        peer_id: String,
    },
    DirectDeny {
        peer_id: String,
    },
    DirectKick {
        peer_id: String,
    },
    DirectFirewallShow,
    DirectFirewallOff,
    DirectFirewallAdd {
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
        index: usize,
    },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum IpcResponse {
    Ready,
    Peers {
        peers: Vec<PeerLite>,
    },
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
    SshReauthRequired {
        reauth_url: String,
        challenge_token: String,
        message: String,
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
    },
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatusInfo {
    pub suffix: String,
    pub upstream: Vec<String>,
    pub peer_dns_active: bool,
    pub cached_entries: usize,
    pub synthetic_base: String,
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
