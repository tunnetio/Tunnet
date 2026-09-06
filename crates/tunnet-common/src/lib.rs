pub mod agent_policy;
pub mod edge;
pub mod ipv6;
pub mod local_api;
pub mod packet;
pub mod policy;
pub mod posture;
pub mod recording;
pub mod send;
pub mod signing;
pub mod ws;

pub use agent_policy::{
    ConfigSource, EffectiveAgentConfig, LocalDualOverrides, LocalOnlySettings, RelayPolicy,
    RemoteAgentPolicy, RemoteAutoUpdatePolicy, RemoteDnsPolicy, RemoteExitNodesPolicy,
    RemotePostureCollectorPolicy, RemoteRelayPolicy, ResolvedSetting, inherit_remote_policy,
    merge_agent_config,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

pub type EndpointIdHex = String;

/// Short git hash baked at compile time (build.rs), `"unknown"` when git
/// was unavailable. Rendered by `tunnet status` for both the CLI and the
/// daemon so stale-binary mismatches are visible instead of debuggable
/// for hours.
pub fn git_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// ALPN identifier for the tunnel protocol (mesh datagrams).
/// Tunnel framing is the only wire format (segmented logical packets, every
/// frame bound to one network). The `/3` is only the negotiated
/// wire-protocol version: it keeps older binaries (raw-IP `/1`, undisclosed
/// `/2` framing) from accidentally speaking an incompatible format. It does
/// not imply any older implementation remains — there is none, and there is
/// no compatibility decoder.
pub const TUNNEL_ALPN: &[u8] = b"tunnet/tunnel/3";

/// ALPN for agent ↔ public edge reverse tunnels.
pub const EDGE_ALPN: &[u8] = b"tunnet/edge/1";

/// ALPN for SSH session recording streams.
pub use recording::RECORDING_ALPN;

/// ALPN for file-transfer offer streams.
pub use send::SEND_ALPN;

/// Header the agent sends with every authenticated request.
pub const HDR_ENDPOINT_ID: &str = "x-endpoint-id";
pub const HDR_TIMESTAMP: &str = "x-timestamp";
pub const HDR_SIGNATURE: &str = "x-endpoint-signature";
pub const HDR_TRACE_ID: &str = "x-trace-id";

/// Maximum allowed clock skew for signature validation.
pub const MAX_SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    pub endpoint_id: EndpointIdHex,
    pub hostname: String,
    pub os: String,
    pub agent_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
}

fn default_enroll_status() -> String {
    "active".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub organization_id: String,
    pub network_id: Uuid,
    pub network_name: String,
    /// `"pending"` for quick enroll awaiting approval; `"active"` otherwise.
    #[serde(default = "default_enroll_status")]
    pub status: String,
    pub snapshot: EndpointSnapshot,
    /// Management API base URL for this deployment (service discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
    /// Dashboard base URL for deep links from Desktop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollStatusRequest {
    pub endpoint_id: EndpointIdHex,
    pub network_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum EnrollStatusResponse {
    Pending {
        organization_id: String,
        network_id: Uuid,
        network_name: String,
    },
    Active {
        organization_id: String,
        network_id: Uuid,
        network_name: String,
        snapshot: Box<EndpointSnapshot>,
    },
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub endpoint_id: EndpointIdHex,
    pub hostname: String,
    pub agent_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    pub endpoint_id: EndpointIdHex,
    pub known_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub ip: Ipv4Addr,
    pub endpoint_id: EndpointIdHex,
    pub hostname: String,
    pub tags: Vec<String>,
    /// OpenSSH public host key line (`ssh-ed25519 AAAA...`), when advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRoute {
    pub cidr: ipnet::Ipv4Net,
    pub via_endpoint_id: EndpointIdHex,
    pub via_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostnameRoute {
    pub hostname: String,
    pub via_endpoint_id: EndpointIdHex,
    pub via_ip: Ipv4Addr,
    #[serde(default)]
    pub is_wildcard: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ip: Option<Ipv4Addr>,
}

fn default_magic_ip() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 100, 53)
}

fn default_synthetic_base() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 0, 1)
}

/// Upstream resolver list. `"system"` (alone) uses OS DNS configuration.
/// Otherwise each entry is a nameserver URL (`udp+tcp://1.1.1.1:53`, `tls://1.1.1.1:853#cloudflare-dns.com`, …).
pub fn default_dns_upstream() -> Vec<String> {
    vec!["udp+tcp://1.1.1.1:53".into(), "udp+tcp://8.8.8.8:53".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub suffix: String,
    #[serde(default = "default_dns_upstream")]
    pub upstream: Vec<String>,
    /// Hickory DNSSEC validation. Off by default: many stub forwarders and
    /// middleboxes break signed zones. Turn on when upstreams are validating-capable.
    #[serde(default)]
    pub dnssec: bool,
    #[serde(default = "default_synthetic_base")]
    pub synthetic_base: Ipv4Addr,
    #[serde(default = "default_magic_ip")]
    pub magic_ip: Ipv4Addr,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            suffix: "tunnet".into(),
            upstream: default_dns_upstream(),
            dnssec: false,
            synthetic_base: default_synthetic_base(),
            magic_ip: default_magic_ip(),
        }
    }
}

/// Exit node advertisement in the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitNodeInfo {
    pub endpoint_id: EndpointIdHex,
    pub via_ip: Ipv4Addr,
    pub allowed_cidrs: Vec<ipnet::Ipv4Net>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SplitTunnelMode {
    Include,
    #[default]
    Exclude,
}

fn default_allow_local_lan() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_endpoint_id: Option<EndpointIdHex>,
    #[serde(default)]
    pub split_tunnel_mode: SplitTunnelMode,
    #[serde(default)]
    pub split_tunnel_cidrs: Vec<ipnet::Ipv4Net>,
    /// When using an exit in Exclude mode, keep RFC1918 LAN via the original gateway.
    #[serde(default = "default_allow_local_lan")]
    pub allow_local_lan: bool,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self {
            exit_node_endpoint_id: None,
            split_tunnel_mode: SplitTunnelMode::default(),
            split_tunnel_cidrs: Vec::new(),
            allow_local_lan: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6PeerEntry {
    pub ip: Ipv6Addr,
    pub endpoint_id: EndpointIdHex,
    pub hostname: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveServe {
    pub id: String,
    pub endpoint_id: EndpointIdHex,
    pub hostname: String,
    pub port: u16,
    pub protocol: String,
    pub internal_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: String,
    pub local_port: u16,
    pub protocol: String,
    pub subdomain: String,
    pub public_hostname: String,
    pub edge_addr: String,
    pub edge_auth_token: String,
    pub status: String,
}

/// Path-based redirect on the agent (multi-port / mesh HTTPS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RedirectRule {
    pub path_pattern: String,
    pub target_port: u16,
    /// When set, agent dials this mesh IP instead of localhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ipv4: Option<Ipv4Addr>,
}

/// Public TCP port mapping on the public edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub external_port: u16,
    pub target_port: u16,
    /// When set, agent dials this mesh IP instead of localhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ipv4: Option<Ipv4Addr>,
}

/// Match an HTTP path against a redirect pattern (`/api/*` or exact).
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

/// Pick the first matching redirect rule (caller should sort by priority desc).
pub fn match_redirect_port(rules: &[RedirectRule], path: &str) -> Option<u16> {
    match_redirect(rules, path).map(|r| r.target_port)
}

/// Pick the first matching redirect rule with optional mesh target IP.
pub fn match_redirect<'a>(rules: &'a [RedirectRule], path: &str) -> Option<&'a RedirectRule> {
    rules.iter().find(|r| path_matches(&r.path_pattern, path))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMembershipSnapshot {
    pub network_id: Uuid,
    pub network_name: String,
    pub assigned_ipv4: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    pub ipv4_peers: Vec<PeerEntry>,
    /// Subnet routes visible to this peer (enabled routes in the network).
    #[serde(default)]
    pub subnet_routes: Vec<SubnetRoute>,
    /// Hostname routes visible to this peer.
    #[serde(default)]
    pub hostname_routes: Vec<HostnameRoute>,
    #[serde(default)]
    pub dns: DnsConfig,
    /// Exit nodes available in this network.
    #[serde(default)]
    pub exit_nodes: Vec<ExitNodeInfo>,
    /// This device's profile (exit selection + split tunnel).
    #[serde(default)]
    pub device_profile: DeviceProfile,
    /// Serves active in this network (discoverability for peers).
    #[serde(default)]
    pub active_serves: Vec<ActiveServe>,
    /// Tunnel configs for *this* endpoint (agent opens reverse tunnels).
    #[serde(default)]
    pub tunnel_config: Vec<TunnelConfig>,
    /// Tags assigned to *this* endpoint (needed for dst tag ACL / SSH policy).
    #[serde(default)]
    pub self_tags: Vec<String>,
    /// This endpoint's hostname (for PeerDNS self-resolution; peers list excludes self).
    #[serde(default)]
    pub self_hostname: String,
    pub policy: policy::PolicyBundle,
    pub gossip_bootstrap: Vec<EndpointIdHex>,
    pub gossip_topic_hex: String,
    /// Merged agent policy for this membership: network ← org ← defaults.
    #[serde(default)]
    pub agent_policy: agent_policy::RemoteAgentPolicy,
    pub version: u64,
}

/// Connectivity relay entry pushed to agents (mesh DERP / hybrid).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityRelayConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub metering: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConnectivityRelayFallback {
    /// No public n0 fallback (Cloud fail-closed, or explicitly disabled).
    #[default]
    None,
    /// Use iroh's public n0 relay map.
    N0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSnapshot {
    pub ipv6_enabled: bool,
    pub tenant_ipv6: Option<Ipv6Addr>,
    pub memberships: Vec<NetworkMembershipSnapshot>,
    pub ipv6_peers: Vec<Ipv6PeerEntry>,
    pub org_policy: policy::PolicyBundle,
    /// Hex-encoded Ed25519 verifying key for `PolicyBundle.signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_verifying_key: Option<String>,
    /// Org-level remote agent policy defaults (before network inheritance).
    #[serde(default)]
    pub agent_policy: agent_policy::RemoteAgentPolicy,
    /// Effective connectivity relays for this endpoint (after org policy).
    #[serde(default)]
    pub connectivity_relays: Vec<ConnectivityRelayConfig>,
    /// Fallback when `connectivity_relays` is empty (agent-side n0 vs disabled).
    #[serde(default)]
    pub connectivity_relay_fallback: ConnectivityRelayFallback,
    /// Org internal CA root cert (PEM) so agents can verify peer Serve TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_ca_pem: Option<String>,
    /// User-defined key-value labels on this machine.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// When this machine is deleted if it stays inactive (RFC3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDelta {
    pub added: Vec<PeerEntry>,
    pub removed: Vec<EndpointIdHex>,
    pub version: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid endpoint id: {0}")]
    InvalidEndpointId(String),
    #[error("network is full")]
    NetworkFull,
    #[error("unauthorized")]
    Unauthorized,
    #[error("signature invalid")]
    BadSignature,
    #[error("stale timestamp")]
    StaleTimestamp,
}

pub fn validate_endpoint_id(s: &str) -> Result<(), ProtocolError> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProtocolError::InvalidEndpointId(s.to_string()));
    }
    Ok(())
}

pub fn validate_network_name(s: &str) -> bool {
    let len_ok = (3..=32).contains(&s.len());
    let chars_ok = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    len_ok && chars_ok
}

pub fn network_topic_hex(id: &uuid::Uuid) -> String {
    hex::encode(blake3::hash(id.as_bytes()).as_bytes())
}

/// Gossip topic for mDNS/DNS-SD service relay records on a network.
pub fn mdns_relay_topic_hex(id: &uuid::Uuid) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(id.as_bytes());
    hasher.update(b"mdns-relay");
    hex::encode(hasher.finalize().as_bytes())
}
