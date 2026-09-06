/** Local Management API (`/v1`) JSON types - mirrors `tunnet_common::local_api`. */

export const API_VERSION = 2;

export type ApiErrorCode =
  | "daemon_not_running"
  | "data_plane_down"
  | "not_enrolled"
  | "not_found"
  | "denied"
  | "invalid_request"
  | "internal";

export interface ApiError {
  code: ApiErrorCode;
  message: string;
}

export interface OkResponse {
  message: string;
}

export type NodeModeApi = "idle" | "direct" | "managed";

export interface LocalUiPolicy {
  enabled: boolean;
  allow_disconnect: boolean;
  allow_serve: boolean;
  allow_tunnel: boolean;
  allow_self_tags: boolean;
}

export interface PeerSummary {
  network_id: string;
  ip: string;
  hostname: string;
  endpoint_id: string;
  tags: string[];
  online?: boolean;
  latency_ms?: number;
  os?: string;
  conn_state?: string;
  path?: string;
  bytes_in?: number;
  bytes_out?: number;
  last_seen_secs_ago?: number;
  keep_alive?: boolean;
  ssh_host_key?: string;
}

export interface NetworkSummary {
  network_id: string;
  network_name: string;
  mode: string;
  ip: string;
  role: string;
  peers_total: number;
  peers_online: number;
  organization_id?: string;
  control_url?: string;
  management_url?: string;
  dashboard_url?: string;
  firewall_drops?: number;
  conntrack_entries?: number;
  relay_status: string;
  expires_at?: string;
  expires_in_secs?: number;
  keep_alive?: boolean;
  control?: ControlPlaneStatusInfo;
}

export interface NodeSummary {
  endpoint_id: string;
  hostname: string;
  mode: NodeModeApi;
  daemon_version: string;
  api_version: number;
  data_plane_up: boolean;
  uptime_secs: number;
  snapshot_version: number;
  networks: NetworkSummary[];
  on_demand?: OnDemandStatusInfo;
  control?: ControlPlaneStatusInfo;
}

export interface MetaInfo {
  api_version: number;
  daemon_version: string;
  mode: NodeModeApi;
  features: string[];
  permissions: string[];
}

export interface NetworksResponse {
  networks: NetworkSummary[];
}

export interface PeersResponse {
  peers: PeerSummary[];
}

export type LocalEvent =
  | { type: "daemon_ready" }
  | { type: "daemon_mode_changed"; mode: NodeModeApi }
  | { type: "data_plane_changed"; up: boolean }
  | { type: "network_added"; network_id: string }
  | { type: "network_removed"; network_id: string }
  | { type: "peer_online"; network_id: string; endpoint_id: string }
  | { type: "peer_offline"; network_id: string; endpoint_id: string }
  | {
      type: "peer_path_changed";
      network_id: string;
      endpoint_id: string;
      path: string;
    }
  | {
      type: "peer_metrics";
      network_id: string;
      endpoint_id: string;
      latency_ms: number;
    }
  | { type: "direct_join_requested"; network_id: string; peer_id: string }
  | { type: "transfer_created"; id: string }
  | { type: "transfer_progress"; id: string; bytes: number }
  | { type: "transfer_completed"; id: string }
  | { type: "control_connected" }
  | { type: "control_disconnected" }
  | { type: "update_available"; version: string }
  | {
      type: "core_update_changed";
      status: import("./invoke").CoreUpdateStatus;
    };

export type PingEvent =
  | ({ type: "probe" } & PingProbe)
  | ({ type: "summary" } & PingSummary);

export interface PingParams {
  peer: string;
  count?: number;
  interval_ms?: number;
}

export interface SshSessionsParams {
  limit?: number;
  status?: string;
}

export interface SshRecordingsParams {
  limit?: number;
}

export interface LocalEnrollRequest {
  control_url: string;
  token?: string;
  org?: string;
  network?: string;
  hostname?: string;
  wait_secs?: number;
  labels?: Record<string, string>;
  expires_in?: string;
  no_encrypt_state?: boolean;
  management_url?: string;
  dashboard_url?: string;
}

export interface NetworkCreateRequest {
  hostname?: string;
  open?: boolean;
  network_name?: string;
  secret?: string;
  cidr?: string;
  no_encrypt_state?: boolean;
}

export interface NetworkJoinRequest {
  invite_code: string;
  hostname?: string;
  auto_accept_firewall?: boolean;
  no_encrypt_state?: boolean;
}

export interface NetworkLeaveRequest {
  network?: string;
  name?: string;
}

export interface NetworkUpgradeRequest {
  control_url: string;
  token?: string;
}

export interface ResetRequest {
  yes?: boolean;
}

export interface ValidateConfigRequest {
  path?: string;
  contents?: string;
}

export interface AuthLoginRequest {
  management_url?: string;
}

export interface UpdateRequest {
  force?: boolean;
  restart?: boolean;
  version?: string;
}

export interface DeviceLabelRequest {
  labels: Record<string, string>;
}

export interface DeviceLabelPatchRequest {
  labels: Record<string, string | null>;
}

export interface DeviceLabelDeleteRequest {
  key: string;
}

export interface DeviceTagAddRequest {
  tag: string;
}

export interface DeviceTagRemoveRequest {
  tag: string;
}

export interface DeviceExpiryRequest {
  duration: string;
}

export interface RouteAddRequest {
  cidr: string;
  description?: string;
}

export interface ServeStartRequest {
  port: number;
  protocol?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  internal_hostname?: string;
  serve_id?: string;
  access_mode?: string;
  allowed_tags?: string[];
  allowed_endpoint_ids?: string[];
}

export interface ServeOffRequest {
  port: number;
}

export interface TunnelStartRequest {
  port: number;
  protocol?: string;
  relay?: string;
  subdomain?: string;
  inspect?: boolean;
  inspect_addr?: string;
}

export interface TunnelOffRequest {
  port: number;
}

export interface SshAuthPollRequest {
  challenge_token: string;
}

export interface SendFileRequest {
  path: string;
  target: string;
  message?: string;
}

export interface SendAcceptRequest {
  transfer_id: string;
}

export interface SendRejectRequest {
  transfer_id: string;
  reason?: string;
}

export interface SendSetConfigRequest {
  consent?: string;
  inbox_path?: string;
  pin_blobs?: boolean;
}

export interface DirectNetworkRequest {
  network?: string;
}

export interface DirectPeerRequest {
  network?: string;
  peer_id: string;
}

export interface DirectInviteRequest {
  network?: string;
  reusable?: boolean;
  expires?: string;
}

export interface DirectFirewallAddRequest {
  network?: string;
  direction: string;
  action: string;
  protocol?: string;
  port?: string;
  peer?: string;
}

export interface DirectFirewallRemoveRequest {
  network?: string;
  index: number;
}

export interface DirectPolicySetRequest {
  network?: string;
  toml: string;
}

export interface DirectKeepAliveRequest {
  hostname: string;
  enable?: boolean;
}

export interface DirectConnectRequest {
  contact_id: string;
}

export interface DirectConnectContactRequest {
  contact_id: string;
}

export interface RouteAddedResponse {
  cidr: string;
}

export interface DataPlaneStatus {
  up: boolean;
}

export interface ServesResponse {
  serves: ServeInfo[];
}

export interface TunnelsResponse {
  tunnels: TunnelInfo[];
}

export interface TransfersResponse {
  transfers: TransferInfo[];
}

export interface SshSessionsResponse {
  sessions: SshSessionInfo[];
}

export interface SshRecordingsResponse {
  recordings: SshRecordingInfo[];
}

export interface SshCastResponse {
  session_id: string;
  cast_text: string;
  content_sha256: string;
}

export interface SshAuthPollResponse {
  status: string;
  proof_token?: string;
}

export interface DirectInviteResponse {
  code: string;
}

export interface DirectPendingResponse {
  requests: DirectPendingInfo[];
}

export interface DirectFirewallResponse {
  enabled: boolean;
  rules: DirectFirewallRuleInfo[];
  conntrack_entries?: number;
  packets_allowed?: number;
  packets_denied?: number;
  packets_rejected?: number;
  suggested_rules?: number;
}

export interface DirectFirewallPendingResponse {
  pending?: string;
}

export interface DirectPolicyResponse {
  json?: string;
}

export interface DirectConnectPendingResponse {
  requests: DirectConnectPendingInfo[];
}

export interface DirectContactResponse {
  contact_id: string;
}

export interface DirectConnectPendingInfo {
  contact_id: string;
  endpoint_id: string;
  hostname: string;
  received_at: string;
}

export interface DirectPendingInfo {
  endpoint_id: string;
  hostname: string;
}

export interface DirectFirewallRuleInfo {
  index: number;
  direction: string;
  action: string;
  protocol: string;
  ports?: string;
  peer?: string;
}

export interface SshSessionInfo {
  id: string;
  src_endpoint_id: string;
  dst_endpoint_id: string;
  src_hostname?: string;
  dst_hostname?: string;
  target_user: string;
  status: string;
  recorded: boolean;
  started_at: string;
  duration_ms?: number;
}

export interface SshRecordingInfo {
  session_id: string;
  src_hostname?: string;
  dst_hostname?: string;
  target_user?: string;
  byte_size: number;
  created_at: string;
  content_sha256?: string;
}

export interface ControlPlaneStatusInfo {
  url: string;
  connected: boolean;
  connected_for_secs?: number;
  last_change_secs_ago?: number;
  reconnects: number;
  last_error?: string;
}

export interface OnDemandStatusInfo {
  reconnect_attempts: number;
  reconnect_success: number;
  reconnect_fail: number;
  packets_buffered: number;
  packets_dropped_timeout: number;
}

export interface DnsStatusInfo {
  suffix: string;
  upstream: string[];
  dnssec: boolean;
  peer_dns_active: boolean;
  cached_entries: number;
  resolver_endpoint: string;
  bind: string;
}

export interface RoutesInfo {
  subnet_routes: SubnetRouteInfo[];
  hostname_routes: HostnameRouteInfo[];
  exit_node?: ExitNodeRouteInfo;
  split_tunnel_mode: string;
  split_tunnel_cidrs: string[];
}

export interface SubnetRouteInfo {
  cidr: string;
  via_hostname: string;
  via_ip: string;
  via_endpoint_id: string;
  advertised_by_self: boolean;
}

export interface HostnameRouteInfo {
  hostname: string;
  is_wildcard: boolean;
  via_hostname: string;
  via_ip: string;
  via_endpoint_id: string;
  target_ip?: string;
}

export interface ExitNodeRouteInfo {
  hostname: string;
  via_ip: string;
  endpoint_id: string;
}

export interface PingProbe {
  seq: number;
  peer: string;
  peer_ip: string;
  latency_ms: number;
  path: string;
}

export interface PingSummary {
  peer: string;
  peer_ip: string;
  transmitted: number;
  received: number;
  loss_pct: number;
  min_ms?: number;
  avg_ms?: number;
  max_ms?: number;
  path: string;
}

export interface DiagInfo {
  nat_type: string;
  endpoint_id: string;
  endpoint_online: boolean;
  relay_reachable: boolean;
  relay_rtt_ms?: number;
  direct_peers: number;
  relayed_peers: number;
  total_peers: number;
  notes: string[];
}

export interface NetcheckInfo {
  ok: boolean;
  checks: NetcheckItem[];
}

export interface NetcheckItem {
  name: string;
  pass: boolean;
  detail: string;
}

export interface ServeInfo {
  id: string;
  port: number;
  protocol: string;
  url: string;
  status: string;
}

export interface TunnelInfo {
  id: string;
  port: number;
  protocol: string;
  public_url: string;
  relay: string;
  status: string;
  inspector_url?: string;
}

export interface TransferInfo {
  transfer_id: string;
  direction: string;
  peer_endpoint_id: string;
  peer_hostname?: string;
  file_name: string;
  size: number;
  hash: string;
  status: string;
  percent: number;
  bytes_transferred: number;
  message?: string;
  error?: string;
  inbox_path?: string;
  is_directory: boolean;
}

export interface SendConfigInfo {
  consent: string;
  inbox_path: string;
  pin_blobs: boolean;
}

export function formatApiError(code: ApiErrorCode, message: string): string {
  switch (code) {
    case "daemon_not_running":
      return "tunnetd is not running (start with `tunnet up` or `tunnet service start`)";
    case "data_plane_down":
      return `${message} (bring data plane up with \`tunnet up\`)`;
    case "not_enrolled":
      return `${message} (enroll or join a network first)`;
    default:
      return message;
  }
}

export class TunnetApiError extends Error {
  readonly code: ApiErrorCode;

  constructor(code: ApiErrorCode, message: string) {
    super(formatApiError(code, message));
    this.name = "TunnetApiError";
    this.code = code;
  }
}
