import {
  apiFetch,
  defaultApiPath,
  networkQuery,
  parseApiFailure,
  parseEventsSse,
  parsePingSse,
  readApiJson,
} from "./transport";
import type {
  AuthLoginRequest,
  CoreUpdateStatus,
  DataPlaneStatus,
  DeviceExpiryRequest,
  DeviceLabelDeleteRequest,
  DeviceLabelPatchRequest,
  DeviceLabelRequest,
  DeviceTagAddRequest,
  DeviceTagRemoveRequest,
  DiagInfo,
  DirectConnectContactRequest,
  DirectConnectPendingResponse,
  DirectConnectRequest,
  DirectContactResponse,
  DirectFirewallAddRequest,
  DirectFirewallPendingResponse,
  DirectFirewallResponse,
  DirectInviteRequest,
  DirectInviteResponse,
  DirectKeepAliveRequest,
  DirectNetworkRequest,
  DirectOverrideIpRequest,
  DirectPendingResponse,
  DirectPolicyResponse,
  DirectPolicySetRequest,
  DnsStatusInfo,
  LocalEnrollRequest,
  LocalEvent,
  MetaInfo,
  NetcheckInfo,
  NetworkCreateRequest,
  NetworkJoinRequest,
  NetworkLeaveRequest,
  NetworkSummary,
  NetworksResponse,
  NetworkUpgradeRequest,
  NodeSummary,
  OkResponse,
  PeersResponse,
  PingEvent,
  ResetRequest,
  RouteAddedResponse,
  RouteAddRequest,
  RoutesInfo,
  SendAcceptRequest,
  SendConfigInfo,
  SendFileRequest,
  SendRejectRequest,
  SendSetConfigRequest,
  ServeInfo,
  ServeStartRequest,
  ServesResponse,
  SshAuthPollRequest,
  SshAuthPollResponse,
  SshCastResponse,
  SshRecordingsResponse,
  SshSessionsResponse,
  TransferInfo,
  TransfersResponse,
  TunnelInfo,
  TunnelStartRequest,
  TunnelsResponse,
  UpdateRequest,
  ValidateConfigRequest,
} from "./types";
import { TunnetApiError } from "./types";

/** HTTP client for the Tunnet Local Management API (`/v1/...`). */
export class TunnetClient {
  readonly path: string;

  constructor(path: string = defaultApiPath()) {
    this.path = path;
  }

  static connect(path?: string): TunnetClient {
    return new TunnetClient(path ?? defaultApiPath());
  }

  // -----------------------------------------------------------------------
  // Status / networking
  // -----------------------------------------------------------------------

  meta(): Promise<MetaInfo> {
    return readApiJson(this.path, "/v1/meta");
  }

  node(): Promise<NodeSummary> {
    return readApiJson(this.path, "/v1/node");
  }

  networks(): Promise<NetworksResponse> {
    return readApiJson(this.path, "/v1/networks");
  }

  network(networkId: string): Promise<NetworkSummary> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}`,
    );
  }

  networkPeers(networkId: string): Promise<PeersResponse> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/peers`,
    );
  }

  networkRoutes(networkId: string): Promise<RoutesInfo> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/routes`,
    );
  }

  networkFirewall(networkId: string): Promise<DirectFirewallResponse> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/firewall`,
    );
  }

  networkJoinRequests(networkId: string): Promise<DirectPendingResponse> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/join-requests`,
    );
  }

  networkJoinAccept(networkId: string, peerId: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/join-requests/${encodeURIComponent(peerId)}/accept`,
      { method: "POST", body: {} },
    );
  }

  networkJoinDeny(networkId: string, peerId: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      `/v1/networks/${encodeURIComponent(networkId)}/join-requests/${encodeURIComponent(peerId)}/deny`,
      { method: "POST", body: {} },
    );
  }

  async *events(): AsyncGenerator<LocalEvent> {
    let response: Awaited<ReturnType<typeof apiFetch>>;
    try {
      response = await apiFetch(this.path, "/v1/events");
    } catch {
      throw new TunnetApiError("daemon_not_running", "");
    }

    if (response.status < 200 || response.status >= 300) {
      const text = await response.text();
      throw parseApiFailure(response.status, text, "GET", "/v1/events");
    }

    yield* parseEventsSse(response.body);
  }

  dns(): Promise<DnsStatusInfo> {
    return readApiJson(this.path, "/v1/dns");
  }

  routes(networkId?: string): Promise<RoutesInfo> {
    const query = networkId
      ? `?network_id=${encodeURIComponent(networkId)}`
      : "";
    return readApiJson(this.path, `/v1/routes${query}`);
  }

  routesAdd(cidr: string, description?: string): Promise<RouteAddedResponse> {
    const body: RouteAddRequest = { cidr, description };
    return readApiJson(this.path, "/v1/routes", {
      method: "POST",
      body,
    });
  }

  async *ping(
    peer: string,
    count = 4,
    intervalMs = 1000,
  ): AsyncGenerator<PingEvent> {
    const uri = `/v1/ping/${encodeURIComponent(peer)}?count=${count}&interval_ms=${intervalMs}`;
    let response: Awaited<ReturnType<typeof apiFetch>>;
    try {
      response = await apiFetch(this.path, uri);
    } catch {
      throw new TunnetApiError("daemon_not_running", "");
    }

    if (response.status < 200 || response.status >= 300) {
      const text = await response.text();
      throw parseApiFailure(response.status, text, "GET", uri);
    }

    yield* parsePingSse(response.body);
  }

  diag(): Promise<DiagInfo> {
    return readApiJson(this.path, "/v1/diag");
  }

  netcheck(): Promise<NetcheckInfo> {
    return readApiJson(this.path, "/v1/netcheck");
  }

  reload(): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/reload", { method: "POST", body: {} });
  }

  // -----------------------------------------------------------------------
  // Data plane
  // -----------------------------------------------------------------------

  dataPlaneStatus(): Promise<DataPlaneStatus> {
    return readApiJson(this.path, "/v1/data-plane");
  }

  dataPlaneUp(): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/data-plane/up", {
      method: "POST",
      body: {},
    });
  }

  dataPlaneDown(): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/data-plane/down", {
      method: "POST",
      body: {},
    });
  }

  // -----------------------------------------------------------------------
  // Serve / tunnel
  // -----------------------------------------------------------------------

  serves(): Promise<ServesResponse> {
    return readApiJson(this.path, "/v1/serves");
  }

  servesStart(body: ServeStartRequest): Promise<ServeInfo> {
    return readApiJson(this.path, "/v1/serves", { method: "POST", body });
  }

  servesOff(port: number): Promise<ServeInfo> {
    return readApiJson(this.path, `/v1/serves/${port}`, { method: "DELETE" });
  }

  tunnels(): Promise<TunnelsResponse> {
    return readApiJson(this.path, "/v1/tunnels");
  }

  tunnelsStart(body: TunnelStartRequest): Promise<TunnelInfo> {
    return readApiJson(this.path, "/v1/tunnels", { method: "POST", body });
  }

  tunnelsOff(port: number): Promise<TunnelInfo> {
    return readApiJson(this.path, `/v1/tunnels/${port}`, { method: "DELETE" });
  }

  // -----------------------------------------------------------------------
  // SSH
  // -----------------------------------------------------------------------

  sshSessions(limit = 50, status?: string): Promise<SshSessionsResponse> {
    let uri = `/v1/ssh/sessions?limit=${limit}`;
    if (status) uri += `&status=${encodeURIComponent(status)}`;
    return readApiJson(this.path, uri);
  }

  sshRecordings(limit = 50): Promise<SshRecordingsResponse> {
    return readApiJson(this.path, `/v1/ssh/recordings?limit=${limit}`);
  }

  sshCast(sessionId: string): Promise<SshCastResponse> {
    return readApiJson(
      this.path,
      `/v1/ssh/recordings/${encodeURIComponent(sessionId)}/cast`,
    );
  }

  sshAuthPoll(challengeToken: string): Promise<SshAuthPollResponse> {
    const body: SshAuthPollRequest = { challenge_token: challengeToken };
    return readApiJson(this.path, "/v1/ssh/auth/poll", {
      method: "POST",
      body,
    });
  }

  // -----------------------------------------------------------------------
  // File transfer (send)
  // -----------------------------------------------------------------------

  transfersSend(body: SendFileRequest): Promise<TransfersResponse> {
    return readApiJson(this.path, "/v1/transfers/send", {
      method: "POST",
      body,
    });
  }

  transfers(): Promise<TransfersResponse> {
    return readApiJson(this.path, "/v1/transfers");
  }

  transfersHistory(): Promise<TransfersResponse> {
    return readApiJson(this.path, "/v1/transfers/history");
  }

  transfersAccept(transferId: string): Promise<TransferInfo> {
    const body: SendAcceptRequest = { transfer_id: transferId };
    return readApiJson(
      this.path,
      `/v1/transfers/${encodeURIComponent(transferId)}/accept`,
      { method: "POST", body },
    );
  }

  transfersReject(transferId: string, reason?: string): Promise<OkResponse> {
    const body: SendRejectRequest = { transfer_id: transferId, reason };
    return readApiJson(
      this.path,
      `/v1/transfers/${encodeURIComponent(transferId)}/reject`,
      { method: "POST", body },
    );
  }

  sendConfig(): Promise<SendConfigInfo> {
    return readApiJson(this.path, "/v1/send/config");
  }

  sendSetConfig(body: SendSetConfigRequest): Promise<SendConfigInfo> {
    return readApiJson(this.path, "/v1/send/config", { method: "PUT", body });
  }

  // -----------------------------------------------------------------------
  // Direct mode
  // -----------------------------------------------------------------------

  directInvite(body: DirectInviteRequest): Promise<DirectInviteResponse> {
    return readApiJson(this.path, "/v1/direct/invites", {
      method: "POST",
      body,
    });
  }

  directRequests(network?: string): Promise<DirectPendingResponse> {
    return readApiJson(this.path, networkQuery("/v1/direct/requests", network));
  }

  directAccept(peerId: string, network?: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      networkQuery(
        `/v1/direct/requests/${encodeURIComponent(peerId)}/accept`,
        network,
      ),
      { method: "POST", body: {} },
    );
  }

  directDeny(peerId: string, network?: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      networkQuery(
        `/v1/direct/requests/${encodeURIComponent(peerId)}/deny`,
        network,
      ),
      { method: "POST", body: {} },
    );
  }

  directKick(peerId: string, network?: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      networkQuery(
        `/v1/direct/peers/${encodeURIComponent(peerId)}/kick`,
        network,
      ),
      { method: "POST", body: {} },
    );
  }

  directFirewallShow(network?: string): Promise<DirectFirewallResponse> {
    return readApiJson(this.path, networkQuery("/v1/direct/firewall", network));
  }

  directFirewallOff(network?: string): Promise<OkResponse> {
    const body: DirectNetworkRequest = { network };
    return readApiJson(this.path, "/v1/direct/firewall/off", {
      method: "POST",
      body,
    });
  }

  directFirewallAdd(body: DirectFirewallAddRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/direct/firewall/rules", {
      method: "POST",
      body,
    });
  }

  directFirewallRemove(index: number, network?: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      networkQuery(`/v1/direct/firewall/rules/${index}`, network),
      { method: "DELETE" },
    );
  }

  directFirewallReset(network?: string): Promise<OkResponse> {
    const body: DirectNetworkRequest = { network };
    return readApiJson(this.path, "/v1/direct/firewall/reset", {
      method: "POST",
      body,
    });
  }

  directFirewallFlushConntrack(network?: string): Promise<OkResponse> {
    const body: DirectNetworkRequest = { network };
    return readApiJson(this.path, "/v1/direct/firewall/conntrack/flush", {
      method: "POST",
      body,
    });
  }

  directFirewallPending(
    network?: string,
  ): Promise<DirectFirewallPendingResponse> {
    return readApiJson(
      this.path,
      networkQuery("/v1/direct/firewall/pending", network),
    );
  }

  directFirewallAcceptSuggestion(network?: string): Promise<OkResponse> {
    const body: DirectNetworkRequest = { network };
    return readApiJson(this.path, "/v1/direct/firewall/pending/accept", {
      method: "POST",
      body,
    });
  }

  directFirewallRejectSuggestion(network?: string): Promise<OkResponse> {
    const body: DirectNetworkRequest = { network };
    return readApiJson(this.path, "/v1/direct/firewall/pending/reject", {
      method: "POST",
      body,
    });
  }

  directPolicyShow(network?: string): Promise<DirectPolicyResponse> {
    return readApiJson(this.path, networkQuery("/v1/direct/policy", network));
  }

  directPolicySet(body: DirectPolicySetRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/direct/policy", { method: "PUT", body });
  }

  directPolicyClear(network?: string): Promise<OkResponse> {
    return readApiJson(this.path, networkQuery("/v1/direct/policy", network), {
      method: "DELETE",
    });
  }

  directKeepAlive(body: DirectKeepAliveRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/direct/keep-alive", {
      method: "POST",
      body,
    });
  }

  directOverrideIp(body: DirectOverrideIpRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/direct/ip-overrides", {
      method: "POST",
      body,
    });
  }

  directConnect(contactId: string): Promise<OkResponse> {
    const body: DirectConnectRequest = { contact_id: contactId };
    return readApiJson(this.path, "/v1/direct/connect", {
      method: "POST",
      body,
    });
  }

  directConnectAllow(contactId: string): Promise<OkResponse> {
    const body: DirectConnectContactRequest = { contact_id: contactId };
    return readApiJson(this.path, "/v1/direct/connect/allow", {
      method: "POST",
      body,
    });
  }

  directConnectPending(): Promise<DirectConnectPendingResponse> {
    return readApiJson(this.path, "/v1/direct/connect/pending");
  }

  directConnectAccept(contactId: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      `/v1/direct/connect/pending/${encodeURIComponent(contactId)}/accept`,
      { method: "POST", body: {} },
    );
  }

  directConnectDeny(contactId: string): Promise<OkResponse> {
    return readApiJson(
      this.path,
      `/v1/direct/connect/pending/${encodeURIComponent(contactId)}/deny`,
      { method: "POST", body: {} },
    );
  }

  directConnectRotate(): Promise<DirectContactResponse> {
    return readApiJson(this.path, "/v1/direct/connect/rotate", {
      method: "POST",
      body: {},
    });
  }

  // -----------------------------------------------------------------------
  // Bootstrap / lifecycle
  // -----------------------------------------------------------------------

  enroll(body: LocalEnrollRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/enroll", { method: "POST", body });
  }

  networkCreate(body: NetworkCreateRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/networks", { method: "POST", body });
  }

  networkJoin(body: NetworkJoinRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/networks/join", {
      method: "POST",
      body,
    });
  }

  networkLeave(body: NetworkLeaveRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/networks/leave", {
      method: "POST",
      body,
    });
  }

  networkUpgrade(body: NetworkUpgradeRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/networks/upgrade", {
      method: "POST",
      body,
    });
  }

  reset(body: ResetRequest = {}): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/reset", { method: "POST", body });
  }

  validateConfig(body: ValidateConfigRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/config/validate", {
      method: "POST",
      body,
    });
  }

  authLogin(body: AuthLoginRequest = {}): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/auth/login", { method: "POST", body });
  }

  authLogout(): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/auth/logout", {
      method: "POST",
      body: {},
    });
  }

  updateCheck(): Promise<CoreUpdateStatus> {
    return readApiJson(this.path, "/v1/update");
  }

  update(body: UpdateRequest): Promise<CoreUpdateStatus> {
    return readApiJson(this.path, "/v1/update", { method: "POST", body });
  }

  // -----------------------------------------------------------------------
  // Device metadata
  // -----------------------------------------------------------------------

  deviceLabelsSet(body: DeviceLabelRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/labels", {
      method: "POST",
      body,
    });
  }

  deviceLabelsPatch(body: DeviceLabelPatchRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/labels/patch", {
      method: "POST",
      body,
    });
  }

  deviceLabelsDelete(body: DeviceLabelDeleteRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/labels/delete", {
      method: "POST",
      body,
    });
  }

  deviceTagsAdd(body: DeviceTagAddRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/tags", { method: "POST", body });
  }

  deviceTagsRemove(body: DeviceTagRemoveRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/tags/remove", {
      method: "POST",
      body,
    });
  }

  deviceExpiry(body: DeviceExpiryRequest): Promise<OkResponse> {
    return readApiJson(this.path, "/v1/device/expiry", {
      method: "POST",
      body,
    });
  }

  // -----------------------------------------------------------------------
  // Low-level HTTP
  // -----------------------------------------------------------------------

  getJson<T>(uri: string): Promise<T> {
    return readApiJson<T>(this.path, uri);
  }

  postJson<T, B>(uri: string, body: B): Promise<T> {
    return readApiJson<T>(this.path, uri, { method: "POST", body });
  }

  putJson<T, B>(uri: string, body: B): Promise<T> {
    return readApiJson<T>(this.path, uri, { method: "PUT", body });
  }

  deleteJson<T>(uri: string): Promise<T> {
    return readApiJson<T>(this.path, uri, { method: "DELETE" });
  }
}

/** Back-compat alias for {@link TunnetClient}. */
export type LocalApiClient = TunnetClient;
