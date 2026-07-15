export const queryKeys = {
  org: (orgId: string) => ["org", orgId] as const,
  networks: (orgId: string) => [...queryKeys.org(orgId), "networks"] as const,
  network: (orgId: string, networkId: string) =>
    [...queryKeys.networks(orgId), networkId] as const,
  devices: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "devices"] as const,
  machines: (orgId: string) => [...queryKeys.org(orgId), "machines"] as const,
  policies: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "policies"] as const,
  organizationPolicies: (orgId: string) =>
    [...queryKeys.org(orgId), "policies"] as const,
  sshPolicies: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "ssh-policies"] as const,
  deviceSshAuth: (orgId: string, endpointId: string) =>
    [...queryKeys.org(orgId), "device-ssh-auth", endpointId] as const,
  ssoSettings: (orgId: string) =>
    [...queryKeys.org(orgId), "sso-settings"] as const,
  subnetRoutes: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "subnet-routes"] as const,
  hostnameRoutes: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "hostname-routes"] as const,
  topology: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "topology"] as const,
  networkMetrics: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "metrics"] as const,
  enrollmentTokens: (orgId: string, networkId: string) =>
    [...queryKeys.network(orgId, networkId), "enrollment-tokens"] as const,
  apiKeys: (orgId: string) => [...queryKeys.org(orgId), "api-keys"] as const,
  auditLog: (orgId: string) => [...queryKeys.org(orgId), "audit-log"] as const,
  members: (orgId: string) => [...queryKeys.org(orgId), "members"] as const,
  invitations: (orgId: string) =>
    [...queryKeys.org(orgId), "invitations"] as const,
  memberRole: (orgId: string) =>
    [...queryKeys.org(orgId), "member-role"] as const,
  device: (orgId: string, endpointId: string) =>
    [...queryKeys.org(orgId), "device", endpointId] as const,
  deviceAddresses: (orgId: string, endpointId: string) =>
    [...queryKeys.org(orgId), "device-addresses", endpointId] as const,
  devicePresence: (orgId: string, endpointId: string) =>
    [...queryKeys.org(orgId), "device-presence", endpointId] as const,
  relays: (orgId: string) => [...queryKeys.org(orgId), "relays"] as const,
  relay: (orgId: string, relayId: string) =>
    [...queryKeys.relays(orgId), relayId] as const,
  relayHealth: (orgId: string, relayId: string) =>
    [...queryKeys.relay(orgId, relayId), "health"] as const,
  tunnels: (orgId: string) => [...queryKeys.org(orgId), "tunnels"] as const,
  tunnelsByNetwork: (orgId: string, networkId: string) =>
    [...queryKeys.tunnels(orgId), networkId] as const,
  tunnelRoutingRules: (orgId: string, networkId: string, tunnelId: string) =>
    [
      ...queryKeys.tunnelsByNetwork(orgId, networkId),
      tunnelId,
      "routing-rules",
    ] as const,
  tunnelTraffic: (orgId: string, networkId: string, tunnelId: string) =>
    [
      ...queryKeys.tunnelsByNetwork(orgId, networkId),
      tunnelId,
      "traffic",
    ] as const,
  serves: (orgId: string) => [...queryKeys.org(orgId), "serves"] as const,
  servesByNetwork: (orgId: string, networkId: string) =>
    [...queryKeys.serves(orgId), networkId] as const,
  servePeers: (orgId: string, networkId: string, serveId: string) =>
    [...queryKeys.serves(orgId), networkId, serveId, "peers"] as const,
  sshSessions: (orgId: string, status?: string) =>
    [...queryKeys.org(orgId), "ssh-sessions", status ?? "all"] as const,
  sshRecordings: (orgId: string) =>
    [...queryKeys.org(orgId), "ssh-recordings"] as const,
  sshRecording: (orgId: string, sessionId: string) =>
    [...queryKeys.org(orgId), "ssh-recording", sessionId] as const,
  transfers: (orgId: string, status?: string) =>
    [...queryKeys.org(orgId), "transfers", status ?? "all"] as const,
  sendSettings: (orgId: string, endpointId: string) =>
    [...queryKeys.org(orgId), "send-settings", endpointId] as const,
  internalCa: (orgId: string) =>
    [...queryKeys.org(orgId), "internal-ca"] as const,
  tunnelSettings: (orgId: string) =>
    [...queryKeys.org(orgId), "tunnel-settings"] as const,
  orgSettings: (orgId: string) =>
    [...queryKeys.org(orgId), "org-settings"] as const,
};
