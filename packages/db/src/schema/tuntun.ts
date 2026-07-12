import { relations, sql } from "drizzle-orm";
import {
  bigint,
  bigserial,
  boolean,
  check,
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { organization, user } from "./auth";

const inet = customType<{ data: string; driverData: string }>({
  dataType() {
    return "inet";
  },
});

const cidr = customType<{ data: string; driverData: string }>({
  dataType() {
    return "cidr";
  },
});

export const policyActionValues = ["allow", "deny"] as const;
export const membershipStatusValues = [
  "active",
  "suspended",
  "pending",
] as const;

export const deviceTypeValues = ["agent", "sdk"] as const;

export const apiKeys = pgTable("api_keys", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  /** First segment after `tt_` for fast lookup before argon2.verify. */
  secretPrefix: text("secret_prefix"),
  hashedSecret: text("hashed_secret").notNull(),
  scopes: text("scopes").array().notNull().default([]),
  /** When null, the key may access every network in the organization. */
  networkIds: uuid("network_ids").array(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const networks = pgTable(
  "networks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    cidr: cidr("cidr").notNull(),
    /** 1280 = IPv6 minimum; safe for QUIC-over-UDP tunnel overhead. */
    mtu: integer("mtu").notNull().default(1280),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    version: bigint("version", { mode: "number" }).notNull().default(0),
  },
  (table) => [unique().on(table.organizationId, table.name)],
);

/** Tenant-scoped machine identity (one row per endpoint_id). */
export const devices = pgTable(
  "devices",
  {
    endpointId: text("endpoint_id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** Stable ULA derived from endpoint_id at enrollment. */
    tenantIpv6: inet("tenant_ipv6").notNull().unique(),
    ipv6Enabled: boolean("ipv6_enabled").notNull().default(false),
    ipv6EnabledAt: timestamp("ipv6_enabled_at", { withTimezone: true }),
    publicIp: inet("public_ip"),
    agentConnected: boolean("agent_connected").notNull().default(false),
    connectedAt: timestamp("connected_at", { withTimezone: true }),
    disconnectedAt: timestamp("disconnected_at", { withTimezone: true }),
    lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
    firstSeen: timestamp("first_seen", { withTimezone: true })
      .defaultNow()
      .notNull(),
    lastSeen: timestamp("last_seen", { withTimezone: true })
      .defaultNow()
      .notNull(),
    type: text("type").notNull().default("agent"),
    name: text("name").notNull().default(""),
    metadata: jsonb("metadata").notNull().default({}),
  },
  (table) => [
    check(
      "devices_endpoint_id_len",
      sql`char_length(${table.endpointId}) = 64`,
    ),
    check("devices_type_check", sql`${table.type} IN ('agent', 'sdk')`),
    check(
      "devices_ipv6_enabled_at_check",
      sql`(NOT ${table.ipv6Enabled}) OR (${table.ipv6EnabledAt} IS NOT NULL)`,
    ),
    index("devices_by_organization_idx").on(table.organizationId),
    index("devices_by_last_seen_idx").on(table.lastSeen),
    index("devices_by_agent_connected_idx").on(table.agentConnected),
  ],
);

/** Per-network membership and IPv4 assignment (authoritative IP ledger). */
export const networkMemberships = pgTable(
  "network_memberships",
  {
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    assignedIp: inet("assigned_ip").notNull(),
    status: text("status").notNull().default("active"),
    firstSeen: timestamp("first_seen", { withTimezone: true })
      .defaultNow()
      .notNull(),
    lastSeen: timestamp("last_seen", { withTimezone: true })
      .defaultNow()
      .notNull(),
    allocatedAt: timestamp("allocated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.endpointId, table.networkId] }),
    unique("network_memberships_network_id_assigned_ip_unique").on(
      table.networkId,
      table.assignedIp,
    ),
    check(
      "network_memberships_status_check",
      sql`${table.status} IN ('active', 'suspended', 'pending')`,
    ),
    index("network_memberships_by_network_idx").on(table.networkId),
    index("network_memberships_by_last_seen_idx").on(table.lastSeen),
  ],
);

export const devicePresenceEvents = pgTable(
  "device_presence_events",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    event: text("event").notNull(),
    publicIp: inet("public_ip"),
    at: timestamp("at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("device_presence_events_by_endpoint_at_idx").on(
      table.endpointId,
      table.at,
    ),
    index("device_presence_events_by_organization_at_idx").on(
      table.organizationId,
      table.at,
    ),
  ],
);

export const deviceTags = pgTable(
  "device_tags",
  {
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    tag: text("tag").notNull(),
  },
  (table) => [primaryKey({ columns: [table.endpointId, table.tag] })],
);

export const policies = pgTable(
  "policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    srcSelector: jsonb("src_selector").notNull(),
    dstSelector: jsonb("dst_selector").notNull(),
    action: text("action").notNull(),
    ports: jsonb("ports").notNull().default([]),
    protocol: text("protocol"),
    priority: integer("priority").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("policies_by_network_idx").on(table.networkId),
    index("policies_by_network_priority_idx").on(
      table.networkId,
      table.priority,
    ),
    check("policies_action_check", sql`${table.action} IN ('allow', 'deny')`),
  ],
);

export const organizationPolicies = pgTable(
  "organization_policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    srcSelector: jsonb("src_selector").notNull(),
    dstSelector: jsonb("dst_selector").notNull(),
    action: text("action").notNull(),
    ports: jsonb("ports").notNull().default([]),
    protocol: text("protocol"),
    priority: integer("priority").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("organization_policies_by_organization_idx").on(table.organizationId),
    index("organization_policies_by_org_priority_idx").on(
      table.organizationId,
      table.priority,
    ),
    check(
      "organization_policies_action_check",
      sql`${table.action} IN ('allow', 'deny')`,
    ),
  ],
);

export const enrollmentTokens = pgTable("enrollment_tokens", {
  tokenHash: text("token_hash").primaryKey(),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  networkId: uuid("network_id")
    .notNull()
    .references(() => networks.id, { onDelete: "cascade" }),
  createdBy: text("created_by")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

/** CIDR ranges advertised by a machine as subnet routes (LAN/IoT gateways). */
export const subnetRoutes = pgTable(
  "subnet_routes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    cidr: cidr("cidr").notNull(),
    description: text("description"),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("subnet_routes_network_cidr_unique").on(table.networkId, table.cidr),
    index("subnet_routes_by_network_idx").on(table.networkId),
    index("subnet_routes_by_endpoint_idx").on(table.endpointId),
    index("subnet_routes_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

/**
 * Hostname → gateway mappings. Traffic for the hostname is sent to the
 * advertising machine, which resolves locally (or via optional target_ip).
 * Wildcards store the suffix without `*.` and set `isWildcard`.
 */
export const hostnameRoutes = pgTable(
  "hostname_routes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    hostname: text("hostname").notNull(),
    isWildcard: boolean("is_wildcard").notNull().default(false),
    /** Optional static IP; when null the gateway resolves locally. */
    targetIp: inet("target_ip"),
    description: text("description"),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("hostname_routes_network_hostname_unique").on(
      table.networkId,
      table.hostname,
      table.isWildcard,
    ),
    index("hostname_routes_by_network_idx").on(table.networkId),
    index("hostname_routes_by_endpoint_idx").on(table.endpointId),
    index("hostname_routes_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

/** Machines that may act as internet exit nodes. */
export const exitNodeConfig = pgTable(
  "exit_node_config",
  {
    endpointId: text("endpoint_id")
      .primaryKey()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    enabled: boolean("enabled").notNull().default(true),
    /** CIDRs this exit is willing to carry; default 0.0.0.0/0. */
    allowedCidrs: cidr("allowed_cidrs")
      .array()
      .notNull()
      .default(["0.0.0.0/0"]),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("exit_node_config_by_network_idx").on(table.networkId),
    index("exit_node_config_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

export const splitTunnelModeValues = ["include", "exclude"] as const;

/** Per-device tunnel preferences (exit node + split tunnel). */
export const deviceProfiles = pgTable(
  "device_profiles",
  {
    endpointId: text("endpoint_id")
      .primaryKey()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    /** When set, route matching traffic through this exit node. */
    exitNodeEndpointId: text("exit_node_endpoint_id").references(
      () => devices.endpointId,
      { onDelete: "set null" },
    ),
    splitTunnelMode: text("split_tunnel_mode").notNull().default("exclude"),
    splitTunnelCidrs: cidr("split_tunnel_cidrs").array().notNull().default([]),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    check(
      "device_profiles_split_tunnel_mode_check",
      sql`${table.splitTunnelMode} IN ('include', 'exclude')`,
    ),
    index("device_profiles_by_network_idx").on(table.networkId),
  ],
);

/** HA groups that share subnet/hostname routes with active/passive failover. */
export const nodeGroups = pgTable(
  "node_groups",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    haEnabled: boolean("ha_enabled").notNull().default(true),
    /** Currently active member (null = none elected yet). */
    activeEndpointId: text("active_endpoint_id").references(
      () => devices.endpointId,
      { onDelete: "set null" },
    ),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("node_groups_network_name_unique").on(table.networkId, table.name),
    index("node_groups_by_network_idx").on(table.networkId),
  ],
);

export const nodeGroupMembers = pgTable(
  "node_group_members",
  {
    groupId: uuid("group_id")
      .notNull()
      .references(() => nodeGroups.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    /** Lower = preferred for promotion. */
    priority: integer("priority").notNull().default(100),
    joinedAt: timestamp("joined_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.groupId, table.endpointId] }),
    index("node_group_members_by_endpoint_idx").on(table.endpointId),
  ],
);

/** Per-peer-pair telemetry reported by agents (latency, throughput, path). */
export const peerMetrics = pgTable(
  "peer_metrics",
  {
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    fromEndpointId: text("from_endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    toEndpointId: text("to_endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    latencyMs: integer("latency_ms"),
    bytesTx: bigint("bytes_tx", { mode: "number" }).notNull().default(0),
    bytesRx: bigint("bytes_rx", { mode: "number" }).notNull().default(0),
    packetLoss: integer("packet_loss_bps"),
    direct: boolean("direct"),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.networkId, table.fromEndpointId, table.toEndpointId],
    }),
    index("peer_metrics_by_network_updated_idx").on(
      table.networkId,
      table.updatedAt,
    ),
  ],
);

export const auditLog = pgTable(
  "audit_log",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    organizationId: text("organization_id").references(() => organization.id, {
      onDelete: "set null",
    }),
    actor: text("actor"),
    action: text("action").notNull(),
    target: text("target"),
    metadata: jsonb("metadata").notNull().default({}),
    traceId: text("trace_id"),
    at: timestamp("at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("audit_log_by_organization_at_idx").on(
      table.organizationId,
      table.at,
    ),
  ],
);

export const relayStatusValues = [
  "pending",
  "healthy",
  "degraded",
  "offline",
  "disabled",
] as const;

export const relayKindValues = ["hosted", "self_hosted"] as const;

/** Public edge relays that terminate tunnels (not mesh members). */
export const relays = pgTable(
  "relays",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    kind: text("kind").notNull().default("self_hosted"),
    region: text("region").notNull().default("unknown"),
    publicIp: inet("public_ip"),
    domain: text("domain").notNull(),
    /** Soft capacity limit (concurrent tunnels). */
    capacityLimit: integer("capacity_limit").notNull().default(100),
    activeTunnels: integer("active_tunnels").notNull().default(0),
    status: text("status").notNull().default("pending"),
    lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
    /** Ed25519 public key hex used to authenticate relay heartbeats. */
    publicKey: text("public_key"),
    metadata: jsonb("metadata").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("relays_organization_name_unique").on(
      table.organizationId,
      table.name,
    ),
    unique("relays_organization_domain_unique").on(
      table.organizationId,
      table.domain,
    ),
    check("relays_kind_check", sql`${table.kind} IN ('hosted', 'self_hosted')`),
    check(
      "relays_status_check",
      sql`${table.status} IN ('pending', 'healthy', 'degraded', 'offline', 'disabled')`,
    ),
    index("relays_by_organization_idx").on(table.organizationId),
    index("relays_by_organization_status_idx").on(
      table.organizationId,
      table.status,
    ),
  ],
);

/** One-time tokens for registering a self-hosted relay (like enrollment tokens). */
export const relayRegistrationTokens = pgTable("relay_registration_tokens", {
  tokenHash: text("token_hash").primaryKey(),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  relayId: uuid("relay_id")
    .notNull()
    .references(() => relays.id, { onDelete: "cascade" }),
  createdBy: text("created_by")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const tunnelStatusValues = [
  "connecting",
  "active",
  "error",
  "stopped",
  "expired",
] as const;

export const tunnelProtocolValues = ["https", "tcp"] as const;

/** Public tunnels: machine port exposed via a relay subdomain. */
export const tunnels = pgTable(
  "tunnels",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    relayId: uuid("relay_id").references(() => relays.id, {
      onDelete: "set null",
    }),
    /** Local port on the machine. */
    localPort: integer("local_port").notNull(),
    protocol: text("protocol").notNull().default("https"),
    subdomain: text("subdomain").notNull(),
    /** Full public hostname, e.g. app.myorg.tuntun.pub */
    publicHostname: text("public_hostname").notNull(),
    status: text("status").notNull().default("connecting"),
    /** Auth token the agent presents to the relay (hashed at rest). */
    relayAuthHash: text("relay_auth_hash"),
    /**
     * Plaintext relay auth for AuthStore sync via heartbeat.
     * Server-side only — never serialize in dashboard list APIs.
     */
    relayAuthToken: text("relay_auth_token"),
    /** Optional HTTP basic auth on the public tunnel. */
    basicAuthUser: text("basic_auth_user"),
    basicAuthPasswordHash: text("basic_auth_password_hash"),
    errorMessage: text("error_message"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("tunnels_organization_subdomain_unique").on(
      table.organizationId,
      table.subdomain,
    ),
    check("tunnels_protocol_check", sql`${table.protocol} IN ('https', 'tcp')`),
    check(
      "tunnels_status_check",
      sql`${table.status} IN ('connecting', 'active', 'error', 'stopped', 'expired')`,
    ),
    check(
      "tunnels_local_port_check",
      sql`${table.localPort} > 0 AND ${table.localPort} <= 65535`,
    ),
    index("tunnels_by_organization_idx").on(table.organizationId),
    index("tunnels_by_network_idx").on(table.networkId),
    index("tunnels_by_endpoint_idx").on(table.endpointId),
    index("tunnels_by_relay_idx").on(table.relayId),
    index("tunnels_by_status_idx").on(table.status),
    index("tunnels_by_expires_at_idx").on(table.expiresAt),
  ],
);

/** Path-based redirect rules for HTTPS tunnels (first match wins by priority). */
export const tunnelRedirectRules = pgTable(
  "tunnel_redirect_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tunnelId: uuid("tunnel_id")
      .notNull()
      .references(() => tunnels.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    priority: integer("priority").notNull().default(0),
    /** e.g. /api/* */
    pathPattern: text("path_pattern").notNull(),
    /** null = same tunnel machine / localhost */
    targetEndpointId: text("target_endpoint_id"),
    targetPort: integer("target_port").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    check(
      "tunnel_redirect_rules_target_port_check",
      sql`${table.targetPort} > 0 AND ${table.targetPort} <= 65535`,
    ),
    index("tunnel_redirect_rules_by_tunnel_idx").on(table.tunnelId),
    index("tunnel_redirect_rules_by_tunnel_priority_idx").on(
      table.tunnelId,
      table.priority,
    ),
    index("tunnel_redirect_rules_by_organization_idx").on(table.organizationId),
  ],
);

/** External port → target mappings for TCP tunnels. */
export const tunnelPortMappings = pgTable(
  "tunnel_port_mappings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tunnelId: uuid("tunnel_id")
      .notNull()
      .references(() => tunnels.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    externalPort: integer("external_port").notNull(),
    /** null = same tunnel machine / localhost */
    targetEndpointId: text("target_endpoint_id"),
    targetPort: integer("target_port").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("tunnel_port_mappings_tunnel_external_port_unique").on(
      table.tunnelId,
      table.externalPort,
    ),
    check(
      "tunnel_port_mappings_external_port_check",
      sql`${table.externalPort} > 0 AND ${table.externalPort} <= 65535`,
    ),
    check(
      "tunnel_port_mappings_target_port_check",
      sql`${table.targetPort} > 0 AND ${table.targetPort} <= 65535`,
    ),
    index("tunnel_port_mappings_by_tunnel_idx").on(table.tunnelId),
    index("tunnel_port_mappings_by_organization_idx").on(table.organizationId),
  ],
);

/** Soft-retained request logs for tunnel traffic (UI lists last N). */
export const tunnelRequestLogs = pgTable(
  "tunnel_request_logs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tunnelId: uuid("tunnel_id")
      .notNull()
      .references(() => tunnels.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    method: text("method").notNull(),
    path: text("path").notNull(),
    statusCode: integer("status_code").notNull(),
    latencyMs: integer("latency_ms").notNull(),
    sourceIp: text("source_ip"),
    requestHeaders: jsonb("request_headers").notNull().default({}),
    responseHeaders: jsonb("response_headers").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("tunnel_request_logs_by_tunnel_created_idx").on(
      table.tunnelId,
      table.createdAt,
    ),
    index("tunnel_request_logs_by_organization_created_idx").on(
      table.organizationId,
      table.createdAt,
    ),
    index("tunnel_request_logs_by_created_idx").on(table.createdAt),
  ],
);

/** Org-level defaults for tunnels / DNS branding. */
export const organizationTunnelSettings = pgTable(
  "organization_tunnel_settings",
  {
    organizationId: text("organization_id")
      .primaryKey()
      .references(() => organization.id, { onDelete: "cascade" }),
    defaultRelayId: uuid("default_relay_id").references(() => relays.id, {
      onDelete: "set null",
    }),
    defaultTtlSeconds: integer("default_ttl_seconds"),
    maxTunnelsPerMachine: integer("max_tunnels_per_machine")
      .notNull()
      .default(10),
    peerDnsSuffix: text("peer_dns_suffix"),
    customTunnelDomain: text("custom_tunnel_domain"),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
);

/** Historical relay heartbeat samples for health charts. */
export const relayHeartbeats = pgTable(
  "relay_heartbeats",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    relayId: uuid("relay_id")
      .notNull()
      .references(() => relays.id, { onDelete: "cascade" }),
    activeTunnels: integer("active_tunnels").notNull().default(0),
    recordedAt: timestamp("recorded_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("relay_heartbeats_by_relay_recorded_idx").on(
      table.relayId,
      table.recordedAt,
    ),
  ],
);

export const serveStatusValues = [
  "starting",
  "active",
  "error",
  "stopped",
] as const;

export const serveProtocolValues = ["https", "tcp"] as const;

export const serveAccessModeValues = ["all_peers", "tags", "machines"] as const;

/** Per-organization internal root CA (encrypted private key at rest). */
export const organizationCas = pgTable("organization_cas", {
  organizationId: text("organization_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  /** PEM-encoded certificate. */
  certificatePem: text("certificate_pem").notNull(),
  /** Encrypted PEM private key (app-level encryption). */
  encryptedPrivateKey: text("encrypted_private_key").notNull(),
  fingerprintSha256: text("fingerprint_sha256").notNull(),
  notBefore: timestamp("not_before", { withTimezone: true }).notNull(),
  notAfter: timestamp("not_after", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
  rotatedAt: timestamp("rotated_at", { withTimezone: true }),
});

/** Per-machine leaf certs signed by the org internal CA. */
export const internalCertificates = pgTable(
  "internal_certificates",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    /** Subject CN / SAN hostname, e.g. db-server.mynet.tuntun */
    hostname: text("hostname").notNull(),
    certificatePem: text("certificate_pem").notNull(),
    /** Encrypted private key PEM for the leaf. */
    encryptedPrivateKey: text("encrypted_private_key").notNull(),
    fingerprintSha256: text("fingerprint_sha256").notNull(),
    notBefore: timestamp("not_before", { withTimezone: true }).notNull(),
    notAfter: timestamp("not_after", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("internal_certificates_endpoint_hostname_unique").on(
      table.endpointId,
      table.hostname,
    ),
    index("internal_certificates_by_organization_idx").on(table.organizationId),
    index("internal_certificates_by_endpoint_idx").on(table.endpointId),
  ],
);

/** Internal mesh serves: HTTPS (internal CA) or TCP on the mesh interface. */
export const serves = pgTable(
  "serves",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    localPort: integer("local_port").notNull(),
    protocol: text("protocol").notNull().default("https"),
    /** e.g. db-server.mynet.tuntun */
    internalHostname: text("internal_hostname").notNull(),
    status: text("status").notNull().default("starting"),
    accessMode: text("access_mode").notNull().default("all_peers"),
    /** Tag allow-list when accessMode = tags. */
    allowedTags: text("allowed_tags").array().notNull().default([]),
    /** Endpoint allow-list when accessMode = machines. */
    allowedEndpointIds: text("allowed_endpoint_ids")
      .array()
      .notNull()
      .default([]),
    certificateId: uuid("certificate_id").references(
      () => internalCertificates.id,
      { onDelete: "set null" },
    ),
    errorMessage: text("error_message"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("serves_endpoint_port_unique").on(table.endpointId, table.localPort),
    check("serves_protocol_check", sql`${table.protocol} IN ('https', 'tcp')`),
    check(
      "serves_status_check",
      sql`${table.status} IN ('starting', 'active', 'error', 'stopped')`,
    ),
    check(
      "serves_access_mode_check",
      sql`${table.accessMode} IN ('all_peers', 'tags', 'machines')`,
    ),
    check(
      "serves_local_port_check",
      sql`${table.localPort} > 0 AND ${table.localPort} <= 65535`,
    ),
    index("serves_by_organization_idx").on(table.organizationId),
    index("serves_by_network_idx").on(table.networkId),
    index("serves_by_endpoint_idx").on(table.endpointId),
    index("serves_by_network_status_idx").on(table.networkId, table.status),
  ],
);

/** Currently connected peers for a mesh serve (agent-reported). */
export const serveSessions = pgTable(
  "serve_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    serveId: uuid("serve_id")
      .notNull()
      .references(() => serves.id, { onDelete: "cascade" }),
    peerEndpointId: text("peer_endpoint_id").notNull(),
    peerHostname: text("peer_hostname"),
    connectedAt: timestamp("connected_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    bytesIn: bigint("bytes_in", { mode: "number" }).notNull().default(0),
    bytesOut: bigint("bytes_out", { mode: "number" }).notNull().default(0),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("serve_sessions_serve_peer_unique").on(
      table.serveId,
      table.peerEndpointId,
    ),
    index("serve_sessions_by_serve_idx").on(table.serveId),
    index("serve_sessions_by_serve_last_seen_idx").on(
      table.serveId,
      table.lastSeenAt,
    ),
  ],
);

export const networksRelations = relations(networks, ({ one, many }) => ({
  organization: one(organization, {
    fields: [networks.organizationId],
    references: [organization.id],
  }),
  memberships: many(networkMemberships),
  policies: many(policies),
  enrollmentTokens: many(enrollmentTokens),
  subnetRoutes: many(subnetRoutes),
  hostnameRoutes: many(hostnameRoutes),
  exitNodeConfigs: many(exitNodeConfig),
  deviceProfiles: many(deviceProfiles),
  nodeGroups: many(nodeGroups),
  tunnels: many(tunnels),
  serves: many(serves),
}));

export const devicesRelations = relations(devices, ({ one, many }) => ({
  organization: one(organization, {
    fields: [devices.organizationId],
    references: [organization.id],
  }),
  memberships: many(networkMemberships),
  tags: many(deviceTags),
  presenceEvents: many(devicePresenceEvents),
  subnetRoutes: many(subnetRoutes),
  hostnameRoutes: many(hostnameRoutes),
  exitNodeConfig: one(exitNodeConfig, {
    fields: [devices.endpointId],
    references: [exitNodeConfig.endpointId],
  }),
  deviceProfile: one(deviceProfiles, {
    fields: [devices.endpointId],
    references: [deviceProfiles.endpointId],
  }),
  tunnels: many(tunnels),
  serves: many(serves),
  internalCertificates: many(internalCertificates),
}));

export const relaysRelations = relations(relays, ({ one, many }) => ({
  organization: one(organization, {
    fields: [relays.organizationId],
    references: [organization.id],
  }),
  tunnels: many(tunnels),
  registrationTokens: many(relayRegistrationTokens),
  heartbeats: many(relayHeartbeats),
}));

export const relayRegistrationTokensRelations = relations(
  relayRegistrationTokens,
  ({ one }) => ({
    organization: one(organization, {
      fields: [relayRegistrationTokens.organizationId],
      references: [organization.id],
    }),
    relay: one(relays, {
      fields: [relayRegistrationTokens.relayId],
      references: [relays.id],
    }),
    creator: one(user, {
      fields: [relayRegistrationTokens.createdBy],
      references: [user.id],
    }),
  }),
);

export const tunnelsRelations = relations(tunnels, ({ one, many }) => ({
  organization: one(organization, {
    fields: [tunnels.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [tunnels.networkId],
    references: [networks.id],
  }),
  device: one(devices, {
    fields: [tunnels.endpointId],
    references: [devices.endpointId],
  }),
  relay: one(relays, {
    fields: [tunnels.relayId],
    references: [relays.id],
  }),
  redirectRules: many(tunnelRedirectRules),
  portMappings: many(tunnelPortMappings),
  requestLogs: many(tunnelRequestLogs),
}));

export const tunnelRedirectRulesRelations = relations(
  tunnelRedirectRules,
  ({ one }) => ({
    tunnel: one(tunnels, {
      fields: [tunnelRedirectRules.tunnelId],
      references: [tunnels.id],
    }),
    organization: one(organization, {
      fields: [tunnelRedirectRules.organizationId],
      references: [organization.id],
    }),
  }),
);

export const tunnelPortMappingsRelations = relations(
  tunnelPortMappings,
  ({ one }) => ({
    tunnel: one(tunnels, {
      fields: [tunnelPortMappings.tunnelId],
      references: [tunnels.id],
    }),
    organization: one(organization, {
      fields: [tunnelPortMappings.organizationId],
      references: [organization.id],
    }),
  }),
);

export const tunnelRequestLogsRelations = relations(
  tunnelRequestLogs,
  ({ one }) => ({
    tunnel: one(tunnels, {
      fields: [tunnelRequestLogs.tunnelId],
      references: [tunnels.id],
    }),
    organization: one(organization, {
      fields: [tunnelRequestLogs.organizationId],
      references: [organization.id],
    }),
  }),
);

export const organizationTunnelSettingsRelations = relations(
  organizationTunnelSettings,
  ({ one }) => ({
    organization: one(organization, {
      fields: [organizationTunnelSettings.organizationId],
      references: [organization.id],
    }),
    defaultRelay: one(relays, {
      fields: [organizationTunnelSettings.defaultRelayId],
      references: [relays.id],
    }),
  }),
);

export const relayHeartbeatsRelations = relations(
  relayHeartbeats,
  ({ one }) => ({
    relay: one(relays, {
      fields: [relayHeartbeats.relayId],
      references: [relays.id],
    }),
  }),
);

export const servesRelations = relations(serves, ({ one, many }) => ({
  organization: one(organization, {
    fields: [serves.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [serves.networkId],
    references: [networks.id],
  }),
  device: one(devices, {
    fields: [serves.endpointId],
    references: [devices.endpointId],
  }),
  certificate: one(internalCertificates, {
    fields: [serves.certificateId],
    references: [internalCertificates.id],
  }),
  sessions: many(serveSessions),
}));

export const serveSessionsRelations = relations(serveSessions, ({ one }) => ({
  serve: one(serves, {
    fields: [serveSessions.serveId],
    references: [serves.id],
  }),
}));

export const organizationCasRelations = relations(
  organizationCas,
  ({ one }) => ({
    organization: one(organization, {
      fields: [organizationCas.organizationId],
      references: [organization.id],
    }),
  }),
);

export const internalCertificatesRelations = relations(
  internalCertificates,
  ({ one, many }) => ({
    organization: one(organization, {
      fields: [internalCertificates.organizationId],
      references: [organization.id],
    }),
    device: one(devices, {
      fields: [internalCertificates.endpointId],
      references: [devices.endpointId],
    }),
    serves: many(serves),
  }),
);

export const subnetRoutesRelations = relations(subnetRoutes, ({ one }) => ({
  device: one(devices, {
    fields: [subnetRoutes.endpointId],
    references: [devices.endpointId],
  }),
  network: one(networks, {
    fields: [subnetRoutes.networkId],
    references: [networks.id],
  }),
}));

export const hostnameRoutesRelations = relations(hostnameRoutes, ({ one }) => ({
  device: one(devices, {
    fields: [hostnameRoutes.endpointId],
    references: [devices.endpointId],
  }),
  network: one(networks, {
    fields: [hostnameRoutes.networkId],
    references: [networks.id],
  }),
}));

export const exitNodeConfigRelations = relations(exitNodeConfig, ({ one }) => ({
  device: one(devices, {
    fields: [exitNodeConfig.endpointId],
    references: [devices.endpointId],
  }),
  network: one(networks, {
    fields: [exitNodeConfig.networkId],
    references: [networks.id],
  }),
}));

export const deviceProfilesRelations = relations(deviceProfiles, ({ one }) => ({
  device: one(devices, {
    fields: [deviceProfiles.endpointId],
    references: [devices.endpointId],
    relationName: "profile_owner",
  }),
  network: one(networks, {
    fields: [deviceProfiles.networkId],
    references: [networks.id],
  }),
  exitNode: one(devices, {
    fields: [deviceProfiles.exitNodeEndpointId],
    references: [devices.endpointId],
    relationName: "profile_exit_node",
  }),
}));

export const nodeGroupsRelations = relations(nodeGroups, ({ one, many }) => ({
  network: one(networks, {
    fields: [nodeGroups.networkId],
    references: [networks.id],
  }),
  activeDevice: one(devices, {
    fields: [nodeGroups.activeEndpointId],
    references: [devices.endpointId],
  }),
  members: many(nodeGroupMembers),
}));

export const nodeGroupMembersRelations = relations(
  nodeGroupMembers,
  ({ one }) => ({
    group: one(nodeGroups, {
      fields: [nodeGroupMembers.groupId],
      references: [nodeGroups.id],
    }),
    device: one(devices, {
      fields: [nodeGroupMembers.endpointId],
      references: [devices.endpointId],
    }),
  }),
);

export const networkMembershipsRelations = relations(
  networkMemberships,
  ({ one }) => ({
    device: one(devices, {
      fields: [networkMemberships.endpointId],
      references: [devices.endpointId],
    }),
    network: one(networks, {
      fields: [networkMemberships.networkId],
      references: [networks.id],
    }),
  }),
);

export const devicePresenceEventsRelations = relations(
  devicePresenceEvents,
  ({ one }) => ({
    device: one(devices, {
      fields: [devicePresenceEvents.endpointId],
      references: [devices.endpointId],
    }),
    organization: one(organization, {
      fields: [devicePresenceEvents.organizationId],
      references: [organization.id],
    }),
    network: one(networks, {
      fields: [devicePresenceEvents.networkId],
      references: [networks.id],
    }),
  }),
);

export const deviceTagsRelations = relations(deviceTags, ({ one }) => ({
  device: one(devices, {
    fields: [deviceTags.endpointId],
    references: [devices.endpointId],
  }),
}));

export const policiesRelations = relations(policies, ({ one }) => ({
  network: one(networks, {
    fields: [policies.networkId],
    references: [networks.id],
  }),
}));

export const organizationPoliciesRelations = relations(
  organizationPolicies,
  ({ one }) => ({
    organization: one(organization, {
      fields: [organizationPolicies.organizationId],
      references: [organization.id],
    }),
  }),
);

export const enrollmentTokensRelations = relations(
  enrollmentTokens,
  ({ one }) => ({
    organization: one(organization, {
      fields: [enrollmentTokens.organizationId],
      references: [organization.id],
    }),
    network: one(networks, {
      fields: [enrollmentTokens.networkId],
      references: [networks.id],
    }),
    creator: one(user, {
      fields: [enrollmentTokens.createdBy],
      references: [user.id],
    }),
  }),
);

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  organization: one(organization, {
    fields: [apiKeys.organizationId],
    references: [organization.id],
  }),
}));
