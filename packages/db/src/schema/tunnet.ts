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
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
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

/** PostgreSQL `interval` as a human-readable string (e.g. `"3 days"`). */
const pgInterval = customType<{ data: string; driverData: string }>({
  dataType() {
    return "interval";
  },
});

const id = () => uuid("id").primaryKey().default(sql`uuidv7()`);

export const policyActionValues = ["allow", "deny"] as const;
export const policyScopeValues = ["network", "organization"] as const;
export const tunnelRoutingKindValues = ["path", "port"] as const;
export const organizationCaStatusValues = [
  "active",
  "rotated",
  "revoked",
] as const;
export const membershipStatusValues = [
  "active",
  "suspended",
  "pending",
] as const;

export const deviceTypeValues = ["agent", "sdk", "k8s"] as const;

export const postureSourceValues = [
  "agent",
  "control",
  "api",
  "integration",
] as const;
export const postureEnforcementModeValues = [
  "monitor",
  "warn",
  "enforce",
] as const;
export const postureIntegrationProviderValues = [
  "crowdstrike",
  "sentinelone",
  "intune",
  "custom",
] as const;

export const apiKeys = pgTable("api_keys", {
  id: id(),
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
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    cidr: cidr("cidr").notNull(),
    /** 1280 = IPv6 minimum; safe for QUIC-over-UDP tunnel overhead. */
    mtu: integer("mtu").notNull().default(1280),
    /** Network overrides for org defaults (e.g. `{ agentPolicy: {...} }`). */
    settings: jsonb("settings").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    version: bigint("version", { mode: "number" }).notNull().default(0),
  },
  (table) => [unique().on(table.organizationId, table.name)],
);

export const devices = pgTable(
  "devices",
  {
    endpointId: text("endpoint_id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
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
    labels: jsonb("labels").notNull().default({}),
    /** Per-machine inactivity TTL override; null inherits org auto-cleanup policy. */
    inactivityTtl: pgInterval("inactivity_ttl"),
    /** Set when soft-expired; used for soft_then_hard grace purge. */
    expiredAt: timestamp("expired_at", { withTimezone: true }),
  },
  (table) => [
    check(
      "devices_endpoint_id_len",
      sql`char_length(${table.endpointId}) = 64`,
    ),
    check("devices_type_check", sql`${table.type} IN ('agent', 'sdk', 'k8s')`),
    check(
      "devices_ipv6_enabled_at_check",
      sql`(NOT ${table.ipv6Enabled}) OR (${table.ipv6EnabledAt} IS NOT NULL)`,
    ),
    index("devices_by_organization_idx").on(table.organizationId),
    index("devices_by_last_seen_idx").on(table.lastSeen),
    index("devices_by_agent_connected_idx").on(table.agentConnected),
    index("devices_by_expired_at_idx").on(table.expiredAt),
  ],
);

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
      sql`${table.status} IN ('active', 'suspended', 'pending', 'expired')`,
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
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** Null = organization-wide policy. */
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    scope: text("scope").notNull(),
    srcSelector: jsonb("src_selector").notNull(),
    dstSelector: jsonb("dst_selector").notNull(),
    action: text("action").notNull(),
    ports: jsonb("ports").notNull().default([]),
    protocol: text("protocol"),
    priority: integer("priority").notNull().default(0),
    /** Posture definition names required on source device; null/empty = inherit org default. */
    srcPosture: jsonb("src_posture").$type<string[] | null>(),
    /** Stable slug for GitOps / Terraform identity. */
    slug: text("slug"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("policies_by_org_priority_idx").on(
      table.organizationId,
      table.priority,
    ),
    index("policies_by_network_priority_idx")
      .on(table.networkId, table.priority)
      .where(sql`${table.networkId} IS NOT NULL`),
    uniqueIndex("policies_org_slug_unique")
      .on(table.organizationId, table.slug)
      .where(sql`${table.slug} IS NOT NULL`),
    check("policies_action_check", sql`${table.action} IN ('allow', 'deny')`),
    check(
      "policies_scope_check",
      sql`${table.scope} IN ('network', 'organization')`,
    ),
    check(
      "policies_scope_network_id_check",
      sql`(${table.scope} = 'organization' AND ${table.networkId} IS NULL)
          OR (${table.scope} = 'network' AND ${table.networkId} IS NOT NULL)`,
    ),
  ],
);

/** Application-level SSH access rules (separate from L3/L4 network ACL). */
export const sshPolicies = pgTable(
  "ssh_policies",
  {
    id: id(),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    srcSelector: jsonb("src_selector").notNull(),
    dstSelector: jsonb("dst_selector").notNull(),
    action: text("action").notNull(),
    users: jsonb("users").notNull().default([]),
    record: boolean("record").notNull().default(false),
    recorder: jsonb("recorder"),
    enforceRecorder: boolean("enforce_recorder").notNull().default(false),
    checkPeriodSecs: integer("check_period_secs"),
    priority: integer("priority").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("ssh_policies_by_network_priority_idx").on(
      table.networkId,
      table.priority,
    ),
    check(
      "ssh_policies_action_check",
      sql`${table.action} IN ('accept', 'check', 'deny')`,
    ),
  ],
);

export const sshSessions = pgTable(
  "ssh_sessions",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    srcEndpointId: text("src_endpoint_id").notNull(),
    dstEndpointId: text("dst_endpoint_id").notNull(),
    srcHostname: text("src_hostname"),
    dstHostname: text("dst_hostname"),
    targetUser: text("target_user").notNull(),
    status: text("status").notNull().default("active"),
    recorded: boolean("recorded").notNull().default(false),
    startedAt: timestamp("started_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    endedAt: timestamp("ended_at", { withTimezone: true }),
    durationMs: integer("duration_ms"),
  },
  (table) => [
    index("ssh_sessions_by_org_started_idx").on(
      table.organizationId,
      table.startedAt,
    ),
    index("ssh_sessions_by_network_started_idx").on(
      table.networkId,
      table.startedAt,
    ),
    index("ssh_sessions_by_dst_started_idx").on(
      table.dstEndpointId,
      table.startedAt,
    ),
    index("ssh_sessions_by_status_idx").on(table.status),
    check(
      "ssh_sessions_status_check",
      sql`${table.status} IN ('active', 'ended', 'killed')`,
    ),
  ],
);

export const sshRecordings = pgTable(
  "ssh_recordings",
  {
    id: id(),
    sessionId: uuid("session_id")
      .notNull()
      .references(() => sshSessions.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    recorderEndpointId: text("recorder_endpoint_id").notNull(),
    castText: text("cast_text").notNull(),
    contentSha256: text("content_sha256").notNull(),
    byteSize: integer("byte_size").notNull(),
    durationMs: integer("duration_ms"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("ssh_recordings_by_session_idx").on(table.sessionId),
    unique("ssh_recordings_session_unique").on(table.sessionId),
    index("ssh_recordings_by_org_created_idx").on(
      table.organizationId,
      table.createdAt,
    ),
    index("ssh_recordings_by_network_created_idx").on(
      table.networkId,
      table.createdAt,
    ),
  ],
);

export const sshAuthChecks = pgTable(
  "ssh_auth_checks",
  {
    endpointId: text("endpoint_id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    method: text("method").notNull().default("oidc"),
    identityEmail: text("identity_email"),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("ssh_auth_checks_by_org_idx").on(table.organizationId),
    check(
      "ssh_auth_checks_method_check",
      sql`${table.method} IN ('oidc', 'session', 'saml')`,
    ),
  ],
);

export const sshAuthChallenges = pgTable(
  "ssh_auth_challenges",
  {
    token: text("token").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id").notNull(),
    dstEndpointId: text("dst_endpoint_id").notNull(),
    status: text("status").notNull().default("pending"),
    proofToken: text("proof_token"),
    proofExpiresAt: timestamp("proof_expires_at", { withTimezone: true }),
    proofConsumedAt: timestamp("proof_consumed_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("ssh_auth_challenges_by_endpoint_idx").on(table.endpointId),
    index("ssh_auth_challenges_by_proof_idx").on(table.proofToken),
    index("ssh_auth_challenges_by_expires_at_idx").on(table.expiresAt),
    check(
      "ssh_auth_challenges_status_check",
      sql`${table.status} IN ('pending', 'completed', 'expired', 'failed')`,
    ),
  ],
);

export const enrollmentTokens = pgTable(
  "enrollment_tokens",
  {
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
    tags: text("tags").array().notNull().default([]),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [index("enrollment_tokens_by_expires_at_idx").on(table.expiresAt)],
);

export const subnetRoutes = pgTable(
  "subnet_routes",
  {
    id: id(),
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
    index("subnet_routes_by_endpoint_idx").on(table.endpointId),
    index("subnet_routes_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

export const hostnameRoutes = pgTable(
  "hostname_routes",
  {
    id: id(),
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
    index("hostname_routes_by_endpoint_idx").on(table.endpointId),
    index("hostname_routes_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

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
    index("exit_node_config_by_network_enabled_idx").on(
      table.networkId,
      table.enabled,
    ),
  ],
);

export const splitTunnelModeValues = ["include", "exclude"] as const;

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

export const nodeGroups = pgTable(
  "node_groups",
  {
    id: id(),
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

/** OCSF-aligned append-only audit events (hash-chained per organization). */
export const auditEvents = pgTable(
  "audit_events",
  {
    organizationId: text("organization_id").notNull(),
    sequenceNumber: bigint("sequence_number", { mode: "number" }).notNull(),
    categoryUid: smallint("category_uid").notNull(),
    classUid: smallint("class_uid").notNull(),
    activityId: smallint("activity_id").notNull(),
    typeUid: integer("type_uid").notNull(),
    severityId: smallint("severity_id").notNull().default(1),
    statusId: smallint("status_id").notNull().default(1),
    time: timestamp("time", { withTimezone: true }).notNull().defaultNow(),
    message: text("message").notNull(),
    actorType: text("actor_type").notNull(),
    actorId: text("actor_id").notNull(),
    actorName: text("actor_name"),
    actorEmail: text("actor_email"),
    actorIp: inet("actor_ip"),
    actorUa: text("actor_ua"),
    targetType: text("target_type").notNull(),
    targetId: text("target_id").notNull(),
    targetName: text("target_name"),
    networkId: uuid("network_id"),
    groupId: text("group_id"),
    diffBefore: jsonb("diff_before"),
    diffAfter: jsonb("diff_after"),
    metadata: jsonb("metadata").notNull().default({}),
    traceId: text("trace_id"),
    prevEntryHash: text("prev_entry_hash").notNull(),
    entryHash: text("entry_hash").notNull(),
    hmacSchemaVersion: smallint("hmac_schema_version").notNull().default(1),
  },
  (table) => [
    primaryKey({
      columns: [table.organizationId, table.sequenceNumber, table.time],
      name: "audit_events_pkey",
    }),
    index("idx_audit_org_time").on(table.organizationId, table.time),
    index("idx_audit_org_class").on(
      table.organizationId,
      table.classUid,
      table.time,
    ),
    index("idx_audit_org_actor").on(
      table.organizationId,
      table.actorId,
      table.time,
    ),
    index("idx_audit_org_target").on(
      table.organizationId,
      table.targetType,
      table.targetId,
      table.time,
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

export const relays = pgTable(
  "relays",
  {
    id: id(),
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
    index("relays_by_organization_status_idx").on(
      table.organizationId,
      table.status,
    ),
  ],
);

export const relayRegistrationTokens = pgTable(
  "relay_registration_tokens",
  {
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
  },
  (table) => [
    index("relay_registration_tokens_by_expires_at_idx").on(table.expiresAt),
  ],
);

export const tunnelStatusValues = [
  "connecting",
  "active",
  "error",
  "stopped",
  "expired",
] as const;

export const tunnelProtocolValues = ["https", "tcp"] as const;

export const tunnels = pgTable(
  "tunnels",
  {
    id: id(),
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
    /** Full public hostname, e.g. app.myorg.tunnet.pub */
    publicHostname: text("public_hostname").notNull(),
    status: text("status").notNull().default("connecting"),
    /** Hash of the relay auth token (verification only - plaintext lives in tunnel_secrets). */
    relayAuthHash: text("relay_auth_hash"),
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

export const tunnelSecrets = pgTable("tunnel_secrets", {
  tunnelId: uuid("tunnel_id")
    .primaryKey()
    .references(() => tunnels.id, { onDelete: "cascade" }),
  relayAuthToken: text("relay_auth_token").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

/** Path or port routing rules for a tunnel (HTTPS → path, TCP → port). */
export const tunnelRoutingRules = pgTable(
  "tunnel_routing_rules",
  {
    id: id(),
    tunnelId: uuid("tunnel_id")
      .notNull()
      .references(() => tunnels.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    priority: integer("priority").notNull().default(0),
    /** HTTPS path pattern, e.g. /api/* - set when kind=path. */
    pathPattern: text("path_pattern"),
    /** TCP external port - set when kind=port. */
    externalPort: integer("external_port"),
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
      "tunnel_routing_rules_kind_check",
      sql`${table.kind} IN ('path', 'port')`,
    ),
    check(
      "tunnel_routing_rules_kind_fields_check",
      sql`(${table.kind} = 'path' AND ${table.pathPattern} IS NOT NULL AND ${table.externalPort} IS NULL)
          OR (${table.kind} = 'port' AND ${table.externalPort} IS NOT NULL AND ${table.pathPattern} IS NULL)`,
    ),
    check(
      "tunnel_routing_rules_target_port_check",
      sql`${table.targetPort} > 0 AND ${table.targetPort} <= 65535`,
    ),
    check(
      "tunnel_routing_rules_external_port_check",
      sql`${table.externalPort} IS NULL OR (${table.externalPort} > 0 AND ${table.externalPort} <= 65535)`,
    ),
    uniqueIndex("tunnel_routing_rules_tunnel_path_unique")
      .on(table.tunnelId, table.pathPattern)
      .where(sql`${table.kind} = 'path'`),
    uniqueIndex("tunnel_routing_rules_tunnel_port_unique")
      .on(table.tunnelId, table.externalPort)
      .where(sql`${table.kind} = 'port'`),
    index("tunnel_routing_rules_by_tunnel_priority_idx").on(
      table.tunnelId,
      table.priority,
    ),
    index("tunnel_routing_rules_by_organization_idx").on(table.organizationId),
  ],
);

export const tunnelRequestLogs = pgTable(
  "tunnel_request_logs",
  {
    id: id(),
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
    id: id(),
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

/** Per-organization internal root CA(s). One active; rotated/revoked retained for leaf validation. */
export const organizationCas = pgTable(
  "organization_cas",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    status: text("status").notNull().default("active"),
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
  },
  (table) => [
    check(
      "organization_cas_status_check",
      sql`${table.status} IN ('active', 'rotated', 'revoked')`,
    ),
    uniqueIndex("organization_cas_one_active_per_org")
      .on(table.organizationId)
      .where(sql`${table.status} = 'active'`),
    index("organization_cas_by_organization_idx").on(table.organizationId),
  ],
);

/** Per-machine leaf certs signed by the org internal CA. */
export const internalCertificates = pgTable(
  "internal_certificates",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    /** Subject CN / SAN hostname, e.g. db-server.mynet.tunnet */
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
    id: id(),
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
    /** e.g. db-server.mynet.tunnet */
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
    index("serves_by_endpoint_idx").on(table.endpointId),
    index("serves_by_network_status_idx").on(table.networkId, table.status),
  ],
);

/** Currently connected peers for a mesh serve (agent-reported). */
export const serveSessions = pgTable(
  "serve_sessions",
  {
    id: id(),
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

/** P2P file transfers reported by agents. */
export const fileTransfers = pgTable(
  "file_transfers",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id")
      .notNull()
      .references(() => networks.id, { onDelete: "cascade" }),
    senderEndpointId: text("sender_endpoint_id").notNull(),
    receiverEndpointId: text("receiver_endpoint_id"),
    fileName: text("file_name").notNull(),
    sizeBytes: bigint("size_bytes", { mode: "number" }).notNull().default(0),
    blake3Hash: text("blake3_hash").notNull(),
    status: text("status").notNull().default("offered"),
    progressPct: integer("progress_pct").notNull().default(0),
    bytesTransferred: bigint("bytes_transferred", { mode: "number" })
      .notNull()
      .default(0),
    error: text("error"),
    message: text("message"),
    inboxPath: text("inbox_path"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  (table) => [
    index("file_transfers_by_org_created_idx").on(
      table.organizationId,
      table.createdAt,
    ),
    index("file_transfers_by_network_created_idx").on(
      table.networkId,
      table.createdAt,
    ),
    index("file_transfers_by_status_idx").on(table.status),
    index("file_transfers_by_sender_idx").on(table.senderEndpointId),
    index("file_transfers_by_receiver_idx").on(table.receiverEndpointId),
    check(
      "file_transfers_status_check",
      sql`${table.status} IN ('offered', 'pending', 'transferring', 'completed', 'failed', 'rejected')`,
    ),
  ],
);

export const postureAttributes = pgTable(
  "posture_attributes",
  {
    id: id(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    namespace: text("namespace").notNull(),
    key: text("key").notNull(),
    value: jsonb("value").notNull(),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    source: text("source").notNull().default("agent"),
  },
  (t) => [
    unique().on(t.endpointId, t.namespace, t.key),
    index("posture_attributes_by_endpoint_idx").on(t.endpointId),
    index("posture_attributes_by_org_idx").on(t.organizationId),
    index("posture_attributes_by_expires_idx").on(t.expiresAt),
    check(
      "posture_attributes_source_check",
      sql`${t.source} IN ('agent', 'control', 'api', 'integration')`,
    ),
  ],
);

export const postureDefinitions = pgTable(
  "posture_definitions",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** Null = org-level default; set = network-level override / addition. */
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    name: text("name").notNull(),
    description: text("description"),
    assertions: jsonb("assertions").$type<string[]>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    uniqueIndex("posture_definitions_org_name_uidx")
      .on(t.organizationId, t.name)
      .where(sql`${t.networkId} IS NULL`),
    uniqueIndex("posture_definitions_network_name_uidx")
      .on(t.organizationId, t.networkId, t.name)
      .where(sql`${t.networkId} IS NOT NULL`),
    index("posture_definitions_by_network_idx").on(t.networkId),
  ],
);

export const postureEvaluations = pgTable(
  "posture_evaluations",
  {
    id: id(),
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => devices.endpointId, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    postureDefinitionId: uuid("posture_definition_id")
      .notNull()
      .references(() => postureDefinitions.id, { onDelete: "cascade" }),
    passed: boolean("passed").notNull(),
    failingAssertions: jsonb("failing_assertions").$type<string[]>(),
    score: integer("score"),
    evaluatedAt: timestamp("evaluated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    index("posture_evaluations_by_endpoint_evaluated_idx").on(
      t.endpointId,
      t.evaluatedAt,
    ),
    index("posture_evaluations_by_org_idx").on(t.organizationId),
  ],
);

export const postureIntegrations = pgTable(
  "posture_integrations",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    config: jsonb("config").notNull().default({}),
    pollingIntervalSecs: integer("polling_interval_secs")
      .notNull()
      .default(300),
    enabled: boolean("enabled").notNull().default(true),
    lastSyncedAt: timestamp("last_synced_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    index("posture_integrations_by_org_idx").on(t.organizationId),
    check(
      "posture_integrations_provider_check",
      sql`${t.provider} IN ('crowdstrike', 'sentinelone', 'intune', 'custom')`,
    ),
  ],
);

export const postureWebhooks = pgTable(
  "posture_webhooks",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    url: text("url").notNull(),
    secret: text("secret"),
    events: jsonb("events").$type<string[]>().notNull().default([]),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [index("posture_webhooks_by_org_idx").on(t.organizationId)],
);

/** Org defaults (`network_id` null) or per-network overrides. */
export const postureOrgSettings = pgTable(
  "posture_org_settings",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** Null = org-level default; set = network override. */
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    mode: text("mode").notNull().default("monitor"),
    gracePeriodMinutes: integer("grace_period_minutes").notNull().default(30),
    recheckOnFailSeconds: integer("recheck_on_fail_seconds")
      .notNull()
      .default(60),
    notifyUser: boolean("notify_user").notNull().default(true),
    notifyAdmin: boolean("notify_admin").notNull().default(false),
    autoReauthorize: boolean("auto_reauthorize").notNull().default(true),
    defaultSrcPosture: jsonb("default_src_posture")
      .$type<string[]>()
      .notNull()
      .default([]),
    scoringWeights: jsonb("scoring_weights").$type<Record<
      string,
      { weight: number; failScore: number }
    > | null>(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    check(
      "posture_org_settings_mode_check",
      sql`${t.mode} IN ('monitor', 'warn', 'enforce')`,
    ),
    uniqueIndex("posture_org_settings_org_default_uidx")
      .on(t.organizationId)
      .where(sql`${t.networkId} IS NULL`),
    uniqueIndex("posture_org_settings_network_uidx")
      .on(t.organizationId, t.networkId)
      .where(sql`${t.networkId} IS NOT NULL`),
    index("posture_org_settings_by_network_idx").on(t.networkId),
  ],
);

/** Per-endpoint file-transfer consent / inbox settings. */
export const endpointSendSettings = pgTable(
  "endpoint_send_settings",
  {
    endpointId: text("endpoint_id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    consentMode: text("consent_mode").notNull().default("prompt"),
    inboxPath: text("inbox_path"),
    pinBlobs: boolean("pin_blobs").notNull().default(false),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("endpoint_send_settings_by_org_idx").on(table.organizationId),
    check(
      "endpoint_send_settings_consent_check",
      sql`${table.consentMode} IN ('auto_accept', 'prompt', 'deny')`,
    ),
  ],
);

export const policyRevisionSourceValues = [
  "dashboard",
  "api",
  "gitops",
  "terraform",
] as const;

/** Tag ownership definitions (Tailscale tagOwners equivalent). */
export const tagDefinitions = pgTable(
  "tag_definitions",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    owners: jsonb("owners").$type<string[]>().notNull().default([]),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.organizationId, t.name),
    index("tag_definitions_by_org_idx").on(t.organizationId),
  ],
);

export const hostAliases = pgTable(
  "host_aliases",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    target: text("target").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.organizationId, t.name),
    index("host_aliases_by_org_idx").on(t.organizationId),
  ],
);

export const ipSets = pgTable(
  "ip_sets",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    entries: jsonb("entries").$type<string[]>().notNull().default([]),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.organizationId, t.name),
    index("ip_sets_by_org_idx").on(t.organizationId),
  ],
);

export const grants = pgTable(
  "grants",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    slug: text("slug").notNull(),
    description: text("description"),
    srcSelectors: jsonb("src_selectors").notNull().default([]),
    dstSelectors: jsonb("dst_selectors").notNull().default([]),
    ipRules: jsonb("ip_rules").notNull().default([]),
    appCapabilities: jsonb("app_capabilities").notNull().default([]),
    priority: integer("priority").notNull().default(0),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.organizationId, t.slug),
    index("grants_by_org_idx").on(t.organizationId),
    index("grants_by_network_idx").on(t.networkId),
  ],
);

export const autoApprovers = pgTable(
  "auto_approvers",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    slug: text("slug").notNull(),
    routes: jsonb("routes")
      .$type<Record<string, string[]>>()
      .notNull()
      .default({}),
    exitNodes: jsonb("exit_nodes").$type<string[]>().notNull().default([]),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.organizationId, t.slug),
    index("auto_approvers_by_org_idx").on(t.organizationId),
  ],
);

export const nodeAttributes = pgTable(
  "node_attributes",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id").references(() => devices.endpointId, {
      onDelete: "cascade",
    }),
    key: text("key").notNull(),
    value: text("value").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    index("node_attributes_by_org_idx").on(t.organizationId),
    index("node_attributes_by_endpoint_idx").on(t.endpointId),
  ],
);

export const policyRevisions = pgTable(
  "policy_revisions",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    networkId: uuid("network_id").references(() => networks.id, {
      onDelete: "cascade",
    }),
    version: bigint("version", { mode: "number" }).notNull(),
    contentHash: text("content_hash").notNull(),
    irSnapshot: jsonb("ir_snapshot"),
    source: text("source").notNull(),
    authorUserId: text("author_user_id"),
    authorApiKeyId: uuid("author_api_key_id"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    index("policy_revisions_by_org_created_idx").on(
      t.organizationId,
      t.createdAt,
    ),
    check(
      "policy_revisions_source_check",
      sql`${t.source} IN ('dashboard', 'api', 'gitops', 'terraform')`,
    ),
  ],
);

/** OAuth2 client credentials clients (Phase 3 - Terraform / automation). */
export const oauthClients = pgTable(
  "oauth_clients",
  {
    id: id(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    clientId: text("client_id").notNull(),
    hashedSecret: text("hashed_secret").notNull(),
    name: text("name").notNull(),
    scopes: text("scopes").array().notNull().default([]),
    networkIds: uuid("network_ids").array(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.clientId),
    index("oauth_clients_by_org_idx").on(t.organizationId),
  ],
);

/** Opaque access tokens issued by client-credentials grant. */
export const oauthAccessTokens = pgTable(
  "oauth_access_tokens",
  {
    id: id(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    scopes: text("scopes").array().notNull().default([]),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (t) => [
    unique().on(t.tokenHash),
    index("oauth_access_tokens_by_client_idx").on(t.clientId),
  ],
);

export const networksRelations = relations(networks, ({ one, many }) => ({
  organization: one(organization, {
    fields: [networks.organizationId],
    references: [organization.id],
  }),
  memberships: many(networkMemberships),
  policies: many(policies),
  sshPolicies: many(sshPolicies),
  sshSessions: many(sshSessions),
  sshRecordings: many(sshRecordings),
  sshAuthChallenges: many(sshAuthChallenges),
  enrollmentTokens: many(enrollmentTokens),
  subnetRoutes: many(subnetRoutes),
  hostnameRoutes: many(hostnameRoutes),
  exitNodeConfigs: many(exitNodeConfig),
  deviceProfiles: many(deviceProfiles),
  nodeGroups: many(nodeGroups),
  tunnels: many(tunnels),
  serves: many(serves),
  fileTransfers: many(fileTransfers),
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
  postureAttributes: many(postureAttributes),
  postureEvaluations: many(postureEvaluations),
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
  secrets: one(tunnelSecrets, {
    fields: [tunnels.id],
    references: [tunnelSecrets.tunnelId],
  }),
  routingRules: many(tunnelRoutingRules),
  requestLogs: many(tunnelRequestLogs),
}));

export const tunnelSecretsRelations = relations(tunnelSecrets, ({ one }) => ({
  tunnel: one(tunnels, {
    fields: [tunnelSecrets.tunnelId],
    references: [tunnels.id],
  }),
}));

export const tunnelRoutingRulesRelations = relations(
  tunnelRoutingRules,
  ({ one }) => ({
    tunnel: one(tunnels, {
      fields: [tunnelRoutingRules.tunnelId],
      references: [tunnels.id],
    }),
    organization: one(organization, {
      fields: [tunnelRoutingRules.organizationId],
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
  organization: one(organization, {
    fields: [policies.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [policies.networkId],
    references: [networks.id],
  }),
}));

export const sshPoliciesRelations = relations(sshPolicies, ({ one }) => ({
  network: one(networks, {
    fields: [sshPolicies.networkId],
    references: [networks.id],
  }),
}));

export const sshSessionsRelations = relations(sshSessions, ({ one, many }) => ({
  organization: one(organization, {
    fields: [sshSessions.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [sshSessions.networkId],
    references: [networks.id],
  }),
  recordings: many(sshRecordings),
}));

export const sshRecordingsRelations = relations(sshRecordings, ({ one }) => ({
  session: one(sshSessions, {
    fields: [sshRecordings.sessionId],
    references: [sshSessions.id],
  }),
  organization: one(organization, {
    fields: [sshRecordings.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [sshRecordings.networkId],
    references: [networks.id],
  }),
}));

export const sshAuthChecksRelations = relations(sshAuthChecks, ({ one }) => ({
  organization: one(organization, {
    fields: [sshAuthChecks.organizationId],
    references: [organization.id],
  }),
}));

export const fileTransfersRelations = relations(fileTransfers, ({ one }) => ({
  organization: one(organization, {
    fields: [fileTransfers.organizationId],
    references: [organization.id],
  }),
  network: one(networks, {
    fields: [fileTransfers.networkId],
    references: [networks.id],
  }),
}));

export const endpointSendSettingsRelations = relations(
  endpointSendSettings,
  ({ one }) => ({
    organization: one(organization, {
      fields: [endpointSendSettings.organizationId],
      references: [organization.id],
    }),
  }),
);

export const sshAuthChallengesRelations = relations(
  sshAuthChallenges,
  ({ one }) => ({
    organization: one(organization, {
      fields: [sshAuthChallenges.organizationId],
      references: [organization.id],
    }),
    network: one(networks, {
      fields: [sshAuthChallenges.networkId],
      references: [networks.id],
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

export const postureAttributesRelations = relations(
  postureAttributes,
  ({ one }) => ({
    device: one(devices, {
      fields: [postureAttributes.endpointId],
      references: [devices.endpointId],
    }),
    organization: one(organization, {
      fields: [postureAttributes.organizationId],
      references: [organization.id],
    }),
  }),
);

export const postureDefinitionsRelations = relations(
  postureDefinitions,
  ({ one, many }) => ({
    organization: one(organization, {
      fields: [postureDefinitions.organizationId],
      references: [organization.id],
    }),
    network: one(networks, {
      fields: [postureDefinitions.networkId],
      references: [networks.id],
    }),
    evaluations: many(postureEvaluations),
  }),
);

export const postureEvaluationsRelations = relations(
  postureEvaluations,
  ({ one }) => ({
    device: one(devices, {
      fields: [postureEvaluations.endpointId],
      references: [devices.endpointId],
    }),
    organization: one(organization, {
      fields: [postureEvaluations.organizationId],
      references: [organization.id],
    }),
    postureDefinition: one(postureDefinitions, {
      fields: [postureEvaluations.postureDefinitionId],
      references: [postureDefinitions.id],
    }),
  }),
);

export const postureIntegrationsRelations = relations(
  postureIntegrations,
  ({ one }) => ({
    organization: one(organization, {
      fields: [postureIntegrations.organizationId],
      references: [organization.id],
    }),
  }),
);

export const postureWebhooksRelations = relations(
  postureWebhooks,
  ({ one }) => ({
    organization: one(organization, {
      fields: [postureWebhooks.organizationId],
      references: [organization.id],
    }),
  }),
);

export const postureOrgSettingsRelations = relations(
  postureOrgSettings,
  ({ one }) => ({
    organization: one(organization, {
      fields: [postureOrgSettings.organizationId],
      references: [organization.id],
    }),
    network: one(networks, {
      fields: [postureOrgSettings.networkId],
      references: [networks.id],
    }),
  }),
);
