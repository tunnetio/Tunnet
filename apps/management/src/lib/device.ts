import { type Database, schema } from "@tuntun/db";
import { formatIp } from "@tuntun/ip";
import { and, eq } from "drizzle-orm";
import { db } from "./db";
import { deviceDisplayName, normalizeDeviceMetadata } from "./device-metadata";
import { toIso } from "./serialize";

type DbConn = Database | Parameters<Parameters<Database["transaction"]>[0]>[0];

type DeviceRow = typeof schema.devices.$inferSelect;
type MembershipRow = typeof schema.networkMemberships.$inferSelect;

function formatNullableIp(value: string | null): string | null {
  if (value === null) return null;
  return formatIp(value);
}

export function serializeDeviceDetail(
  device: DeviceRow,
  memberships: Array<MembershipRow & { networkName: string }>,
) {
  return {
    endpointId: device.endpointId,
    organizationId: device.organizationId,
    name: deviceDisplayName(device.name, device.metadata, device.endpointId),
    metadata: normalizeDeviceMetadata(device.metadata, device.endpointId),
    publicIp: formatNullableIp(device.publicIp),
    ipv6Enabled: device.ipv6Enabled,
    ipv6EnabledAt: toIso(device.ipv6EnabledAt),
    tenantIpv6: formatIp(device.tenantIpv6),
    agentConnected: device.agentConnected,
    connectedAt: toIso(device.connectedAt),
    disconnectedAt: toIso(device.disconnectedAt),
    lastHeartbeatAt: toIso(device.lastHeartbeatAt),
    firstSeen: toIso(device.firstSeen)!,
    lastSeen: toIso(device.lastSeen)!,
    memberships: memberships.map((m) => ({
      networkId: m.networkId,
      networkName: m.networkName,
      assignedIp: formatIp(m.assignedIp),
      status: m.status as "active" | "suspended" | "pending",
      firstSeen: toIso(m.firstSeen)!,
      lastSeen: toIso(m.lastSeen)!,
    })),
  };
}

export async function getDeviceInOrg(
  endpointId: string,
  organizationId: string,
  conn: DbConn = db,
) {
  const device = await conn.query.devices.findFirst({
    where: and(
      eq(schema.devices.endpointId, endpointId),
      eq(schema.devices.organizationId, organizationId),
    ),
    with: {
      memberships: {
        with: { network: true },
      },
    },
  });

  if (!device) return null;

  return serializeDeviceDetail(
    device,
    device.memberships.map((m) => ({
      ...m,
      networkName: m.network.name,
    })),
  );
}

export async function applyDevicePatch(
  conn: DbConn,
  endpointId: string,
  organizationId: string,
  patch: { name?: string; ipv6Enabled?: boolean },
) {
  const device = await conn.query.devices.findFirst({
    where: and(
      eq(schema.devices.endpointId, endpointId),
      eq(schema.devices.organizationId, organizationId),
    ),
  });
  if (!device) return null;

  const updates: Partial<typeof schema.devices.$inferInsert> = {};

  if (patch.name !== undefined) {
    updates.name = patch.name;
  }

  if (patch.ipv6Enabled !== undefined) {
    updates.ipv6Enabled = patch.ipv6Enabled;
    updates.ipv6EnabledAt = patch.ipv6Enabled ? new Date() : null;
  }

  if (Object.keys(updates).length === 0) {
    return getDeviceInOrg(endpointId, organizationId, conn);
  }

  const [updated] = await conn
    .update(schema.devices)
    .set(updates)
    .where(eq(schema.devices.endpointId, endpointId))
    .returning();

  if (!updated) return null;

  return getDeviceInOrg(endpointId, organizationId, conn);
}
