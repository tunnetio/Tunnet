import {
  deleteDevicesBody,
  patchDeviceBody,
  patchDeviceMembershipBody,
} from "@tuntun/api/management";
import { schema } from "@tuntun/db";
import { and, eq } from "drizzle-orm";
import { Elysia } from "elysia";
import { writeAudit } from "../../lib/audit";
import { db } from "../../lib/db";
import { applyDevicePatch, getDeviceInOrg } from "../../lib/device";
import { bumpNetworkAndNotify, bumpOrgAndNotify } from "../../lib/notify";
import { removeDeviceMembership } from "../../lib/remove-device-membership";
import { serializeDevice } from "../../lib/serialize-device";
import { getAuth, requireAdmin, requireAuth } from "./middleware/authz";
import { notFound, sessionPlugin } from "./middleware/session";

async function getNetworkInOrg(networkId: string, organizationId: string) {
  return db.query.networks.findFirst({
    where: and(
      eq(schema.networks.id, networkId),
      eq(schema.networks.organizationId, organizationId),
    ),
  });
}

async function listDevicesOnNetwork(networkId: string) {
  const rows = await db
    .select({
      endpointId: schema.devices.endpointId,
      organizationId: schema.devices.organizationId,
      networkId: schema.networkMemberships.networkId,
      name: schema.devices.name,
      metadata: schema.devices.metadata,
      type: schema.devices.type,
      assignedIp: schema.networkMemberships.assignedIp,
      publicIp: schema.devices.publicIp,
      tenantIpv6: schema.devices.tenantIpv6,
      ipv6Enabled: schema.devices.ipv6Enabled,
      agentConnected: schema.devices.agentConnected,
      connectedAt: schema.devices.connectedAt,
      disconnectedAt: schema.devices.disconnectedAt,
      lastHeartbeatAt: schema.devices.lastHeartbeatAt,
      firstSeen: schema.networkMemberships.firstSeen,
      lastSeen: schema.networkMemberships.lastSeen,
      status: schema.networkMemberships.status,
    })
    .from(schema.networkMemberships)
    .innerJoin(
      schema.devices,
      eq(schema.networkMemberships.endpointId, schema.devices.endpointId),
    )
    .where(eq(schema.networkMemberships.networkId, networkId));

  return rows.map(serializeDevice);
}

export const devicesRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get(
    "/organizations/:orgId/networks/:networkId/devices",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      return { devices: await listDevicesOnNetwork(params.networkId) };
    },
  )
  .get(
    "/organizations/:orgId/devices/:endpointId",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const device = await getDeviceInOrg(
        params.endpointId,
        auth.organizationId,
      );
      if (!device) return notFound("Device not found");
      return device;
    },
  )
  .group("", (app) =>
    app
      .use(requireAdmin)
      .patch(
        "/organizations/:orgId/devices/:endpointId",
        async ({ authContext, params, body }) => {
          const auth = getAuth({ authContext });
          const parsed = patchDeviceBody.parse(body);

          const updated = await db.transaction(async (tx) => {
            const row = await applyDevicePatch(
              tx,
              params.endpointId,
              auth.organizationId,
              parsed,
            );
            if (!row) return null;

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "device.updated",
              target: row.endpointId,
              metadata: parsed,
            });

            if (parsed.ipv6Enabled !== undefined) {
              await bumpOrgAndNotify(tx, auth.organizationId);
            }

            return row;
          });

          if (!updated) return notFound("Device not found");
          return updated;
        },
      )
      .patch(
        "/organizations/:orgId/networks/:networkId/devices/:endpointId",
        async ({ authContext, params, body }) => {
          const auth = getAuth({ authContext });
          const parsed = patchDeviceMembershipBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const row = await db.transaction(async (tx) => {
            const [updated] = await tx
              .update(schema.networkMemberships)
              .set({ status: parsed.status })
              .where(
                and(
                  eq(schema.networkMemberships.endpointId, params.endpointId),
                  eq(schema.networkMemberships.networkId, params.networkId),
                ),
              )
              .returning();

            if (!updated) {
              throw new Error("Device not found");
            }

            const device = await tx.query.devices.findFirst({
              where: eq(schema.devices.endpointId, params.endpointId),
            });
            if (!device || device.organizationId !== auth.organizationId) {
              throw new Error("Device not found");
            }

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "device.updated",
              target: updated.endpointId,
              metadata: { status: parsed.status, networkId: params.networkId },
            });

            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );

            return { device, membership: updated };
          });

          return serializeDevice({
            endpointId: row.device.endpointId,
            organizationId: row.device.organizationId,
            networkId: row.membership.networkId,
            name: row.device.name,
            metadata: row.device.metadata,
            type: row.device.type,
            assignedIp: row.membership.assignedIp,
            publicIp: row.device.publicIp,
            tenantIpv6: row.device.tenantIpv6,
            ipv6Enabled: row.device.ipv6Enabled,
            agentConnected: row.device.agentConnected,
            connectedAt: row.device.connectedAt,
            disconnectedAt: row.device.disconnectedAt,
            lastHeartbeatAt: row.device.lastHeartbeatAt,
            firstSeen: row.membership.firstSeen,
            lastSeen: row.membership.lastSeen,
            status: row.membership.status,
          });
        },
      ),
  )
  .group("", (app) =>
    app
      .use(requireAdmin)
      .delete(
        "/organizations/:orgId/devices",
        async ({ authContext, body }) => {
          const auth = getAuth({ authContext });
          const parsed = deleteDevicesBody.parse(body);

          const seen = new Set<string>();
          const items = parsed.items.filter((item) => {
            const key = `${item.networkId}:${item.endpointId}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          });

          await db.transaction(async (tx) => {
            for (const item of items) {
              await removeDeviceMembership(tx, {
                organizationId: auth.organizationId,
                actor: auth.user.id,
                networkId: item.networkId,
                endpointId: item.endpointId,
              });
            }
          });

          return { ok: true as const, deleted: items.length };
        },
      )
      .delete(
        "/organizations/:orgId/networks/:networkId/devices/:endpointId",
        async ({ authContext, params }) => {
          const auth = getAuth({ authContext });
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          await db.transaction(async (tx) => {
            await removeDeviceMembership(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              networkId: params.networkId,
              endpointId: params.endpointId,
            });
          });

          return { ok: true };
        },
      ),
  );
