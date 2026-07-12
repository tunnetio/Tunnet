import {
  upsertDeviceProfileBody,
  upsertExitNodeBody,
} from "@tuntun/api/management";
import { schema } from "@tuntun/db";
import { formatIpv4Cidr } from "@tuntun/ip";
import { and, eq } from "drizzle-orm";
import { Elysia } from "elysia";
import { writeAudit } from "../../lib/audit";
import { db } from "../../lib/db";
import { deviceDisplayName } from "../../lib/device-metadata";
import { bumpNetworkAndNotify } from "../../lib/notify";
import { toIso } from "../../lib/serialize";
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

export const deviceProfilesRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get(
    "/organizations/:orgId/networks/:networkId/exit-nodes",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const rows = await db
        .select({
          config: schema.exitNodeConfig,
          assignedIp: schema.networkMemberships.assignedIp,
          name: schema.devices.name,
          metadata: schema.devices.metadata,
        })
        .from(schema.exitNodeConfig)
        .innerJoin(
          schema.devices,
          eq(schema.exitNodeConfig.endpointId, schema.devices.endpointId),
        )
        .leftJoin(
          schema.networkMemberships,
          and(
            eq(
              schema.networkMemberships.endpointId,
              schema.exitNodeConfig.endpointId,
            ),
            eq(
              schema.networkMemberships.networkId,
              schema.exitNodeConfig.networkId,
            ),
          ),
        )
        .where(eq(schema.exitNodeConfig.networkId, params.networkId));

      return {
        exitNodes: rows.map(({ config, assignedIp, name, metadata }) => {
          return {
            endpointId: config.endpointId,
            networkId: config.networkId,
            enabled: config.enabled,
            allowedCidrs: config.allowedCidrs,
            createdAt: toIso(config.createdAt)!,
            updatedAt: toIso(config.updatedAt)!,
            hostname: deviceDisplayName(name, metadata, config.endpointId),
            viaIp: assignedIp ?? undefined,
          };
        }),
      };
    },
  )
  .get(
    "/organizations/:orgId/networks/:networkId/devices/:endpointId/profile",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const row = await db.query.deviceProfiles.findFirst({
        where: and(
          eq(schema.deviceProfiles.endpointId, params.endpointId),
          eq(schema.deviceProfiles.networkId, params.networkId),
        ),
      });
      if (!row) {
        return {
          endpointId: params.endpointId,
          networkId: params.networkId,
          exitNodeEndpointId: null,
          splitTunnelMode: "exclude" as const,
          splitTunnelCidrs: [] as string[],
          updatedAt: new Date(0).toISOString(),
        };
      }
      return {
        endpointId: row.endpointId,
        networkId: row.networkId,
        exitNodeEndpointId: row.exitNodeEndpointId,
        splitTunnelMode: row.splitTunnelMode as "include" | "exclude",
        splitTunnelCidrs: row.splitTunnelCidrs,
        updatedAt: toIso(row.updatedAt)!,
      };
    },
  )
  .group("", (app) =>
    app
      .use(requireAdmin)
      .put(
        "/organizations/:orgId/networks/:networkId/devices/:endpointId/exit-node",
        async ({ authContext, params, body, set }) => {
          const auth = getAuth({ authContext });
          const parsed = upsertExitNodeBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const membership = await db.query.networkMemberships.findFirst({
            where: and(
              eq(schema.networkMemberships.endpointId, params.endpointId),
              eq(schema.networkMemberships.networkId, params.networkId),
            ),
          });
          if (!membership) {
            set.status = 400;
            return { error: "Device is not a member of this network" };
          }

          const allowedCidrs = parsed.allowedCidrs.map(formatIpv4Cidr);
          const now = new Date();

          const row = await db.transaction(async (tx) => {
            const [upserted] = await tx
              .insert(schema.exitNodeConfig)
              .values({
                endpointId: params.endpointId,
                networkId: params.networkId,
                enabled: parsed.enabled,
                allowedCidrs,
                updatedAt: now,
              })
              .onConflictDoUpdate({
                target: schema.exitNodeConfig.endpointId,
                set: {
                  enabled: parsed.enabled,
                  allowedCidrs,
                  networkId: params.networkId,
                  updatedAt: now,
                },
              })
              .returning();

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "exit_node.upserted",
              target: params.endpointId,
              metadata: parsed,
            });
            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );
            return upserted;
          });

          return {
            endpointId: row!.endpointId,
            networkId: row!.networkId,
            enabled: row!.enabled,
            allowedCidrs: row!.allowedCidrs,
            createdAt: toIso(row!.createdAt)!,
            updatedAt: toIso(row!.updatedAt)!,
            viaIp: membership.assignedIp,
          };
        },
      )
      .delete(
        "/organizations/:orgId/networks/:networkId/devices/:endpointId/exit-node",
        async ({ authContext, params }) => {
          const auth = getAuth({ authContext });
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const deleted = await db.transaction(async (tx) => {
            const [row] = await tx
              .delete(schema.exitNodeConfig)
              .where(
                and(
                  eq(schema.exitNodeConfig.endpointId, params.endpointId),
                  eq(schema.exitNodeConfig.networkId, params.networkId),
                ),
              )
              .returning();
            if (!row) return null;
            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "exit_node.deleted",
              target: params.endpointId,
              metadata: {},
            });
            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );
            return row;
          });

          if (!deleted) return notFound("Exit node not found");
          return { ok: true as const };
        },
      )
      .put(
        "/organizations/:orgId/networks/:networkId/devices/:endpointId/profile",
        async ({ authContext, params, body, set }) => {
          const auth = getAuth({ authContext });
          const parsed = upsertDeviceProfileBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const membership = await db.query.networkMemberships.findFirst({
            where: and(
              eq(schema.networkMemberships.endpointId, params.endpointId),
              eq(schema.networkMemberships.networkId, params.networkId),
            ),
          });
          if (!membership) {
            set.status = 400;
            return { error: "Device is not a member of this network" };
          }

          if (parsed.exitNodeEndpointId) {
            const exit = await db.query.exitNodeConfig.findFirst({
              where: and(
                eq(schema.exitNodeConfig.endpointId, parsed.exitNodeEndpointId),
                eq(schema.exitNodeConfig.networkId, params.networkId),
                eq(schema.exitNodeConfig.enabled, true),
              ),
            });
            if (!exit) {
              set.status = 400;
              return { error: "Selected exit node is not available" };
            }
          }

          const now = new Date();
          const splitTunnelCidrs = parsed.splitTunnelCidrs?.map(formatIpv4Cidr);

          const row = await db.transaction(async (tx) => {
            const existing = await tx.query.deviceProfiles.findFirst({
              where: eq(schema.deviceProfiles.endpointId, params.endpointId),
            });

            const values = {
              endpointId: params.endpointId,
              networkId: params.networkId,
              exitNodeEndpointId:
                parsed.exitNodeEndpointId !== undefined
                  ? parsed.exitNodeEndpointId
                  : (existing?.exitNodeEndpointId ?? null),
              splitTunnelMode:
                parsed.splitTunnelMode ??
                existing?.splitTunnelMode ??
                "exclude",
              splitTunnelCidrs:
                splitTunnelCidrs ?? existing?.splitTunnelCidrs ?? [],
              updatedAt: now,
            };

            const [upserted] = await tx
              .insert(schema.deviceProfiles)
              .values(values)
              .onConflictDoUpdate({
                target: schema.deviceProfiles.endpointId,
                set: {
                  networkId: values.networkId,
                  exitNodeEndpointId: values.exitNodeEndpointId,
                  splitTunnelMode: values.splitTunnelMode,
                  splitTunnelCidrs: values.splitTunnelCidrs,
                  updatedAt: now,
                },
              })
              .returning();

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "device_profile.upserted",
              target: params.endpointId,
              metadata: parsed,
            });
            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );
            return upserted;
          });

          return {
            endpointId: row!.endpointId,
            networkId: row!.networkId,
            exitNodeEndpointId: row!.exitNodeEndpointId,
            splitTunnelMode: row!.splitTunnelMode as "include" | "exclude",
            splitTunnelCidrs: row!.splitTunnelCidrs,
            updatedAt: toIso(row!.updatedAt)!,
          };
        },
      ),
  );
