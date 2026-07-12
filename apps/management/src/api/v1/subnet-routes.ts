import {
  createSubnetRouteBody,
  patchSubnetRouteBody,
} from "@tuntun/api/management";
import { schema } from "@tuntun/db";
import { formatIpv4Cidr, ipv4CidrsOverlap, overlapsMeshCidr } from "@tuntun/ip";
import { and, eq } from "drizzle-orm";
import { Elysia } from "elysia";
import { writeAudit } from "../../lib/audit";
import { db } from "../../lib/db";
import { deviceDisplayName } from "../../lib/device-metadata";
import { bumpNetworkAndNotify } from "../../lib/notify";
import { toIso } from "../../lib/serialize";
import { getAuth, requireAdmin, requireAuth } from "./middleware/authz";
import { notFound, sessionPlugin } from "./middleware/session";

function serializeRoute(
  row: typeof schema.subnetRoutes.$inferSelect,
  extras?: { hostname?: string; viaIp?: string },
) {
  return {
    id: row.id,
    endpointId: row.endpointId,
    networkId: row.networkId,
    cidr: row.cidr,
    description: row.description,
    enabled: row.enabled,
    createdAt: toIso(row.createdAt)!,
    hostname: extras?.hostname,
    viaIp: extras?.viaIp,
  };
}

async function getNetworkInOrg(networkId: string, organizationId: string) {
  return db.query.networks.findFirst({
    where: and(
      eq(schema.networks.id, networkId),
      eq(schema.networks.organizationId, organizationId),
    ),
  });
}

export const subnetRoutesRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get(
    "/organizations/:orgId/networks/:networkId/routes",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const rows = await db
        .select({
          route: schema.subnetRoutes,
          assignedIp: schema.networkMemberships.assignedIp,
          name: schema.devices.name,
          metadata: schema.devices.metadata,
        })
        .from(schema.subnetRoutes)
        .innerJoin(
          schema.devices,
          eq(schema.subnetRoutes.endpointId, schema.devices.endpointId),
        )
        .leftJoin(
          schema.networkMemberships,
          and(
            eq(
              schema.networkMemberships.endpointId,
              schema.subnetRoutes.endpointId,
            ),
            eq(
              schema.networkMemberships.networkId,
              schema.subnetRoutes.networkId,
            ),
          ),
        )
        .where(eq(schema.subnetRoutes.networkId, params.networkId));

      return {
        routes: rows.map(({ route, assignedIp, name, metadata }) => {
          return serializeRoute(route, {
            hostname: deviceDisplayName(name, metadata, route.endpointId),
            viaIp: assignedIp ?? undefined,
          });
        }),
      };
    },
  )
  .group("", (app) =>
    app
      .use(requireAdmin)
      .post(
        "/organizations/:orgId/networks/:networkId/routes",
        async ({ authContext, params, body, set }) => {
          const auth = getAuth({ authContext });
          const parsed = createSubnetRouteBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const cidr = formatIpv4Cidr(parsed.cidr);
          if (overlapsMeshCidr(cidr, network.cidr)) {
            set.status = 400;
            return {
              error: `CIDR ${cidr} overlaps the mesh range ${network.cidr}`,
            };
          }

          const membership = await db.query.networkMemberships.findFirst({
            where: and(
              eq(schema.networkMemberships.endpointId, parsed.endpointId),
              eq(schema.networkMemberships.networkId, params.networkId),
            ),
          });
          if (!membership) {
            set.status = 400;
            return { error: "Device is not a member of this network" };
          }

          const existing = await db.query.subnetRoutes.findMany({
            where: eq(schema.subnetRoutes.networkId, params.networkId),
          });
          for (const route of existing) {
            if (ipv4CidrsOverlap(cidr, route.cidr)) {
              set.status = 409;
              return {
                error: `CIDR ${cidr} overlaps existing route ${route.cidr}`,
              };
            }
          }

          try {
            const row = await db.transaction(async (tx) => {
              const [created] = await tx
                .insert(schema.subnetRoutes)
                .values({
                  endpointId: parsed.endpointId,
                  networkId: params.networkId,
                  cidr,
                  description: parsed.description ?? null,
                  enabled: parsed.enabled,
                })
                .returning();

              if (!created) throw new Error("Failed to create subnet route");

              await writeAudit(tx, {
                organizationId: auth.organizationId,
                actor: auth.user.id,
                action: "subnet_route.created",
                target: created.id,
                metadata: {
                  networkId: params.networkId,
                  endpointId: parsed.endpointId,
                  cidr,
                },
              });

              await bumpNetworkAndNotify(
                tx,
                params.networkId,
                auth.organizationId,
              );

              return created;
            });

            return serializeRoute(row, {
              viaIp: membership.assignedIp,
            });
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            if (message.includes("subnet_routes_network_cidr_unique")) {
              set.status = 409;
              return { error: `CIDR ${cidr} already exists in this network` };
            }
            throw err;
          }
        },
      )
      .patch(
        "/organizations/:orgId/networks/:networkId/routes/:routeId",
        async ({ authContext, params, body }) => {
          const auth = getAuth({ authContext });
          const parsed = patchSubnetRouteBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const updated = await db.transaction(async (tx) => {
            const [row] = await tx
              .update(schema.subnetRoutes)
              .set({
                ...(parsed.description !== undefined
                  ? { description: parsed.description }
                  : {}),
                ...(parsed.enabled !== undefined
                  ? { enabled: parsed.enabled }
                  : {}),
              })
              .where(
                and(
                  eq(schema.subnetRoutes.id, params.routeId),
                  eq(schema.subnetRoutes.networkId, params.networkId),
                ),
              )
              .returning();

            if (!row) return null;

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "subnet_route.updated",
              target: row.id,
              metadata: parsed,
            });

            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );

            return row;
          });

          if (!updated) return notFound("Subnet route not found");
          return serializeRoute(updated);
        },
      )
      .delete(
        "/organizations/:orgId/networks/:networkId/routes/:routeId",
        async ({ authContext, params }) => {
          const auth = getAuth({ authContext });
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const deleted = await db.transaction(async (tx) => {
            const [row] = await tx
              .delete(schema.subnetRoutes)
              .where(
                and(
                  eq(schema.subnetRoutes.id, params.routeId),
                  eq(schema.subnetRoutes.networkId, params.networkId),
                ),
              )
              .returning();

            if (!row) return null;

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "subnet_route.deleted",
              target: row.id,
              metadata: {
                networkId: params.networkId,
                endpointId: row.endpointId,
                cidr: row.cidr,
              },
            });

            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );

            return row;
          });

          if (!deleted) return notFound("Subnet route not found");
          return { ok: true as const };
        },
      ),
  );
