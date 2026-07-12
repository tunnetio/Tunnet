import { createServeBody, patchServeBody } from "@tuntun/api/management";
import { schema } from "@tuntun/db";
import { and, desc, eq } from "drizzle-orm";
import { Elysia } from "elysia";

import { writeAudit } from "../../lib/audit";
import { pushStartServe, pushStopServe } from "../../lib/control-plane-client";
import { db } from "../../lib/db";
import { deviceDisplayName } from "../../lib/device-metadata";
import { issueLeafCertificate } from "../../lib/internal-ca";
import { bumpNetworkAndNotify, notifyEntityChanged } from "../../lib/notify";
import { toIso } from "../../lib/serialize";
import { getAuth, requireAdmin, requireAuth } from "./middleware/authz";
import { notFound, sessionPlugin } from "./middleware/session";

function serializeServe(
  row: typeof schema.serves.$inferSelect,
  extras?: { hostname?: string },
) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    networkId: row.networkId,
    endpointId: row.endpointId,
    localPort: row.localPort,
    protocol: row.protocol as "https" | "tcp",
    internalHostname: row.internalHostname,
    status: row.status as "starting" | "active" | "error" | "stopped",
    accessMode: row.accessMode as "all_peers" | "tags" | "machines",
    allowedTags: row.allowedTags ?? [],
    allowedEndpointIds: row.allowedEndpointIds ?? [],
    errorMessage: row.errorMessage,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!,
    hostname: extras?.hostname,
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

function deviceLabel(
  name: string | null | undefined,
  metadata: unknown,
  endpointId: string,
): string {
  return deviceDisplayName(name, metadata, endpointId);
}

export const servesRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get(
    "/organizations/:orgId/networks/:networkId/serves",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const rows = await db
        .select({
          serve: schema.serves,
          name: schema.devices.name,
          metadata: schema.devices.metadata,
        })
        .from(schema.serves)
        .innerJoin(
          schema.devices,
          eq(schema.serves.endpointId, schema.devices.endpointId),
        )
        .where(eq(schema.serves.networkId, params.networkId))
        .orderBy(desc(schema.serves.createdAt));

      return {
        serves: rows.map((r) =>
          serializeServe(r.serve, {
            hostname: deviceLabel(r.name, r.metadata, r.serve.endpointId),
          }),
        ),
      };
    },
  )
  .get(
    "/organizations/:orgId/networks/:networkId/serves/:serveId",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const row = await db.query.serves.findFirst({
        where: and(
          eq(schema.serves.id, params.serveId),
          eq(schema.serves.networkId, params.networkId),
        ),
      });
      if (!row) return notFound("Serve not found");
      return { serve: serializeServe(row) };
    },
  )
  .get(
    "/organizations/:orgId/networks/:networkId/serves/:serveId/peers",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const serve = await db.query.serves.findFirst({
        where: and(
          eq(schema.serves.id, params.serveId),
          eq(schema.serves.networkId, params.networkId),
        ),
      });
      if (!serve) return notFound("Serve not found");

      const peers = await db
        .select()
        .from(schema.serveSessions)
        .where(eq(schema.serveSessions.serveId, params.serveId))
        .orderBy(desc(schema.serveSessions.connectedAt));

      return {
        peers: peers.map((p) => ({
          id: p.id,
          serveId: p.serveId,
          peerEndpointId: p.peerEndpointId,
          peerHostname: p.peerHostname,
          connectedAt: toIso(p.connectedAt)!,
          bytesIn: Number(p.bytesIn),
          bytesOut: Number(p.bytesOut),
          lastSeenAt: toIso(p.lastSeenAt)!,
        })),
      };
    },
  )
  .group("", (app) =>
    app
      .use(requireAdmin)
      .post(
        "/organizations/:orgId/networks/:networkId/serves",
        async ({ authContext, params, body }) => {
          const auth = getAuth({ authContext });
          const parsed = createServeBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const membership = await db.query.networkMemberships.findFirst({
            where: and(
              eq(schema.networkMemberships.endpointId, parsed.endpointId),
              eq(schema.networkMemberships.networkId, params.networkId),
              eq(schema.networkMemberships.status, "active"),
            ),
          });
          if (!membership) return notFound("Machine not in this network");

          const device = await db.query.devices.findFirst({
            where: eq(schema.devices.endpointId, parsed.endpointId),
          });
          if (!device) return notFound("Machine not found");

          const host = deviceLabel(
            device.name,
            device.metadata,
            device.endpointId,
          )
            .toLowerCase()
            .replace(/[^a-z0-9-]/g, "-")
            .replace(/^-+|-+$/g, "")
            .slice(0, 40);
          const internalHostname = `${host || "node"}.${network.name}.tuntun`;

          let certificateId: string | null = null;
          let leafPrivateKeyPem: string | undefined;
          let leafCertificatePem: string | undefined;

          if (parsed.protocol === "https") {
            const leaf = await issueLeafCertificate({
              organizationId: auth.organizationId,
              endpointId: parsed.endpointId,
              hostname: internalHostname,
            });
            certificateId = leaf.id;
            leafPrivateKeyPem = leaf.privateKeyPem;
            leafCertificatePem = leaf.certificatePem;
          }

          const serve = await db.transaction(async (tx) => {
            const [created] = await tx
              .insert(schema.serves)
              .values({
                organizationId: auth.organizationId,
                networkId: params.networkId,
                endpointId: parsed.endpointId,
                localPort: parsed.localPort,
                protocol: parsed.protocol,
                internalHostname,
                status: "starting",
                accessMode: parsed.accessMode,
                allowedTags: parsed.allowedTags,
                allowedEndpointIds: parsed.allowedEndpointIds,
                certificateId,
              })
              .returning();

            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );

            await notifyEntityChanged(tx, {
              organizationId: auth.organizationId,
              kind: "serve",
              entityId: created!.id,
              networkId: params.networkId,
            });

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "serve.create",
              target: created!.id,
              metadata: {
                internalHostname,
                endpointId: parsed.endpointId,
                localPort: parsed.localPort,
              },
            });

            return created!;
          });

          try {
            await pushStartServe({
              endpointId: parsed.endpointId,
              serveId: serve.id,
              port: parsed.localPort,
              protocol: parsed.protocol,
              internalHostname,
              certificatePem: leafCertificatePem,
              privateKeyPem: leafPrivateKeyPem,
              accessMode: serve.accessMode,
              allowedTags: serve.allowedTags ?? [],
              allowedEndpointIds: serve.allowedEndpointIds ?? [],
            });
          } catch (e) {
            const message =
              e instanceof Error ? e.message : "pushStartServe failed";
            console.error("pushStartServe failed", e);
            const [errored] = await db
              .update(schema.serves)
              .set({
                status: "error",
                errorMessage: message,
                updatedAt: new Date(),
              })
              .where(eq(schema.serves.id, serve.id))
              .returning();
            return {
              serve: serializeServe(errored ?? serve, {
                hostname: deviceLabel(
                  device.name,
                  device.metadata,
                  device.endpointId,
                ),
              }),
            };
          }

          return {
            serve: serializeServe(serve, {
              hostname: deviceLabel(
                device.name,
                device.metadata,
                device.endpointId,
              ),
            }),
            /** Delivered once so the agent can start TLS — never logged. */
            ...(leafCertificatePem && leafPrivateKeyPem
              ? {
                  certificatePem: leafCertificatePem,
                  privateKeyPem: leafPrivateKeyPem,
                }
              : {}),
          };
        },
      )
      .patch(
        "/organizations/:orgId/networks/:networkId/serves/:serveId",
        async ({ authContext, params, body }) => {
          const auth = getAuth({ authContext });
          const parsed = patchServeBody.parse(body);
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const existing = await db.query.serves.findFirst({
            where: and(
              eq(schema.serves.id, params.serveId),
              eq(schema.serves.networkId, params.networkId),
            ),
          });
          if (!existing) return notFound("Serve not found");

          const [updated] = await db
            .update(schema.serves)
            .set({
              ...parsed,
              updatedAt: new Date(),
            })
            .where(eq(schema.serves.id, params.serveId))
            .returning();

          await bumpNetworkAndNotify(db, params.networkId, auth.organizationId);

          await notifyEntityChanged(db, {
            organizationId: auth.organizationId,
            kind: "serve",
            entityId: updated!.id,
            networkId: params.networkId,
          });

          return { serve: serializeServe(updated!) };
        },
      )
      .delete(
        "/organizations/:orgId/networks/:networkId/serves/:serveId",
        async ({ authContext, params }) => {
          const auth = getAuth({ authContext });
          const network = await getNetworkInOrg(
            params.networkId,
            auth.organizationId,
          );
          if (!network) return notFound("Network not found");

          const existing = await db.query.serves.findFirst({
            where: and(
              eq(schema.serves.id, params.serveId),
              eq(schema.serves.networkId, params.networkId),
            ),
          });
          if (!existing) return notFound("Serve not found");

          await db.transaction(async (tx) => {
            await tx
              .update(schema.serves)
              .set({ status: "stopped", updatedAt: new Date() })
              .where(eq(schema.serves.id, params.serveId));

            await bumpNetworkAndNotify(
              tx,
              params.networkId,
              auth.organizationId,
            );

            await notifyEntityChanged(tx, {
              organizationId: auth.organizationId,
              kind: "serve",
              entityId: params.serveId,
              networkId: params.networkId,
            });

            await writeAudit(tx, {
              organizationId: auth.organizationId,
              actor: auth.user.id,
              action: "serve.stop",
              target: params.serveId,
              metadata: { internalHostname: existing.internalHostname },
            });
          });

          try {
            await pushStopServe({
              endpointId: existing.endpointId,
              serveId: params.serveId,
            });
          } catch (e) {
            console.error("pushStopServe failed", e);
          }

          return { ok: true };
        },
      ),
  );
