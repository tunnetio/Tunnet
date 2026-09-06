import { schema } from "@tunnet/db";
import { formatIp } from "@tunnet/ip";
import { and, desc, eq } from "drizzle-orm";
import { Elysia } from "elysia";
import { db } from "../../lib/db";
import {
  ENTITY_NOTIFY_CHANNEL,
  PRESENCE_NOTIFY_CHANNEL,
} from "../../lib/notify";
import { getPresenceNotifyHub } from "../../lib/presence-notify-hub";
import {
  serializePresenceEvent,
  serializePresencePatch,
} from "../../lib/serialize-device";
import { getAuth, requireAuth } from "./middleware/authz";
import { notFound } from "./middleware/session";

export const presenceRoutes = new Elysia()
  .use(requireAuth)
  .get(
    "/organizations/:orgId/presence/stream",
    ({ authContext, params, request }) => {
      getAuth({ authContext });
      const orgId = params.orgId;
      const encoder = new TextEncoder();
      let heartbeat: ReturnType<typeof setInterval> | null = null;
      let unsubscribe: (() => void) | null = null;
      let closed = false;

      const cleanup = () => {
        if (closed) return;
        closed = true;
        if (heartbeat) {
          clearInterval(heartbeat);
          heartbeat = null;
        }
        unsubscribe?.();
        unsubscribe = null;
      };

      const stream = new ReadableStream({
        start: (controller) => {
          const send = (data: unknown) => {
            if (closed) return;
            try {
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify(data)}\n\n`),
              );
            } catch {
              cleanup();
            }
          };

          send({ type: "ready", organizationId: orgId });

          unsubscribe = getPresenceNotifyHub().subscribe((channel, payload) => {
            if (closed) return;

            if (channel === PRESENCE_NOTIFY_CHANNEL) {
              void (async () => {
                try {
                  const parsed = JSON.parse(payload) as {
                    organizationId?: string;
                    endpointId?: string;
                  };
                  if (parsed.organizationId !== orgId || !parsed.endpointId) {
                    return;
                  }

                  const row = await db.query.devices.findFirst({
                    where: and(
                      eq(schema.devices.endpointId, parsed.endpointId),
                      eq(schema.devices.organizationId, orgId),
                    ),
                    with: {
                      memberships: {
                        limit: 1,
                      },
                    },
                  });
                  if (!row || closed) return;

                  const networkId = row.memberships[0]?.networkId;
                  if (!networkId) return;

                  send({
                    type: "presence",
                    patch: serializePresencePatch({
                      ...row,
                      networkId,
                    }),
                  });
                } catch {
                  // ignore malformed payloads
                }
              })();
              return;
            }

            if (channel === ENTITY_NOTIFY_CHANNEL) {
              try {
                const parsed = JSON.parse(payload) as {
                  organizationId?: string;
                  kind?: string;
                  entityId?: string;
                  networkId?: string | null;
                };
                if (
                  parsed.organizationId !== orgId ||
                  !parsed.kind ||
                  !parsed.entityId
                ) {
                  return;
                }
                send({
                  type: "entity",
                  kind: parsed.kind,
                  entityId: parsed.entityId,
                  networkId: parsed.networkId ?? null,
                });
              } catch {
                // ignore malformed payloads
              }
            }
          });

          heartbeat = setInterval(() => {
            if (closed) {
              if (heartbeat) {
                clearInterval(heartbeat);
                heartbeat = null;
              }
              return;
            }
            try {
              controller.enqueue(encoder.encode(": keepalive\n\n"));
            } catch {
              cleanup();
            }
          }, 25_000);

          request.signal.addEventListener(
            "abort",
            () => {
              cleanup();
              try {
                controller.close();
              } catch {
                // already closed
              }
            },
            { once: true },
          );
        },
        cancel: () => {
          cleanup();
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
        },
      });
    },
  )
  .get(
    "/organizations/:orgId/devices/:endpointId/presence",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const device = await db.query.devices.findFirst({
        where: and(
          eq(schema.devices.endpointId, params.endpointId),
          eq(schema.devices.organizationId, auth.organizationId),
        ),
      });
      if (!device) return notFound("Device not found");

      const events = await db.query.devicePresenceEvents.findMany({
        where: eq(schema.devicePresenceEvents.endpointId, params.endpointId),
        orderBy: desc(schema.devicePresenceEvents.at),
        limit: 100,
      });

      return { events: events.map(serializePresenceEvent) };
    },
  )
  .get(
    "/organizations/:orgId/devices/:endpointId/addresses",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const device = await db.query.devices.findFirst({
        where: and(
          eq(schema.devices.endpointId, params.endpointId),
          eq(schema.devices.organizationId, auth.organizationId),
        ),
        with: {
          memberships: {
            with: { network: true },
          },
        },
      });
      if (!device) return notFound("Device not found");

      return {
        endpointId: device.endpointId,
        publicIp: device.publicIp ? formatIp(device.publicIp) : null,
        ipv6Enabled: device.ipv6Enabled,
        tenantIpv6:
          device.ipv6Enabled && device.tenantIpv6
            ? formatIp(device.tenantIpv6)
            : null,
        addresses: device.memberships.map((m) => ({
          networkId: m.networkId,
          networkName: m.network.name,
          assignedIp: formatIp(m.assignedIp),
        })),
      };
    },
  );
