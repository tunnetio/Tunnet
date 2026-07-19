import { schema } from "@tunnet/db";
import { and, eq, inArray } from "drizzle-orm";
import { Elysia } from "elysia";
import { db } from "../../lib/db";
import {
  deviceDisplayName,
  deviceKind,
  deviceNodeKind,
} from "../../lib/device-metadata";
import { toIso } from "../../lib/serialize";
import { getAuth, requireAuth } from "./middleware/authz";
import { notFound, sessionPlugin } from "./middleware/session";

async function getNetworkInOrg(networkId: string, organizationId: string) {
  return db.query.networks.findFirst({
    where: and(
      eq(schema.networks.id, networkId),
      eq(schema.networks.organizationId, organizationId),
    ),
  });
}

function isOnline(
  agentConnected: boolean,
  _lastHeartbeatAt: Date | null,
): boolean {
  // Trust control-plane WS session flag; heartbeats keep it alive server-side.
  return agentConnected;
}

export const topologyRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get(
    "/organizations/:orgId/networks/:networkId/topology",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const memberships = await db
        .select({
          endpointId: schema.devices.endpointId,
          type: schema.devices.type,
          name: schema.devices.name,
          metadata: schema.devices.metadata,
          assignedIp: schema.networkMemberships.assignedIp,
          agentConnected: schema.devices.agentConnected,
          lastHeartbeatAt: schema.devices.lastHeartbeatAt,
          status: schema.networkMemberships.status,
        })
        .from(schema.networkMemberships)
        .innerJoin(
          schema.devices,
          eq(schema.networkMemberships.endpointId, schema.devices.endpointId),
        )
        .where(eq(schema.networkMemberships.networkId, params.networkId));

      const subnetRoutes = await db.query.subnetRoutes.findMany({
        where: and(
          eq(schema.subnetRoutes.networkId, params.networkId),
          eq(schema.subnetRoutes.enabled, true),
        ),
      });

      const hostnameRoutes = await db.query.hostnameRoutes.findMany({
        where: and(
          eq(schema.hostnameRoutes.networkId, params.networkId),
          eq(schema.hostnameRoutes.enabled, true),
        ),
      });

      const exitNodes = await db.query.exitNodeConfig.findMany({
        where: and(
          eq(schema.exitNodeConfig.networkId, params.networkId),
          eq(schema.exitNodeConfig.enabled, true),
        ),
      });

      const metrics = await db.query.peerMetrics.findMany({
        where: eq(schema.peerMetrics.networkId, params.networkId),
      });

      const metricMap = new Map<
        string,
        {
          latencyMs: number | null;
          bytesTx: number;
          bytesRx: number;
          direct: boolean | null;
        }
      >();
      for (const m of metrics) {
        metricMap.set(`${m.fromEndpointId}:${m.toEndpointId}`, {
          latencyMs: m.latencyMs,
          bytesTx: m.bytesTx,
          bytesRx: m.bytesRx,
          direct: m.direct,
        });
      }

      const nodes: Array<{
        id: string;
        kind: "machine" | "subnet" | "hostname" | "exit" | "relay";
        label: string;
        secondary?: string | null;
        endpointId?: string | null;
        online?: boolean;
        agentConnected?: boolean;
        lastHeartbeatAt?: string | null;
        assignedIp?: string | null;
        cidr?: string | null;
        viaEndpointId?: string | null;
        serveCount?: number;
        tunnelCount?: number;
        publicHostname?: string | null;
        deviceType?: "agent" | "sdk" | "k8s" | null;
        nodeKind?: string | null;
      }> = [];

      const edges: Array<{
        id: string;
        source: string;
        target: string;
        kind: "peer" | "subnet" | "hostname" | "exit" | "tunnel";
        intensity: number;
        latencyMs?: number | null;
        direct?: boolean;
      }> = [];

      const activeServes = await db.query.serves.findMany({
        where: and(
          eq(schema.serves.networkId, params.networkId),
          eq(schema.serves.status, "active"),
        ),
      });
      const activeTunnels = await db.query.tunnels.findMany({
        where: and(
          eq(schema.tunnels.networkId, params.networkId),
          inArray(schema.tunnels.status, ["active", "connecting"]),
        ),
      });
      const orgRelays = await db.query.relays.findMany({
        where: and(
          eq(schema.relays.organizationId, auth.organizationId),
          inArray(schema.relays.status, ["healthy", "pending", "degraded"]),
        ),
      });

      const serveCountByEndpoint = new Map<string, number>();
      for (const s of activeServes) {
        serveCountByEndpoint.set(
          s.endpointId,
          (serveCountByEndpoint.get(s.endpointId) ?? 0) + 1,
        );
      }
      const tunnelCountByEndpoint = new Map<string, number>();
      for (const t of activeTunnels) {
        tunnelCountByEndpoint.set(
          t.endpointId,
          (tunnelCountByEndpoint.get(t.endpointId) ?? 0) + 1,
        );
      }

      const activeMachines = memberships.filter((m) => m.status === "active");

      for (const m of activeMachines) {
        const label = deviceDisplayName(m.name, m.metadata, m.endpointId);
        nodes.push({
          id: `machine:${m.endpointId}`,
          kind: "machine",
          label,
          secondary: m.assignedIp,
          endpointId: m.endpointId,
          online: isOnline(m.agentConnected, m.lastHeartbeatAt),
          agentConnected: m.agentConnected,
          lastHeartbeatAt: toIso(m.lastHeartbeatAt),
          assignedIp: m.assignedIp,
          serveCount: serveCountByEndpoint.get(m.endpointId) ?? 0,
          tunnelCount: tunnelCountByEndpoint.get(m.endpointId) ?? 0,
          deviceType: deviceKind(m.type, m.metadata),
          nodeKind: deviceNodeKind(m.metadata),
        });
      }

      // Mesh edges among online agents and k8s nodes (P2P / mesh topology).
      const onlineAgents = activeMachines.filter(
        (m) =>
          (m.type === "agent" || m.type === "k8s") &&
          isOnline(m.agentConnected, m.lastHeartbeatAt),
      );
      for (let i = 0; i < onlineAgents.length; i++) {
        for (let j = i + 1; j < onlineAgents.length; j++) {
          const a = onlineAgents[i]!;
          const b = onlineAgents[j]!;
          const ab = metricMap.get(`${a.endpointId}:${b.endpointId}`);
          const ba = metricMap.get(`${b.endpointId}:${a.endpointId}`);
          const bytes =
            (ab?.bytesTx ?? 0) +
            (ab?.bytesRx ?? 0) +
            (ba?.bytesTx ?? 0) +
            (ba?.bytesRx ?? 0);
          const intensity = Math.min(1, 0.25 + Math.log10(bytes + 10) / 8);
          edges.push({
            id: `peer:${a.endpointId}:${b.endpointId}`,
            source: `machine:${a.endpointId}`,
            target: `machine:${b.endpointId}`,
            kind: "peer",
            intensity,
            latencyMs: ab?.latencyMs ?? ba?.latencyMs ?? null,
            direct: ab?.direct ?? ba?.direct ?? true,
          });
        }
      }

      const machineIds = new Set(
        activeMachines.map((m) => `machine:${m.endpointId}`),
      );

      for (const route of subnetRoutes) {
        const via = `machine:${route.endpointId}`;
        if (!machineIds.has(via)) continue;
        const id = `subnet:${route.id}`;
        nodes.push({
          id,
          kind: "subnet",
          label: route.cidr,
          secondary: route.description,
          cidr: route.cidr,
          viaEndpointId: route.endpointId,
        });
        edges.push({
          id: `edge-subnet:${route.id}`,
          source: via,
          target: id,
          kind: "subnet",
          intensity: 0.45,
        });
      }

      for (const route of hostnameRoutes) {
        const via = `machine:${route.endpointId}`;
        if (!machineIds.has(via)) continue;
        const label = route.isWildcard ? `*.${route.hostname}` : route.hostname;
        const id = `hostname:${route.id}`;
        nodes.push({
          id,
          kind: "hostname",
          label,
          secondary: route.targetIp ?? "resolve locally",
          viaEndpointId: route.endpointId,
        });
        edges.push({
          id: `edge-hostname:${route.id}`,
          source: via,
          target: id,
          kind: "hostname",
          intensity: 0.4,
        });
      }

      for (const exit of exitNodes) {
        const via = `machine:${exit.endpointId}`;
        if (!machineIds.has(via)) continue;
        const id = `exit:${exit.endpointId}`;
        nodes.push({
          id,
          kind: "exit",
          label: "Internet",
          secondary: exit.allowedCidrs.join(", "),
          endpointId: exit.endpointId,
          viaEndpointId: exit.endpointId,
        });
        edges.push({
          id: `edge-exit:${exit.endpointId}`,
          source: via,
          target: id,
          kind: "exit",
          intensity: 0.55,
        });
      }

      const tunnelCountByRelay = new Map<string, number>();
      for (const t of activeTunnels) {
        if (!t.relayId) continue;
        tunnelCountByRelay.set(
          t.relayId,
          (tunnelCountByRelay.get(t.relayId) ?? 0) + 1,
        );
      }

      for (const relay of orgRelays) {
        nodes.push({
          id: `relay:${relay.id}`,
          kind: "relay",
          label: relay.name,
          secondary: relay.domain,
          online: relay.status === "healthy",
          tunnelCount: tunnelCountByRelay.get(relay.id) ?? relay.activeTunnels,
        });
      }

      for (const tunnel of activeTunnels) {
        if (!tunnel.relayId) continue;
        const machineId = `machine:${tunnel.endpointId}`;
        const relayId = `relay:${tunnel.relayId}`;
        if (!machineIds.has(machineId)) continue;
        edges.push({
          id: `tunnel:${tunnel.id}`,
          source: relayId,
          target: machineId,
          kind: "tunnel",
          intensity: tunnel.status === "active" ? 0.7 : 0.35,
        });
      }

      return {
        networkId: params.networkId,
        nodes,
        edges,
      };
    },
  )
  .get(
    "/organizations/:orgId/networks/:networkId/metrics",
    async ({ authContext, params }) => {
      const auth = getAuth({ authContext });
      const network = await getNetworkInOrg(
        params.networkId,
        auth.organizationId,
      );
      if (!network) return notFound("Network not found");

      const rows = await db.query.peerMetrics.findMany({
        where: eq(schema.peerMetrics.networkId, params.networkId),
      });

      return {
        networkId: params.networkId,
        peers: rows.map((r) => ({
          fromEndpointId: r.fromEndpointId,
          toEndpointId: r.toEndpointId,
          latencyMs: r.latencyMs,
          bytesTx: r.bytesTx,
          bytesRx: r.bytesRx,
          packetLoss:
            r.packetLoss === null || r.packetLoss === undefined
              ? null
              : r.packetLoss / 10_000,
          direct: r.direct,
          updatedAt: toIso(r.updatedAt)!,
        })),
      };
    },
  );
