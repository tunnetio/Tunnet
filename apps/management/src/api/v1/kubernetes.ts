import { schema } from "@tunnet/db";
import { formatIp, formatIpv4Cidr } from "@tunnet/ip";
import { and, eq, inArray } from "drizzle-orm";
import { Elysia } from "elysia";
import { db } from "../../lib/db";
import { normalizeDeviceLabels } from "../../lib/device-labels";
import {
  deviceDisplayName,
  deviceHostname,
  deviceKind,
  deviceNodeKind,
} from "../../lib/device-metadata";
import { toIso } from "../../lib/serialize";
import { getAuth, requireAuth } from "./middleware/authz";
import { sessionPlugin } from "./middleware/session";

function isOnline(
  agentConnected: boolean,
  _lastHeartbeatAt: Date | null,
): boolean {
  return agentConnected;
}

function safeFormatCidr(value: string): string | null {
  try {
    return formatIpv4Cidr(value);
  } catch {
    return typeof value === "string" && value.length > 0 ? value : null;
  }
}

function safeFormatIp(value: string): string {
  try {
    return formatIp(value);
  } catch {
    return value;
  }
}

export const kubernetesRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get("/organizations/:orgId/kubernetes", async ({ authContext }) => {
    const auth = getAuth({ authContext });

    const rows = await db
      .select({
        endpointId: schema.devices.endpointId,
        name: schema.devices.name,
        metadata: schema.devices.metadata,
        type: schema.devices.type,
        labels: schema.devices.labels,
        agentConnected: schema.devices.agentConnected,
        lastHeartbeatAt: schema.devices.lastHeartbeatAt,
        networkId: schema.networkMemberships.networkId,
        networkName: schema.networks.name,
        assignedIp: schema.networkMemberships.assignedIp,
        status: schema.networkMemberships.status,
        lastSeen: schema.networkMemberships.lastSeen,
      })
      .from(schema.networkMemberships)
      .innerJoin(
        schema.devices,
        eq(schema.networkMemberships.endpointId, schema.devices.endpointId),
      )
      .innerJoin(
        schema.networks,
        eq(schema.networkMemberships.networkId, schema.networks.id),
      )
      .where(
        and(
          eq(schema.devices.organizationId, auth.organizationId),
          eq(schema.networks.organizationId, auth.organizationId),
        ),
      );

    const k8sRows = rows.filter(
      (r) => deviceKind(r.type, r.metadata) === "k8s",
    );
    if (k8sRows.length === 0) {
      return { nodes: [], byNetwork: [] };
    }

    const endpointIds = [...new Set(k8sRows.map((r) => r.endpointId))];

    const [tagRows, subnetRoutes, serves, tunnels] = await Promise.all([
      db.query.deviceTags.findMany({
        where: inArray(schema.deviceTags.endpointId, endpointIds),
      }),
      db.query.subnetRoutes.findMany({
        where: inArray(schema.subnetRoutes.endpointId, endpointIds),
      }),
      db.query.serves.findMany({
        where: and(
          eq(schema.serves.organizationId, auth.organizationId),
          inArray(schema.serves.endpointId, endpointIds),
          eq(schema.serves.status, "active"),
        ),
      }),
      db.query.tunnels.findMany({
        where: and(
          eq(schema.tunnels.organizationId, auth.organizationId),
          inArray(schema.tunnels.endpointId, endpointIds),
          inArray(schema.tunnels.status, ["active", "connecting"]),
        ),
      }),
    ]);

    const tagsByEndpoint = new Map<string, string[]>();
    for (const t of tagRows) {
      const list = tagsByEndpoint.get(t.endpointId) ?? [];
      list.push(t.tag);
      tagsByEndpoint.set(t.endpointId, list);
    }

    const routesByEndpoint = new Map<
      string,
      Array<{
        id: string;
        cidr: string;
        enabled: boolean;
        advertised: boolean;
      }>
    >();
    for (const r of subnetRoutes) {
      const cidr = safeFormatCidr(r.cidr);
      if (!cidr) continue;
      const list = routesByEndpoint.get(r.endpointId) ?? [];
      list.push({
        id: r.id,
        cidr,
        enabled: r.enabled,
        advertised: r.enabled,
      });
      routesByEndpoint.set(r.endpointId, list);
    }

    const serveCountByEndpoint = new Map<string, number>();
    for (const s of serves) {
      serveCountByEndpoint.set(
        s.endpointId,
        (serveCountByEndpoint.get(s.endpointId) ?? 0) + 1,
      );
    }
    const tunnelCountByEndpoint = new Map<string, number>();
    for (const t of tunnels) {
      tunnelCountByEndpoint.set(
        t.endpointId,
        (tunnelCountByEndpoint.get(t.endpointId) ?? 0) + 1,
      );
    }

    const nodes = k8sRows.map((r) => {
      const routes = routesByEndpoint.get(r.endpointId) ?? [];
      const kind =
        deviceNodeKind(r.metadata) ??
        (deviceKind(r.type, r.metadata) === "k8s" ? "k8s" : "k8s");
      return {
        endpointId: r.endpointId,
        name: deviceDisplayName(r.name, r.metadata, r.endpointId),
        hostname: deviceHostname(r.metadata, r.endpointId),
        networkId: r.networkId,
        networkName: r.networkName,
        meshIp: safeFormatIp(r.assignedIp),
        online: isOnline(r.agentConnected, r.lastHeartbeatAt),
        type: "k8s" as const,
        kind,
        labels: normalizeDeviceLabels(r.labels),
        tags: tagsByEndpoint.get(r.endpointId) ?? [],
        status: r.status as "active" | "suspended" | "pending" | "expired",
        lastSeen: toIso(r.lastSeen) ?? new Date(0).toISOString(),
        subnetRouteCount: routes.length,
        serveCount: serveCountByEndpoint.get(r.endpointId) ?? 0,
        tunnelCount: tunnelCountByEndpoint.get(r.endpointId) ?? 0,
        subnetRoutes: routes,
      };
    });

    const byNetworkMap = new Map<
      string,
      {
        networkId: string;
        networkName: string;
        nodeCount: number;
        onlineCount: number;
      }
    >();
    for (const n of nodes) {
      const entry = byNetworkMap.get(n.networkId) ?? {
        networkId: n.networkId,
        networkName: n.networkName,
        nodeCount: 0,
        onlineCount: 0,
      };
      entry.nodeCount += 1;
      if (n.online) entry.onlineCount += 1;
      byNetworkMap.set(n.networkId, entry);
    }

    return {
      nodes,
      byNetwork: [...byNetworkMap.values()].sort((a, b) =>
        a.networkName.localeCompare(b.networkName),
      ),
    };
  });
