import type {
  Serve,
  TopologyEdge,
  TopologyNode,
  Tunnel,
} from "@tunnet/api/management";

import type {
  MeshKindFilter,
  MeshStatusFilter,
  TopologyFlowEdge,
  TopologyFlowNode,
} from "@/components/topology/types";

function matchesKind(node: TopologyNode, kind: MeshKindFilter): boolean {
  if (kind === "all") return true;
  if (kind === "k8s") {
    return node.kind === "machine" && node.deviceType === "k8s";
  }
  if (kind === "serve" || kind === "tunnel") return false;
  if (kind === "machine") {
    return node.kind === "machine" && node.deviceType !== "k8s";
  }
  return node.kind === kind;
}

function matchesStatus(node: TopologyNode, status: MeshStatusFilter): boolean {
  if (status === "all") return true;
  if (node.kind !== "machine") return true;
  if (status === "online") return node.online === true;
  return node.online !== true;
}

function peerType(node: TopologyNode): "peer" | "gateway" | "k8s" {
  if (node.deviceType === "k8s") return "k8s";
  if (node.nodeKind === "gateway" || node.nodeKind === "exit-node") {
    return "gateway";
  }
  return "peer";
}

function resourceType(
  kind: TopologyNode["kind"],
): "relay" | "subnet" | "hostname" | "exit" {
  if (kind === "relay") return "relay";
  if (kind === "subnet") return "subnet";
  if (kind === "hostname") return "hostname";
  return "exit";
}

export function topologyToFlowNodes(
  nodes: TopologyNode[],
  opts: {
    statusFilter: MeshStatusFilter;
    kindFilter: MeshKindFilter;
    serves?: Array<Serve & { networkName?: string }>;
    tunnels?: Array<Tunnel & { networkName?: string }>;
    networkId: string;
    includeEnrollZone?: boolean;
  },
): TopologyFlowNode[] {
  const filtered = nodes.filter(
    (n) =>
      matchesKind(n, opts.kindFilter) && matchesStatus(n, opts.statusFilter),
  );

  const flowNodes: TopologyFlowNode[] = filtered.map((node, index) => {
    const position = { x: (index % 6) * 200, y: Math.floor(index / 6) * 120 };
    if (node.kind === "machine") {
      const type = peerType(node);
      return {
        id: node.id,
        type,
        position,
        connectable: true,
        data: { topology: node, isGateway: type === "gateway" },
      };
    }
    return {
      id: node.id,
      type: resourceType(node.kind),
      position,
      data: { topology: node },
    };
  });

  const machineIds = new Set(
    filtered.filter((n) => n.kind === "machine").map((n) => n.id),
  );
  const endpointToNodeId = new Map(
    filtered
      .filter((n) => n.kind === "machine" && n.endpointId)
      .map((n) => [n.endpointId!, n.id]),
  );

  const showServes =
    opts.kindFilter === "all" ||
    opts.kindFilter === "serve" ||
    opts.kindFilter === "machine" ||
    opts.kindFilter === "k8s";
  const showTunnels =
    opts.kindFilter === "all" ||
    opts.kindFilter === "tunnel" ||
    opts.kindFilter === "machine" ||
    opts.kindFilter === "k8s";

  if (showServes) {
    for (const serve of opts.serves ?? []) {
      if (serve.networkId !== opts.networkId) continue;
      const parentId = endpointToNodeId.get(serve.endpointId);
      if (!parentId || !machineIds.has(parentId)) continue;
      flowNodes.push({
        id: `serve:${serve.id}`,
        type: "serve",
        position: { x: 0, y: 0 },
        data: {
          serveId: serve.id,
          label: `Serve :${serve.localPort}`,
          secondary: serve.hostname || serve.internalHostname,
          endpointId: serve.endpointId,
          networkId: serve.networkId,
        },
      });
    }
  }

  if (showTunnels) {
    for (const tunnel of opts.tunnels ?? []) {
      if (tunnel.networkId !== opts.networkId) continue;
      const parentId = endpointToNodeId.get(tunnel.endpointId);
      if (!parentId || !machineIds.has(parentId)) continue;
      flowNodes.push({
        id: `tunnel:${tunnel.id}`,
        type: "tunnel",
        position: { x: 0, y: 0 },
        data: {
          tunnelId: tunnel.id,
          label: `Tunnel :${tunnel.localPort}`,
          secondary: tunnel.publicHostname || tunnel.subdomain,
          endpointId: tunnel.endpointId,
          networkId: tunnel.networkId,
          publicHostname: tunnel.publicHostname,
        },
      });
    }
  }

  if (opts.includeEnrollZone) {
    flowNodes.push({
      id: `enroll:${opts.networkId}`,
      type: "enroll",
      position: { x: 0, y: 0 },
      data: {
        networkId: opts.networkId,
        label: "Enroll machine",
      },
    });
  }

  return flowNodes;
}

export function topologyToFlowEdges(
  edges: TopologyEdge[],
  visibleNodeIds: Set<string>,
  opts: {
    heatmap?: boolean;
    serves?: Array<Serve & { networkName?: string }>;
    tunnels?: Array<Tunnel & { networkName?: string }>;
    networkId: string;
    endpointToNodeId: Map<string, string>;
    machines?: TopologyNode[];
  },
): TopologyFlowEdge[] {
  const result: TopologyFlowEdge[] = edges
    .filter(
      (edge) =>
        visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
    )
    .map((edge) => {
      const isPeer = edge.kind === "peer";
      const direct = edge.direct !== false;
      let stroke = "var(--color-muted-foreground)";
      if (isPeer) {
        stroke = direct ? "#22c55e" : "#eab308";
      } else if (edge.kind === "tunnel") {
        stroke = "#a855f7";
      } else if (edge.kind === "subnet") {
        stroke = "#34d399";
      } else if (edge.kind === "hostname") {
        stroke = "#0ea5e9";
      } else if (edge.kind === "exit") {
        stroke = "#f59e0b";
      }

      const width = opts.heatmap
        ? 1 + edge.intensity * 4
        : isPeer
          ? 1.75
          : 1.25;

      const latency =
        edge.latencyMs != null ? ` · ${Math.round(edge.latencyMs)}ms` : "";

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: isPeer ? "mesh" : "subnetRoute",
        animated: isPeer && direct,
        style: {
          stroke,
          strokeWidth: width,
          strokeDasharray: isPeer && !direct ? "6 4" : undefined,
        },
        data: {
          kind: edge.kind,
          intensity: edge.intensity,
          latencyMs: edge.latencyMs,
          direct: edge.direct,
          label: isPeer
            ? `${direct ? "direct" : "relay"}${latency}`
            : edge.latencyMs != null
              ? `${Math.round(edge.latencyMs)}ms`
              : undefined,
        },
      } satisfies TopologyFlowEdge;
    });

  const linked = new Set<string>();
  for (const edge of result) {
    if (edge.data?.kind !== "peer") continue;
    linked.add([edge.source, edge.target].sort().join("|"));
  }

  const machines = (opts.machines ?? []).filter(
    (n) => n.kind === "machine" && visibleNodeIds.has(n.id),
  );
  for (let i = 0; i < machines.length; i++) {
    for (let j = i + 1; j < machines.length; j++) {
      const a = machines[i]!;
      const b = machines[j]!;
      const pair = [a.id, b.id].sort().join("|");
      if (linked.has(pair)) continue;
      linked.add(pair);
      const reachable = a.online === true && b.online === true;
      result.push({
        id: `mesh-syn:${a.id}:${b.id}`,
        source: a.id,
        target: b.id,
        type: "mesh",
        animated: false,
        style: {
          stroke: reachable ? "#22c55e" : "#ef4444",
          strokeWidth: 1.5,
          strokeDasharray: reachable ? undefined : "4 4",
        },
        data: {
          kind: "peer",
          intensity: reachable ? 0.4 : 0.2,
          direct: reachable,
          label: reachable ? "direct" : "unreachable",
        },
      });
    }
  }

  for (const serve of opts.serves ?? []) {
    if (serve.networkId !== opts.networkId) continue;
    const parentId = opts.endpointToNodeId.get(serve.endpointId);
    const satId = `serve:${serve.id}`;
    if (
      !parentId ||
      !visibleNodeIds.has(parentId) ||
      !visibleNodeIds.has(satId)
    ) {
      continue;
    }
    result.push({
      id: `sat-${satId}`,
      source: parentId,
      target: satId,
      sourceHandle: "serve",
      type: "subnetRoute",
      style: { stroke: "#a855f7", strokeWidth: 1.5 },
      data: { kind: "subnetRoute", intensity: 0.3, label: "serve" },
    });
  }

  for (const tunnel of opts.tunnels ?? []) {
    if (tunnel.networkId !== opts.networkId) continue;
    const parentId = opts.endpointToNodeId.get(tunnel.endpointId);
    const satId = `tunnel:${tunnel.id}`;
    if (
      !parentId ||
      !visibleNodeIds.has(parentId) ||
      !visibleNodeIds.has(satId)
    ) {
      continue;
    }
    result.push({
      id: `sat-${satId}`,
      source: parentId,
      target: satId,
      sourceHandle: "tunnel",
      type: "subnetRoute",
      style: { stroke: "#a855f7", strokeWidth: 1.5 },
      data: { kind: "subnetRoute", intensity: 0.3, label: "tunnel" },
    });
  }

  return result;
}

export function buildEndpointToNodeId(
  nodes: TopologyNode[],
): Map<string, string> {
  return new Map(
    nodes
      .filter((n) => n.kind === "machine" && n.endpointId)
      .map((n) => [n.endpointId!, n.id]),
  );
}
