import type {
  Device,
  Network,
  Serve,
  TopologyResponse,
  Tunnel,
} from "@tunnet/api/management";

import type {
  TopologyFlowEdge,
  TopologyFlowNode,
} from "@/components/topology/types";
import { getMachinePresence } from "@/lib/machine-utils";

type SubnetRouteLike = {
  id: string;
  networkId: string;
  cidr: string;
  endpointId: string;
  enabled?: boolean;
};

const PEER_W = 188;
const PEER_H = 80;
const SAT_W = 118;
const SAT_H = 46;
const PAD_X = 36;
const PAD_Y = 64;
const GAP_X = 72;
const GAP_Y = 72;
const COLS = 2;
const GROUP_GAP_X = 112;
const GROUP_GAP_Y = 112;

function peerNodeType(device: Device): "peer" | "gateway" | "k8s" {
  if (device.type === "k8s") return "k8s";
  return "peer";
}

function meshEdgeStyle(opts: {
  direct?: boolean | null;
  reachable: boolean;
  latencyMs?: number | null;
}): Pick<TopologyFlowEdge, "style" | "animated" | "data" | "type"> {
  if (!opts.reachable) {
    return {
      type: "mesh",
      animated: false,
      style: { stroke: "#ef4444", strokeWidth: 1.5, strokeDasharray: "4 4" },
      data: {
        kind: "peer",
        intensity: 0.2,
        latencyMs: opts.latencyMs,
        direct: false,
        label: "unreachable",
      },
    };
  }
  const direct = opts.direct !== false;
  const latency =
    opts.latencyMs != null ? ` · ${Math.round(opts.latencyMs)}ms` : "";
  return {
    type: "mesh",
    animated: direct,
    style: {
      stroke: direct ? "#22c55e" : "#eab308",
      strokeWidth: 1.75,
      strokeDasharray: direct ? undefined : "6 4",
    },
    data: {
      kind: "peer",
      intensity: 0.55,
      latencyMs: opts.latencyMs,
      direct,
      label: `${direct ? "direct" : "relay"}${latency}`,
    },
  };
}

/** Org topology: networks as parent groups with peers, mesh edges, and satellites. */
export function orgToFlow(
  networks: Network[],
  machines: Device[],
  tunnels: Array<Tunnel & { networkName?: string }>,
  serves: Array<Serve & { networkName?: string }>,
  subnetRoutes: SubnetRouteLike[],
  topologies: TopologyResponse[],
  now: number,
): { nodes: TopologyFlowNode[]; edges: TopologyFlowEdge[] } {
  const edges: TopologyFlowEdge[] = [];
  const seenNetEdges = new Set<string>();

  const tunnelByNet = new Map<string, number>();
  for (const t of tunnels) {
    tunnelByNet.set(t.networkId, (tunnelByNet.get(t.networkId) ?? 0) + 1);
  }
  const serveByNet = new Map<string, number>();
  for (const s of serves) {
    serveByNet.set(s.networkId, (serveByNet.get(s.networkId) ?? 0) + 1);
  }

  const topoByNet = new Map(topologies.map((t) => [t.networkId, t]));
  const endpointToFlowId = new Map<string, string>();

  const childNodes: TopologyFlowNode[] = [];
  const groupNodes: TopologyFlowNode[] = [];
  let groupCol = 0;

  for (const network of networks) {
    const netMachines = machines.filter(
      (m) =>
        m.networkId === network.id &&
        (m.type === "agent" || m.type === "k8s" || m.type === "sdk"),
    );
    const online = netMachines.filter(
      (m) => getMachinePresence(m, now) === "online",
    ).length;
    const health =
      netMachines.length === 0
        ? "empty"
        : online === 0
          ? "degraded"
          : online < netMachines.length
            ? "degraded"
            : "online";

    const childPositions: Array<{ id: string; x: number; y: number }> = [];
    let col = 0;
    let row = 0;
    const colW = Math.max(PEER_W, SAT_W * 2 + 10);
    const rowH = PEER_H + SAT_H + 28;

    for (const machine of netMachines) {
      const flowId = `peer:${network.id}:${machine.endpointId}`;
      endpointToFlowId.set(`${network.id}:${machine.endpointId}`, flowId);
      endpointToFlowId.set(machine.endpointId, flowId);
      // Topology API ids
      endpointToFlowId.set(`machine:${machine.endpointId}`, flowId);

      const x = PAD_X + col * (colW + GAP_X);
      const y = PAD_Y + row * (rowH + GAP_Y);
      childPositions.push({ id: flowId, x, y });

      const onlinePresence = getMachinePresence(machine, now) === "online";
      const type = peerNodeType(machine);
      childNodes.push({
        id: flowId,
        type,
        parentId: network.id,
        extent: "parent",
        expandParent: false,
        position: { x, y },
        width: PEER_W,
        height: PEER_H,
        style: { width: PEER_W, height: PEER_H },
        data: {
          topology: {
            id: flowId,
            kind: "machine",
            label: machine.hostname || machine.endpointId.slice(0, 8),
            secondary: machine.assignedIp,
            endpointId: machine.endpointId,
            online: onlinePresence,
            assignedIp: machine.assignedIp,
            deviceType: machine.type,
            nodeKind: null,
            serveCount: serves.filter(
              (s) => s.endpointId === machine.endpointId,
            ).length,
            tunnelCount: tunnels.filter(
              (t) => t.endpointId === machine.endpointId,
            ).length,
          },
          isGateway: type === "gateway",
        },
        draggable: true,
        connectable: true,
      });

      col += 1;
      if (col >= COLS) {
        col = 0;
        row += 1;
      }
    }

    // Serve / tunnel satellites under each peer
    for (const serve of serves.filter((s) => s.networkId === network.id)) {
      const parentFlowId = endpointToFlowId.get(
        `${network.id}:${serve.endpointId}`,
      );
      if (!parentFlowId) continue;
      const parentPos = childPositions.find((p) => p.id === parentFlowId);
      if (!parentPos) continue;
      const satId = `serve:${serve.id}`;
      const serveIndex = serves
        .filter(
          (s) =>
            s.networkId === network.id && s.endpointId === serve.endpointId,
        )
        .findIndex((s) => s.id === serve.id);
      childNodes.push({
        id: satId,
        type: "serve",
        parentId: network.id,
        extent: "parent",
        expandParent: false,
        position: {
          x: parentPos.x + serveIndex * (SAT_W + 10),
          y: parentPos.y + PEER_H + 18,
        },
        width: SAT_W,
        height: SAT_H,
        style: { width: SAT_W, height: SAT_H },
        data: {
          serveId: serve.id,
          label: `Serve :${serve.localPort}`,
          secondary: serve.hostname || serve.internalHostname,
          endpointId: serve.endpointId,
          networkId: serve.networkId,
        },
        connectable: false,
        draggable: false,
      });
      edges.push({
        id: `sat-${satId}`,
        source: parentFlowId,
        target: satId,
        sourceHandle: "serve",
        type: "subnetRoute",
        style: { stroke: "#a855f7", strokeWidth: 1.5 },
        data: { kind: "subnetRoute", intensity: 0.35, label: "serve" },
      });
    }

    for (const tunnel of tunnels.filter((t) => t.networkId === network.id)) {
      const parentFlowId = endpointToFlowId.get(
        `${network.id}:${tunnel.endpointId}`,
      );
      if (!parentFlowId) continue;
      const parentPos = childPositions.find((p) => p.id === parentFlowId);
      if (!parentPos) continue;
      const satId = `tunnel:${tunnel.id}`;
      const peerServeCount = serves.filter(
        (s) => s.networkId === network.id && s.endpointId === tunnel.endpointId,
      ).length;
      const tunnelIndex = tunnels
        .filter(
          (t) =>
            t.networkId === network.id && t.endpointId === tunnel.endpointId,
        )
        .findIndex((t) => t.id === tunnel.id);
      childNodes.push({
        id: satId,
        type: "tunnel",
        parentId: network.id,
        extent: "parent",
        expandParent: false,
        position: {
          x:
            parentPos.x +
            peerServeCount * (SAT_W + 10) +
            tunnelIndex * (SAT_W + 10),
          y: parentPos.y + PEER_H + 18,
        },
        width: SAT_W,
        height: SAT_H,
        style: { width: SAT_W, height: SAT_H },
        data: {
          tunnelId: tunnel.id,
          label: `Tunnel :${tunnel.localPort}`,
          secondary: tunnel.publicHostname || tunnel.subdomain,
          endpointId: tunnel.endpointId,
          networkId: tunnel.networkId,
          publicHostname: tunnel.publicHostname,
        },
        connectable: false,
        draggable: false,
      });
      edges.push({
        id: `sat-${satId}`,
        source: parentFlowId,
        target: satId,
        sourceHandle: "tunnel",
        type: "subnetRoute",
        style: { stroke: "#a855f7", strokeWidth: 1.5 },
        data: { kind: "subnetRoute", intensity: 0.35, label: "tunnel" },
      });
    }

    // Mesh edges: prefer topology API, then fill missing pairs
    const topo = topoByNet.get(network.id);
    const linked = new Set<string>();

    if (topo) {
      for (const edge of topo.edges) {
        if (edge.kind !== "peer") continue;
        const source =
          endpointToFlowId.get(edge.source) ??
          endpointToFlowId.get(
            `${network.id}:${edge.source.replace(/^machine:/, "")}`,
          );
        const target =
          endpointToFlowId.get(edge.target) ??
          endpointToFlowId.get(
            `${network.id}:${edge.target.replace(/^machine:/, "")}`,
          );
        if (!source || !target) continue;
        const pair = [source, target].sort().join("|");
        linked.add(pair);
        const style = meshEdgeStyle({
          direct: edge.direct,
          reachable: true,
          latencyMs: edge.latencyMs,
        });
        edges.push({
          id: `mesh:${network.id}:${edge.id}`,
          source,
          target,
          ...style,
        });
      }
    }

    // Synthesize remaining peer pairs (offline / missing metrics → unreachable)
    for (let i = 0; i < netMachines.length; i++) {
      for (let j = i + 1; j < netMachines.length; j++) {
        const a = netMachines[i]!;
        const b = netMachines[j]!;
        const source = endpointToFlowId.get(`${network.id}:${a.endpointId}`)!;
        const target = endpointToFlowId.get(`${network.id}:${b.endpointId}`)!;
        const pair = [source, target].sort().join("|");
        if (linked.has(pair)) continue;
        linked.add(pair);
        const aOnline = getMachinePresence(a, now) === "online";
        const bOnline = getMachinePresence(b, now) === "online";
        const style = meshEdgeStyle({
          reachable: aOnline && bOnline,
          direct: true,
          latencyMs: null,
        });
        edges.push({
          id: `mesh-syn:${network.id}:${a.endpointId.slice(0, 8)}:${b.endpointId.slice(0, 8)}`,
          source,
          target,
          ...style,
        });
      }
    }

    const peerRows = Math.max(
      1,
      Math.ceil(Math.max(netMachines.length, 1) / COLS),
    );
    const peerCols = Math.min(COLS, Math.max(netMachines.length, 1));
    const contentW =
      netMachines.length === 0
        ? 320
        : PAD_X * 2 + peerCols * colW + (peerCols - 1) * GAP_X;
    const contentH =
      netMachines.length === 0
        ? 140
        : PAD_Y + peerRows * rowH + (peerRows - 1) * GAP_Y + PAD_X;

    const displayW = Math.max(contentW, 360);
    const displayH = Math.max(contentH, 200);

    groupNodes.push({
      id: network.id,
      type: "networkGroup",
      position: {
        x: (groupCol % 2) * (displayW + GROUP_GAP_X),
        y: Math.floor(groupCol / 2) * (displayH + GROUP_GAP_Y),
      },
      width: displayW,
      height: displayH,
      style: { width: displayW, height: displayH },
      data: {
        networkId: network.id,
        name: network.name,
        cidr: network.cidr,
        totalPeers: netMachines.length,
        onlinePeers: online,
        tunnelCount: tunnelByNet.get(network.id) ?? 0,
        serveCount: serveByNet.get(network.id) ?? 0,
        health,
      },
      draggable: true,
      connectable: false,
    });

    groupCol += 1;
  }

  // Cross-network edges
  const networkByCidr = new Map(networks.map((n) => [n.cidr, n.id]));
  for (const route of subnetRoutes) {
    if (route.enabled === false) continue;
    const targetNetId = networkByCidr.get(route.cidr);
    if (!targetNetId || targetNetId === route.networkId) continue;
    const key = [route.networkId, targetNetId].sort().join(":");
    if (seenNetEdges.has(key)) continue;
    seenNetEdges.add(key);
    edges.push({
      id: `route:${route.id}`,
      source: route.networkId,
      target: targetNetId,
      type: "subnetRoute",
      label: route.cidr,
      style: { stroke: "#34d399", strokeWidth: 1.75 },
      data: {
        kind: "subnetRoute",
        intensity: 0.5,
        label: `subnet ${route.cidr}`,
      },
    });
  }

  const endpointNets = new Map<string, Set<string>>();
  for (const machine of machines) {
    const set = endpointNets.get(machine.endpointId) ?? new Set();
    set.add(machine.networkId);
    endpointNets.set(machine.endpointId, set);
  }
  for (const [endpointId, nets] of endpointNets) {
    if (nets.size < 2) continue;
    const list = [...nets];
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const a = list[i]!;
        const b = list[j]!;
        const key = [a, b].sort().join(":");
        if (seenNetEdges.has(key)) continue;
        seenNetEdges.add(key);
        edges.push({
          id: `shared-gw:${endpointId.slice(0, 8)}:${key}`,
          source: a,
          target: b,
          type: "subnetRoute",
          style: {
            stroke: "#f59e0b",
            strokeWidth: 1.5,
            strokeDasharray: "4 3",
          },
          data: {
            kind: "subnetRoute",
            intensity: 0.4,
            label: "shared gateway",
          },
        });
      }
    }
  }

  return { nodes: [...groupNodes, ...childNodes], edges };
}
