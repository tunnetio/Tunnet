import type { Edge, Node } from "@xyflow/react";
import ELK, { type ElkNode } from "elkjs/lib/elk.bundled.js";

const elk = new ELK();

const NODE_SIZE: Record<string, { width: number; height: number }> = {
  networkGroup: { width: 220, height: 120 },
  peer: { width: 180, height: 72 },
  gateway: { width: 180, height: 72 },
  k8s: { width: 180, height: 72 },
  relay: { width: 140, height: 56 },
  subnet: { width: 140, height: 56 },
  hostname: { width: 140, height: 56 },
  exit: { width: 140, height: 56 },
  serve: { width: 120, height: 48 },
  tunnel: { width: 120, height: 48 },
  enroll: { width: 140, height: 56 },
};

export type ElkLayoutMode = "layered" | "force" | "stress";

function sizeFor(type: string | undefined) {
  return NODE_SIZE[type ?? "peer"] ?? { width: 160, height: 64 };
}

export async function layoutWithElk<
  N extends Node = Node,
  E extends Edge = Edge,
>(
  nodes: N[],
  edges: E[],
  mode: ElkLayoutMode = "layered",
): Promise<{ nodes: N[]; edges: E[] }> {
  if (nodes.length === 0) return { nodes, edges };

  const options: Record<string, string> =
    mode === "layered"
      ? {
          "elk.algorithm": "layered",
          "elk.direction": "RIGHT",
          "elk.spacing.nodeNode": "48",
          "elk.layered.spacing.nodeNodeBetweenLayers": "72",
          "elk.edgeRouting": "SPLINES",
        }
      : mode === "stress"
        ? {
            "elk.algorithm": "stress",
            "elk.spacing.nodeNode": "64",
            "elk.stress.desiredEdgeLength": "140",
          }
        : {
            "elk.algorithm": "force",
            "elk.spacing.nodeNode": "56",
            "elk.force.iterations": "300",
          };

  const graph: ElkNode = {
    id: "root",
    layoutOptions: options,
    children: nodes.map((node) => {
      const size = sizeFor(node.type);
      return {
        id: node.id,
        width: size.width,
        height: size.height,
      };
    }),
    edges: edges.map((edge) => ({
      id: edge.id,
      sources: [edge.source],
      targets: [edge.target],
    })),
  };

  const layouted = await elk.layout(graph);
  const positions = new Map(
    (layouted.children ?? []).map((child) => [
      child.id,
      { x: child.x ?? 0, y: child.y ?? 0 },
    ]),
  );

  return {
    nodes: nodes.map((node) => {
      const pos = positions.get(node.id);
      if (!pos) return node;
      return {
        ...node,
        position: pos,
      };
    }),
    edges,
  };
}

const STORAGE_PREFIX = "tunnet:topology:positions:";

export function loadSavedPositions(
  key: string,
): Record<string, { x: number; y: number }> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + key);
    if (!raw) return null;
    return JSON.parse(raw) as Record<string, { x: number; y: number }>;
  } catch {
    return null;
  }
}

export function savePositions(
  key: string,
  nodes: Array<{ id: string; position: { x: number; y: number } }>,
) {
  if (typeof window === "undefined") return;
  const map: Record<string, { x: number; y: number }> = {};
  for (const node of nodes) {
    map[node.id] = node.position;
  }
  localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(map));
}

export function applySavedPositions<N extends Node>(
  nodes: N[],
  saved: Record<string, { x: number; y: number }> | null,
): N[] {
  if (!saved) return nodes;
  return nodes.map((node) => {
    const pos = saved[node.id];
    if (!pos) return node;
    return { ...node, position: pos };
  });
}

/**
 * Patch graph data onto the live canvas without resetting positions,
 * selection, or measurement (avoids jump on poll/refetch).
 */
export function mergeFlowNodes<N extends Node>(
  prev: N[],
  next: N[],
  options?: { resetPositions?: boolean },
): N[] {
  if (options?.resetPositions || prev.length === 0) {
    return next;
  }

  const prevById = new Map(prev.map((node) => [node.id, node]));
  let changed = prev.length !== next.length;

  const merged = next.map((node) => {
    const existing = prevById.get(node.id);
    if (!existing) {
      changed = true;
      return node;
    }

    const dataSame =
      existing.type === node.type &&
      existing.parentId === node.parentId &&
      shallowEqual(existing.data, node.data);
    const sizeSame =
      (existing.width ?? node.width) === (node.width ?? existing.width) &&
      (existing.height ?? node.height) === (node.height ?? existing.height);

    if (dataSame && sizeSame) {
      return existing;
    }

    changed = true;
    return {
      ...node,
      position: existing.position,
      selected: existing.selected,
      dragging: existing.dragging,
      measured: existing.measured,
      width: node.width ?? existing.width,
      height: node.height ?? existing.height,
      style: {
        ...existing.style,
        ...node.style,
      },
    };
  });

  return changed ? merged : prev;
}

export function mergeFlowEdges<E extends Edge>(prev: E[], next: E[]): E[] {
  if (prev.length === 0) return next;
  const prevById = new Map(prev.map((edge) => [edge.id, edge]));
  let changed = prev.length !== next.length;

  const merged = next.map((edge) => {
    const existing = prevById.get(edge.id);
    if (!existing) {
      changed = true;
      return edge;
    }
    if (
      existing.source === edge.source &&
      existing.target === edge.target &&
      existing.sourceHandle === edge.sourceHandle &&
      existing.targetHandle === edge.targetHandle &&
      existing.type === edge.type &&
      existing.animated === edge.animated &&
      shallowEqual(existing.data, edge.data) &&
      shallowEqual(existing.style, edge.style)
    ) {
      return existing;
    }
    changed = true;
    return { ...edge, selected: existing.selected };
  });

  return changed ? merged : prev;
}

function shallowEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (
    typeof a !== "object" ||
    typeof b !== "object" ||
    a === null ||
    b === null
  ) {
    return false;
  }
  const aRec = a as Record<string, unknown>;
  const bRec = b as Record<string, unknown>;
  const aKeys = Object.keys(aRec);
  const bKeys = Object.keys(bRec);
  if (aKeys.length !== bKeys.length) return false;
  for (const key of aKeys) {
    if (!Object.is(aRec[key], bRec[key])) return false;
  }
  return true;
}
