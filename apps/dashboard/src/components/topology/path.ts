import type { Edge, Node } from "@xyflow/react";

/** BFS shortest path between two node ids. Returns node ids on the path. */
export function findNodePath(
  nodes: Node[],
  edges: Edge[],
  startId: string,
  endId: string,
): string[] | null {
  if (startId === endId) return [startId];
  const adj = new Map<string, string[]>();
  for (const node of nodes) {
    adj.set(node.id, []);
  }
  for (const edge of edges) {
    adj.get(edge.source)?.push(edge.target);
    adj.get(edge.target)?.push(edge.source);
  }

  const queue = [startId];
  const prev = new Map<string, string | null>([[startId, null]]);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur === endId) break;
    for (const next of adj.get(cur) ?? []) {
      if (prev.has(next)) continue;
      prev.set(next, cur);
      queue.push(next);
    }
  }
  if (!prev.has(endId)) return null;

  const path: string[] = [];
  let cur: string | null = endId;
  while (cur) {
    path.push(cur);
    cur = prev.get(cur) ?? null;
  }
  return path.reverse();
}

export function edgeIdsOnPath(
  edges: Edge[],
  pathNodeIds: string[],
): Set<string> {
  const onPath = new Set(pathNodeIds);
  const ids = new Set<string>();
  for (const edge of edges) {
    if (onPath.has(edge.source) && onPath.has(edge.target)) {
      const si = pathNodeIds.indexOf(edge.source);
      const ti = pathNodeIds.indexOf(edge.target);
      if (si >= 0 && ti >= 0 && Math.abs(si - ti) === 1) {
        ids.add(edge.id);
      }
    }
  }
  return ids;
}
