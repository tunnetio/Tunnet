import { useNavigate } from "@tanstack/react-router";
import {
  Background,
  type Connection,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  type OnSelectionChangeParams,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  SelectionMode,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
} from "@xyflow/react";
import { useCallback, useEffect, useMemo, useRef } from "react";
import { toast } from "sonner";

import { DetailPanel } from "@/components/topology/DetailPanel";
import {
  applySavedPositions,
  layoutWithElk,
  loadSavedPositions,
  mergeFlowEdges,
  mergeFlowNodes,
  savePositions,
} from "@/components/topology/layout/elk";
import {
  buildEndpointToNodeId,
  topologyToFlowEdges,
  topologyToFlowNodes,
} from "@/components/topology/mappers/topologyToFlow";
import { ConnectDialogs } from "@/components/topology/overlays/ConnectDialogs";
import {
  openTopologyContextMenu,
  TopologyContextMenus,
} from "@/components/topology/overlays/ContextMenus";
import { TopologyToolbar } from "@/components/topology/overlays/TopologyToolbar";
import { edgeIdsOnPath, findNodePath } from "@/components/topology/path";
import {
  topologyEdgeTypes,
  topologyNodeTypes,
} from "@/components/topology/registry";
import { useTopologyUi } from "@/components/topology/TopologyProvider";
import type {
  MeshEdgeData,
  PeerNodeData,
  ServeSatelliteData,
  TunnelSatelliteData,
} from "@/components/topology/types";
import { Skeleton } from "@/components/ui/skeleton";
import { useServes, useTopology, useTunnels } from "@/lib/queries/management";
import { cn } from "@/lib/utils";

type NetworkCanvasInnerProps = {
  orgId: string;
  networkId: string;
};

function NetworkCanvasInner({ orgId, networkId }: NetworkCanvasInnerProps) {
  const navigate = useNavigate();
  const {
    statusFilter,
    kindFilter,
    heatmap,
    searchQuery,
    selected,
    setSelected,
    setConnectIntent,
    highlightedPath,
    setHighlightedPath,
    pathPickMode,
    setPathPickMode,
    pathEndpoints,
    setPathEndpoints,
    layoutNonce,
    setKindFilter,
  } = useTopologyUi();

  const { data: topology, isPending } = useTopology(orgId, networkId);
  const { data: serves } = useServes(orgId);
  const { data: tunnels } = useTunnels(orgId);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const nodesInitialized = useNodesInitialized();
  const layoutKey = `network:${orgId}:${networkId}`;
  const lastFingerprint = useRef("");
  const appliedLayoutNonce = useRef(0);
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const didFitView = useRef(false);

  const fingerprint = useMemo(() => {
    if (!topology) return "";
    return JSON.stringify({
      n: topology.nodes.map((x) => [
        x.id,
        x.online,
        x.serveCount,
        x.tunnelCount,
        x.label,
        x.assignedIp,
      ]),
      e: topology.edges.map((x) => [x.id, x.direct, x.intensity, x.latencyMs]),
      statusFilter,
      kindFilter,
      heatmap,
      serves: serves
        ?.filter((s) => s.networkId === networkId)
        .map((s) => [s.id, s.endpointId, s.localPort]),
      tunnels: tunnels
        ?.filter((t) => t.networkId === networkId)
        .map((t) => [t.id, t.endpointId, t.localPort]),
      layoutNonce,
    });
  }, [
    topology,
    statusFilter,
    kindFilter,
    heatmap,
    serves,
    tunnels,
    networkId,
    layoutNonce,
  ]);

  useEffect(() => {
    if (!topology) return;
    if (fingerprint === lastFingerprint.current) return;
    let cancelled = false;

    async function run() {
      const flowNodes = topologyToFlowNodes(topology!.nodes, {
        statusFilter,
        kindFilter,
        serves,
        tunnels,
        networkId,
        includeEnrollZone: true,
      });
      const visibleIds = new Set(flowNodes.map((n) => n.id));
      const endpointMap = buildEndpointToNodeId(topology!.nodes);
      const flowEdges = topologyToFlowEdges(topology!.edges, visibleIds, {
        heatmap,
        serves,
        tunnels,
        networkId,
        endpointToNodeId: endpointMap,
        machines: topology!.nodes,
      });

      const prev = nodesRef.current;
      const resetPositions = layoutNonce !== appliedLayoutNonce.current;
      let nextNodes: Node[];

      if (prev.length === 0) {
        const saved = loadSavedPositions(layoutKey);
        if (saved && Object.keys(saved).length > 0) {
          nextNodes = applySavedPositions(flowNodes, saved) as Node[];
        } else {
          const layouted = await layoutWithElk(flowNodes, flowEdges, "stress");
          if (cancelled) return;
          nextNodes = layouted.nodes as Node[];
          savePositions(layoutKey, nextNodes);
        }
        appliedLayoutNonce.current = layoutNonce;
      } else if (resetPositions) {
        const layouted = await layoutWithElk(flowNodes, flowEdges, "stress");
        if (cancelled) return;
        nextNodes = layouted.nodes as Node[];
        appliedLayoutNonce.current = layoutNonce;
        savePositions(layoutKey, nextNodes);
      } else {
        nextNodes = mergeFlowNodes(prev, flowNodes as Node[]);
      }

      if (cancelled) return;
      lastFingerprint.current = fingerprint;
      setNodes(nextNodes);
      setEdges((prev) => mergeFlowEdges(prev, flowEdges as Edge[]));
    }

    void run();
    return () => {
      cancelled = true;
    };
  }, [
    fingerprint,
    topology,
    statusFilter,
    kindFilter,
    heatmap,
    serves,
    tunnels,
    networkId,
    layoutNonce,
    layoutKey,
    setNodes,
    setEdges,
  ]);

  // Sync kind filter from URL search on mount handled by parent

  const displayNodes = useMemo(() => {
    if (!searchQuery.trim()) return nodes;
    const q = searchQuery.trim().toLowerCase();
    return nodes.map((node) => {
      const label = nodeLabel(node).toLowerCase();
      const match = label.includes(q);
      return {
        ...node,
        style: {
          ...node.style,
          opacity: match ? 1 : 0.2,
        },
      };
    });
  }, [nodes, searchQuery]);

  const displayEdges = useMemo(() => {
    if (highlightedPath.size === 0) return edges;
    return edges.map((edge) => {
      const on = highlightedPath.has(edge.id);
      return {
        ...edge,
        data: { ...(edge.data as MeshEdgeData), highlighted: on },
        style: {
          ...edge.style,
          opacity: on ? 1 : 0.15,
          strokeWidth: on
            ? Number(edge.style?.strokeWidth ?? 1.5) + 1.5
            : edge.style?.strokeWidth,
        },
      };
    });
  }, [edges, highlightedPath]);

  const onConnect = useCallback(
    (connection: Connection) => {
      const source = nodes.find((n) => n.id === connection.source);
      const target = nodes.find((n) => n.id === connection.target);
      if (!source || !target) return;

      if (target.type === "enroll") {
        setConnectIntent({ type: "enroll", networkId });
        return;
      }

      if (connection.sourceHandle === "serve" || target.type === "serve") {
        const peer = asPeer(source);
        if (peer) {
          setConnectIntent({
            type: "serve",
            endpointId: peer.endpointId,
            networkId,
          });
        }
        return;
      }

      if (connection.sourceHandle === "tunnel" || target.type === "tunnel") {
        const peer = asPeer(source);
        if (peer) {
          setConnectIntent({
            type: "tunnel",
            endpointId: peer.endpointId,
            networkId,
          });
        }
        return;
      }

      const srcPeer = asPeer(source);
      const dstPeer = asPeer(target);
      if (
        srcPeer?.endpointId &&
        dstPeer?.endpointId &&
        srcPeer.endpointId !== dstPeer.endpointId
      ) {
        setConnectIntent({
          type: "policy",
          sourceEndpointId: srcPeer.endpointId,
          targetEndpointId: dstPeer.endpointId,
          sourceLabel: srcPeer.label,
          targetLabel: dstPeer.label,
          networkId,
        });
      }
    },
    [nodes, networkId, setConnectIntent],
  );

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (pathPickMode) {
        const next = [...pathEndpoints, node.id].slice(-2);
        setPathEndpoints(next);
        if (next.length === 2) {
          const path = findNodePath(nodes, edges, next[0]!, next[1]!);
          if (!path) {
            toast.message("No path between selected nodes");
            setHighlightedPath(new Set());
          } else {
            setHighlightedPath(edgeIdsOnPath(edges, path));
          }
          setPathPickMode(false);
          setPathEndpoints([]);
        }
        return;
      }

      if (node.type === "enroll") {
        setConnectIntent({ type: "enroll", networkId });
        return;
      }
      if (node.type === "serve") {
        setSelected({
          kind: "serve",
          data: node.data as ServeSatelliteData,
        });
        return;
      }
      if (node.type === "tunnel") {
        setSelected({
          kind: "tunnel",
          data: node.data as TunnelSatelliteData,
        });
        return;
      }
      if (
        node.type === "peer" ||
        node.type === "gateway" ||
        node.type === "k8s" ||
        node.type === "relay" ||
        node.type === "subnet" ||
        node.type === "hostname" ||
        node.type === "exit"
      ) {
        const data = node.data as
          | PeerNodeData
          | { topology: PeerNodeData["topology"] };
        if ("topology" in data) {
          setSelected({ kind: "topology", node: data.topology });
        }
      }
    },
    [
      pathPickMode,
      pathEndpoints,
      nodes,
      edges,
      networkId,
      setPathEndpoints,
      setHighlightedPath,
      setPathPickMode,
      setConnectIntent,
      setSelected,
    ],
  );

  const onNodeContextMenu = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (
        node.type === "peer" ||
        node.type === "gateway" ||
        node.type === "k8s"
      ) {
        const data = node.data as PeerNodeData;
        setSelected({ kind: "topology", node: data.topology });
        openTopologyContextMenu(event, {
          kind: "peer",
          label: data.topology.label,
          endpointId: data.topology.endpointId ?? undefined,
          networkId,
        });
      }
    },
    [networkId, setSelected],
  );

  const onNodeDragStop = useCallback(() => {
    savePositions(layoutKey, nodes);
  }, [layoutKey, nodes]);

  const onSelectionChange = useCallback(
    ({ nodes: selectedNodes }: OnSelectionChangeParams) => {
      if (selectedNodes.length <= 1) return;
      // multi-select retained in React Flow; actions via toolbar later
    },
    [],
  );

  if (isPending) {
    return <Skeleton className="h-full w-full rounded-none" />;
  }

  return (
    <div className="relative flex h-full min-h-0 w-full">
      <div className="relative min-h-0 min-w-0 flex-1">
        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          onNodeContextMenu={onNodeContextMenu}
          onNodeDragStop={onNodeDragStop}
          onSelectionChange={onSelectionChange}
          nodeTypes={topologyNodeTypes}
          edgeTypes={topologyEdgeTypes}
          nodesDraggable={nodesInitialized}
          nodesConnectable={nodesInitialized}
          selectionMode={SelectionMode.Partial}
          selectionOnDrag
          panOnDrag={[1, 2]}
          multiSelectionKeyCode="Shift"
          proOptions={{ hideAttribution: true }}
          className="mesh-surface"
          defaultEdgeOptions={{ type: "mesh" }}
          onInit={(instance) => {
            if (didFitView.current) return;
            didFitView.current = true;
            void instance.fitView({ padding: 0.2 });
          }}
        >
          <Background gap={16} size={1} color="oklch(1 0 0 / 0.06)" />
          <Controls showInteractive={false} className="!shadow-sm" />
          <MiniMap
            pannable
            zoomable
            className="!bg-card/90 !shadow-sm"
            maskColor="oklch(0 0 0 / 0.45)"
          />
          <Panel position="top-left" className="m-3 max-w-[min(100%,720px)]">
            <TopologyToolbar
              mode="network"
              actions={
                kindFilter === "k8s" ? (
                  <button
                    type="button"
                    className="text-muted-foreground hover:text-foreground h-8 px-2 text-[12px]"
                    onClick={() => {
                      setKindFilter("all");
                      void navigate({
                        to: "/app/networks/$networkId",
                        params: { networkId },
                        search: {},
                      });
                    }}
                  >
                    Clear k8s filter
                  </button>
                ) : null
              }
            />
          </Panel>
          {pathPickMode ? (
            <Panel position="top-center" className="m-3">
              <div className="rounded-md border border-border/70 bg-card px-3 py-1.5 text-[12px] shadow-sm">
                Click two nodes to highlight path
                {pathEndpoints.length === 1 ? " (1 selected)" : ""}
              </div>
            </Panel>
          ) : null}
        </ReactFlow>
      </div>
      <div
        className={cn(
          "z-10 w-full max-w-sm border-l border-border/70",
          selected ? "flex" : "hidden",
        )}
      >
        <DetailPanel orgId={orgId} networkId={networkId} />
      </div>
      <ConnectDialogs orgId={orgId} networkId={networkId} />
      <TopologyContextMenus orgId={orgId} networkId={networkId} />
    </div>
  );
}

function nodeLabel(node: Node): string {
  const data = node.data as Record<string, unknown>;
  if (typeof data.name === "string") return data.name;
  if (typeof data.label === "string") {
    return `${data.label} ${typeof data.secondary === "string" ? data.secondary : ""}`;
  }
  if (data.topology && typeof data.topology === "object") {
    const t = data.topology as {
      label?: string;
      assignedIp?: string | null;
      secondary?: string | null;
    };
    return `${t.label ?? ""} ${t.assignedIp ?? ""} ${t.secondary ?? ""}`;
  }
  return node.id;
}

function asPeer(node: Node): { endpointId: string; label: string } | null {
  if (node.type !== "peer" && node.type !== "gateway" && node.type !== "k8s") {
    return null;
  }
  const data = node.data as PeerNodeData;
  if (!data.topology.endpointId) return null;
  return {
    endpointId: data.topology.endpointId,
    label: data.topology.label,
  };
}

export function NetworkCanvas(props: NetworkCanvasInnerProps) {
  return (
    <ReactFlowProvider>
      <NetworkCanvasInner {...props} />
    </ReactFlowProvider>
  );
}
