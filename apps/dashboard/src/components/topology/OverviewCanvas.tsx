import { useQueries } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  Background,
  type Connection,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
} from "@xyflow/react";
import { PlusIcon, ShieldIcon, WaypointsIcon } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { CreateNetworkDialog } from "@/components/app/create-network-dialog";
import { AccessCanvas } from "@/components/topology/AccessCanvas";
import { DetailPanel } from "@/components/topology/DetailPanel";
import {
  loadSavedPositions,
  mergeFlowEdges,
  mergeFlowNodes,
  savePositions,
} from "@/components/topology/layout/elk";
import { orgToFlow } from "@/components/topology/mappers/orgToFlow";
import { ConnectDialogs } from "@/components/topology/overlays/ConnectDialogs";
import {
  openTopologyContextMenu,
  TopologyContextMenus,
} from "@/components/topology/overlays/ContextMenus";
import { TopologyToolbar } from "@/components/topology/overlays/TopologyToolbar";
import {
  topologyEdgeTypes,
  topologyNodeTypes,
} from "@/components/topology/registry";
import { useTopologyUi } from "@/components/topology/TopologyProvider";
import type {
  NetworkGroupNodeData,
  PeerNodeData,
  ServeSatelliteData,
  TunnelSatelliteData,
} from "@/components/topology/types";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/hooks/use-permission";
import { createManagementClient } from "@/lib/management-client";
import { usePresenceClock } from "@/lib/presence-clock";
import {
  useMachines,
  useNetworks,
  useServes,
  useTunnels,
} from "@/lib/queries/management";
import { queryKeys } from "@/lib/query-keys";
import { cn } from "@/lib/utils";

const FIT_VIEW_OPTIONS = { padding: 0.2 };
const DEFAULT_EDGE_OPTIONS = { interactionWidth: 24 };
const PRO_OPTIONS = { hideAttribution: true };

function applySavedPositionsToGroups(
  nodes: Array<
    Node | { id: string; parentId?: string; position: { x: number; y: number } }
  >,
  saved: Record<string, { x: number; y: number }> | null,
) {
  if (!saved) return nodes;
  return nodes.map((node) => {
    if ("parentId" in node && node.parentId) return node;
    const pos = saved[node.id];
    if (!pos) return node;
    return { ...node, position: pos };
  });
}

function TopologyOverviewInner({ orgId }: { orgId: string }) {
  const navigate = useNavigate();
  const now = usePresenceClock();
  const { data: canCreate = false } = useCan(orgId, "network", "create");
  const { data: networks, isPending: networksPending } = useNetworks(orgId);
  const { data: machines, isPending: machinesPending } = useMachines(orgId);
  const { data: tunnels } = useTunnels(orgId);
  const { data: serves } = useServes(orgId);
  const {
    searchQuery,
    setSelected,
    selected,
    connectIntent,
    setConnectIntent,
    layoutNonce,
  } = useTopologyUi();
  const [createOpen, setCreateOpen] = useState(false);

  const routeQueries = useQueries({
    queries: (networks ?? []).map((network) => ({
      queryKey: queryKeys.subnetRoutes(orgId, network.id),
      queryFn: async () => {
        const client = createManagementClient(orgId);
        const { routes } = await client.listSubnetRoutes(network.id);
        return routes;
      },
      enabled: Boolean(orgId && networks?.length),
    })),
  });

  const topologyQueries = useQueries({
    queries: (networks ?? []).map((network) => ({
      queryKey: queryKeys.topology(orgId, network.id),
      queryFn: async () => {
        const client = createManagementClient(orgId);
        return client.getTopology(network.id);
      },
      enabled: Boolean(orgId && networks?.length),
      refetchInterval: 15_000,
    })),
  });

  const routeDataKey = routeQueries
    .map((q) =>
      (q.data ?? [])
        .map((r) => `${r.id}:${r.cidr}:${r.networkId}:${r.enabled !== false}`)
        .join(","),
    )
    .join("|");
  const topoDataKey = topologyQueries
    .map((q) => {
      const t = q.data;
      if (!t) return "";
      return `${t.networkId}:${t.edges
        .map((e) => `${e.id}:${e.direct}:${e.latencyMs ?? ""}`)
        .join(",")}`;
    })
    .join("|");

  // biome-ignore lint/correctness/useExhaustiveDependencies: useQueries identity is unstable; keyed by routeDataKey
  const subnetRoutes = useMemo(
    () => routeQueries.flatMap((q) => q.data ?? []),
    [routeDataKey],
  );

  // biome-ignore lint/correctness/useExhaustiveDependencies: useQueries identity is unstable; keyed by topoDataKey
  const topologies = useMemo(
    () =>
      topologyQueries
        .map((q) => q.data)
        .filter((t): t is NonNullable<typeof t> => Boolean(t)),
    [topoDataKey],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const nodesInitialized = useNodesInitialized();
  const layoutKey = `org-topo:${orgId}`;
  const lastFingerprint = useRef("");
  const appliedLayoutNonce = useRef(0);
  const didFitView = useRef(false);

  const pending = networksPending || machinesPending;

  const fingerprint = useMemo(
    () =>
      JSON.stringify({
        networks: networks?.map((n) => [n.id, n.cidr, n.name]),
        machines: machines?.map((m) => [
          m.endpointId,
          m.networkId,
          m.agentConnected,
          // Presence for UI; omit volatile heartbeat timestamps.
          m.status,
        ]),
        tunnels: tunnels?.map((t) => [
          t.id,
          t.endpointId,
          t.status,
          t.localPort,
        ]),
        serves: serves?.map((s) => [s.id, s.endpointId, s.status, s.localPort]),
        routes: subnetRoutes.map((r) => [r.id, r.cidr, r.networkId, r.enabled]),
        topos: topologies.map((t) => [
          t.networkId,
          t.edges.map((e) => [e.id, e.direct, e.latencyMs]),
        ]),
        layoutNonce,
        nowBucket: Math.floor(now / 30_000),
      }),
    [
      networks,
      machines,
      tunnels,
      serves,
      subnetRoutes,
      topologies,
      layoutNonce,
      now,
    ],
  );

  useEffect(() => {
    if (!networks || !machines) return;
    if (fingerprint === lastFingerprint.current) return;

    const { nodes: nextNodes, edges: nextEdges } = orgToFlow(
      networks,
      machines,
      tunnels ?? [],
      serves ?? [],
      subnetRoutes,
      topologies,
      now,
    );

    lastFingerprint.current = fingerprint;
    setNodes((prev) => {
      const resetPositions = layoutNonce !== appliedLayoutNonce.current;
      if (resetPositions) {
        appliedLayoutNonce.current = layoutNonce;
      }

      if (prev.length === 0) {
        const saved = loadSavedPositions(layoutKey);
        return applySavedPositionsToGroups(nextNodes, saved) as Node[];
      }

      if (resetPositions) {
        return nextNodes as Node[];
      }

      return mergeFlowNodes(prev, nextNodes as Node[]);
    });
    setEdges((prev) => mergeFlowEdges(prev, nextEdges as Edge[]));
  }, [
    fingerprint,
    networks,
    machines,
    tunnels,
    serves,
    subnetRoutes,
    topologies,
    now,
    layoutNonce,
    layoutKey,
    setNodes,
    setEdges,
  ]);

  const displayNodes = useMemo(() => {
    if (!searchQuery.trim()) return nodes;
    const q = searchQuery.trim().toLowerCase();
    return nodes.map((node) => {
      if (node.type === "networkGroup") {
        const data = node.data as NetworkGroupNodeData;
        const match =
          data.name.toLowerCase().includes(q) ||
          data.cidr.toLowerCase().includes(q);
        return { ...node, style: { ...node.style, opacity: match ? 1 : 0.25 } };
      }
      const label = JSON.stringify(node.data).toLowerCase();
      return {
        ...node,
        style: { ...node.style, opacity: label.includes(q) ? 1 : 0.2 },
      };
    });
  }, [nodes, searchQuery]);

  const onConnect = useCallback(
    (connection: Connection) => {
      const source = nodes.find((n) => n.id === connection.source);
      const target = nodes.find((n) => n.id === connection.target);
      if (!source || !target) return;

      const srcPeer =
        source.type === "peer" ||
        source.type === "gateway" ||
        source.type === "k8s"
          ? (source.data as PeerNodeData)
          : null;
      const dstPeer =
        target.type === "peer" ||
        target.type === "gateway" ||
        target.type === "k8s"
          ? (target.data as PeerNodeData)
          : null;

      if (connection.sourceHandle === "serve" && srcPeer?.topology.endpointId) {
        const networkId = source.parentId;
        if (networkId) {
          setConnectIntent({
            type: "serve",
            endpointId: srcPeer.topology.endpointId,
            networkId,
          });
        }
        return;
      }
      if (
        connection.sourceHandle === "tunnel" &&
        srcPeer?.topology.endpointId
      ) {
        const networkId = source.parentId;
        if (networkId) {
          setConnectIntent({
            type: "tunnel",
            endpointId: srcPeer.topology.endpointId,
            networkId,
          });
        }
        return;
      }

      if (
        srcPeer?.topology.endpointId &&
        dstPeer?.topology.endpointId &&
        srcPeer.topology.endpointId !== dstPeer.topology.endpointId &&
        source.parentId &&
        source.parentId === target.parentId
      ) {
        setConnectIntent({
          type: "policy",
          sourceEndpointId: srcPeer.topology.endpointId,
          targetEndpointId: dstPeer.topology.endpointId,
          sourceLabel: srcPeer.topology.label,
          targetLabel: dstPeer.topology.label,
          networkId: source.parentId,
        });
      }
    },
    [nodes, setConnectIntent],
  );

  if (pending) {
    return <Skeleton className="h-full w-full" />;
  }

  return (
    <div className="relative flex h-full min-h-0 w-full">
      <div className="relative min-h-0 min-w-0 flex-1">
        <ReactFlow
          nodes={displayNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodesConnectable={nodesInitialized}
          nodesDraggable={nodesInitialized}
          elementsSelectable
          elevateNodesOnSelect={false}
          fitViewOptions={FIT_VIEW_OPTIONS}
          proOptions={PRO_OPTIONS}
          className="mesh-surface"
          nodeTypes={topologyNodeTypes}
          edgeTypes={topologyEdgeTypes}
          defaultEdgeOptions={DEFAULT_EDGE_OPTIONS}
          onInit={(instance) => {
            if (didFitView.current) return;
            didFitView.current = true;
            void instance.fitView(FIT_VIEW_OPTIONS);
          }}
          onNodeClick={(_, node: Node) => {
            if (node.type === "networkGroup") {
              setSelected({
                kind: "network",
                data: node.data as NetworkGroupNodeData,
              });
              return;
            }
            if (
              node.type === "peer" ||
              node.type === "gateway" ||
              node.type === "k8s"
            ) {
              setSelected({
                kind: "topology",
                node: (node.data as PeerNodeData).topology,
              });
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
            }
          }}
          onNodeDoubleClick={(_, node: Node) => {
            if (node.type !== "networkGroup") return;
            const data = node.data as NetworkGroupNodeData;
            void navigate({
              to: "/app/networks/$networkId",
              params: { networkId: data.networkId },
            });
          }}
          onNodeContextMenu={(event, node) => {
            if (node.type === "networkGroup") {
              const data = node.data as NetworkGroupNodeData;
              setSelected({ kind: "network", data });
              openTopologyContextMenu(event, {
                kind: "network",
                label: data.name,
                networkId: data.networkId,
              });
              return;
            }
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
                networkId: data.topology.id.split(":")[1],
              });
            }
          }}
          onNodeDragStop={(_, _n, all) => {
            const topLevel = all.filter((n) => !n.parentId);
            savePositions(layoutKey, topLevel);
          }}
        >
          <Background gap={16} size={1} color="oklch(1 0 0 / 0.06)" />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable className="!bg-card/90" />
          <Panel position="top-left" className="m-3 max-w-[min(100%,720px)]">
            <TopologyToolbar
              mode="overview"
              actions={
                canCreate ? (
                  <Button
                    size="sm"
                    className="h-8 text-[12px]"
                    onClick={() => setCreateOpen(true)}
                  >
                    <PlusIcon className="size-3.5" />
                    Network
                  </Button>
                ) : null
              }
            />
          </Panel>
          {networks?.length === 0 ? (
            <Panel position="top-center" className="m-8">
              <div className="rounded-lg border border-border/70 bg-card px-6 py-5 text-center shadow-sm">
                <p className="text-[14px] font-medium">No networks yet</p>
                <p className="text-muted-foreground mt-1 text-[12px]">
                  Create a network to start building your mesh.
                </p>
                {canCreate ? (
                  <Button
                    size="sm"
                    className="mt-3"
                    onClick={() => setCreateOpen(true)}
                  >
                    Create network
                  </Button>
                ) : null}
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
        <DetailPanel orgId={orgId} />
      </div>
      <CreateNetworkDialog
        orgId={orgId}
        open={createOpen}
        onOpenChange={setCreateOpen}
      />
      {(() => {
        const dialogNetworkId =
          connectIntent && "networkId" in connectIntent
            ? connectIntent.networkId
            : selected?.kind === "network"
              ? selected.data.networkId
              : null;
        return dialogNetworkId ? (
          <ConnectDialogs orgId={orgId} networkId={dialogNetworkId} />
        ) : null;
      })()}
      <TopologyContextMenus orgId={orgId} />
    </div>
  );
}

function TopologyOverviewCanvas({ orgId }: { orgId: string }) {
  return (
    <ReactFlowProvider>
      <TopologyOverviewInner orgId={orgId} />
    </ReactFlowProvider>
  );
}

export function OverviewCanvas({ orgId }: { orgId: string }) {
  const { overviewMode, setOverviewMode, setSelected } = useTopologyUi();

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-border/60 px-3 py-2">
        <div className="bg-muted/60 flex rounded-md p-0.5">
          <Button
            type="button"
            size="sm"
            variant={overviewMode === "topology" ? "secondary" : "ghost"}
            className="h-7 gap-1.5 text-[11px]"
            onClick={() => {
              setOverviewMode("topology");
              setSelected(null);
            }}
          >
            <WaypointsIcon className="size-3.5" />
            Topology
          </Button>
          <Button
            type="button"
            size="sm"
            variant={overviewMode === "access" ? "secondary" : "ghost"}
            className="h-7 gap-1.5 text-[11px]"
            onClick={() => {
              setOverviewMode("access");
              setSelected(null);
            }}
          >
            <ShieldIcon className="size-3.5" />
            Access
          </Button>
        </div>
        <p className="text-muted-foreground hidden text-[11px] sm:block">
          {overviewMode === "topology"
            ? "Live mesh map across networks"
            : "Who can access where and why"}
        </p>
      </div>
      <div className="min-h-0 flex-1">
        {overviewMode === "access" ? (
          <AccessCanvas orgId={orgId} />
        ) : (
          <TopologyOverviewCanvas orgId={orgId} />
        )}
      </div>
    </div>
  );
}
