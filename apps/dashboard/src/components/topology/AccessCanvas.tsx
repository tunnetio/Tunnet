import { useQueries } from "@tanstack/react-query";
import {
  Background,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import { useEffect, useMemo, useRef } from "react";

import { DetailPanel } from "@/components/topology/DetailPanel";
import {
  mergeFlowEdges,
  mergeFlowNodes,
} from "@/components/topology/layout/elk";
import { accessToFlow } from "@/components/topology/mappers/accessToFlow";
import {
  topologyEdgeTypes,
  topologyNodeTypes,
} from "@/components/topology/registry";
import { useTopologyUi } from "@/components/topology/TopologyProvider";
import type {
  AccessDestinationNodeData,
  AccessEntityTab,
  AccessPolicyNodeData,
} from "@/components/topology/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getMachinePresence } from "@/lib/machine-utils";
import { createManagementClient } from "@/lib/management-client";
import { usePresenceClock } from "@/lib/presence-clock";
import {
  useMachines,
  useNetworks,
  useOrganizationPolicies,
  useServes,
  useTagDefinitions,
} from "@/lib/queries/management";
import { queryKeys } from "@/lib/query-keys";
import { cn } from "@/lib/utils";

function AccessCanvasInner({ orgId }: { orgId: string }) {
  const now = usePresenceClock();
  const {
    accessTab,
    setAccessTab,
    accessSource,
    setAccessSource,
    searchQuery,
    setSearchQuery,
    selected,
    setSelected,
  } = useTopologyUi();

  const { data: networks, isPending: networksPending } = useNetworks(orgId);
  const { data: machines, isPending: machinesPending } = useMachines(orgId);
  const { data: orgPolicies } = useOrganizationPolicies(orgId);
  const { data: tags } = useTagDefinitions(orgId);
  const { data: serves } = useServes(orgId);

  const networkPolicyQueries = useQueries({
    queries: (networks ?? []).map((network) => ({
      queryKey: queryKeys.policies(orgId, network.id),
      queryFn: async () => {
        const { policies } = await createManagementClient(orgId).listPolicies(
          network.id,
        );
        return policies;
      },
      enabled: Boolean(orgId && networks?.length),
    })),
  });

  const policyIdsKey = [
    ...(orgPolicies ?? []).map((p) => p.id),
    ...networkPolicyQueries.flatMap((q) => (q.data ?? []).map((p) => p.id)),
  ].join(",");

  // biome-ignore lint/correctness/useExhaustiveDependencies: useQueries identity is unstable; keyed by policyIdsKey
  const allPolicies = useMemo(() => {
    return [
      ...(orgPolicies ?? []),
      ...networkPolicyQueries.flatMap((q) => q.data ?? []),
    ];
  }, [orgPolicies, policyIdsKey]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const lastFingerprint = useRef("");
  const didFitView = useRef(false);

  const fingerprint = useMemo(
    () =>
      JSON.stringify({
        source: accessSource,
        policies: policyIdsKey,
        machines: machines?.map((m) => [
          m.endpointId,
          m.hostname,
          m.assignedIp,
          m.agentConnected,
          m.status,
        ]),
        networks: networks?.map((n) => [n.id, n.name, n.cidr]),
        tags: tags?.map((t) => [t.id, t.name]),
        serves: serves?.map((s) => [s.id, s.endpointId, s.localPort]),
        nowBucket: Math.floor(now / 30_000),
      }),
    [accessSource, policyIdsKey, machines, networks, tags, serves, now],
  );

  useEffect(() => {
    if (fingerprint === lastFingerprint.current) return;
    const { nodes: nextNodes, edges: nextEdges } = accessToFlow(
      accessSource,
      allPolicies,
      machines ?? [],
      networks ?? [],
      tags ?? [],
      serves ?? [],
      now,
    );
    lastFingerprint.current = fingerprint;
    setNodes((prev) => mergeFlowNodes(prev, nextNodes as Node[]));
    setEdges((prev) => mergeFlowEdges(prev, nextEdges as Edge[]));
  }, [
    fingerprint,
    accessSource,
    allPolicies,
    machines,
    networks,
    tags,
    serves,
    now,
    setNodes,
    setEdges,
  ]);

  const filteredPeers = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (machines ?? []).filter((m) => {
      if (!q) return true;
      return (
        m.hostname.toLowerCase().includes(q) ||
        m.assignedIp.includes(q) ||
        m.tags.some((t) => t.includes(q))
      );
    });
  }, [machines, searchQuery]);

  const filteredTags = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (tags ?? []).filter((t) => !q || t.name.toLowerCase().includes(q));
  }, [tags, searchQuery]);

  const filteredNetworks = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return (networks ?? []).filter(
      (n) => !q || n.name.toLowerCase().includes(q) || n.cidr.includes(q),
    );
  }, [networks, searchQuery]);

  if (networksPending || machinesPending) {
    return <Skeleton className="h-full w-full" />;
  }

  return (
    <div className="flex h-full min-h-0 w-full">
      <aside className="flex w-64 shrink-0 flex-col border-r border-border/70 bg-card/50">
        <div className="border-b border-border/60 px-3 py-2.5">
          <Tabs
            value={accessTab}
            onValueChange={(v) => {
              if (v) {
                setAccessTab(v as AccessEntityTab);
                setAccessSource(null);
              }
            }}
          >
            <TabsList variant="line" className="w-full justify-start">
              <TabsTrigger value="peers" className="px-2 text-[11px]">
                Peers
              </TabsTrigger>
              <TabsTrigger value="groups" className="px-2 text-[11px]">
                Groups
              </TabsTrigger>
              <TabsTrigger value="tags" className="px-2 text-[11px]">
                Tags
              </TabsTrigger>
            </TabsList>
          </Tabs>
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter…"
            className="mt-2 h-8 text-[12px]"
          />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {accessTab === "peers"
            ? filteredPeers.map((m) => {
                const online = getMachinePresence(m, now) === "online";
                const active =
                  accessSource?.kind === "peer" &&
                  accessSource.endpointId === m.endpointId;
                return (
                  <button
                    key={`${m.networkId}:${m.endpointId}`}
                    type="button"
                    onClick={() =>
                      setAccessSource({
                        kind: "peer",
                        endpointId: m.endpointId,
                        label: m.hostname,
                        networkId: m.networkId,
                      })
                    }
                    className={cn(
                      "hover:bg-muted/60 flex w-full flex-col items-start rounded-md px-2.5 py-2 text-left",
                      active && "bg-muted",
                    )}
                  >
                    <span className="flex items-center gap-1.5 text-[12px] font-medium">
                      <span
                        className={cn(
                          "size-1.5 rounded-full",
                          online ? "bg-emerald-500" : "bg-slate-400",
                        )}
                      />
                      {m.hostname}
                    </span>
                    <span className="text-muted-foreground font-mono text-[10px]">
                      {m.assignedIp}
                    </span>
                  </button>
                );
              })
            : null}

          {accessTab === "groups"
            ? filteredNetworks.map((n) => {
                const active =
                  accessSource?.kind === "group" &&
                  accessSource.networkId === n.id;
                const count =
                  machines?.filter((m) => m.networkId === n.id).length ?? 0;
                return (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() =>
                      setAccessSource({
                        kind: "group",
                        networkId: n.id,
                        label: n.name,
                      })
                    }
                    className={cn(
                      "hover:bg-muted/60 flex w-full flex-col items-start rounded-md px-2.5 py-2 text-left",
                      active && "bg-muted",
                    )}
                  >
                    <span className="text-[12px] font-medium">{n.name}</span>
                    <span className="text-muted-foreground font-mono text-[10px]">
                      {n.cidr} · {count} peers
                    </span>
                  </button>
                );
              })
            : null}

          {accessTab === "tags"
            ? filteredTags.map((t) => {
                const active =
                  accessSource?.kind === "tag" && accessSource.tag === t.name;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() =>
                      setAccessSource({
                        kind: "tag",
                        tag: t.name,
                        label: t.name,
                      })
                    }
                    className={cn(
                      "hover:bg-muted/60 flex w-full flex-col items-start rounded-md px-2.5 py-2 text-left",
                      active && "bg-muted",
                    )}
                  >
                    <span className="font-mono text-[12px] font-medium">
                      {t.name}
                    </span>
                    <span className="text-muted-foreground text-[10px]">
                      {t.machineCount ?? 0} machines
                    </span>
                  </button>
                );
              })
            : null}

          {accessTab === "tags" && filteredTags.length === 0 ? (
            <p className="text-muted-foreground px-2 py-4 text-[11px]">
              No tags defined.
            </p>
          ) : null}
        </div>
      </aside>

      <div className="relative min-h-0 min-w-0 flex-1">
        {!accessSource ? (
          <div className="text-muted-foreground absolute inset-0 z-10 flex items-center justify-center text-[13px]">
            Select a peer, group, or tag to see its access map
          </div>
        ) : null}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, node) => {
            if (node.type === "accessPolicy") {
              setSelected({
                kind: "accessPolicy",
                data: node.data as AccessPolicyNodeData,
              });
            } else if (node.type === "accessDestination") {
              setSelected({
                kind: "accessDestination",
                data: node.data as AccessDestinationNodeData,
              });
            }
          }}
          nodeTypes={topologyNodeTypes}
          edgeTypes={topologyEdgeTypes}
          nodesConnectable={false}
          nodesDraggable={false}
          proOptions={{ hideAttribution: true }}
          className="mesh-surface"
          onInit={(instance) => {
            if (didFitView.current) return;
            didFitView.current = true;
            void instance.fitView({ padding: 0.2 });
          }}
        >
          <Background gap={16} size={1} color="oklch(1 0 0 / 0.06)" />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable className="!bg-card/90" />
          {accessSource ? (
            <Panel position="top-left" className="m-3">
              <div className="rounded-lg border border-border/70 bg-card/95 px-3 py-2 text-[12px] shadow-sm">
                <span className="text-muted-foreground">Access map for </span>
                <span className="font-medium">{accessSource.label}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="ml-2 h-7 text-[11px]"
                  onClick={() => setAccessSource(null)}
                >
                  Clear
                </Button>
              </div>
            </Panel>
          ) : null}
          {accessSource && nodes.length <= 1 ? (
            <Panel position="top-center" className="m-8">
              <div className="rounded-lg border border-border/70 bg-card px-5 py-4 text-center text-[12px] shadow-sm">
                No policies match this source.
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
    </div>
  );
}

export function AccessCanvas({ orgId }: { orgId: string }) {
  return (
    <ReactFlowProvider>
      <AccessCanvasInner orgId={orgId} />
    </ReactFlowProvider>
  );
}
