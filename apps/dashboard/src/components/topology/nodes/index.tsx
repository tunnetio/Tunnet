import { Handle, type NodeProps, Position } from "@xyflow/react";
import {
  BoxIcon,
  GlobeIcon,
  HardDriveIcon,
  LaptopIcon,
  PlusIcon,
  RadioIcon,
  ServerIcon,
  Share2Icon,
} from "lucide-react";

import type {
  AccessDestinationFlowNode,
  AccessPolicyFlowNode,
  AccessSourceFlowNode,
  EnrollFlowNode,
  ExitFlowNode,
  GatewayFlowNode,
  HostnameFlowNode,
  K8sFlowNode,
  NetworkGroupFlowNode,
  PeerFlowNode,
  RelayFlowNode,
  ServeFlowNode,
  SubnetFlowNode,
  TunnelFlowNode,
} from "@/components/topology/types";
import { cn } from "@/lib/utils";

function NodeShell({
  selected,
  className,
  children,
  handles = "both",
  accent,
}: {
  selected?: boolean;
  className?: string;
  children: React.ReactNode;
  handles?: "both" | "target" | "source" | "none";
  accent?: string;
}) {
  return (
    <div
      className={cn(
        "relative min-w-[140px] rounded-lg border bg-card px-3 py-2 shadow-sm",
        selected && "ring-2 ring-ring",
        className,
      )}
      style={accent ? { borderColor: accent } : undefined}
    >
      {(handles === "both" || handles === "target") && (
        <Handle
          type="target"
          position={Position.Left}
          className="!size-2.5 !border-border !bg-muted-foreground"
        />
      )}
      {children}
      {(handles === "both" || handles === "source") && (
        <Handle
          type="source"
          position={Position.Right}
          className="!size-2.5 !border-border !bg-muted-foreground"
        />
      )}
    </div>
  );
}

export function NetworkGroupNode({
  data,
  selected,
}: NodeProps<NetworkGroupFlowNode>) {
  const healthColor =
    data.health === "online"
      ? "bg-emerald-500"
      : data.health === "degraded"
        ? "bg-amber-500"
        : "bg-slate-400";
  return (
    <div
      className={cn(
        "relative h-full w-full rounded-xl border border-border/80 bg-card/40 shadow-sm",
        selected && "ring-2 ring-ring",
      )}
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 flex items-center gap-2 border-b border-border/50 bg-card/80 px-3 py-2 backdrop-blur">
        <Share2Icon className="text-primary size-3.5 shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12px] font-medium tracking-tight">
            {data.name}
          </div>
          <div className="text-muted-foreground font-mono text-[10px]">
            {data.cidr} · {data.onlinePeers}/{data.totalPeers} online
          </div>
        </div>
        <span className={cn("size-2 shrink-0 rounded-full", healthColor)} />
      </div>
      {data.totalPeers === 0 ? (
        <div className="text-muted-foreground absolute inset-0 flex items-center justify-center pt-8 text-[11px]">
          Empty network
        </div>
      ) : null}
    </div>
  );
}

function PeerLikeNode({
  data,
  selected,
  icon,
  accent,
}: {
  data: PeerFlowNode["data"];
  selected?: boolean;
  icon: React.ReactNode;
  accent?: string;
}) {
  const online = data.topology.online;
  return (
    <NodeShell selected={selected} accent={accent} className="min-w-[168px]">
      <div className="flex items-center gap-2">
        <div className="text-muted-foreground shrink-0">{icon}</div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-[12px] font-medium">
              {data.topology.label}
            </span>
            <span
              className={cn(
                "size-1.5 shrink-0 rounded-full",
                online ? "bg-emerald-500" : "bg-slate-400",
              )}
            />
          </div>
          <div className="text-muted-foreground font-mono text-[10px]">
            {data.topology.assignedIp ?? data.topology.secondary ?? "—"}
          </div>
        </div>
      </div>
      {((data.topology.serveCount ?? 0) > 0 ||
        (data.topology.tunnelCount ?? 0) > 0) && (
        <div className="text-muted-foreground mt-1.5 flex gap-2 text-[10px]">
          {(data.topology.serveCount ?? 0) > 0 && (
            <span>{data.topology.serveCount} serve</span>
          )}
          {(data.topology.tunnelCount ?? 0) > 0 && (
            <span>{data.topology.tunnelCount} tunnel</span>
          )}
        </div>
      )}
      <Handle
        id="serve"
        type="source"
        position={Position.Bottom}
        className="!left-[30%] !size-2 !border-indigo-400 !bg-indigo-500"
        style={{ left: "30%" }}
      />
      <Handle
        id="tunnel"
        type="source"
        position={Position.Bottom}
        className="!left-[70%] !size-2 !border-purple-400 !bg-purple-500"
        style={{ left: "70%" }}
      />
    </NodeShell>
  );
}

export function PeerNode(props: NodeProps<PeerFlowNode>) {
  return <PeerLikeNode {...props} icon={<LaptopIcon className="size-3.5" />} />;
}

export function GatewayNode(props: NodeProps<GatewayFlowNode>) {
  return (
    <PeerLikeNode
      {...props}
      icon={<ServerIcon className="size-3.5" />}
      accent="#f59e0b"
    />
  );
}

export function K8sNode(props: NodeProps<K8sFlowNode>) {
  return (
    <PeerLikeNode
      {...props}
      icon={<BoxIcon className="size-3.5" />}
      accent="#22d3ee"
    />
  );
}

function ResourceNode({
  data,
  selected,
  icon,
  accent,
}: {
  data: {
    topology: {
      label: string;
      secondary?: string | null;
      cidr?: string | null;
    };
  };
  selected?: boolean;
  icon: React.ReactNode;
  accent: string;
}) {
  return (
    <NodeShell selected={selected} accent={accent} className="min-w-[128px]">
      <div className="flex items-center gap-2">
        <div style={{ color: accent }}>{icon}</div>
        <div className="min-w-0">
          <div className="truncate text-[11px] font-medium">
            {data.topology.label}
          </div>
          <div className="text-muted-foreground font-mono text-[10px]">
            {data.topology.cidr ?? data.topology.secondary ?? ""}
          </div>
        </div>
      </div>
    </NodeShell>
  );
}

export function RelayNode({ data, selected }: NodeProps<RelayFlowNode>) {
  return (
    <ResourceNode
      data={data}
      selected={selected}
      icon={<RadioIcon className="size-3.5" />}
      accent="#ef4444"
    />
  );
}

export function SubnetNode({ data, selected }: NodeProps<SubnetFlowNode>) {
  return (
    <ResourceNode
      data={data}
      selected={selected}
      icon={<HardDriveIcon className="size-3.5" />}
      accent="#34d399"
    />
  );
}

export function HostnameNode({ data, selected }: NodeProps<HostnameFlowNode>) {
  return (
    <ResourceNode
      data={data}
      selected={selected}
      icon={<GlobeIcon className="size-3.5" />}
      accent="#0ea5e9"
    />
  );
}

export function ExitNode({ data, selected }: NodeProps<ExitFlowNode>) {
  return (
    <ResourceNode
      data={data}
      selected={selected}
      icon={<GlobeIcon className="size-3.5" />}
      accent="#f59e0b"
    />
  );
}

export function ServeNode({ data, selected }: NodeProps<ServeFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      accent="#6366f1"
      className="min-w-[110px] py-1.5"
    >
      <div className="truncate text-[11px] font-medium text-indigo-600 dark:text-indigo-400">
        {data.label}
      </div>
      {data.secondary ? (
        <div className="text-muted-foreground font-mono text-[9px]">
          {data.secondary}
        </div>
      ) : null}
    </NodeShell>
  );
}

export function TunnelNode({ data, selected }: NodeProps<TunnelFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      accent="#a855f7"
      className="min-w-[110px] py-1.5"
    >
      <div className="truncate text-[11px] font-medium text-purple-600 dark:text-purple-400">
        {data.label}
      </div>
      {data.secondary ? (
        <div className="text-muted-foreground font-mono text-[9px]">
          {data.secondary}
        </div>
      ) : null}
    </NodeShell>
  );
}

export function EnrollNode({ data, selected }: NodeProps<EnrollFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      handles="target"
      className="border-dashed border-muted-foreground/40 bg-muted/30 min-w-[130px]"
    >
      <div className="text-muted-foreground flex items-center gap-1.5 text-[11px]">
        <PlusIcon className="size-3.5" />
        {data.label}
      </div>
    </NodeShell>
  );
}

export function AccessSourceNode({
  data,
  selected,
}: NodeProps<AccessSourceFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      className="min-w-[200px] px-3.5 py-3"
      handles="source"
    >
      <div className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">
        Source
      </div>
      <div className="flex items-center gap-2">
        <span
          className={cn(
            "size-2 shrink-0 rounded-full",
            data.online === true
              ? "bg-emerald-500"
              : data.online === false
                ? "bg-slate-400"
                : "bg-primary/60",
          )}
        />
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium">{data.title}</div>
          {data.subtitle ? (
            <div className="text-muted-foreground font-mono text-[10px]">
              {data.subtitle}
            </div>
          ) : null}
        </div>
      </div>
      {data.tags && data.tags.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1">
          {data.tags.slice(0, 4).map((tag) => (
            <span
              key={tag}
              className="bg-muted rounded px-1.5 py-0.5 font-mono text-[9px]"
            >
              {tag}
            </span>
          ))}
        </div>
      ) : null}
    </NodeShell>
  );
}

export function AccessPolicyNode({
  data,
  selected,
}: NodeProps<AccessPolicyFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      className="min-w-[200px] px-3 py-2.5"
      accent={data.action === "allow" ? "#3b82f6" : "#ef4444"}
    >
      <div className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">
        Policy
      </div>
      <div className="truncate text-[12px] font-medium">{data.title}</div>
      <div className="text-muted-foreground mt-0.5 font-mono text-[10px]">
        {data.subtitle}
      </div>
    </NodeShell>
  );
}

export function AccessDestinationNode({
  data,
  selected,
}: NodeProps<AccessDestinationFlowNode>) {
  return (
    <NodeShell
      selected={selected}
      className="min-w-[180px] px-3 py-2.5"
      handles="target"
    >
      <div className="text-muted-foreground mb-1 text-[10px] tracking-wide uppercase">
        Destination
      </div>
      <div className="truncate text-[12px] font-medium">{data.title}</div>
      <div className="text-muted-foreground mt-0.5 text-[10px]">
        {data.subtitle}
        {data.peerCount != null ? ` · ${data.peerCount}` : ""}
      </div>
    </NodeShell>
  );
}
