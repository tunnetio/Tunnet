import { Link } from "@tanstack/react-router";
import { XIcon } from "lucide-react";
import { useState } from "react";
import { CreateServeDialog } from "@/components/app/create-serve-dialog";
import { CreateTunnelDialog } from "@/components/app/create-tunnel-dialog";
import { useTopologyUi } from "@/components/topology/TopologyProvider";
import { Button } from "@/components/ui/button";
import { deviceKindLabel, deviceTypeLabel } from "@/lib/device-type";
import { cn } from "@/lib/utils";

export function DetailPanel({
  orgId,
  networkId,
}: {
  orgId?: string;
  networkId?: string;
}) {
  const { selected, setSelected, setConnectIntent } = useTopologyUi();
  const [serveOpen, setServeOpen] = useState(false);
  const [tunnelOpen, setTunnelOpen] = useState(false);

  if (!selected) return null;

  return (
    <aside className="pointer-events-auto flex h-full w-full max-w-sm flex-col bg-card/95 shadow-lg backdrop-blur">
      <div className="flex items-start justify-between gap-2 border-b border-border/60 px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-[14px] font-medium tracking-tight">
            {selected.kind === "topology"
              ? selected.node.label
              : selected.kind === "network"
                ? selected.data.name
                : selected.kind === "accessPolicy" ||
                    selected.kind === "accessDestination"
                  ? selected.data.title
                  : selected.data.label}
          </h2>
          <p className="text-muted-foreground mt-0.5 font-mono text-[11px]">
            {selected.kind === "topology"
              ? (selected.node.secondary ?? selected.node.kind)
              : selected.kind === "network"
                ? selected.data.cidr
                : selected.kind === "accessPolicy"
                  ? selected.data.subtitle
                  : selected.kind === "accessDestination"
                    ? (selected.data.subtitle ?? selected.data.destKind)
                    : (selected.data.secondary ?? selected.kind)}
          </p>
        </div>
        <Button
          type="button"
          size="icon-sm"
          variant="ghost"
          onClick={() => setSelected(null)}
        >
          <XIcon className="size-4" />
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {selected.kind === "topology" ? (
          <div className="space-y-0">
            <MetaRow label="Kind" value={selected.node.kind} mono />
            {selected.node.kind === "machine" && selected.node.deviceType ? (
              <MetaRow
                label="Type"
                value={deviceTypeLabel(selected.node.deviceType)}
              />
            ) : null}
            {selected.node.kind === "machine" && selected.node.nodeKind ? (
              <MetaRow
                label="Node kind"
                value={
                  deviceKindLabel(selected.node.nodeKind) ??
                  selected.node.nodeKind
                }
                mono
              />
            ) : null}
            {selected.node.assignedIp ? (
              <MetaRow label="Mesh IP" value={selected.node.assignedIp} mono />
            ) : null}
            {selected.node.cidr ? (
              <MetaRow label="CIDR" value={selected.node.cidr} mono />
            ) : null}
            {selected.node.kind === "machine" ? (
              <MetaRow
                label="Presence"
                value={selected.node.online ? "Online" : "Offline"}
                tone={selected.node.online ? "ok" : "muted"}
              />
            ) : null}
            {(selected.node.serveCount ?? 0) > 0 ? (
              <MetaRow
                label="Serves"
                value={String(selected.node.serveCount)}
              />
            ) : null}
            {(selected.node.tunnelCount ?? 0) > 0 ? (
              <MetaRow
                label="Tunnels"
                value={String(selected.node.tunnelCount)}
              />
            ) : null}
          </div>
        ) : null}

        {selected.kind === "network" ? (
          <div className="space-y-0">
            <MetaRow
              label="Peers"
              value={`${selected.data.onlinePeers}/${selected.data.totalPeers} online`}
            />
            <MetaRow
              label="Tunnels"
              value={String(selected.data.tunnelCount)}
            />
            <MetaRow label="Serves" value={String(selected.data.serveCount)} />
            <MetaRow label="Health" value={selected.data.health} />
          </div>
        ) : null}

        {selected.kind === "serve" || selected.kind === "tunnel" ? (
          <div className="space-y-0">
            <MetaRow label="Type" value={selected.kind} />
            {selected.data.secondary ? (
              <MetaRow label="Detail" value={selected.data.secondary} mono />
            ) : null}
          </div>
        ) : null}

        {selected.kind === "accessPolicy" ? (
          <div className="space-y-0">
            <MetaRow label="Action" value={selected.data.action} />
            <MetaRow label="Rule" value={selected.data.subtitle} mono />
            {selected.data.networkId ? (
              <MetaRow label="Network" value={selected.data.networkId} mono />
            ) : (
              <MetaRow label="Scope" value="organization" />
            )}
          </div>
        ) : null}

        {selected.kind === "accessDestination" ? (
          <div className="space-y-0">
            <MetaRow label="Kind" value={selected.data.destKind} />
            {selected.data.peerCount != null ? (
              <MetaRow label="Peers" value={String(selected.data.peerCount)} />
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="flex flex-col gap-2 border-t border-border/60 px-4 py-3">
        {selected.kind === "topology" && selected.node.endpointId ? (
          <>
            <Button
              size="sm"
              variant="secondary"
              className="justify-start"
              nativeButton={false}
              render={
                <Link
                  to="/app/machines/$endpointId"
                  params={{ endpointId: selected.node.endpointId }}
                />
              }
            >
              Open machine detail
            </Button>
            {orgId && networkId ? (
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="flex-1"
                  onClick={() => setServeOpen(true)}
                >
                  Add serve
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="flex-1"
                  onClick={() => setTunnelOpen(true)}
                >
                  Add tunnel
                </Button>
              </div>
            ) : null}
            {orgId && networkId ? (
              <>
                <CreateServeDialog
                  orgId={orgId}
                  open={serveOpen}
                  onOpenChange={setServeOpen}
                  defaultEndpointId={selected.node.endpointId}
                  defaultNetworkId={networkId}
                />
                <CreateTunnelDialog
                  orgId={orgId}
                  open={tunnelOpen}
                  onOpenChange={setTunnelOpen}
                  defaultEndpointId={selected.node.endpointId}
                  defaultNetworkId={networkId}
                />
              </>
            ) : null}
          </>
        ) : null}

        {selected.kind === "network" ? (
          <div className="flex flex-col gap-2">
            <Button
              size="sm"
              variant="secondary"
              className="justify-start"
              nativeButton={false}
              render={
                <Link
                  to="/app/networks/$networkId"
                  params={{ networkId: selected.data.networkId }}
                />
              }
            >
              Open mesh
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="justify-start"
              nativeButton={false}
              render={
                <Link
                  to="/app/networks/$networkId/access"
                  params={{ networkId: selected.data.networkId }}
                />
              }
            >
              View ACLs
            </Button>
            {orgId ? (
              <Button
                size="sm"
                variant="outline"
                className="justify-start"
                onClick={() =>
                  setConnectIntent({
                    type: "enroll",
                    networkId: selected.data.networkId,
                  })
                }
              >
                Add peer
              </Button>
            ) : null}
          </div>
        ) : null}

        {selected.kind === "serve" ? (
          <Button
            size="sm"
            variant="secondary"
            className="justify-start"
            nativeButton={false}
            render={
              <Link
                to="/app/serves/$serveId"
                params={{ serveId: selected.data.serveId }}
              />
            }
          >
            Open serve
          </Button>
        ) : null}

        {selected.kind === "accessPolicy" && selected.data.networkId ? (
          <Button
            size="sm"
            variant="secondary"
            className="justify-start"
            nativeButton={false}
            render={
              <Link
                to="/app/networks/$networkId/access"
                params={{ networkId: selected.data.networkId }}
              />
            }
          >
            Edit in Access tab
          </Button>
        ) : null}

        {selected.kind === "accessPolicy" && !selected.data.networkId ? (
          <Button
            size="sm"
            variant="secondary"
            className="justify-start"
            nativeButton={false}
            render={<Link to="/app/access" />}
          >
            Edit org policies
          </Button>
        ) : null}
      </div>
    </aside>
  );
}

function MetaRow({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  tone?: "ok" | "muted";
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2.5 text-[12px] last:border-0">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span
        className={cn(
          "min-w-0 truncate text-right",
          mono && "font-mono text-[11px]",
          tone === "ok" && "text-emerald-600 dark:text-emerald-400",
          tone === "muted" && "text-muted-foreground",
        )}
      >
        {value}
      </span>
    </div>
  );
}
