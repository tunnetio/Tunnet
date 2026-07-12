import { useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import type { Device, TopologyNode } from "@tuntun/api/management";
import {
  ChevronRightIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  WaypointsIcon,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";

import { DataTable } from "@/components/app/data-table";
import { EnrollmentTokenDialog } from "@/components/app/enrollment-token-dialog";
import { LastSeenCell } from "@/components/app/last-seen-cell";
import { MachineAddressPopover } from "@/components/app/machine-address-popover";
import { NetworkForceGraph } from "@/components/app/network-force-graph";
import { PageHeader } from "@/components/app/page-header";
import { StatusBadge } from "@/components/app/status-badge";
import { TopologyNodeSheet } from "@/components/app/topology-node-sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { isAdminRole, useMemberRole } from "@/hooks/use-member-role";
import {
  seedPresenceCache,
  usePresenceStream,
} from "@/hooks/use-presence-stream";
import { useActiveOrganization } from "@/lib/auth-client";
import { getMachinePresence } from "@/lib/machine-utils";
import { usePresenceClock } from "@/lib/presence-clock";
import {
  useDevices,
  useHostnameRoutes,
  useNetwork,
  useSubnetRoutes,
  useTopology,
} from "@/lib/queries/management";
import { cn } from "@/lib/utils";

export function NetworkOverviewPage() {
  const { networkId } = useParams({ from: "/app/networks/$networkId/" });
  const queryClient = useQueryClient();
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const now = usePresenceClock();

  const { data: network } = useNetwork(orgId, networkId);
  const { data: devices, isPending: devicesPending } = useDevices(
    orgId,
    networkId,
  );
  const { data: topology, isPending: topoPending } = useTopology(
    orgId,
    networkId,
  );
  const { data: subnetRoutes } = useSubnetRoutes(orgId, networkId);
  const { data: hostnameRoutes } = useHostnameRoutes(orgId, networkId);

  usePresenceStream(orgId);
  useEffect(() => {
    if (orgId && devices) seedPresenceCache(queryClient, orgId, devices);
  }, [orgId, devices, queryClient]);

  const [statusFilter, setStatusFilter] = useState<
    "all" | "online" | "offline"
  >("all");
  const [kindFilter, setKindFilter] = useState<"all" | TopologyNode["kind"]>(
    "all",
  );
  const [heatmap, setHeatmap] = useState(false);
  const [search, setSearch] = useState("");
  const [tableStatus, setTableStatus] = useState<"all" | "online" | "offline">(
    "all",
  );
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [enrollOpen, setEnrollOpen] = useState(false);

  const onlineCount = useMemo(() => {
    if (!devices) return 0;
    return devices.filter((d) => getMachinePresence(d, now) === "online")
      .length;
  }, [devices, now]);

  const routeCount =
    (subnetRoutes?.length ?? 0) + (hostnameRoutes?.length ?? 0);

  const filteredDevices = useMemo(() => {
    const list = devices ?? [];
    const q = search.trim().toLowerCase();
    return list.filter((d) => {
      const presence = getMachinePresence(d, now);
      if (tableStatus === "online" && presence !== "online") return false;
      if (tableStatus === "offline" && presence === "online") return false;
      if (!q) return true;
      return (
        d.name.toLowerCase().includes(q) ||
        d.hostname.toLowerCase().includes(q) ||
        d.assignedIp.includes(q) ||
        (d.os?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [devices, search, tableStatus, now]);

  const columns = useMemo<ColumnDef<Device>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        cell: ({ row }) => (
          <Link
            to="/app/machines/$endpointId"
            params={{ endpointId: row.original.endpointId }}
            className="font-medium hover:underline"
          >
            {row.original.name}
          </Link>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge orgId={orgId} device={row.original} />,
      },
      {
        id: "ip",
        header: "Mesh IP",
        cell: ({ row }) =>
          orgId ? (
            <MachineAddressPopover
              orgId={orgId}
              endpointId={row.original.endpointId}
              assignedIp={row.original.assignedIp}
              ipv6Enabled={row.original.ipv6Enabled}
              tenantIpv6={row.original.tenantIpv6}
            />
          ) : (
            <span className="font-mono text-xs">{row.original.assignedIp}</span>
          ),
      },
      {
        id: "os",
        header: "OS",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-[13px]">
            {row.original.os ?? "—"}
          </span>
        ),
      },
      {
        id: "lastSeen",
        header: "Last seen",
        cell: ({ row }) => <LastSeenCell orgId={orgId} device={row.original} />,
      },
    ],
    [orgId],
  );

  if (!network) return null;

  return (
    <div className="space-y-6">
      <PageHeader
        dense
        title={network.name}
        description="Private mesh between your machines — route LAN, hostnames, and exits without bastions."
        actions={
          isAdmin ? (
            <Button size="sm" onClick={() => setEnrollOpen(true)}>
              <PlusIcon className="size-3.5" />
              Add machine
            </Button>
          ) : undefined
        }
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="min-w-0 space-y-5">
          <div className="panel overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 px-3 py-2.5">
              <div className="min-w-0">
                <span className="text-[13px] font-medium tracking-tight">
                  Mesh
                </span>
                <p className="text-muted-foreground text-[11px]">
                  {onlineCount} online · {devices?.length ?? 0} machines
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Select
                  value={statusFilter}
                  onValueChange={(v) =>
                    v && setStatusFilter(v as typeof statusFilter)
                  }
                >
                  <SelectTrigger className="h-8 w-[130px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    <SelectItem value="online">Online</SelectItem>
                    <SelectItem value="offline">Offline</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={kindFilter}
                  onValueChange={(v) =>
                    v && setKindFilter(v as typeof kindFilter)
                  }
                >
                  <SelectTrigger className="h-8 w-[120px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All types</SelectItem>
                    <SelectItem value="machine">Machines</SelectItem>
                    <SelectItem value="subnet">Subnets</SelectItem>
                    <SelectItem value="hostname">Hostnames</SelectItem>
                    <SelectItem value="exit">Exits</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  size="sm"
                  variant={heatmap ? "secondary" : "outline"}
                  className="h-8 text-xs"
                  onClick={() => setHeatmap((v) => !v)}
                >
                  Heatmap
                </Button>
              </div>
            </div>
            {topoPending ? (
              <Skeleton className="h-[360px] w-full rounded-none sm:h-[440px]" />
            ) : (
              <NetworkForceGraph
                nodes={topology?.nodes ?? []}
                edges={topology?.edges ?? []}
                statusFilter={statusFilter}
                kindFilter={kindFilter}
                heatmap={heatmap}
                onSelect={setSelected}
                className="rounded-none border-0"
              />
            )}
          </div>

          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[200px] flex-1">
                <SearchIcon className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search nodes…"
                  className="h-8 pl-8 text-xs"
                />
              </div>
              <Select
                value={tableStatus}
                onValueChange={(v) =>
                  v && setTableStatus(v as typeof tableStatus)
                }
              >
                <SelectTrigger className="h-8 w-[100px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="online">Online</SelectItem>
                  <SelectItem value="offline">Offline</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {devicesPending ? (
              <Skeleton className="h-40 w-full" />
            ) : filteredDevices.length === 0 ? (
              <div className="text-muted-foreground flex h-28 items-center justify-center rounded-lg border border-dashed border-border/60 text-sm">
                No machines
              </div>
            ) : (
              <div className="panel overflow-hidden">
                <DataTable
                  columns={columns}
                  data={filteredDevices}
                  getRowId={(row) => row.endpointId}
                />
              </div>
            )}
          </div>
        </div>

        <aside className="space-y-4">
          <section className="space-y-2">
            <h2 className="text-muted-foreground text-[11px] font-medium tracking-wider uppercase">
              Usage
            </h2>
            <div className="grid grid-cols-3 gap-2 lg:grid-cols-1">
              <StatTile label="Online" value={onlineCount} />
              <StatTile label="Mesh nodes" value={devices?.length ?? 0} />
              <StatTile label="Routes" value={routeCount} />
            </div>
          </section>

          <section className="space-y-2">
            <h2 className="text-muted-foreground text-[11px] font-medium tracking-wider uppercase">
              Next steps
            </h2>
            <div className="space-y-2">
              <RailLink
                to="/app/networks/$networkId/enrollment"
                params={{ networkId }}
                title="Connect a machine"
                body="Install the agent and join with an enrollment token."
                icon={<PlusIcon className="size-4" />}
              />
              <RailLink
                to="/app/networks/$networkId/routes"
                params={{ networkId }}
                title="Advertise routes"
                body="Expose LAN CIDRs or hostnames through a gateway."
                icon={<WaypointsIcon className="size-4" />}
              />
              <RailLink
                to="/app/networks/$networkId/access"
                params={{ networkId }}
                title="Tighten access"
                body="Policies control who can talk to whom on the mesh."
                icon={<ShieldIcon className="size-4" />}
              />
            </div>
          </section>

          <section className="panel space-y-2.5 p-3 text-[12px]">
            <div className="text-muted-foreground font-medium tracking-wide uppercase">
              Network
            </div>
            <MetaRow label="CIDR" value={network.cidr} mono />
            <MetaRow label="MTU" value={String(network.mtu)} />
            <MetaRow label="Version" value={String(network.version)} />
          </section>
        </aside>
      </div>

      <TopologyNodeSheet
        node={selected}
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      />

      {orgId ? (
        <EnrollmentTokenDialog
          open={enrollOpen}
          onOpenChange={setEnrollOpen}
          orgId={orgId}
          defaultNetworkId={networkId}
        />
      ) : null}
    </div>
  );
}

function StatTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="panel px-3 py-2.5">
      <div className="text-muted-foreground text-[11px]">{label}</div>
      <div className="mt-0.5 text-xl font-semibold tabular-nums tracking-tight">
        {value}
      </div>
    </div>
  );
}

function MetaRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn(mono && "font-mono", "text-foreground")}>
        {value}
      </span>
    </div>
  );
}

function RailLink({
  to,
  params,
  title,
  body,
  icon,
}: {
  to:
    | "/app/networks/$networkId/enrollment"
    | "/app/networks/$networkId/routes"
    | "/app/networks/$networkId/access";
  params: { networkId: string };
  title: string;
  body: string;
  icon: ReactNode;
}) {
  return (
    <Link
      to={to}
      params={params}
      className="panel hover:border-border group flex items-start gap-3 p-3 transition-colors"
    >
      <span className="bg-secondary text-muted-foreground group-hover:text-foreground mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md">
        {icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-medium">{title}</span>
        <span className="text-muted-foreground mt-0.5 block text-[12px] leading-snug">
          {body}
        </span>
      </span>
      <ChevronRightIcon className="text-muted-foreground mt-1 size-4 shrink-0 opacity-60 transition-transform group-hover:translate-x-0.5" />
    </Link>
  );
}
