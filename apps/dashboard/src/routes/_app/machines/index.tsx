import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import type { RowSelectionState } from "@tanstack/react-table";
import { Button } from "@tunnet/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@tunnet/ui/components/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@tunnet/ui/components/select";
import { Skeleton } from "@tunnet/ui/components/skeleton";
import { MoreHorizontalIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { AddMachinePanel } from "@/components/app/add-machine-panel";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CreateServeDialog } from "@/components/app/create-serve-dialog";
import { CreateTunnelDialog } from "@/components/app/create-tunnel-dialog";
import {
  DataTable,
  type DataTableColumnDef,
} from "@/components/app/data-table";
import { EmptyState } from "@/components/app/empty-state";
import { EnrollmentTokenDialog } from "@/components/app/enrollment-token-dialog";
import { LastSeenCell } from "@/components/app/last-seen-cell";
import { MachineAddressPopover } from "@/components/app/machine-address-popover";
import {
  MachineExpiryDialog,
  MachineLabelsEditor,
} from "@/components/app/machine-labels";
import {
  BulkTagsDialog,
  MachineTagsEditor,
  MachineTagsList,
} from "@/components/app/machine-tags";
import { PageHeader } from "@/components/app/page-header";
import { PageToolbar } from "@/components/app/page-toolbar";
import { StatusBadge } from "@/components/app/status-badge";
import { useCan } from "@/hooks/use-permission";
import { seedPresenceCache } from "@/hooks/use-presence-stream";
import { useActiveOrganization } from "@/lib/auth-client";
import { deviceKindLabel, deviceTypeLabel } from "@/lib/device-type";
import {
  deriveInactivityLimitCompact,
  type ExpiryDevice,
  getExpiryUrgency,
  matchesLabelSearch,
} from "@/lib/machine-expiry";
import type { AggregatedMachine } from "@/lib/machine-utils";
import { getMachinePresence } from "@/lib/machine-utils";
import { formatNetworkName } from "@/lib/network-utils";
import {
  useDeviceMutations,
  useMachines,
  useOrgSettings,
} from "@/lib/queries/management";

export const Route = createFileRoute("/_app/machines/")({
  component: MachinesPage,
});

function MachinesPage() {
  const queryClient = useQueryClient();
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: canManage = false } = useCan(orgId, "device", "update");
  const { data: machines, isPending } = useMachines(orgId);
  const { data: orgSettings } = useOrgSettings(orgId);

  const withOrgExpiry = useCallback(
    (machine: AggregatedMachine): ExpiryDevice => ({
      ...machine,
      orgAutoCleanupEnabled: orgSettings?.machines.autoCleanup.enabled ?? false,
      orgInactivityAfter:
        orgSettings?.machines.autoCleanup.inactivityAfter ?? null,
    }),
    [orgSettings],
  );

  const deviceMutations = useDeviceMutations(orgId);

  useEffect(() => {
    if (orgId && machines) {
      seedPresenceCache(queryClient, orgId, machines);
    }
  }, [orgId, machines, queryClient]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<
    "all" | "online" | "offline" | "pending" | "expired"
  >("all");
  const [typeFilter, setTypeFilter] = useState<"all" | "agent" | "sdk" | "k8s">(
    "all",
  );
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [tunnelOpen, setTunnelOpen] = useState(false);
  const [serveOpen, setServeOpen] = useState(false);
  const [actionEndpointId, setActionEndpointId] = useState<
    string | undefined
  >();
  const [actionNetworkId, setActionNetworkId] = useState<string | undefined>();
  const [actionHostname, setActionHostname] = useState<string | undefined>();
  const [confirmRemove, setConfirmRemove] = useState<{
    networkId: string;
    endpointId: string;
    name: string;
  } | null>(null);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [confirmBulkRemove, setConfirmBulkRemove] = useState(false);
  const [labelsEditor, setLabelsEditor] = useState<AggregatedMachine | null>(
    null,
  );
  const [tagsEditor, setTagsEditor] = useState<AggregatedMachine | null>(null);
  const [bulkTagsOpen, setBulkTagsOpen] = useState(false);
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [expiryEditor, setExpiryEditor] = useState<AggregatedMachine | null>(
    null,
  );

  const pendingCount = useMemo(
    () => (machines ?? []).filter((m) => m.status === "pending").length,
    [machines],
  );

  const filtered = useMemo(() => {
    const now = Date.now();
    let list = machines ?? [];
    if (statusFilter === "all") {
      list = list.filter((m) => getMachinePresence(m, now) !== "expired");
    } else {
      list = list.filter((m) => {
        const presence = getMachinePresence(m, now);
        if (statusFilter === "pending") return presence === "pending";
        if (statusFilter === "online") {
          return (
            presence === "online" ||
            presence === "degraded" ||
            presence === "connecting"
          );
        }
        if (statusFilter === "expired") return presence === "expired";
        return (
          presence !== "online" &&
          presence !== "degraded" &&
          presence !== "connecting" &&
          presence !== "pending" &&
          presence !== "expired"
        );
      });
    }
    const q = search.trim().toLowerCase();
    if (typeFilter !== "all") {
      list = list.filter((m) => m.type === typeFilter);
    }
    if (tagFilter) {
      list = list.filter((m) => (m.tags ?? []).includes(tagFilter));
    }
    if (!q) return list;
    return list.filter((m) => {
      if (matchesLabelSearch(m.labels, q)) return true;
      if (
        (m.tags ?? []).some(
          (t) => t.toLowerCase().includes(q) || `tag:${t}`.includes(q),
        )
      ) {
        return true;
      }
      return (
        m.name.toLowerCase().includes(q) ||
        m.hostname.toLowerCase().includes(q) ||
        m.networkName.toLowerCase().includes(q) ||
        m.assignedIp.includes(q) ||
        (m.tenantIpv6?.includes(q) ?? false) ||
        (m.os?.toLowerCase().includes(q) ?? false) ||
        deviceTypeLabel(m.type).toLowerCase().includes(q) ||
        (m.kind?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [machines, search, statusFilter, typeFilter, tagFilter]);

  const selectedMachines = useMemo(() => {
    if (!filtered.length) return [];
    const selectedIds = new Set(
      Object.entries(rowSelection)
        .filter(([, selected]) => selected)
        .map(([id]) => id),
    );
    return filtered.filter((machine) =>
      selectedIds.has(`${machine.networkId}-${machine.endpointId}`),
    );
  }, [filtered, rowSelection]);

  const columns = useMemo<DataTableColumnDef<AggregatedMachine>[]>(
    () => [
      {
        id: "machine",
        header: "Machine",
        cell: ({ row }) => {
          const machine = row.original;
          const urgency = getExpiryUrgency(withOrgExpiry(machine));
          return (
            <div className="min-w-0 py-0.5">
              <Link
                to="/machines/$endpointId"
                params={{ endpointId: machine.endpointId }}
                className={
                  urgency === "warning"
                    ? "text-[13px] font-medium text-amber-600 hover:underline dark:text-amber-400"
                    : urgency === "critical"
                      ? "text-destructive text-[13px] font-medium hover:underline"
                      : "text-[13px] font-medium hover:underline"
                }
              >
                {machine.name}
              </Link>
              {machine.hostname !== machine.name ? (
                <p className="text-muted-foreground truncate font-mono text-[11px]">
                  {machine.hostname}
                </p>
              ) : null}
            </div>
          );
        },
      },
      {
        id: "status",
        header: "Presence",
        cell: ({ row }) => <StatusBadge orgId={orgId} device={row.original} />,
      },
      {
        id: "network",
        header: "Network",
        cell: ({ row }) => (
          <Link
            to="/networks/$networkId"
            params={{ networkId: row.original.networkId }}
            search={row.original.type === "k8s" ? { kind: "k8s" as const } : {}}
            className="text-[13px] hover:underline"
          >
            {formatNetworkName(row.original.networkName)}
          </Link>
        ),
      },
      {
        id: "address",
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
            <span className="font-mono text-[11px]">
              {row.original.assignedIp}
            </span>
          ),
      },
      {
        id: "tags",
        header: "Tags",
        cell: ({ row }) => (
          <MachineTagsList
            tags={row.original.tags ?? []}
            onTagClick={(tag) =>
              setTagFilter((prev) => (prev === tag ? null : tag))
            }
            empty="—"
          />
        ),
      },
      {
        id: "type",
        header: "Type",
        cell: ({ row }) => (
          <div className="text-[12px]">
            <span>{deviceTypeLabel(row.original.type)}</span>
            {row.original.kind && row.original.type === "k8s" ? (
              <p className="text-muted-foreground text-[11px]">
                {deviceKindLabel(row.original.kind) ?? row.original.kind}
              </p>
            ) : null}
          </div>
        ),
      },
      {
        id: "lastSeen",
        header: "Last seen",
        cell: ({ row }) => <LastSeenCell orgId={orgId} device={row.original} />,
      },
      {
        id: "mesh",
        header: "",
        meta: { headerClassName: "w-[88px]", className: "w-[88px]" },
        cell: ({ row }) => (
          <Link
            to="/networks/$networkId"
            params={{ networkId: row.original.networkId }}
            search={row.original.type === "k8s" ? { kind: "k8s" as const } : {}}
            className="text-muted-foreground hover:text-foreground text-[11px] whitespace-nowrap"
          >
            View on Mesh
          </Link>
        ),
      },
      {
        id: "actions",
        header: "",
        meta: { headerClassName: "w-10" },
        cell: ({ row }) => {
          const machine = row.original;
          return (
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button variant="ghost" size="icon" className="size-8" />
                }
              >
                <MoreHorizontalIcon className="size-4" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuGroup>
                  <DropdownMenuItem
                    render={
                      <Link
                        to="/machines/$endpointId"
                        params={{ endpointId: machine.endpointId }}
                      />
                    }
                  >
                    View details
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    render={
                      <Link
                        to="/networks/$networkId"
                        params={{ networkId: machine.networkId }}
                        search={
                          machine.type === "k8s" ? { kind: "k8s" as const } : {}
                        }
                      />
                    }
                  >
                    Open Mesh
                  </DropdownMenuItem>
                  {canManage ? (
                    machine.status === "pending" ? (
                      <>
                        <DropdownMenuItem
                          onClick={() =>
                            void deviceMutations.approve
                              .mutateAsync({
                                networkId: machine.networkId,
                                endpointId: machine.endpointId,
                              })
                              .then(() => toast.success("Machine approved"))
                              .catch((err: Error) => toast.error(err.message))
                          }
                        >
                          Approve
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          variant="destructive"
                          onClick={() =>
                            void deviceMutations.reject
                              .mutateAsync({
                                networkId: machine.networkId,
                                endpointId: machine.endpointId,
                              })
                              .then(() => toast.success("Machine rejected"))
                              .catch((err: Error) => toast.error(err.message))
                          }
                        >
                          Reject
                        </DropdownMenuItem>
                      </>
                    ) : (
                      <>
                        <DropdownMenuItem
                          onClick={() => {
                            setActionEndpointId(machine.endpointId);
                            setActionNetworkId(machine.networkId);
                            setActionHostname(machine.name);
                            setTunnelOpen(true);
                          }}
                        >
                          Create tunnel
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => {
                            setActionEndpointId(machine.endpointId);
                            setActionNetworkId(machine.networkId);
                            setActionHostname(machine.name);
                            setServeOpen(true);
                          }}
                        >
                          Create serve
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => setLabelsEditor(machine)}
                        >
                          Edit labels
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => setTagsEditor(machine)}
                        >
                          Edit tags
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => setExpiryEditor(machine)}
                        >
                          Set expiry
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() =>
                            void deviceMutations.updateMembership
                              .mutateAsync({
                                networkId: machine.networkId,
                                endpointId: machine.endpointId,
                                status:
                                  machine.status === "active"
                                    ? "suspended"
                                    : "active",
                              })
                              .then(() =>
                                toast.success(
                                  machine.status === "active"
                                    ? "Machine suspended"
                                    : "Machine activated",
                                ),
                              )
                              .catch((err: Error) => toast.error(err.message))
                          }
                        >
                          {machine.status === "active" ? "Suspend" : "Activate"}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          variant="destructive"
                          onClick={() =>
                            setConfirmRemove({
                              networkId: machine.networkId,
                              endpointId: machine.endpointId,
                              name: machine.name,
                            })
                          }
                        >
                          Remove
                        </DropdownMenuItem>
                      </>
                    )
                  ) : null}
                </DropdownMenuGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          );
        },
      },
    ],
    [
      deviceMutations.approve,
      deviceMutations.reject,
      deviceMutations.updateMembership,
      canManage,
      orgId,
      withOrgExpiry,
    ],
  );

  return (
    <>
      <PageHeader
        title="Machines"
        description="Org-wide fleet index - open Mesh for topology, or a machine for detail."
        dense
        actions={
          canManage ? (
            <Button onClick={() => setEnrollOpen(true)}>
              <PlusIcon className="mr-2 size-4" />
              Add machine
            </Button>
          ) : null
        }
      />

      {canManage && pendingCount > 0 ? (
        <div className="bg-amber-500/10 text-amber-950 dark:text-amber-100 mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-500/30 px-4 py-3 text-sm">
          <p>
            {pendingCount === 1
              ? "1 machine is waiting for approval."
              : `${pendingCount} machines are waiting for approval.`}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setStatusFilter("pending")}
          >
            Show pending
          </Button>
        </div>
      ) : null}

      <PageToolbar
        search={search}
        onSearchChange={(value) => {
          setSearch(value);
          setRowSelection({});
        }}
        searchPlaceholder="Search name, tags, labels, network, IP..."
        count={filtered.length}
        countLabel={filtered.length === 1 ? "machine" : "machines"}
        filters={
          <>
            <Select
              value={statusFilter}
              onValueChange={(value) =>
                setStatusFilter(
                  (value as
                    | "all"
                    | "online"
                    | "offline"
                    | "pending"
                    | "expired") ?? "all",
                )
              }
            >
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="online">Online</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={typeFilter}
              onValueChange={(value) =>
                setTypeFilter(
                  (value as "all" | "agent" | "sdk" | "k8s") ?? "all",
                )
              }
            >
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="agent">Agent</SelectItem>
                <SelectItem value="sdk">SDK</SelectItem>
                <SelectItem value="k8s">Kubernetes</SelectItem>
              </SelectContent>
            </Select>
            {tagFilter ? (
              <Button
                variant="secondary"
                size="sm"
                className="h-9 gap-1.5"
                onClick={() => setTagFilter(null)}
              >
                tag:{tagFilter}
                <span className="text-muted-foreground">×</span>
              </Button>
            ) : null}
          </>
        }
        actions={
          canManage && selectedMachines.length > 0 ? (
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={() => setBulkTagsOpen(true)}>
                Assign tag
              </Button>
              <Button
                variant="destructive"
                onClick={() => setConfirmBulkRemove(true)}
              >
                <Trash2Icon className="mr-2 size-4" />
                Remove {selectedMachines.length}{" "}
                {selectedMachines.length === 1 ? "machine" : "machines"}
              </Button>
            </div>
          ) : null
        }
      />

      {isPending ? (
        <Skeleton className="h-64 w-full" />
      ) : filtered.length === 0 ? (
        <EmptyState
          title="No machines yet"
          description="Create an enrollment token and install the Tunnet agent on a device."
          action={
            canManage ? (
              <Button onClick={() => setEnrollOpen(true)}>Add machine</Button>
            ) : undefined
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={filtered}
          getRowId={(row) => `${row.networkId}-${row.endpointId}`}
          selectable={canManage}
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
        />
      )}

      {(machines?.length ?? 0) < 3 ? (
        <AddMachinePanel className="mt-8" />
      ) : null}

      {orgId ? (
        <>
          <EnrollmentTokenDialog
            orgId={orgId}
            open={enrollOpen}
            onOpenChange={setEnrollOpen}
          />
          <CreateTunnelDialog
            orgId={orgId}
            open={tunnelOpen}
            onOpenChange={setTunnelOpen}
            defaultEndpointId={actionEndpointId}
            defaultNetworkId={actionNetworkId}
            defaultHostname={actionHostname}
          />
          <CreateServeDialog
            orgId={orgId}
            open={serveOpen}
            onOpenChange={setServeOpen}
            defaultEndpointId={actionEndpointId}
            defaultNetworkId={actionNetworkId}
            defaultHostname={actionHostname}
          />
        </>
      ) : null}

      <ConfirmDialog
        open={confirmRemove !== null}
        onOpenChange={(open) => !open && setConfirmRemove(null)}
        title="Remove machine"
        description={`Remove ${confirmRemove?.name ?? "this machine"} from the network? This cannot be undone.`}
        confirmLabel="Remove"
        destructive
        loading={deviceMutations.remove.isPending}
        onConfirm={async () => {
          if (!confirmRemove) return;
          try {
            await deviceMutations.remove.mutateAsync(confirmRemove);
            toast.success("Machine removed");
            setConfirmRemove(null);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to remove",
            );
          }
        }}
      />

      <ConfirmDialog
        open={confirmBulkRemove}
        onOpenChange={setConfirmBulkRemove}
        title="Remove machines"
        description={`Remove ${selectedMachines.length} ${
          selectedMachines.length === 1 ? "machine" : "machines"
        } from their networks? This cannot be undone.`}
        confirmLabel="Remove"
        destructive
        loading={deviceMutations.removeMany.isPending}
        onConfirm={async () => {
          if (selectedMachines.length === 0) return;
          try {
            await deviceMutations.removeMany.mutateAsync(
              selectedMachines.map((machine) => ({
                networkId: machine.networkId,
                endpointId: machine.endpointId,
              })),
            );
            toast.success(
              selectedMachines.length === 1
                ? "Machine removed"
                : `${selectedMachines.length} machines removed`,
            );
            setRowSelection({});
            setConfirmBulkRemove(false);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to remove machines",
            );
          }
        }}
      />

      <MachineLabelsEditor
        open={labelsEditor !== null}
        onOpenChange={(open) => !open && setLabelsEditor(null)}
        labels={labelsEditor?.labels ?? {}}
        loading={deviceMutations.updateLabels.isPending}
        onSave={async (patch) => {
          if (!labelsEditor) return;
          await deviceMutations.updateLabels.mutateAsync({
            endpointId: labelsEditor.endpointId,
            body: patch,
          });
        }}
      />

      <MachineTagsEditor
        orgId={orgId}
        open={tagsEditor !== null}
        onOpenChange={(open) => !open && setTagsEditor(null)}
        tags={tagsEditor?.tags ?? []}
        loading={deviceMutations.putTags.isPending}
        onSave={async (tags) => {
          if (!tagsEditor) return;
          await deviceMutations.putTags.mutateAsync({
            endpointId: tagsEditor.endpointId,
            tags,
          });
        }}
      />

      <BulkTagsDialog
        orgId={orgId}
        open={bulkTagsOpen}
        onOpenChange={setBulkTagsOpen}
        loading={deviceMutations.bulkAssignTags.isPending}
        onSubmit={async (add) => {
          await deviceMutations.bulkAssignTags.mutateAsync({
            endpointIds: selectedMachines.map((m) => m.endpointId),
            add,
          });
        }}
      />

      <MachineExpiryDialog
        open={expiryEditor !== null}
        onOpenChange={(open) => !open && setExpiryEditor(null)}
        current={
          expiryEditor ? deriveInactivityLimitCompact(expiryEditor) : null
        }
        loading={deviceMutations.update.isPending}
        onSave={async (expiresIn) => {
          if (!expiryEditor) return;
          await deviceMutations.update.mutateAsync({
            endpointId: expiryEditor.endpointId,
            body: { expiresIn },
          });
        }}
      />
    </>
  );
}
