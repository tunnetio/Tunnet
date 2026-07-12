import { useMutation, useQueryClient } from "@tanstack/react-query";
import type {
  CreateHostnameRouteBody,
  CreateSubnetRouteBody,
} from "@tuntun/api/management";
import { PlusIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { DataTable } from "@/components/app/data-table";
import { EmptyState } from "@/components/app/empty-state";
import {
  AddRouteTypeDialog,
  buildMachineRouteColumns,
  CreateHostnameRouteDialog,
  CreateSubnetRouteDialog,
  MachineConnectedRoutesDiagram,
  toUnifiedRoutes,
  type UnifiedRoute,
} from "@/components/app/route-management";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { createManagementClient } from "@/lib/management-client";
import {
  useDevices,
  useHostnameRoutes,
  useSubnetRoutes,
} from "@/lib/queries/management";
import { queryKeys } from "@/lib/query-keys";

type MachineRoutesPanelProps = {
  orgId: string;
  networkId: string | undefined;
  endpointId: string;
  hostname: string;
  isAdmin: boolean;
};

export function MachineRoutesPanel({
  orgId,
  networkId,
  endpointId,
  hostname,
  isAdmin,
}: MachineRoutesPanelProps) {
  const queryClient = useQueryClient();
  const { data: subnetRoutes, isPending: subnetsPending } = useSubnetRoutes(
    orgId,
    networkId ?? "",
  );
  const { data: hostnameRoutes, isPending: hostnamesPending } =
    useHostnameRoutes(orgId, networkId ?? "");
  const { data: devices } = useDevices(orgId, networkId ?? "");

  const [typePickerOpen, setTypePickerOpen] = useState(false);
  const [createSubnetOpen, setCreateSubnetOpen] = useState(false);
  const [createHostnameOpen, setCreateHostnameOpen] = useState(false);
  const [deleteSubnetId, setDeleteSubnetId] = useState<string | null>(null);
  const [deleteHostnameId, setDeleteHostnameId] = useState<string | null>(null);

  const deviceType = devices?.find((d) => d.endpointId === endpointId)?.type;
  const canAdvertise = deviceType !== "sdk";

  const machineSubnets = useMemo(
    () => (subnetRoutes ?? []).filter((r) => r.endpointId === endpointId),
    [subnetRoutes, endpointId],
  );
  const machineHostnames = useMemo(
    () => (hostnameRoutes ?? []).filter((r) => r.endpointId === endpointId),
    [hostnameRoutes, endpointId],
  );

  const rows = useMemo(
    () => toUnifiedRoutes(machineSubnets, machineHostnames),
    [machineSubnets, machineHostnames],
  );

  const invalidateRoutes = () => {
    if (!networkId) return;
    void queryClient.invalidateQueries({
      queryKey: queryKeys.subnetRoutes(orgId, networkId),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.hostnameRoutes(orgId, networkId),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.topology(orgId, networkId),
    });
  };

  const createSubnet = useMutation({
    mutationFn: async (body: CreateSubnetRouteBody) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).createSubnetRoute(networkId, body);
    },
    onSuccess: invalidateRoutes,
  });
  const toggleSubnet = useMutation({
    mutationFn: async ({
      routeId,
      enabled,
    }: {
      routeId: string;
      enabled: boolean;
    }) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).updateSubnetRoute(
        networkId,
        routeId,
        { enabled },
      );
    },
    onSuccess: invalidateRoutes,
  });
  const deleteSubnet = useMutation({
    mutationFn: async (routeId: string) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).deleteSubnetRoute(
        networkId,
        routeId,
      );
    },
    onSuccess: invalidateRoutes,
  });

  const createHostname = useMutation({
    mutationFn: async (body: CreateHostnameRouteBody) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).createHostnameRoute(networkId, body);
    },
    onSuccess: invalidateRoutes,
  });
  const toggleHostname = useMutation({
    mutationFn: async ({
      routeId,
      enabled,
    }: {
      routeId: string;
      enabled: boolean;
    }) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).updateHostnameRoute(
        networkId,
        routeId,
        { enabled },
      );
    },
    onSuccess: invalidateRoutes,
  });
  const deleteHostname = useMutation({
    mutationFn: async (routeId: string) => {
      if (!networkId) throw new Error("No network");
      return createManagementClient(orgId).deleteHostnameRoute(
        networkId,
        routeId,
      );
    },
    onSuccess: invalidateRoutes,
  });

  const columns = useMemo(
    () =>
      buildMachineRouteColumns({
        isAdmin,
        onToggle: (r) => {
          const run = r.kind === "subnet" ? toggleSubnet : toggleHostname;
          void run
            .mutateAsync({ routeId: r.id, enabled: !r.enabled })
            .then(() => toast.success("Updated"))
            .catch((err: unknown) =>
              toast.error(
                err instanceof Error ? err.message : "Failed to update",
              ),
            );
        },
        onDelete: (r: UnifiedRoute) => {
          if (r.kind === "subnet") setDeleteSubnetId(r.id);
          else setDeleteHostnameId(r.id);
        },
      }),
    [isAdmin, toggleHostname, toggleSubnet],
  );

  if (!networkId) {
    return (
      <EmptyState
        title="No network membership"
        description="Join a network before advertising private routes through this machine."
      />
    );
  }

  if (deviceType === "sdk") {
    return (
      <EmptyState
        title="Routes not available"
        description="SDK machines cannot advertise subnet or hostname routes. Use an agent machine as a gateway."
      />
    );
  }

  const pending = subnetsPending || hostnamesPending;
  const canAdd = isAdmin && canAdvertise;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-2xl space-y-1">
          <h2 className="text-sm font-medium tracking-tight">Routes</h2>
          <p className="text-muted-foreground text-sm leading-relaxed">
            Add private network routes so devices on your mesh can reach hosts
            behind this machine - even if those hosts aren&apos;t running the
            agent.
          </p>
        </div>
        {canAdd ? (
          <Button size="sm" onClick={() => setTypePickerOpen(true)}>
            <PlusIcon className="size-3.5" />
            Add route
          </Button>
        ) : null}
      </div>

      <MachineConnectedRoutesDiagram
        hostname={hostname}
        subnets={machineSubnets}
        hostnames={machineHostnames}
        canAdd={canAdd}
        onAddRoute={() => setTypePickerOpen(true)}
      />

      {pending ? (
        <Skeleton className="h-48 w-full" />
      ) : rows.length === 0 ? (
        <div className="text-muted-foreground flex h-32 flex-col items-center justify-center rounded-lg border border-dashed border-border/70 px-6 text-center text-sm">
          <p className="font-medium text-foreground">No routes configured</p>
          <p className="mt-1 max-w-md text-xs leading-relaxed">
            Add a private network route that will be accessible through this
            machine. Traffic to this destination will be routed through the
            node.
          </p>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          getRowId={(row) => `${row.kind}:${row.id}`}
        />
      )}

      <AddRouteTypeDialog
        open={typePickerOpen}
        onOpenChange={setTypePickerOpen}
        onSelect={(kind) => {
          setTypePickerOpen(false);
          window.setTimeout(() => {
            if (kind === "subnet") setCreateSubnetOpen(true);
            else setCreateHostnameOpen(true);
          }, 150);
        }}
      />

      <CreateSubnetRouteDialog
        open={createSubnetOpen}
        onOpenChange={setCreateSubnetOpen}
        fixedEndpointId={endpointId}
        loading={createSubnet.isPending}
        onSubmit={async (body) => {
          try {
            await createSubnet.mutateAsync(body);
            toast.success("Created");
            setCreateSubnetOpen(false);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to create",
            );
          }
        }}
      />

      <CreateHostnameRouteDialog
        open={createHostnameOpen}
        onOpenChange={setCreateHostnameOpen}
        fixedEndpointId={endpointId}
        loading={createHostname.isPending}
        onSubmit={async (body) => {
          try {
            await createHostname.mutateAsync(body);
            toast.success("Created");
            setCreateHostnameOpen(false);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to create",
            );
          }
        }}
      />

      <ConfirmDialog
        open={deleteSubnetId !== null}
        onOpenChange={(open) => !open && setDeleteSubnetId(null)}
        title="Delete subnet route"
        description="This CIDR will stop advertising through this machine."
        confirmLabel="Delete"
        destructive
        loading={deleteSubnet.isPending}
        onConfirm={async () => {
          if (!deleteSubnetId) return;
          try {
            await deleteSubnet.mutateAsync(deleteSubnetId);
            toast.success("Deleted");
            setDeleteSubnetId(null);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to delete",
            );
          }
        }}
      />

      <ConfirmDialog
        open={deleteHostnameId !== null}
        onOpenChange={(open) => !open && setDeleteHostnameId(null)}
        title="Delete hostname route"
        description="This hostname will stop resolving through this machine."
        confirmLabel="Delete"
        destructive
        loading={deleteHostname.isPending}
        onConfirm={async () => {
          if (!deleteHostnameId) return;
          try {
            await deleteHostname.mutateAsync(deleteHostnameId);
            toast.success("Deleted");
            setDeleteHostnameId(null);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to delete",
            );
          }
        }}
      />
    </div>
  );
}
