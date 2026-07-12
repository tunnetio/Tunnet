import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import type { DeviceMetadata } from "@tuntun/api/management";
import { formatDistanceToNow } from "date-fns";
import { ChevronRightIcon, PlusIcon } from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CopyField } from "@/components/app/copy-field";
import { CreateServeDialog } from "@/components/app/create-serve-dialog";
import { CreateTunnelDialog } from "@/components/app/create-tunnel-dialog";
import { EmptyState } from "@/components/app/empty-state";
import { EntityStatus } from "@/components/app/entity-status";
import { LastSeenCell } from "@/components/app/last-seen-cell";
import { MachineRoutesPanel } from "@/components/app/machine-routes-panel";
import { PageHeader } from "@/components/app/page-header";
import { StatusBadge } from "@/components/app/status-badge";
import { Badge } from "@/components/ui/badge";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { isAdminRole, useMemberRole } from "@/hooks/use-member-role";
import {
  seedPresenceCache,
  usePresenceStream,
} from "@/hooks/use-presence-stream";
import { useActiveOrganization } from "@/lib/auth-client";
import {
  useDevice,
  useDeviceMutations,
  useServes,
  useTunnels,
} from "@/lib/queries/management";

export const Route = createFileRoute("/app/machines/$endpointId")({
  component: MachineDetailPage,
});

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6 border-b border-border/50 py-3 last:border-0">
      <span className="text-muted-foreground shrink-0 text-sm">{label}</span>
      <div className="min-w-0 text-right text-sm">{children}</div>
    </div>
  );
}

function formatBytes(bytes: number) {
  const gb = bytes / 1024 ** 3;
  if (gb >= 1) return `${gb.toFixed(1)} GB`;
  const mb = bytes / 1024 ** 2;
  return `${mb.toFixed(0)} MB`;
}

function formatMetadataValue(key: string, value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (key === "totalMemoryBytes" && typeof value === "number") {
    return formatBytes(value);
  }
  if (key === "reportedAt" && typeof value === "string") {
    return formatDistanceToNow(new Date(value), { addSuffix: true });
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

const METADATA_LABELS: Record<string, string> = {
  hostname: "Hostname",
  os: "Operating system",
  osVersion: "OS version",
  arch: "Architecture",
  family: "OS family",
  agentVersion: "Agent version",
  cpuCount: "CPU cores",
  totalMemoryBytes: "Memory",
  reportedAt: "Last reported",
};

function SystemTab({ metadata }: { metadata: DeviceMetadata }) {
  const entries = Object.entries(metadata).filter(
    ([, value]) => value !== undefined && value !== null && value !== "",
  );

  if (entries.length === 0) {
    return (
      <Card>
        <CardContent className="text-muted-foreground py-10 text-center text-sm">
          System information will appear after the agent connects.
        </CardContent>
      </Card>
    );
  }

  const orderedKeys = [
    "hostname",
    "os",
    "osVersion",
    "arch",
    "family",
    "cpuCount",
    "totalMemoryBytes",
    "agentVersion",
    "reportedAt",
  ];

  const sorted = [
    ...orderedKeys
      .filter((key) => key in metadata)
      .map((key) => [key, metadata[key]] as const),
    ...entries.filter(([key]) => !orderedKeys.includes(key)),
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">System information</CardTitle>
      </CardHeader>
      <CardContent>
        {sorted.map(([key, value]) => (
          <DetailRow key={key} label={METADATA_LABELS[key] ?? key}>
            {formatMetadataValue(key, value)}
          </DetailRow>
        ))}
      </CardContent>
    </Card>
  );
}

function MachineDetailPage() {
  const { endpointId } = Route.useParams();
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const {
    data: device,
    isPending,
    isError,
    error,
  } = useDevice(orgId, endpointId);
  const deviceMutations = useDeviceMutations(orgId);
  const { data: tunnels } = useTunnels(orgId);
  const { data: serves } = useServes(orgId);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [createTunnelOpen, setCreateTunnelOpen] = useState(false);
  const [createServeOpen, setCreateServeOpen] = useState(false);
  const queryClient = useQueryClient();
  usePresenceStream(orgId);

  const machineTunnels = useMemo(
    () => (tunnels ?? []).filter((t) => t.endpointId === endpointId),
    [tunnels, endpointId],
  );
  const machineServes = useMemo(
    () => (serves ?? []).filter((s) => s.endpointId === endpointId),
    [serves, endpointId],
  );

  const networkId =
    device?.memberships.find((m) => m.status === "active")?.networkId ??
    device?.memberships[0]?.networkId;

  const membership = useMemo(
    () => device?.memberships.find((m) => m.networkId === networkId),
    [device, networkId],
  );

  const listDevice = useMemo(() => {
    if (!device || !membership || !networkId) return undefined;
    return {
      endpointId: device.endpointId,
      organizationId: device.organizationId,
      networkId,
      hostname: device.metadata.hostname,
      os: device.metadata.os,
      agentVersion: device.metadata.agentVersion ?? null,
      assignedIp: membership.assignedIp,
      publicIp: device.publicIp,
      ipv6Enabled: device.ipv6Enabled,
      tenantIpv6: device.ipv6Enabled ? device.tenantIpv6 : null,
      agentConnected: device.agentConnected,
      connectedAt: device.connectedAt,
      disconnectedAt: device.disconnectedAt,
      lastHeartbeatAt: device.lastHeartbeatAt,
      firstSeen: membership.firstSeen,
      lastSeen: membership.lastSeen,
      status: membership.status,
    };
  }, [device, membership, networkId]);

  useEffect(() => {
    if (orgId && listDevice) {
      seedPresenceCache(queryClient, orgId, [listDevice]);
    }
  }, [orgId, listDevice, queryClient]);

  if (!orgId || isPending) {
    return <Skeleton className="h-96 w-full" />;
  }

  if (isError || !device) {
    return (
      <div className="space-y-4">
        <p className="text-muted-foreground">
          {isError && error instanceof Error
            ? error.message
            : "Machine not found."}
        </p>
        <Button nativeButton={false} render={<Link to="/app/machines" />}>
          Back to machines
        </Button>
      </div>
    );
  }

  return (
    <>
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink render={<Link to="/app/machines" />}>
              Machines
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator>
            <ChevronRightIcon className="size-4" />
          </BreadcrumbSeparator>
          <BreadcrumbItem>
            <BreadcrumbPage>{device.metadata.hostname}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <PageHeader
        title={device.metadata.hostname}
        description={
          membership
            ? `Member of ${membership.networkName}`
            : `${device.memberships.length} network membership${device.memberships.length === 1 ? "" : "s"}`
        }
      />

      <Tabs defaultValue="overview" className="gap-4">
        <TabsList variant="line">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="networking">Networking</TabsTrigger>
          <TabsTrigger value="routes">Routes</TabsTrigger>
          <TabsTrigger value="tunnels">Tunnels</TabsTrigger>
          <TabsTrigger value="serves">Serves</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
          {isAdmin ? (
            <TabsTrigger value="settings">Settings</TabsTrigger>
          ) : null}
        </TabsList>

        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Presence</CardTitle>
              </CardHeader>
              <CardContent>
                {listDevice ? (
                  <DetailRow label="Status">
                    <StatusBadge orgId={orgId} device={listDevice} />
                  </DetailRow>
                ) : null}
                <DetailRow label="Agent session">
                  {device.agentConnected ? "Connected" : "Disconnected"}
                </DetailRow>
                {device.connectedAt ? (
                  <DetailRow label="Connected">
                    {formatDistanceToNow(new Date(device.connectedAt), {
                      addSuffix: true,
                    })}
                  </DetailRow>
                ) : null}
                {device.disconnectedAt && !device.agentConnected ? (
                  <DetailRow label="Disconnected">
                    {formatDistanceToNow(new Date(device.disconnectedAt), {
                      addSuffix: true,
                    })}
                  </DetailRow>
                ) : null}
                {listDevice ? (
                  <DetailRow label="Last seen">
                    <LastSeenCell orgId={orgId} device={listDevice} />
                  </DetailRow>
                ) : (
                  <DetailRow label="Last seen">
                    {formatDistanceToNow(new Date(device.lastSeen), {
                      addSuffix: true,
                    })}
                  </DetailRow>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Identity</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <CopyField label="Endpoint ID" value={device.endpointId} />
                <DetailRow label="First seen">
                  {formatDistanceToNow(new Date(device.firstSeen), {
                    addSuffix: true,
                  })}
                </DetailRow>
                <DetailRow label="Agent version">
                  {device.metadata.agentVersion ?? "—"}
                </DetailRow>
                <DetailRow label="Operating system">
                  {device.metadata.os}
                </DetailRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="networking">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Addresses</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {membership ? (
                  <CopyField
                    label="Network IPv4"
                    value={membership.assignedIp}
                  />
                ) : null}
                <CopyField label="Tenant IPv6" value={device.tenantIpv6} />
                <DetailRow label="IPv6 routing">
                  <Badge variant={device.ipv6Enabled ? "default" : "secondary"}>
                    {device.ipv6Enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </DetailRow>
                {device.publicIp ? (
                  <CopyField label="Public IP" value={device.publicIp} />
                ) : (
                  <DetailRow label="Public IP">Not detected</DetailRow>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Network memberships</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {device.memberships.length === 0 ? (
                  <p className="text-muted-foreground text-sm">
                    Not assigned to any network.
                  </p>
                ) : (
                  device.memberships.map((m) => (
                    <div
                      key={m.networkId}
                      className="flex items-center justify-between gap-3 rounded-lg border p-3"
                    >
                      <div className="min-w-0">
                        <p className="truncate font-medium text-sm">
                          {m.networkName}
                        </p>
                        <p className="text-muted-foreground font-mono text-xs">
                          {m.assignedIp}
                        </p>
                      </div>
                      <Badge
                        variant={
                          m.networkId === networkId ? "default" : "secondary"
                        }
                      >
                        {m.status}
                      </Badge>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="routes">
          <MachineRoutesPanel
            orgId={orgId}
            networkId={networkId}
            endpointId={endpointId}
            hostname={device.metadata.hostname}
            isAdmin={isAdmin}
          />
        </TabsContent>

        <TabsContent value="tunnels">
          <div className="mb-4 flex items-center justify-between gap-3">
            <p className="text-muted-foreground text-sm">
              Public tunnels originating from this machine.
            </p>
            {isAdmin ? (
              <Button size="sm" onClick={() => setCreateTunnelOpen(true)}>
                <PlusIcon className="mr-2 size-4" />
                Create tunnel
              </Button>
            ) : null}
          </div>
          {machineTunnels.length === 0 ? (
            <EmptyState
              title="No tunnels"
              description="Create a tunnel to expose a local port publicly."
              action={
                isAdmin ? (
                  <Button onClick={() => setCreateTunnelOpen(true)}>
                    Create tunnel
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="space-y-2">
              {machineTunnels.map((tunnel) => (
                <div
                  key={tunnel.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-border/60 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <Link
                      to="/app/tunnels/$tunnelId"
                      params={{ tunnelId: tunnel.id }}
                      className="font-mono text-sm hover:underline"
                    >
                      https://{tunnel.publicHostname}
                    </Link>
                    <p className="text-muted-foreground text-xs">
                      {tunnel.protocol.toUpperCase()} · port {tunnel.localPort}
                    </p>
                  </div>
                  <EntityStatus status={tunnel.status} />
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="serves">
          <div className="mb-4 flex items-center justify-between gap-3">
            <p className="text-muted-foreground text-sm">
              Mesh serves published from this machine.
            </p>
            {isAdmin ? (
              <Button size="sm" onClick={() => setCreateServeOpen(true)}>
                <PlusIcon className="mr-2 size-4" />
                Create serve
              </Button>
            ) : null}
          </div>
          {machineServes.length === 0 ? (
            <EmptyState
              title="No serves"
              description="Publish a local port for other machines on the mesh."
              action={
                isAdmin ? (
                  <Button onClick={() => setCreateServeOpen(true)}>
                    Create serve
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="space-y-2">
              {machineServes.map((serve) => (
                <div
                  key={serve.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-border/60 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <Link
                      to="/app/serves/$serveId"
                      params={{ serveId: serve.id }}
                      className="font-mono text-sm hover:underline"
                    >
                      {serve.internalHostname}
                    </Link>
                    <p className="text-muted-foreground text-xs">
                      {serve.protocol.toUpperCase()} · port {serve.localPort}
                    </p>
                  </div>
                  <EntityStatus status={serve.status} />
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="system">
          <SystemTab metadata={device.metadata} />
        </TabsContent>

        {isAdmin ? (
          <TabsContent value="settings">
            <div className="mx-auto flex max-w-2xl flex-col gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Connectivity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <Label htmlFor="ipv6-routing" className="text-sm">
                        IPv6 routing
                      </Label>
                      <p className="text-muted-foreground text-xs leading-relaxed">
                        When enabled, this machine routes traffic on its tenant
                        IPv6 address ({device.tenantIpv6}). Disabling stops IPv6
                        routing without releasing the address.
                      </p>
                    </div>
                    <Switch
                      id="ipv6-routing"
                      checked={device.ipv6Enabled}
                      disabled={deviceMutations.update.isPending}
                      onCheckedChange={(checked) => {
                        void deviceMutations.update
                          .mutateAsync({
                            endpointId,
                            body: { ipv6Enabled: checked },
                          })
                          .then(() =>
                            toast.success(
                              checked
                                ? "IPv6 routing enabled"
                                : "IPv6 routing disabled",
                            ),
                          )
                          .catch((err: Error) => toast.error(err.message));
                      }}
                    />
                  </div>
                </CardContent>
              </Card>

              {membership && networkId ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">
                      {membership.networkName}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-muted-foreground text-sm">
                      Control whether this machine can participate on this
                      network.
                    </p>
                    <Button
                      variant="outline"
                      className="w-full"
                      disabled={deviceMutations.updateMembership.isPending}
                      onClick={() =>
                        void deviceMutations.updateMembership
                          .mutateAsync({
                            networkId,
                            endpointId,
                            status:
                              membership.status === "active"
                                ? "suspended"
                                : "active",
                          })
                          .then(() => toast.success("Network status updated"))
                          .catch((err: Error) => toast.error(err.message))
                      }
                    >
                      {membership.status === "active"
                        ? "Suspend on this network"
                        : "Activate on this network"}
                    </Button>
                  </CardContent>
                </Card>
              ) : null}

              {membership && networkId ? (
                <Card className="border-destructive/30">
                  <CardHeader>
                    <CardTitle className="text-base text-destructive">
                      Danger zone
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-muted-foreground text-sm">
                      Remove this machine from {membership.networkName}. If it
                      has no other network memberships, the device record is
                      deleted.
                    </p>
                    <Button
                      variant="destructive"
                      onClick={() => setConfirmRemove(true)}
                    >
                      Remove machine
                    </Button>
                  </CardContent>
                </Card>
              ) : null}
            </div>
          </TabsContent>
        ) : null}
      </Tabs>

      {membership && networkId ? (
        <ConfirmDialog
          open={confirmRemove}
          onOpenChange={setConfirmRemove}
          title="Remove machine"
          description={`Remove ${device.metadata.hostname} from ${membership.networkName}?`}
          confirmLabel="Remove"
          destructive
          loading={deviceMutations.remove.isPending}
          onConfirm={async () => {
            try {
              await deviceMutations.remove.mutateAsync({
                networkId,
                endpointId,
              });
              toast.success("Machine removed");
              window.location.href = "/app/machines";
            } catch (err) {
              toast.error(
                err instanceof Error ? err.message : "Failed to remove",
              );
            }
          }}
        />
      ) : null}

      {orgId ? (
        <>
          <CreateTunnelDialog
            orgId={orgId}
            open={createTunnelOpen}
            onOpenChange={setCreateTunnelOpen}
            defaultEndpointId={endpointId}
            defaultNetworkId={networkId}
            defaultHostname={device?.metadata.hostname}
          />
          <CreateServeDialog
            orgId={orgId}
            open={createServeOpen}
            onOpenChange={setCreateServeOpen}
            defaultEndpointId={endpointId}
            defaultNetworkId={networkId}
            defaultHostname={device?.metadata.hostname}
          />
        </>
      ) : null}
    </>
  );
}
