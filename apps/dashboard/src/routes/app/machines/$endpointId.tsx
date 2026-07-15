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
import {
  MachineExpiryCountdown,
  MachineExpirySettings,
} from "@/components/app/machine-expiry-display";
import {
  MachineExpiryDialog,
  MachineLabelChips,
  MachineLabelsEditor,
} from "@/components/app/machine-labels";
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
import { Input } from "@/components/ui/input";
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
import { deriveInactivityLimitCompact } from "@/lib/machine-expiry";
import {
  useDevice,
  useDeviceMutations,
  useDeviceSshAuth,
  useOrgSettings,
  useServes,
  useSshSessions,
  useTunnels,
} from "@/lib/queries/management";
import { cn } from "@/lib/utils";

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

function SettingsSection({
  title,
  description,
  children,
  footer,
  danger,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  danger?: boolean;
}) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-xl border bg-card",
        danger ? "border-destructive/25" : "border-border/80",
      )}
    >
      <div className="border-b border-border/70 px-5 py-4">
        <h2
          className={cn(
            "text-sm font-semibold tracking-tight",
            danger && "text-destructive",
          )}
        >
          {title}
        </h2>
        {description ? (
          <p className="text-muted-foreground mt-1 text-sm leading-relaxed">
            {description}
          </p>
        ) : null}
      </div>
      <div className="px-5 py-5">{children}</div>
      {footer ? (
        <div className="bg-muted/30 border-t border-border/70 px-5 py-3">
          {footer}
        </div>
      ) : null}
    </section>
  );
}

function formatBytes(bytes: number) {
  const gb = bytes / 1024 ** 3;
  if (gb >= 1) return `${gb.toFixed(1)} GB`;
  const mb = bytes / 1024 ** 2;
  return `${mb.toFixed(0)} MB`;
}

function formatMetadataValue(key: string, value: unknown) {
  if (value === null || value === undefined || value === "") return "-";
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
      <div className="text-muted-foreground rounded-xl border border-dashed px-6 py-12 text-center text-sm">
        System information will appear after the agent connects.
      </div>
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
    <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
      <div className="border-b border-border/70 px-5 py-4">
        <h2 className="text-sm font-semibold tracking-tight">
          System information
        </h2>
      </div>
      <div className="px-5">
        {sorted.map(([key, value]) => (
          <DetailRow key={key} label={METADATA_LABELS[key] ?? key}>
            {formatMetadataValue(key, value)}
          </DetailRow>
        ))}
      </div>
    </section>
  );
}

function MachineSshTab({
  orgId,
  endpointId,
  hostname,
}: {
  orgId: string | undefined;
  endpointId: string;
  hostname: string;
}) {
  const { data: auth, isPending: authPending } = useDeviceSshAuth(
    orgId,
    endpointId,
  );
  const { data: sessions, isPending: sessionsPending } = useSshSessions(
    orgId,
    "active",
  );
  const related = (sessions ?? []).filter(
    (s) => s.srcEndpointId === endpointId || s.dstEndpointId === endpointId,
  );

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Connect</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-muted-foreground text-sm">
            From another mesh machine with SSH rules allowing access:
          </p>
          <CopyField label="CLI" value={`tuntun ssh ${hostname}`} />
          <p className="text-muted-foreground text-xs leading-relaxed">
            Check-mode rules open a browser for IdP re-auth when the last
            authentication is older than the rule&apos;s check period.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Last check-mode auth</CardTitle>
        </CardHeader>
        <CardContent>
          {authPending ? (
            <Skeleton className="h-20 w-full" />
          ) : !auth?.authenticatedAt ? (
            <p className="text-muted-foreground text-sm">
              No IdP re-auth recorded for this machine yet.
            </p>
          ) : (
            <>
              <DetailRow label="Authenticated">
                {formatDistanceToNow(new Date(auth.authenticatedAt), {
                  addSuffix: true,
                })}
              </DetailRow>
              <DetailRow label="Method">{auth.method ?? "-"}</DetailRow>
              <DetailRow label="Identity">
                {auth.identityEmail ?? "-"}
              </DetailRow>
            </>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Active SSH sessions</CardTitle>
        </CardHeader>
        <CardContent>
          {sessionsPending ? (
            <Skeleton className="h-24 w-full" />
          ) : related.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No active sessions involving this machine.
            </p>
          ) : (
            <div className="space-y-2">
              {related.map((session) => (
                <div
                  key={session.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-border/60 px-3 py-2.5"
                >
                  <div className="min-w-0 text-sm">
                    <p className="font-mono text-xs">
                      {session.srcHostname ?? session.srcEndpointId.slice(0, 8)}{" "}
                      →{" "}
                      {session.dstHostname ?? session.dstEndpointId.slice(0, 8)}{" "}
                      as {session.targetUser}
                    </p>
                    <p className="text-muted-foreground text-xs">
                      started{" "}
                      {formatDistanceToNow(new Date(session.startedAt), {
                        addSuffix: true,
                      })}
                      {session.recorded ? " · recorded" : ""}
                    </p>
                  </div>
                  <Link
                    to="/app/ssh-sessions"
                    className="text-muted-foreground text-xs hover:underline"
                  >
                    View
                  </Link>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
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
  const { data: orgSettings } = useOrgSettings(orgId);
  const deviceMutations = useDeviceMutations(orgId);
  const { data: tunnels } = useTunnels(orgId);
  const { data: serves } = useServes(orgId);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [createTunnelOpen, setCreateTunnelOpen] = useState(false);
  const [createServeOpen, setCreateServeOpen] = useState(false);
  const [labelsOpen, setLabelsOpen] = useState(false);
  const [expiryOpen, setExpiryOpen] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
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
      name: device.name,
      hostname: device.metadata.hostname,
      type: (device.metadata.kind === "sdk" ? "sdk" : "agent") as
        | "agent"
        | "sdk",
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
      labels: device.labels,
      inactivityTtl: device.inactivityTtl,
      expiredAt: device.expiredAt,
    };
  }, [device, membership, networkId]);

  useEffect(() => {
    if (device?.name) setNameDraft(device.name);
  }, [device?.name]);

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
            <BreadcrumbPage>{device.name}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <PageHeader
        title={device.name}
        description={
          membership
            ? `Member of ${membership.networkName}`
            : `${device.memberships.length} network membership${device.memberships.length === 1 ? "" : "s"}`
        }
      />

      <Tabs defaultValue="overview" className="gap-5">
        <div className="border-b border-border/70">
          <TabsList
            variant="line"
            className="h-auto w-full justify-start gap-0 overflow-x-auto overflow-y-hidden rounded-none bg-transparent p-0"
          >
            <TabsTrigger value="overview" className="rounded-none px-3">
              Overview
            </TabsTrigger>
            <TabsTrigger value="networking" className="rounded-none px-3">
              Networking
            </TabsTrigger>
            <TabsTrigger value="routes" className="rounded-none px-3">
              Routes
            </TabsTrigger>
            <TabsTrigger value="tunnels" className="rounded-none px-3">
              Tunnels
            </TabsTrigger>
            <TabsTrigger value="serves" className="rounded-none px-3">
              Serves
            </TabsTrigger>
            <TabsTrigger value="ssh" className="rounded-none px-3">
              SSH
            </TabsTrigger>
            <TabsTrigger value="system" className="rounded-none px-3">
              System
            </TabsTrigger>
            {isAdmin ? (
              <TabsTrigger value="settings" className="rounded-none px-3">
                Settings
              </TabsTrigger>
            ) : null}
          </TabsList>
        </div>

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
                <DetailRow label="Expiry">
                  <MachineExpiryCountdown
                    device={{
                      ...device,
                      orgAutoCleanupEnabled:
                        orgSettings?.machines.autoCleanup.enabled ?? false,
                      orgInactivityAfter:
                        orgSettings?.machines.autoCleanup.inactivityAfter ??
                        null,
                    }}
                  />
                </DetailRow>
                {Object.keys(device.labels).length > 0 ? (
                  <DetailRow label="Labels">
                    <MachineLabelChips
                      labels={device.labels}
                      max={8}
                      empty={null}
                      className="justify-end"
                    />
                  </DetailRow>
                ) : null}
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
                  {device.metadata.agentVersion ?? "-"}
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
            hostname={device.name}
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

        <TabsContent value="ssh">
          <MachineSshTab
            orgId={orgId}
            endpointId={endpointId}
            hostname={device.name}
          />
        </TabsContent>

        <TabsContent value="system">
          <SystemTab metadata={device.metadata} />
        </TabsContent>

        {isAdmin ? (
          <TabsContent value="settings" className="mt-0">
            <div className="mx-auto flex max-w-2xl flex-col gap-4">
              <SettingsSection
                title="Profile"
                description="Display name used across the dashboard and CLI."
                footer={
                  <Button
                    size="sm"
                    disabled={
                      deviceMutations.update.isPending ||
                      nameDraft.trim().length === 0 ||
                      nameDraft.trim() === device.name
                    }
                    onClick={() =>
                      void deviceMutations.update
                        .mutateAsync({
                          endpointId,
                          body: { name: nameDraft.trim() },
                        })
                        .then(() => toast.success("Machine name updated"))
                        .catch((err: Error) => toast.error(err.message))
                    }
                  >
                    {deviceMutations.update.isPending
                      ? "Saving..."
                      : "Save name"}
                  </Button>
                }
              >
                <div className="space-y-2">
                  <Label htmlFor="machine-name">Display name</Label>
                  <Input
                    id="machine-name"
                    value={nameDraft}
                    onChange={(e) => setNameDraft(e.target.value)}
                    maxLength={253}
                    placeholder={device.metadata.hostname}
                  />
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    Defaults to hostname{" "}
                    <span className="font-mono">
                      {device.metadata.hostname}
                    </span>
                    . Changing it does not affect the reported hostname.
                  </p>
                </div>
              </SettingsSection>

              <SettingsSection
                title="Labels"
                description="Key/value tags for search and grouping."
                footer={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setLabelsOpen(true)}
                  >
                    Edit labels
                  </Button>
                }
              >
                <MachineLabelChips
                  labels={device.labels}
                  max={20}
                  empty="No labels yet"
                />
              </SettingsSection>

              <SettingsSection
                title="Connectivity"
                description="Network protocol options for this machine."
              >
                <div className="bg-muted/25 flex items-start justify-between gap-4 rounded-lg border border-border/70 px-4 py-3.5">
                  <div className="min-w-0 space-y-1">
                    <Label
                      htmlFor="ipv6-routing"
                      className="text-sm font-medium"
                    >
                      IPv6 routing
                    </Label>
                    <p className="text-muted-foreground text-xs leading-relaxed">
                      Route traffic on tenant IPv6{" "}
                      <span className="font-mono">{device.tenantIpv6}</span>.
                      Disabling stops routing without releasing the address.
                    </p>
                  </div>
                  <Switch
                    id="ipv6-routing"
                    checked={device.ipv6Enabled}
                    disabled={deviceMutations.update.isPending}
                    className="mt-0.5 shrink-0"
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
              </SettingsSection>

              <SettingsSection
                title="Auto-expiry"
                description="Remove this machine after a period of inactivity."
                footer={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setExpiryOpen(true)}
                    disabled={deviceMutations.update.isPending}
                  >
                    {device.inactivityTtl ? "Change expiry" : "Set expiry"}
                  </Button>
                }
              >
                <MachineExpirySettings
                  device={{
                    ...device,
                    orgAutoCleanupEnabled:
                      orgSettings?.machines.autoCleanup.enabled ?? false,
                    orgInactivityAfter:
                      orgSettings?.machines.autoCleanup.inactivityAfter ?? null,
                  }}
                />
              </SettingsSection>

              {membership && networkId ? (
                <SettingsSection
                  title="Network membership"
                  description={`Control participation on ${membership.networkName}.`}
                  footer={
                    <Button
                      variant="outline"
                      size="sm"
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
                  }
                >
                  <div className="flex items-center justify-between gap-4 text-sm">
                    <span className="text-muted-foreground">Status</span>
                    <Badge
                      variant={
                        membership.status === "active" ? "default" : "secondary"
                      }
                    >
                      {membership.status}
                    </Badge>
                  </div>
                </SettingsSection>
              ) : null}

              {membership && networkId ? (
                <SettingsSection
                  title="Danger zone"
                  description={`Remove this machine from ${membership.networkName}. If it has no other memberships, the device record is deleted.`}
                  danger
                  footer={
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => setConfirmRemove(true)}
                    >
                      Remove machine
                    </Button>
                  }
                >
                  <p className="text-muted-foreground text-sm leading-relaxed">
                    This cannot be undone from the dashboard. The agent must
                    re-enroll to join again.
                  </p>
                </SettingsSection>
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
          description={`Remove ${device.name} from ${membership.networkName}?`}
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
            defaultHostname={device?.name}
          />
          <CreateServeDialog
            orgId={orgId}
            open={createServeOpen}
            onOpenChange={setCreateServeOpen}
            defaultEndpointId={endpointId}
            defaultNetworkId={networkId}
            defaultHostname={device?.name}
          />
        </>
      ) : null}

      <MachineLabelsEditor
        open={labelsOpen}
        onOpenChange={setLabelsOpen}
        labels={device.labels}
        loading={deviceMutations.updateLabels.isPending}
        onSave={async (patch) => {
          await deviceMutations.updateLabels.mutateAsync({
            endpointId,
            body: patch,
          });
        }}
      />

      <MachineExpiryDialog
        open={expiryOpen}
        onOpenChange={setExpiryOpen}
        current={deriveInactivityLimitCompact(device)}
        loading={deviceMutations.update.isPending}
        onSave={async (expiresIn) => {
          await deviceMutations.update.mutateAsync({
            endpointId,
            body: { expiresIn },
          });
        }}
      />
    </>
  );
}
