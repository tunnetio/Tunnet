import { createFileRoute, Link } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import type { TunnelTrafficLog } from "@tuntun/api/management";
import { formatDistanceToNow } from "date-fns";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  ChevronRightIcon,
  ExternalLinkIcon,
  Trash2Icon,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CopyField } from "@/components/app/copy-field";
import { DataTable } from "@/components/app/data-table";
import { EmptyState } from "@/components/app/empty-state";
import { EntityStatus } from "@/components/app/entity-status";
import { PageHeader } from "@/components/app/page-header";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { isAdminRole, useMemberRole } from "@/hooks/use-member-role";
import { useActiveOrganization } from "@/lib/auth-client";
import {
  useMachines,
  useTunnelMutations,
  useTunnelPortMappings,
  useTunnelRedirectRules,
  useTunnels,
  useTunnelTraffic,
} from "@/lib/queries/management";

export const Route = createFileRoute("/app/tunnels/$tunnelId")({
  component: TunnelDetailPage,
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

function TunnelDetailPage() {
  const { tunnelId } = Route.useParams();
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const { data: tunnels, isPending } = useTunnels(orgId);
  const mutations = useTunnelMutations(orgId);
  const [confirmDestroy, setConfirmDestroy] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);

  const tunnel = useMemo(
    () => (tunnels ?? []).find((t) => t.id === tunnelId),
    [tunnels, tunnelId],
  );

  const networkId = tunnel?.networkId ?? "";
  const { data: redirectRules } = useTunnelRedirectRules(
    orgId,
    networkId,
    tunnelId,
  );
  const { data: portMappings } = useTunnelPortMappings(
    orgId,
    networkId,
    tunnelId,
  );
  const { data: trafficLogs } = useTunnelTraffic(orgId, networkId, tunnelId);

  const [localPort, setLocalPort] = useState("");
  const [subdomain, setSubdomain] = useState("");
  const [basicAuthUser, setBasicAuthUser] = useState("");
  const [basicAuthPassword, setBasicAuthPassword] = useState("");
  const [clearBasicAuth, setClearBasicAuth] = useState(false);
  const [pathPattern, setPathPattern] = useState("/api/*");
  const [targetPort, setTargetPort] = useState("8080");
  const [targetEndpointId, setTargetEndpointId] = useState("localhost");
  const [externalPort, setExternalPort] = useState("5432");
  const [mappingTargetPort, setMappingTargetPort] = useState("5432");
  const [mappingTargetEndpointId, setMappingTargetEndpointId] =
    useState("localhost");

  const { data: machines } = useMachines(orgId);
  const networkMachines = useMemo(
    () => (machines ?? []).filter((m) => m.networkId === tunnel?.networkId),
    [machines, tunnel?.networkId],
  );

  useEffect(() => {
    if (!tunnel) return;
    setLocalPort(String(tunnel.localPort));
    setSubdomain(tunnel.subdomain);
    setBasicAuthUser(tunnel.basicAuth?.username ?? "");
    setBasicAuthPassword("");
    setClearBasicAuth(false);
  }, [tunnel]);

  const sortedRules = useMemo(
    () => [...(redirectRules ?? [])].sort((a, b) => b.priority - a.priority),
    [redirectRules],
  );

  const trafficColumns = useMemo<ColumnDef<TunnelTrafficLog>[]>(
    () => [
      {
        id: "time",
        header: "Time",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs whitespace-nowrap">
            {formatDistanceToNow(new Date(row.original.createdAt), {
              addSuffix: true,
            })}
          </span>
        ),
      },
      {
        id: "method",
        header: "Method",
        cell: ({ row }) => (
          <button
            type="button"
            className="font-mono text-xs hover:underline"
            onClick={() => {
              void navigator.clipboard
                .writeText(row.original.method)
                .then(() => toast.success("Copied"));
            }}
          >
            {row.original.method}
          </button>
        ),
      },
      {
        id: "path",
        header: "Path",
        cell: ({ row }) => (
          <button
            type="button"
            className="max-w-[240px] truncate font-mono text-xs hover:underline"
            title={row.original.path}
            onClick={() => {
              void navigator.clipboard
                .writeText(row.original.path)
                .then(() => toast.success("Copied"));
            }}
          >
            {row.original.path}
          </button>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.statusCode}</span>
        ),
      },
      {
        id: "latency",
        header: "Latency",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.latencyMs}ms
          </span>
        ),
      },
      {
        id: "source",
        header: "Source IP",
        cell: ({ row }) =>
          row.original.sourceIp ? (
            <button
              type="button"
              className="font-mono text-xs hover:underline"
              onClick={() => {
                void navigator.clipboard
                  .writeText(row.original.sourceIp!)
                  .then(() => toast.success("Copied"));
              }}
            >
              {row.original.sourceIp}
            </button>
          ) : (
            "—"
          ),
      },
    ],
    [],
  );

  if (!orgId || isPending) {
    return <Skeleton className="h-96 w-full" />;
  }

  if (!tunnel) {
    return (
      <div className="space-y-4">
        <p className="text-muted-foreground">Tunnel not found.</p>
        <Button nativeButton={false} render={<Link to="/app/tunnels" />}>
          Back to tunnels
        </Button>
      </div>
    );
  }

  const url = `https://${tunnel.publicHostname}`;

  async function saveConfig() {
    if (!tunnel) return;
    try {
      const body: {
        localPort: number;
        subdomain?: string;
        basicAuth?: { username: string; password: string } | null;
      } = {
        localPort: Number(localPort),
        subdomain: subdomain.trim() || undefined,
      };
      if (clearBasicAuth) {
        body.basicAuth = null;
      } else if (basicAuthUser.trim() && basicAuthPassword) {
        body.basicAuth = {
          username: basicAuthUser.trim(),
          password: basicAuthPassword,
        };
      }
      await mutations.update.mutateAsync({
        networkId: tunnel.networkId,
        tunnelId: tunnel.id,
        body,
      });
      setBasicAuthPassword("");
      setClearBasicAuth(false);
      toast.success("Tunnel updated");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to update");
    }
  }

  async function moveRule(
    ruleId: string,
    currentPriority: number,
    direction: "up" | "down",
  ) {
    if (!tunnel) return;
    const next =
      direction === "up"
        ? currentPriority + 1
        : Math.max(0, currentPriority - 1);
    try {
      await mutations.updateRedirectRule.mutateAsync({
        networkId: tunnel.networkId,
        tunnelId: tunnel.id,
        ruleId,
        body: { priority: next },
      });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to reorder");
    }
  }

  return (
    <>
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink render={<Link to="/app/tunnels" />}>
              Tunnels
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator>
            <ChevronRightIcon className="size-4" />
          </BreadcrumbSeparator>
          <BreadcrumbItem>
            <BreadcrumbPage>{tunnel.subdomain}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <PageHeader
        title={tunnel.publicHostname}
        description={`${tunnel.protocol.toUpperCase()} · port ${tunnel.localPort}`}
        actions={
          <div className="flex items-center gap-2">
            <EntityStatus status={tunnel.status} />
            <Button
              variant="outline"
              size="sm"
              nativeButton={false}
              render={<a href={url} target="_blank" rel="noreferrer" />}
            >
              <ExternalLinkIcon className="mr-1.5 size-3.5" />
              Open
            </Button>
          </div>
        }
      />

      <Tabs defaultValue="overview" className="gap-4">
        <TabsList variant="line">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
          {tunnel.protocol === "https" ? (
            <TabsTrigger value="redirects">Redirects</TabsTrigger>
          ) : (
            <TabsTrigger value="port-mappings">Port mappings</TabsTrigger>
          )}
          {isAdmin ? (
            <TabsTrigger value="danger">Danger zone</TabsTrigger>
          ) : null}
        </TabsList>

        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Public endpoint</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <CopyField label="URL" value={url} />
                {tunnel.errorMessage ? (
                  <p className="text-destructive text-sm">
                    {tunnel.errorMessage}
                  </p>
                ) : null}
                <DetailRow label="Created">
                  {formatDistanceToNow(new Date(tunnel.createdAt), {
                    addSuffix: true,
                  })}
                </DetailRow>
                <DetailRow label="Expires">
                  {tunnel.expiresAt
                    ? formatDistanceToNow(new Date(tunnel.expiresAt), {
                        addSuffix: true,
                      })
                    : "Never"}
                </DetailRow>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Machine → Relay</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap items-center justify-center gap-2 rounded-lg border border-border/60 bg-secondary/20 px-4 py-6">
                  <Link
                    to="/app/machines/$endpointId"
                    params={{ endpointId: tunnel.endpointId }}
                    className="rounded-md border border-border/60 bg-background px-3 py-1.5 text-sm font-medium hover:underline"
                  >
                    {tunnel.hostname ?? tunnel.endpointId.slice(0, 12)}
                  </Link>
                  <span className="text-muted-foreground text-xs">→</span>
                  <span className="text-muted-foreground font-mono text-xs">
                    :{tunnel.localPort}
                  </span>
                  <span className="text-muted-foreground text-xs">→</span>
                  {tunnel.relayId ? (
                    <Link
                      to="/app/relays/$relayId"
                      params={{ relayId: tunnel.relayId }}
                      className="rounded-md border border-border/60 bg-background px-3 py-1.5 text-sm font-medium hover:underline"
                    >
                      {tunnel.relayName ?? "Relay"}
                    </Link>
                  ) : (
                    <span className="text-sm">No relay</span>
                  )}
                </div>
                <DetailRow label="Network">
                  <Link
                    to="/app/networks/$networkId"
                    params={{ networkId: tunnel.networkId }}
                    className="hover:underline"
                  >
                    {tunnel.networkName ?? tunnel.networkId.slice(0, 8)}
                  </Link>
                </DetailRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="traffic">
          {(trafficLogs ?? []).length === 0 ? (
            <EmptyState
              title="No traffic yet"
              description="Requests through this tunnel appear here within a few seconds. Polls every 5s."
            />
          ) : (
            <DataTable
              columns={trafficColumns}
              data={trafficLogs ?? []}
              getRowId={(r) => r.id}
            />
          )}
        </TabsContent>

        <TabsContent value="configuration">
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle className="text-base">Tunnel settings</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="space-y-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  void saveConfig();
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="cfg-port">Local port</Label>
                  <Input
                    id="cfg-port"
                    type="number"
                    min={1}
                    max={65535}
                    value={localPort}
                    onChange={(e) => setLocalPort(e.target.value)}
                    disabled={!isAdmin}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cfg-subdomain">Subdomain</Label>
                  <Input
                    id="cfg-subdomain"
                    value={subdomain}
                    onChange={(e) => setSubdomain(e.target.value)}
                    pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                    disabled={!isAdmin}
                  />
                  <p className="text-muted-foreground text-xs">
                    Preview: {subdomain || tunnel.subdomain}.
                    {tunnel.publicHostname.split(".").slice(1).join(".") ||
                      "tuntun.pub"}
                  </p>
                </div>
                <DetailRow label="Protocol">
                  {tunnel.protocol.toUpperCase()}
                </DetailRow>
                <DetailRow label="TTL / expires">
                  {tunnel.expiresAt
                    ? formatDistanceToNow(new Date(tunnel.expiresAt), {
                        addSuffix: true,
                      })
                    : "Never"}
                </DetailRow>
                <div className="space-y-3 border-t border-border/50 pt-4">
                  <div>
                    <Label>HTTP Basic Auth</Label>
                    <p className="text-muted-foreground mt-1 text-xs">
                      Protect public HTTPS visitors. Leave password blank to
                      keep the current credential.
                    </p>
                  </div>
                  {tunnel.basicAuth ? (
                    <p className="text-sm">
                      Enabled for user{" "}
                      <span className="font-mono">
                        {tunnel.basicAuth.username}
                      </span>
                    </p>
                  ) : (
                    <p className="text-muted-foreground text-sm">
                      Not configured
                    </p>
                  )}
                  {isAdmin ? (
                    <>
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="cfg-basic-user">Username</Label>
                          <Input
                            id="cfg-basic-user"
                            value={basicAuthUser}
                            onChange={(e) => {
                              setBasicAuthUser(e.target.value);
                              setClearBasicAuth(false);
                            }}
                            autoComplete="off"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="cfg-basic-pass">
                            {tunnel.basicAuth ? "New password" : "Password"}
                          </Label>
                          <Input
                            id="cfg-basic-pass"
                            type="password"
                            value={basicAuthPassword}
                            onChange={(e) => {
                              setBasicAuthPassword(e.target.value);
                              setClearBasicAuth(false);
                            }}
                            autoComplete="new-password"
                          />
                        </div>
                      </div>
                      {tunnel.basicAuth ? (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setClearBasicAuth(true);
                            setBasicAuthUser("");
                            setBasicAuthPassword("");
                          }}
                        >
                          Clear basic auth
                        </Button>
                      ) : null}
                      {clearBasicAuth ? (
                        <p className="text-muted-foreground text-xs">
                          Basic auth will be removed on save.
                        </p>
                      ) : null}
                    </>
                  ) : null}
                </div>
                {isAdmin ? (
                  <div className="flex flex-wrap gap-2">
                    <Button type="submit" disabled={mutations.update.isPending}>
                      {mutations.update.isPending
                        ? "Saving..."
                        : "Save changes"}
                    </Button>
                    {tunnel.status !== "stopped" ? (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setConfirmStop(true)}
                      >
                        Stop tunnel
                      </Button>
                    ) : null}
                  </div>
                ) : null}
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {tunnel.protocol === "https" ? (
          <TabsContent value="redirects">
            <div className="space-y-4">
              <p className="text-muted-foreground text-sm">
                Path patterns are evaluated top to bottom. First match wins.
              </p>
              {sortedRules.length === 0 ? (
                <EmptyState
                  title="No redirect rules"
                  description="Add a path pattern to route subsets of traffic to another port."
                />
              ) : (
                <ul className="divide-y divide-border/60 rounded-lg border border-border/60">
                  {sortedRules.map((rule, index) => (
                    <li
                      key={rule.id}
                      className="flex flex-wrap items-center gap-3 px-4 py-3"
                    >
                      <div className="flex flex-col gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          disabled={!isAdmin || index === 0}
                          onClick={() =>
                            void moveRule(rule.id, rule.priority, "up")
                          }
                        >
                          <ArrowUpIcon className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          disabled={
                            !isAdmin || index === sortedRules.length - 1
                          }
                          onClick={() =>
                            void moveRule(rule.id, rule.priority, "down")
                          }
                        >
                          <ArrowDownIcon className="size-3.5" />
                        </Button>
                      </div>
                      <code className="flex-1 font-mono text-sm">
                        {rule.pathPattern}
                      </code>
                      <span className="text-muted-foreground text-xs">→</span>
                      <span className="font-mono text-sm">
                        {rule.targetEndpointId
                          ? (networkMachines.find(
                              (m) => m.endpointId === rule.targetEndpointId,
                            )?.name ?? `${rule.targetEndpointId.slice(0, 8)}…`)
                          : "localhost"}
                        :{rule.targetPort}
                      </span>
                      {isAdmin ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-destructive"
                          onClick={() =>
                            void mutations.removeRedirectRule
                              .mutateAsync({
                                networkId: tunnel.networkId,
                                tunnelId: tunnel.id,
                                ruleId: rule.id,
                              })
                              .then(() => toast.success("Rule removed"))
                              .catch((err: Error) => toast.error(err.message))
                          }
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {isAdmin ? (
                <form
                  className="flex flex-wrap items-end gap-3 rounded-lg border border-dashed border-border/60 p-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void mutations.createRedirectRule
                      .mutateAsync({
                        networkId: tunnel.networkId,
                        tunnelId: tunnel.id,
                        body: {
                          pathPattern: pathPattern.trim(),
                          targetPort: Number(targetPort),
                          targetEndpointId:
                            targetEndpointId === "localhost"
                              ? null
                              : targetEndpointId,
                          priority: (sortedRules[0]?.priority ?? 0) + 1,
                        },
                      })
                      .then(() => {
                        toast.success("Rule added");
                        setPathPattern("/api/*");
                        setTargetPort("8080");
                        setTargetEndpointId("localhost");
                      })
                      .catch((err: Error) => toast.error(err.message));
                  }}
                >
                  <div className="min-w-[160px] flex-1 space-y-2">
                    <Label htmlFor="rule-path">Path pattern</Label>
                    <Input
                      id="rule-path"
                      value={pathPattern}
                      onChange={(e) => setPathPattern(e.target.value)}
                      placeholder="/api/*"
                      required
                    />
                  </div>
                  <div className="min-w-[160px] space-y-2">
                    <Label>Target machine</Label>
                    <Select
                      value={targetEndpointId}
                      onValueChange={(value) =>
                        setTargetEndpointId(value ?? "localhost")
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="localhost">
                          This machine (localhost)
                        </SelectItem>
                        {networkMachines
                          .filter((m) => m.endpointId !== tunnel.endpointId)
                          .map((m) => (
                            <SelectItem key={m.endpointId} value={m.endpointId}>
                              {m.name}
                            </SelectItem>
                          ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="w-28 space-y-2">
                    <Label htmlFor="rule-port">Target port</Label>
                    <Input
                      id="rule-port"
                      type="number"
                      min={1}
                      max={65535}
                      value={targetPort}
                      onChange={(e) => setTargetPort(e.target.value)}
                      required
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={mutations.createRedirectRule.isPending}
                  >
                    Add rule
                  </Button>
                </form>
              ) : null}
            </div>
          </TabsContent>
        ) : (
          <TabsContent value="port-mappings">
            <div className="space-y-4">
              <p className="text-muted-foreground text-sm">
                Map public TCP ports on the tunnel hostname to local target
                ports.
              </p>
              {(portMappings ?? []).length === 0 ? (
                <EmptyState
                  title="No port mappings"
                  description="Add an external → target port mapping for TCP traffic."
                />
              ) : (
                <ul className="divide-y divide-border/60 rounded-lg border border-border/60">
                  {(portMappings ?? []).map((mapping) => (
                    <li
                      key={mapping.id}
                      className="flex items-center gap-3 px-4 py-3"
                    >
                      <code className="font-mono text-sm">
                        :{mapping.externalPort}
                      </code>
                      <span className="text-muted-foreground text-xs">→</span>
                      <code className="font-mono text-sm">
                        {mapping.targetEndpointId
                          ? (networkMachines.find(
                              (m) => m.endpointId === mapping.targetEndpointId,
                            )?.name ??
                            `${mapping.targetEndpointId.slice(0, 8)}…`)
                          : "localhost"}
                        :{mapping.targetPort}
                      </code>
                      {isAdmin ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="ml-auto size-8 text-destructive"
                          onClick={() =>
                            void mutations.removePortMapping
                              .mutateAsync({
                                networkId: tunnel.networkId,
                                tunnelId: tunnel.id,
                                mappingId: mapping.id,
                              })
                              .then(() => toast.success("Mapping removed"))
                              .catch((err: Error) => toast.error(err.message))
                          }
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {isAdmin ? (
                <form
                  className="flex flex-wrap items-end gap-3 rounded-lg border border-dashed border-border/60 p-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void mutations.createPortMapping
                      .mutateAsync({
                        networkId: tunnel.networkId,
                        tunnelId: tunnel.id,
                        body: {
                          externalPort: Number(externalPort),
                          targetPort: Number(mappingTargetPort),
                          targetEndpointId:
                            mappingTargetEndpointId === "localhost"
                              ? null
                              : mappingTargetEndpointId,
                        },
                      })
                      .then(() => {
                        toast.success("Mapping added");
                        setExternalPort("5432");
                        setMappingTargetPort("5432");
                        setMappingTargetEndpointId("localhost");
                      })
                      .catch((err: Error) => toast.error(err.message));
                  }}
                >
                  <div className="w-32 space-y-2">
                    <Label htmlFor="ext-port">External port</Label>
                    <Input
                      id="ext-port"
                      type="number"
                      min={1}
                      max={65535}
                      value={externalPort}
                      onChange={(e) => setExternalPort(e.target.value)}
                      required
                    />
                  </div>
                  <div className="min-w-[160px] space-y-2">
                    <Label>Target machine</Label>
                    <Select
                      value={mappingTargetEndpointId}
                      onValueChange={(value) =>
                        setMappingTargetEndpointId(value ?? "localhost")
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="localhost">
                          This machine (localhost)
                        </SelectItem>
                        {networkMachines
                          .filter((m) => m.endpointId !== tunnel.endpointId)
                          .map((m) => (
                            <SelectItem key={m.endpointId} value={m.endpointId}>
                              {m.name}
                            </SelectItem>
                          ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="w-32 space-y-2">
                    <Label htmlFor="map-target">Target port</Label>
                    <Input
                      id="map-target"
                      type="number"
                      min={1}
                      max={65535}
                      value={mappingTargetPort}
                      onChange={(e) => setMappingTargetPort(e.target.value)}
                      required
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={mutations.createPortMapping.isPending}
                  >
                    Add mapping
                  </Button>
                </form>
              ) : null}
            </div>
          </TabsContent>
        )}

        {isAdmin ? (
          <TabsContent value="danger">
            <Card className="max-w-xl border-destructive/30">
              <CardHeader>
                <CardTitle className="text-base text-destructive">
                  Danger zone
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-muted-foreground text-sm">
                  Destroying this tunnel removes the public URL immediately.
                  Traffic stops and DNS may take a moment to clear.
                </p>
                <Button
                  variant="destructive"
                  onClick={() => setConfirmDestroy(true)}
                >
                  Destroy tunnel
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        ) : null}
      </Tabs>

      <ConfirmDialog
        open={confirmStop}
        onOpenChange={setConfirmStop}
        title="Stop tunnel"
        description={`Stop ${url}? You can recreate it later; the subdomain may become available.`}
        confirmLabel="Stop"
        destructive
        loading={mutations.update.isPending}
        onConfirm={async () => {
          try {
            await mutations.update.mutateAsync({
              networkId: tunnel.networkId,
              tunnelId: tunnel.id,
              body: { status: "stopped" },
            });
            toast.success("Tunnel stopped");
            setConfirmStop(false);
          } catch (err) {
            toast.error(err instanceof Error ? err.message : "Failed to stop");
          }
        }}
      />

      <ConfirmDialog
        open={confirmDestroy}
        onOpenChange={setConfirmDestroy}
        title="Destroy tunnel"
        description={`Destroy ${url}? Public access will stop immediately.`}
        confirmLabel="Destroy"
        destructive
        loading={mutations.remove.isPending}
        onConfirm={async () => {
          try {
            await mutations.remove.mutateAsync({
              networkId: tunnel.networkId,
              tunnelId: tunnel.id,
            });
            toast.success("Tunnel destroyed");
            window.location.href = "/app/tunnels";
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to destroy",
            );
          }
        }}
      />
    </>
  );
}
