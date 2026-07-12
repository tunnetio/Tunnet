import { createFileRoute, Link } from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import { ChevronRightIcon, XIcon } from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CopyField } from "@/components/app/copy-field";
import { EntityStatus } from "@/components/app/entity-status";
import { PageHeader } from "@/components/app/page-header";
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
import { Checkbox } from "@/components/ui/checkbox";
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
import { getMachinePresence } from "@/lib/machine-utils";
import {
  useMachines,
  useServeMutations,
  useServePeers,
  useServes,
} from "@/lib/queries/management";

export const Route = createFileRoute("/app/serves/$serveId")({
  component: ServeDetailPage,
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

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function ServeDetailPage() {
  const { serveId } = Route.useParams();
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const { data: serves, isPending } = useServes(orgId);
  const { data: machines } = useMachines(orgId);
  const mutations = useServeMutations(orgId);
  const [confirmStop, setConfirmStop] = useState(false);

  const serve = useMemo(
    () => (serves ?? []).find((s) => s.id === serveId),
    [serves, serveId],
  );

  const { data: peers, isPending: peersPending } = useServePeers(
    orgId,
    serve?.networkId,
    serve?.id,
  );

  const [accessMode, setAccessMode] = useState<
    "all_peers" | "tags" | "machines"
  >("all_peers");
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);

  useEffect(() => {
    if (!serve) return;
    setAccessMode(serve.accessMode);
    setTags(serve.allowedTags);
    setSelectedEndpoints(serve.allowedEndpointIds);
  }, [serve]);

  const networkMachines = useMemo(() => {
    if (!serve) return [];
    const now = Date.now();
    return (machines ?? []).filter(
      (m) =>
        m.networkId === serve.networkId &&
        getMachinePresence(m, now) === "online",
    );
  }, [machines, serve]);

  if (!orgId || isPending) {
    return <Skeleton className="h-96 w-full" />;
  }

  if (!serve) {
    return (
      <div className="space-y-4">
        <p className="text-muted-foreground">Serve not found.</p>
        <Button nativeButton={false} render={<Link to="/app/serves" />}>
          Back to serves
        </Button>
      </div>
    );
  }

  function addTag() {
    const next = tagInput.trim();
    if (!next || tags.includes(next)) {
      setTagInput("");
      return;
    }
    setTags([...tags, next]);
    setTagInput("");
  }

  async function saveAccess() {
    if (!serve) return;
    try {
      await mutations.update.mutateAsync({
        networkId: serve.networkId,
        serveId: serve.id,
        body: {
          accessMode,
          allowedTags: accessMode === "tags" ? tags : [],
          allowedEndpointIds:
            accessMode === "machines" ? selectedEndpoints : [],
        },
      });
      toast.success("Access control updated");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to update");
    }
  }

  return (
    <>
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink render={<Link to="/app/serves" />}>
              Serves
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator>
            <ChevronRightIcon className="size-4" />
          </BreadcrumbSeparator>
          <BreadcrumbItem>
            <BreadcrumbPage>{serve.internalHostname}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <PageHeader
        title={serve.internalHostname}
        description={`${serve.protocol.toUpperCase()} · port ${serve.localPort}`}
        actions={<EntityStatus status={serve.status} />}
      />

      <Tabs defaultValue="overview" className="gap-4">
        <TabsList variant="line">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="peers">
            Connected peers
            {(peers?.length ?? 0) > 0 ? (
              <Badge variant="secondary" className="ml-1.5">
                {peers!.length}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="access">Access control</TabsTrigger>
          {isAdmin ? (
            <TabsTrigger value="danger">Danger zone</TabsTrigger>
          ) : null}
        </TabsList>

        <TabsContent value="overview">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Service</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <CopyField
                  label="Internal hostname"
                  value={serve.internalHostname}
                />
                {serve.errorMessage ? (
                  <p className="text-destructive text-sm">
                    {serve.errorMessage}
                  </p>
                ) : null}
                <DetailRow label="Access">
                  <span className="capitalize">
                    {serve.accessMode.replace("_", " ")}
                  </span>
                </DetailRow>
                <DetailRow label="Created">
                  {formatDistanceToNow(new Date(serve.createdAt), {
                    addSuffix: true,
                  })}
                </DetailRow>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Routing</CardTitle>
              </CardHeader>
              <CardContent>
                <DetailRow label="Machine">
                  <Link
                    to="/app/machines/$endpointId"
                    params={{ endpointId: serve.endpointId }}
                    className="hover:underline"
                  >
                    {serve.hostname ?? serve.endpointId.slice(0, 12)}
                  </Link>
                </DetailRow>
                <DetailRow label="Network">
                  <Link
                    to="/app/networks/$networkId"
                    params={{ networkId: serve.networkId }}
                    className="hover:underline"
                  >
                    {serve.networkName ?? serve.networkId.slice(0, 8)}
                  </Link>
                </DetailRow>
                <DetailRow label="Port">{serve.localPort}</DetailRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="peers">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Connected peers</CardTitle>
            </CardHeader>
            <CardContent>
              {peersPending ? (
                <Skeleton className="h-24 w-full" />
              ) : !peers || peers.length === 0 ? (
                <p className="text-muted-foreground text-sm">
                  No peers connected right now.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-muted-foreground border-b text-left text-xs">
                        <th className="pb-2 font-medium">Peer</th>
                        <th className="pb-2 font-medium">Connected</th>
                        <th className="pb-2 font-medium">In</th>
                        <th className="pb-2 font-medium">Out</th>
                      </tr>
                    </thead>
                    <tbody>
                      {peers.map((peer) => (
                        <tr
                          key={peer.id}
                          className="border-b border-border/40 last:border-0"
                        >
                          <td className="py-2.5">
                            <Link
                              to="/app/machines/$endpointId"
                              params={{ endpointId: peer.peerEndpointId }}
                              className="hover:underline"
                            >
                              {peer.peerHostname ??
                                peer.peerEndpointId.slice(0, 12)}
                            </Link>
                          </td>
                          <td className="text-muted-foreground py-2.5">
                            {formatDistanceToNow(new Date(peer.connectedAt), {
                              addSuffix: true,
                            })}
                          </td>
                          <td className="py-2.5 font-mono text-xs">
                            {formatBytes(peer.bytesIn)}
                          </td>
                          <td className="py-2.5 font-mono text-xs">
                            {formatBytes(peer.bytesOut)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="access">
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle className="text-base">Who can access</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Access mode</Label>
                <Select
                  value={accessMode}
                  onValueChange={(value) =>
                    setAccessMode(
                      (value as "all_peers" | "tags" | "machines") ??
                        "all_peers",
                    )
                  }
                  disabled={!isAdmin}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all_peers">All peers</SelectItem>
                    <SelectItem value="tags">Specific tags</SelectItem>
                    <SelectItem value="machines">Specific machines</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {accessMode === "tags" ? (
                <div className="space-y-2">
                  <Label>Allowed tags</Label>
                  <div className="flex flex-wrap gap-1.5">
                    {tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="gap-1">
                        {tag}
                        {isAdmin ? (
                          <button
                            type="button"
                            onClick={() =>
                              setTags(tags.filter((t) => t !== tag))
                            }
                          >
                            <XIcon className="size-3" />
                          </button>
                        ) : null}
                      </Badge>
                    ))}
                  </div>
                  {isAdmin ? (
                    <div className="flex gap-2">
                      <Input
                        value={tagInput}
                        onChange={(e) => setTagInput(e.target.value)}
                        placeholder="Add tag"
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            addTag();
                          }
                        }}
                      />
                      <Button type="button" variant="outline" onClick={addTag}>
                        Add
                      </Button>
                    </div>
                  ) : null}
                </div>
              ) : null}

              {accessMode === "machines" ? (
                <div className="space-y-2">
                  <Label>Allowed machines</Label>
                  <div className="max-h-56 space-y-2 overflow-y-auto rounded-lg border border-border/60 p-3">
                    {networkMachines.length === 0 ? (
                      <p className="text-muted-foreground text-sm">
                        No online machines in this network.
                      </p>
                    ) : (
                      networkMachines.map((machine) => {
                        const checked = selectedEndpoints.includes(
                          machine.endpointId,
                        );
                        return (
                          <div
                            key={machine.endpointId}
                            className="flex items-center gap-2 text-sm"
                          >
                            <Checkbox
                              checked={checked}
                              disabled={!isAdmin}
                              onCheckedChange={(value) => {
                                if (value) {
                                  setSelectedEndpoints([
                                    ...selectedEndpoints,
                                    machine.endpointId,
                                  ]);
                                } else {
                                  setSelectedEndpoints(
                                    selectedEndpoints.filter(
                                      (id) => id !== machine.endpointId,
                                    ),
                                  );
                                }
                              }}
                            />
                            {machine.name}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              ) : null}

              {isAdmin ? (
                <Button
                  onClick={() => void saveAccess()}
                  disabled={mutations.update.isPending}
                >
                  {mutations.update.isPending ? "Saving..." : "Save access"}
                </Button>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

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
                  Stopping this serve removes the internal hostname from the
                  mesh snapshot.
                </p>
                <Button
                  variant="destructive"
                  onClick={() => setConfirmStop(true)}
                >
                  Stop serve
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        ) : null}
      </Tabs>

      <ConfirmDialog
        open={confirmStop}
        onOpenChange={setConfirmStop}
        title="Stop serve"
        description={`Stop ${serve.internalHostname}? Peers will no longer reach this service.`}
        confirmLabel="Stop"
        destructive
        loading={mutations.remove.isPending}
        onConfirm={async () => {
          try {
            await mutations.remove.mutateAsync({
              networkId: serve.networkId,
              serveId: serve.id,
            });
            toast.success("Serve stopped");
            window.location.href = "/app/serves";
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to stop serve",
            );
          }
        }}
      />
    </>
  );
}
