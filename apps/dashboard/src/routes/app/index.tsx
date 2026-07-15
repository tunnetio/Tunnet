import { createFileRoute, Link } from "@tanstack/react-router";
import { CopyIcon, ExternalLinkIcon } from "lucide-react";
import { useMemo } from "react";
import { toast } from "sonner";
import { EmptyState } from "@/components/app/empty-state";
import { EntityStatus } from "@/components/app/entity-status";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useActiveOrganization } from "@/lib/auth-client";
import { getMachinePresence } from "@/lib/machine-utils";
import { formatNetworkName } from "@/lib/network-utils";
import {
  useMachines,
  useNetworks,
  useRelays,
  useServes,
  useTunnels,
} from "@/lib/queries/management";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/")({
  component: OverviewPage,
});

function HealthCounter({
  to,
  label,
  value,
  detail,
  tone,
}: {
  to: string;
  label: string;
  value: string;
  detail: string;
  tone: "ok" | "warn" | "bad";
}) {
  return (
    <Link
      to={to}
      className={cn(
        "group rounded-xl border bg-card px-4 py-3.5 transition-colors hover:bg-secondary/50",
        tone === "ok" && "border-border/70",
        tone === "warn" && "border-amber-500/35",
        tone === "bad" && "border-destructive/35",
      )}
    >
      <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
        {label}
      </p>
      <p
        className={cn(
          "mt-1.5 text-2xl font-semibold tracking-tight tabular-nums",
          tone === "ok" && "text-foreground",
          tone === "warn" && "text-amber-600 dark:text-amber-400",
          tone === "bad" && "text-destructive",
        )}
      >
        {value}
      </p>
      <p className="text-muted-foreground mt-1 text-xs">{detail}</p>
    </Link>
  );
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value);
  toast.success("Copied to clipboard");
}

function OverviewPage() {
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: machines, isPending: machinesPending } = useMachines(orgId);
  const { data: relays, isPending: relaysPending } = useRelays(orgId);
  const { data: tunnels, isPending: tunnelsPending } = useTunnels(orgId);
  const { data: serves, isPending: servesPending } = useServes(orgId);
  const { data: networks } = useNetworks(orgId);

  const now = Date.now();

  const onlineMachines = useMemo(
    () =>
      (machines ?? []).filter((m) => getMachinePresence(m, now) === "online")
        .length,
    [machines, now],
  );
  const totalMachines = machines?.length ?? 0;
  const healthyRelays = useMemo(
    () => (relays ?? []).filter((r) => r.status === "healthy").length,
    [relays],
  );
  const totalRelays = relays?.length ?? 0;
  const activeTunnels = useMemo(
    () => (tunnels ?? []).filter((t) => t.status === "active"),
    [tunnels],
  );
  const errorTunnels = useMemo(
    () => (tunnels ?? []).filter((t) => t.status === "error").length,
    [tunnels],
  );
  const activeServes = useMemo(
    () => (serves ?? []).filter((s) => s.status === "active"),
    [serves],
  );
  const firstNetwork = networks?.[0];

  const machinesTone: "ok" | "warn" | "bad" =
    totalMachines === 0
      ? "warn"
      : onlineMachines === totalMachines
        ? "ok"
        : onlineMachines === 0
          ? "bad"
          : "warn";
  const relaysTone: "ok" | "warn" | "bad" =
    totalRelays === 0
      ? "warn"
      : healthyRelays === totalRelays
        ? "ok"
        : healthyRelays === 0
          ? "bad"
          : "warn";
  const tunnelsTone: "ok" | "warn" | "bad" =
    errorTunnels > 0 ? "bad" : activeTunnels.length > 0 ? "ok" : "warn";
  const servesTone: "ok" | "warn" | "bad" =
    activeServes.length > 0 ? "ok" : "warn";

  const pending =
    machinesPending || relaysPending || tunnelsPending || servesPending;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Health and activity across your organization."
        actions={
          firstNetwork ? (
            <Button
              variant="outline"
              nativeButton={false}
              render={
                <Link
                  to="/app/networks/$networkId/map"
                  params={{ networkId: firstNetwork.id }}
                />
              }
            >
              <ExternalLinkIcon className="mr-2 size-4" />
              Network map
            </Button>
          ) : null
        }
      />

      {pending ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <HealthCounter
            to="/app/machines"
            label="Machines"
            value={`${onlineMachines}/${totalMachines}`}
            detail={`${onlineMachines} online`}
            tone={machinesTone}
          />
          <HealthCounter
            to="/app/relays"
            label="Relays"
            value={String(healthyRelays)}
            detail={`${healthyRelays} of ${totalRelays} healthy`}
            tone={relaysTone}
          />
          <HealthCounter
            to="/app/tunnels"
            label="Tunnels"
            value={String(activeTunnels.length)}
            detail={
              errorTunnels > 0
                ? `${errorTunnels} in error`
                : `${activeTunnels.length} active`
            }
            tone={tunnelsTone}
          />
          <HealthCounter
            to="/app/serves"
            label="Serves"
            value={String(activeServes.length)}
            detail={`${activeServes.length} active`}
            tone={servesTone}
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">Active tunnels</CardTitle>
            <Button
              variant="ghost"
              size="sm"
              nativeButton={false}
              render={<Link to="/app/tunnels" />}
            >
              View all
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {pending ? (
              <Skeleton className="h-24 w-full" />
            ) : activeTunnels.length === 0 ? (
              <EmptyState
                title="No active tunnels"
                description="Share a public URL to a port on one of your machines."
                steps={[
                  "Create tunnel (or run tuntun tunnel).",
                  "Pick an online machine and local port.",
                  "Copy the https:// URL and open it in a browser.",
                ]}
                className="py-8"
                action={
                  <Button
                    size="sm"
                    nativeButton={false}
                    render={<Link to="/app/tunnels" />}
                  >
                    Go to tunnels
                  </Button>
                }
              />
            ) : (
              activeTunnels.slice(0, 6).map((tunnel) => {
                const url = `https://${tunnel.publicHostname}`;
                return (
                  <div
                    key={tunnel.id}
                    className="flex items-center justify-between gap-3 rounded-lg border border-border/60 px-3 py-2.5"
                  >
                    <div className="min-w-0">
                      <Link
                        to="/app/tunnels/$tunnelId"
                        params={{ tunnelId: tunnel.id }}
                        className="truncate font-mono text-sm hover:underline"
                      >
                        {url}
                      </Link>
                      <p className="text-muted-foreground truncate text-xs">
                        {tunnel.hostname ?? tunnel.endpointId.slice(0, 8)} ·
                        port {tunnel.localPort}
                        {tunnel.relayName ? ` · ${tunnel.relayName}` : ""}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-8 shrink-0"
                      onClick={() => void copyText(url)}
                    >
                      <CopyIcon className="size-3.5" />
                    </Button>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">Active serves</CardTitle>
            <Button
              variant="ghost"
              size="sm"
              nativeButton={false}
              render={<Link to="/app/serves" />}
            >
              View all
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {pending ? (
              <Skeleton className="h-24 w-full" />
            ) : activeServes.length === 0 ? (
              <EmptyState
                title="No active serves"
                description="Expose a service to peers on the mesh with HTTPS."
                steps={[
                  "Create serve (or run tuntun serve).",
                  "Choose access: all peers, tags, or specific machines.",
                  "Peers connect via the internal hostname.",
                ]}
                className="py-8"
                action={
                  <Button
                    size="sm"
                    nativeButton={false}
                    render={<Link to="/app/serves" />}
                  >
                    Go to serves
                  </Button>
                }
              />
            ) : (
              activeServes.slice(0, 6).map((serve) => (
                <div
                  key={serve.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-border/60 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <Link
                      to="/app/serves/$serveId"
                      params={{ serveId: serve.id }}
                      className="truncate font-mono text-sm hover:underline"
                    >
                      {serve.internalHostname}
                    </Link>
                    <p className="text-muted-foreground truncate text-xs">
                      {serve.hostname ?? serve.endpointId.slice(0, 8)} ·{" "}
                      {serve.protocol.toUpperCase()} :{serve.localPort}
                    </p>
                  </div>
                  <EntityStatus status={serve.status} />
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {firstNetwork ? (
        <Link
          to="/app/networks/$networkId/map"
          params={{ networkId: firstNetwork.id }}
          className="group block overflow-hidden rounded-lg border border-border/60 transition-colors hover:border-border hover:bg-secondary/20"
        >
          <div className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <p className="text-sm font-medium">
                Network map · {formatNetworkName(firstNetwork.name)}
              </p>
              <p className="text-muted-foreground text-xs">
                Machines, relays, tunnels, and peer links
              </p>
            </div>
            <ExternalLinkIcon className="text-muted-foreground size-4 transition-transform group-hover:translate-x-0.5" />
          </div>
          <div className="mesh-surface relative h-28 border-t border-border/40">
            <div className="absolute inset-0 opacity-60">
              <div className="absolute top-1/2 left-[18%] size-2.5 -translate-y-1/2 rounded-full bg-emerald-400/80" />
              <div className="absolute top-[38%] left-[42%] size-2.5 rounded-full bg-emerald-400/80" />
              <div className="absolute top-[58%] left-[58%] size-2 rounded-full bg-slate-400/60" />
              <div className="absolute top-1/2 right-[22%] size-3 -translate-y-1/2 rotate-45 bg-red-400/70" />
              <svg className="absolute inset-0 size-full" aria-hidden="true">
                <title>Network mesh preview</title>
                <line
                  x1="20%"
                  y1="50%"
                  x2="42%"
                  y2="42%"
                  stroke="rgba(34,197,94,0.45)"
                  strokeWidth="1.5"
                />
                <line
                  x1="42%"
                  y1="42%"
                  x2="58%"
                  y2="58%"
                  stroke="rgba(34,197,94,0.35)"
                  strokeWidth="1.5"
                />
                <line
                  x1="58%"
                  y1="58%"
                  x2="78%"
                  y2="50%"
                  stroke="rgba(239,68,68,0.55)"
                  strokeWidth="1.5"
                  strokeDasharray="4 3"
                />
              </svg>
            </div>
          </div>
        </Link>
      ) : null}
    </>
  );
}
