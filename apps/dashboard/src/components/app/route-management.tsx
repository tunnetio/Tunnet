import type { ColumnDef } from "@tanstack/react-table";
import type {
  CreateHostnameRouteBody,
  CreateSubnetRouteBody,
  Device,
  HostnameRoute,
  SubnetRoute,
} from "@tuntun/api/management";
import { LockIcon, NetworkIcon, PlusIcon, TrashIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

export type UnifiedRoute = {
  id: string;
  kind: "subnet" | "hostname";
  name: string;
  destination: string;
  service: string;
  via: string;
  description: string;
  enabled: boolean;
};

export function toUnifiedRoutes(
  subnetRoutes: SubnetRoute[],
  hostnameRoutes: HostnameRoute[],
): UnifiedRoute[] {
  const subnets: UnifiedRoute[] = subnetRoutes.map((r) => ({
    id: r.id,
    kind: "subnet" as const,
    name: r.cidr,
    destination: r.cidr,
    service: "-",
    via: r.viaIp || r.endpointId.slice(0, 8),
    description: r.description ?? "",
    enabled: r.enabled,
  }));
  const hosts: UnifiedRoute[] = hostnameRoutes.map((r) => ({
    id: r.id,
    kind: "hostname" as const,
    name: r.hostnameLabel ?? r.hostname,
    destination: r.hostnameLabel ?? r.hostname,
    service: r.targetIp || "local resolve",
    via: r.viaIp || r.endpointId.slice(0, 8),
    description: r.description ?? "",
    enabled: r.enabled,
  }));
  return [...subnets, ...hosts];
}

export function GatewaySelect({
  devices,
  value,
  onChange,
}: {
  devices: Device[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="space-y-2">
      <Label>Gateway</Label>
      <Select value={value} onValueChange={(v) => v && onChange(v)}>
        <SelectTrigger>
          <SelectValue placeholder="Select machine" />
        </SelectTrigger>
        <SelectContent>
          {devices.map((device) => (
            <SelectItem key={device.endpointId} value={device.endpointId}>
              {device.name} ({device.assignedIp})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function AddRouteTypeDialog({
  open,
  onOpenChange,
  onSelect,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (kind: "subnet" | "hostname") => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl" showCloseButton>
        <DialogHeader className="gap-1.5">
          <DialogTitle className="text-xl">Add route</DialogTitle>
          <DialogDescription className="text-sm">
            Choose the type of route to add to this node.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-2 sm:grid-cols-2">
          <button
            type="button"
            onClick={() => onSelect("subnet")}
            className="hover:bg-muted/80 flex flex-col items-start gap-3 rounded-xl border border-border/80 bg-muted/40 p-5 text-left transition-colors"
          >
            <NetworkIcon
              className="text-foreground size-5"
              strokeWidth={1.75}
            />
            <div className="space-y-1">
              <p className="text-sm font-semibold tracking-tight">
                Private CIDR
              </p>
              <p className="text-muted-foreground text-xs leading-relaxed">
                Route traffic for a private network range through this node.
              </p>
            </div>
          </button>
          <button
            type="button"
            onClick={() => onSelect("hostname")}
            className="hover:bg-muted/80 flex flex-col items-start gap-3 rounded-xl border border-border/80 bg-muted/40 p-5 text-left transition-colors"
          >
            <LockIcon className="text-foreground size-5" strokeWidth={1.75} />
            <div className="space-y-1">
              <p className="text-sm font-semibold tracking-tight">
                Private hostname
              </p>
              <p className="text-muted-foreground text-xs leading-relaxed">
                Map a private hostname to this node so devices can resolve it.
              </p>
            </div>
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function CreateSubnetRouteDialog({
  open,
  onOpenChange,
  devices,
  fixedEndpointId,
  loading,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  devices?: Device[];
  /** When set, gateway is fixed and the select is hidden. */
  fixedEndpointId?: string;
  loading: boolean;
  onSubmit: (body: CreateSubnetRouteBody) => Promise<void>;
}) {
  const [endpointId, setEndpointId] = useState(fixedEndpointId ?? "");
  const [cidr, setCidr] = useState("");
  const [description, setDescription] = useState("");
  const agentDevices = (devices ?? []).filter((d) => d.type === "agent");

  useEffect(() => {
    if (open) {
      setEndpointId(fixedEndpointId ?? "");
      setCidr("");
      setDescription("");
    }
  }, [open, fixedEndpointId]);

  const resolvedEndpointId = fixedEndpointId ?? endpointId;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void onSubmit({
              endpointId: resolvedEndpointId,
              cidr,
              description: description.trim() || undefined,
              enabled: true,
            });
          }}
        >
          <DialogHeader>
            <DialogTitle>Add subnet route</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {!fixedEndpointId ? (
              <GatewaySelect
                devices={agentDevices}
                value={endpointId}
                onChange={setEndpointId}
              />
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="cidr">CIDR</Label>
              <Input
                id="cidr"
                className="font-mono"
                placeholder="10.0.0.0/24"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="subnet-desc">Description</Label>
              <Input
                id="subnet-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={loading || !resolvedEndpointId || !cidr}
            >
              {loading ? "Creating..." : "Add route"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function CreateHostnameRouteDialog({
  open,
  onOpenChange,
  devices,
  fixedEndpointId,
  loading,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  devices?: Device[];
  fixedEndpointId?: string;
  loading: boolean;
  onSubmit: (body: CreateHostnameRouteBody) => Promise<void>;
}) {
  const [endpointId, setEndpointId] = useState(fixedEndpointId ?? "");
  const [hostname, setHostname] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [description, setDescription] = useState("");
  const agentDevices = (devices ?? []).filter((d) => d.type === "agent");

  useEffect(() => {
    if (open) {
      setEndpointId(fixedEndpointId ?? "");
      setHostname("");
      setTargetIp("");
      setDescription("");
    }
  }, [open, fixedEndpointId]);

  const resolvedEndpointId = fixedEndpointId ?? endpointId;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void onSubmit({
              endpointId: resolvedEndpointId,
              hostname,
              targetIp: targetIp.trim() || undefined,
              description: description.trim() || undefined,
              enabled: true,
            });
          }}
        >
          <DialogHeader>
            <DialogTitle>Add hostname route</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {!fixedEndpointId ? (
              <GatewaySelect
                devices={agentDevices}
                value={endpointId}
                onChange={setEndpointId}
              />
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="hostname">Hostname</Label>
              <Input
                id="hostname"
                className="font-mono"
                placeholder="wiki.internal or *.staging"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="target-ip">Target IP</Label>
              <Input
                id="target-ip"
                className="font-mono"
                placeholder="Optional - resolves locally if empty"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="host-desc">Description</Label>
              <Input
                id="host-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={loading || !resolvedEndpointId || !hostname}
            >
              {loading ? "Creating..." : "Add route"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function NetworkRoutesMiniDiagram({
  subnets,
  hostnames,
}: {
  subnets: SubnetRoute[];
  hostnames: HostnameRoute[];
}) {
  const items = [
    ...subnets.slice(0, 6).map((r) => ({
      id: r.id,
      label: r.cidr,
      tone: "subnet" as const,
    })),
    ...hostnames.slice(0, 6).map((r) => ({
      id: r.id,
      label: r.hostnameLabel ?? r.hostname,
      tone: "hostname" as const,
    })),
  ].slice(0, 8);

  return (
    <div className="relative overflow-hidden rounded-lg border border-border/60 bg-[#0b0d10]">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "radial-gradient(circle at 1px 1px, rgba(148,163,184,0.25) 1px, transparent 0)",
          backgroundSize: "16px 16px",
        }}
      />
      <div className="relative flex min-h-[140px] items-center justify-center gap-10 px-8 py-8">
        <div className="flex flex-col items-center gap-2">
          <div className="flex size-11 items-center justify-center rounded-full border border-emerald-400/40 bg-emerald-400/10 text-[10px] font-medium tracking-wide text-emerald-300 uppercase">
            Mesh
          </div>
        </div>
        <div className="relative flex min-w-[40%] flex-1 flex-col items-stretch gap-2">
          {items.length === 0 ? (
            <div className="text-muted-foreground text-center text-xs">
              No advertised routes
            </div>
          ) : (
            items.map((item, i) => (
              <div
                key={item.id}
                className="relative flex items-center gap-3"
                style={{ marginLeft: `${(i % 3) * 12}px` }}
              >
                <div
                  className={cn(
                    "h-px flex-1",
                    item.tone === "subnet"
                      ? "bg-linear-to-r from-emerald-400/70 to-emerald-400/10"
                      : "bg-linear-to-r from-sky-400/70 to-sky-400/10",
                  )}
                />
                <span
                  className={cn(
                    "rounded border px-2 py-1 font-mono text-[11px]",
                    item.tone === "subnet"
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                      : "border-sky-500/30 bg-sky-500/10 text-sky-200",
                  )}
                >
                  {item.label}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export function MachineConnectedRoutesDiagram({
  hostname,
  subnets,
  hostnames,
  canAdd,
  onAddRoute,
}: {
  hostname: string;
  subnets: SubnetRoute[];
  hostnames: HostnameRoute[];
  canAdd: boolean;
  onAddRoute?: () => void;
}) {
  const items = [
    ...subnets.map((r) => ({
      id: r.id,
      label: r.cidr,
      tone: "subnet" as const,
    })),
    ...hostnames.map((r) => ({
      id: r.id,
      label: r.hostnameLabel ?? r.hostname,
      tone: "hostname" as const,
    })),
  ];
  const visible = items.slice(0, 6);
  const overflow = items.length - visible.length;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium tracking-tight">Connected routes</h3>
      <div className="relative overflow-hidden rounded-lg border border-border/60 bg-muted/30">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-50"
          style={{
            backgroundImage:
              "radial-gradient(circle at 1px 1px, color-mix(in oklab, var(--border) 80%, transparent) 1px, transparent 0)",
            backgroundSize: "14px 14px",
          }}
        />
        <div className="relative flex min-h-[160px] items-center justify-center gap-6 px-6 py-10">
          {items.length === 0 && canAdd ? (
            <>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="bg-background shadow-sm"
                onClick={onAddRoute}
              >
                <PlusIcon className="size-3.5" />
                Add route
              </Button>
              <div
                aria-hidden
                className="bg-border h-px w-16 shrink-0 sm:w-24"
              />
            </>
          ) : null}

          {visible.length > 0 ? (
            <div className="flex max-w-[40%] flex-col items-end gap-2">
              {visible.map((item) => (
                <span
                  key={item.id}
                  className={cn(
                    "rounded-md border bg-background px-2.5 py-1 font-mono text-[11px] shadow-sm",
                    item.tone === "subnet"
                      ? "border-border text-foreground"
                      : "border-border text-foreground",
                  )}
                >
                  {item.label}
                </span>
              ))}
              {overflow > 0 ? (
                <span className="text-muted-foreground text-[11px]">
                  +{overflow} more
                </span>
              ) : null}
            </div>
          ) : null}

          {visible.length > 0 ? (
            <div aria-hidden className="bg-border h-px w-10 shrink-0 sm:w-16" />
          ) : null}

          <div className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 shadow-sm">
            <span
              aria-hidden
              className="grid size-4 shrink-0 grid-cols-3 gap-px"
            >
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
              <span className="bg-muted-foreground/50 size-1 rounded-[1px]" />
            </span>
            <span className="max-w-40 truncate text-sm font-medium">
              {hostname}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function buildNetworkRouteColumns({
  isAdmin,
  onToggle,
  onDelete,
}: {
  isAdmin: boolean;
  onToggle: (route: UnifiedRoute) => void;
  onDelete: (route: UnifiedRoute) => void;
}): ColumnDef<UnifiedRoute>[] {
  return [
    {
      id: "type",
      header: "Type",
      meta: { headerClassName: "w-28" },
      cell: ({ row }) => (
        <Badge variant="outline" className="capitalize">
          {row.original.kind}
        </Badge>
      ),
    },
    {
      id: "name",
      header: "Route",
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.name}</span>
      ),
    },
    {
      id: "destination",
      header: "Destination",
      cell: ({ row }) => (
        <span className="text-muted-foreground font-mono text-sm">
          {row.original.kind === "hostname"
            ? row.original.service
            : row.original.destination}
        </span>
      ),
    },
    {
      id: "via",
      header: "Via",
      cell: ({ row }) => (
        <span className="text-muted-foreground font-mono text-xs">
          {row.original.via}
        </span>
      ),
    },
    {
      id: "status",
      header: "Status",
      meta: { headerClassName: "w-28" },
      cell: ({ row }) => (
        <Badge variant={row.original.enabled ? "default" : "outline"}>
          {row.original.enabled ? "Enabled" : "Disabled"}
        </Badge>
      ),
    },
    ...(isAdmin
      ? [
          {
            id: "actions",
            header: "",
            meta: { headerClassName: "w-32" },
            cell: ({ row }: { row: { original: UnifiedRoute } }) => {
              const r = row.original;
              return (
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => onToggle(r)}>
                    {r.enabled ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(r)}
                  >
                    <TrashIcon className="size-4" />
                  </Button>
                </div>
              );
            },
          } satisfies ColumnDef<UnifiedRoute>,
        ]
      : []),
  ];
}

export function buildMachineRouteColumns({
  isAdmin,
  onToggle,
  onDelete,
}: {
  isAdmin: boolean;
  onToggle: (route: UnifiedRoute) => void;
  onDelete: (route: UnifiedRoute) => void;
}): ColumnDef<UnifiedRoute>[] {
  return [
    {
      id: "type",
      header: "Type",
      meta: { headerClassName: "w-28" },
      cell: ({ row }) => (
        <Badge variant="outline">
          {row.original.kind === "subnet" ? "CIDR" : "Hostname"}
        </Badge>
      ),
    },
    {
      id: "destination",
      header: "Destination",
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.destination}</span>
      ),
    },
    {
      id: "service",
      header: "Service",
      cell: ({ row }) => (
        <span className="text-muted-foreground font-mono text-sm">
          {row.original.service}
        </span>
      ),
    },
    {
      id: "description",
      header: "Description",
      cell: ({ row }) => (
        <span className="text-muted-foreground text-sm">
          {row.original.description || "-"}
        </span>
      ),
    },
    ...(isAdmin
      ? [
          {
            id: "actions",
            header: "",
            meta: { headerClassName: "w-32" },
            cell: ({ row }: { row: { original: UnifiedRoute } }) => {
              const r = row.original;
              return (
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => onToggle(r)}>
                    {r.enabled ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(r)}
                  >
                    <TrashIcon className="size-4" />
                  </Button>
                </div>
              );
            },
          } satisfies ColumnDef<UnifiedRoute>,
        ]
      : []),
  ];
}
