import { ExternalLinkIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { CopyField } from "@/components/app/copy-field";
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
import { getMachinePresence } from "@/lib/machine-utils";
import {
  useMachines,
  useRelays,
  useTunnelMutations,
} from "@/lib/queries/management";

type CreateTunnelDialogProps = {
  orgId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set, create for this machine only — no picker. */
  defaultEndpointId?: string;
  defaultNetworkId?: string;
  /** Display name when locked to a machine (optional). */
  defaultHostname?: string;
};

const TTL_OPTIONS = [
  { value: "never", label: "Never", seconds: undefined },
  { value: "1h", label: "1 hour", seconds: 3600 },
  { value: "24h", label: "24 hours", seconds: 86400 },
  { value: "7d", label: "7 days", seconds: 604800 },
] as const;

export function CreateTunnelDialog({
  orgId,
  open,
  onOpenChange,
  defaultEndpointId,
  defaultNetworkId,
  defaultHostname,
}: CreateTunnelDialogProps) {
  const { create } = useTunnelMutations(orgId);
  const { data: machines } = useMachines(orgId);
  const { data: relays } = useRelays(orgId);
  const locked = Boolean(defaultEndpointId);
  const [endpointId, setEndpointId] = useState(defaultEndpointId ?? "");
  const [port, setPort] = useState("3000");
  const [protocol, setProtocol] = useState<"https" | "tcp">("https");
  const [relayId, setRelayId] = useState("auto");
  const [subdomain, setSubdomain] = useState("");
  const [ttl, setTtl] = useState("never");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [basicAuthUser, setBasicAuthUser] = useState("");
  const [basicAuthPassword, setBasicAuthPassword] = useState("");
  const [createdUrl, setCreatedUrl] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [suggestedSubdomain, setSuggestedSubdomain] = useState<string | null>(
    null,
  );

  useEffect(() => {
    if (open && defaultEndpointId) {
      setEndpointId(defaultEndpointId);
    }
  }, [open, defaultEndpointId]);

  const onlineMachines = useMemo(() => {
    const now = Date.now();
    return (machines ?? []).filter(
      (m) => getMachinePresence(m, now) === "online",
    );
  }, [machines]);

  const lockedMachine = useMemo(() => {
    if (!defaultEndpointId) return null;
    return (
      (machines ?? []).find((m) => m.endpointId === defaultEndpointId) ?? null
    );
  }, [machines, defaultEndpointId]);

  const selectedMachine = locked
    ? lockedMachine
    : (onlineMachines.find((m) => m.endpointId === endpointId) ??
      onlineMachines[0]);

  const networkId = locked
    ? (defaultNetworkId ?? lockedMachine?.networkId ?? "")
    : (selectedMachine?.networkId ?? defaultNetworkId ?? "");

  const targetEndpointId = locked
    ? defaultEndpointId!
    : (selectedMachine?.endpointId ?? "");

  const machineLabel =
    defaultHostname ??
    lockedMachine?.name ??
    selectedMachine?.name ??
    defaultEndpointId?.slice(0, 12);

  const healthyRelays = useMemo(
    () => (relays ?? []).filter((r) => r.status === "healthy"),
    [relays],
  );

  const selectedRelay =
    relayId === "auto"
      ? null
      : (healthyRelays.find((r) => r.id === relayId) ?? null);

  const domainPreview =
    selectedRelay?.domain ?? healthyRelays[0]?.domain ?? "*.tuntun.pub";

  const hostnameForPreview =
    machineLabel ?? selectedMachine?.name ?? lockedMachine?.name;

  const subdomainPreview =
    subdomain.trim() ||
    hostnameForPreview
      ?.toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/^-+|-+$/g, "") ||
    "my-app";

  const hostnamePreview = domainPreview.startsWith("*.")
    ? `${subdomainPreview}.${domainPreview.slice(2)}`
    : `${subdomainPreview}.${domainPreview}`;

  const cliHint = [
    `tuntun tunnel ${port}`,
    protocol !== "https" ? `--protocol ${protocol}` : null,
    subdomain.trim() ? `--subdomain ${subdomain.trim()}` : null,
  ]
    .filter(Boolean)
    .join(" ");

  const canSubmit = locked
    ? Boolean(targetEndpointId && networkId)
    : onlineMachines.length > 0;

  function reset() {
    setEndpointId(defaultEndpointId ?? "");
    setPort("3000");
    setProtocol("https");
    setRelayId("auto");
    setSubdomain("");
    setTtl("never");
    setShowAdvanced(false);
    setBasicAuthUser("");
    setBasicAuthPassword("");
    setCreatedUrl(null);
    setFormError(null);
    setSuggestedSubdomain(null);
  }

  function handleClose(next: boolean) {
    if (!next) reset();
    onOpenChange(next);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);

    let submitEndpointId = targetEndpointId;
    let submitNetworkId = networkId;

    if (!locked) {
      const machine =
        onlineMachines.find((m) => m.endpointId === endpointId) ??
        onlineMachines[0];
      if (!machine) {
        setFormError("Select an online machine");
        return;
      }
      submitEndpointId = machine.endpointId;
      submitNetworkId = machine.networkId;
    }

    if (!submitEndpointId || !submitNetworkId) {
      setFormError("Missing machine or network");
      return;
    }

    const ttlOpt = TTL_OPTIONS.find((o) => o.value === ttl);
    try {
      const result = await create.mutateAsync({
        networkId: submitNetworkId,
        body: {
          endpointId: submitEndpointId,
          localPort: Number(port),
          protocol,
          relayId: relayId === "auto" ? undefined : relayId,
          subdomain: subdomain.trim() || undefined,
          ttlSeconds: ttlOpt?.seconds,
          basicAuth:
            basicAuthUser.trim() && basicAuthPassword
              ? {
                  username: basicAuthUser.trim(),
                  password: basicAuthPassword,
                }
              : undefined,
        },
      });
      setCreatedUrl(`https://${result.tunnel.publicHostname}`);
      toast.success("Tunnel created");
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to create tunnel";
      const suggestionMatch = message.match(/Try "([^"]+)" instead/i);
      const conflict =
        /already|conflict|taken|subdomain/i.test(message) ||
        (err instanceof Error &&
          "status" in err &&
          (err as { status?: number }).status === 409);
      if (suggestionMatch?.[1]) {
        setSuggestedSubdomain(suggestionMatch[1]);
        setFormError(message);
      } else if (conflict) {
        const suggestion = `${subdomainPreview}-${Math.random().toString(36).slice(2, 6)}`;
        setSuggestedSubdomain(suggestion);
        setFormError(`${message}. Suggested: ${suggestion}`);
      } else {
        setSuggestedSubdomain(null);
        setFormError(message);
      }
      toast.error(message);
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-lg">
        {createdUrl ? (
          <>
            <DialogHeader>
              <DialogTitle>Tunnel ready</DialogTitle>
              <DialogDescription>
                Your public URL is live. Share it or open it in a browser.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <CopyField label="Public URL" value={createdUrl} />
              <CopyField label="CLI equivalent" value={cliHint} />
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                nativeButton={false}
                render={
                  <a href={createdUrl} target="_blank" rel="noreferrer" />
                }
              >
                <ExternalLinkIcon className="mr-1.5 size-3.5" />
                Open in browser
              </Button>
              <Button onClick={() => handleClose(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)}>
            <DialogHeader>
              <DialogTitle>Create tunnel</DialogTitle>
              <DialogDescription>
                {locked
                  ? `Expose a local port on ${machineLabel} through a public relay URL.`
                  : "Expose a local port on a machine through a public relay URL."}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              {!locked && onlineMachines.length === 0 ? (
                <p className="text-muted-foreground rounded-lg border border-dashed border-border/60 px-3 py-4 text-sm">
                  No online machines. Enroll an agent and wait until it shows
                  online before creating a tunnel.
                </p>
              ) : null}
              {locked ? (
                <div className="space-y-1">
                  <Label>Machine</Label>
                  <p className="text-sm font-medium">{machineLabel}</p>
                </div>
              ) : (
                <div className="space-y-2">
                  <Label>Machine</Label>
                  <Select
                    value={selectedMachine?.endpointId ?? ""}
                    onValueChange={(value) => setEndpointId(value ?? "")}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select online machine" />
                    </SelectTrigger>
                    <SelectContent>
                      {onlineMachines.map((machine) => (
                        <SelectItem
                          key={machine.endpointId}
                          value={machine.endpointId}
                        >
                          {machine.name} ({machine.networkName})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {networkId ? (
                    <p className="text-muted-foreground text-xs">
                      Network is taken from the selected machine.
                    </p>
                  ) : null}
                </div>
              )}
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="tunnel-port">Port</Label>
                  <Input
                    id="tunnel-port"
                    type="number"
                    min={1}
                    max={65535}
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label>Protocol</Label>
                  <Select
                    value={protocol}
                    onValueChange={(value) =>
                      setProtocol((value as "https" | "tcp") ?? "https")
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="https">HTTPS</SelectItem>
                      <SelectItem value="tcp">TCP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Relay</Label>
                <Select
                  value={relayId}
                  onValueChange={(value) => setRelayId(value ?? "auto")}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">Auto (closest healthy)</SelectItem>
                    {healthyRelays.map((relay) => (
                      <SelectItem key={relay.id} value={relay.id}>
                        {relay.name} ({relay.region})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="tunnel-subdomain">Subdomain (optional)</Label>
                <Input
                  id="tunnel-subdomain"
                  value={subdomain}
                  onChange={(e) => {
                    setSubdomain(e.target.value);
                    setFormError(null);
                    setSuggestedSubdomain(null);
                  }}
                  placeholder="my-app"
                  pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                />
                <p className="text-muted-foreground font-mono text-xs">
                  → https://{hostnamePreview}
                </p>
                {formError ? (
                  <p className="text-destructive text-sm">{formError}</p>
                ) : null}
                {suggestedSubdomain ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setSubdomain(suggestedSubdomain);
                      setSuggestedSubdomain(null);
                      setFormError(null);
                    }}
                  >
                    Use “{suggestedSubdomain}”
                  </Button>
                ) : null}
              </div>
              <div className="space-y-2">
                <Label>Auto-expire</Label>
                <Select
                  value={ttl}
                  onValueChange={(value) => setTtl(value ?? "never")}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TTL_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-3">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="px-0"
                  onClick={() => setShowAdvanced((v) => !v)}
                >
                  {showAdvanced ? "Hide advanced" : "Show advanced"}
                </Button>
                {showAdvanced ? (
                  <div className="space-y-3 rounded-lg border border-border/60 p-3">
                    <p className="text-muted-foreground text-xs">
                      Optional HTTP Basic Auth for public visitors (HTTPS
                      tunnels).
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="basic-user">Username</Label>
                        <Input
                          id="basic-user"
                          value={basicAuthUser}
                          onChange={(e) => setBasicAuthUser(e.target.value)}
                          autoComplete="off"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="basic-pass">Password</Label>
                        <Input
                          id="basic-pass"
                          type="password"
                          value={basicAuthPassword}
                          onChange={(e) => setBasicAuthPassword(e.target.value)}
                          autoComplete="new-password"
                        />
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleClose(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending || !canSubmit}>
                {create.isPending ? "Creating..." : "Create tunnel"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
