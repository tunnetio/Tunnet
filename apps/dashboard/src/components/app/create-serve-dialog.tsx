import { XIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { CopyField } from "@/components/app/copy-field";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { useMachines, useServeMutations } from "@/lib/queries/management";

type CreateServeDialogProps = {
  orgId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set with defaultNetworkId, create for this machine only — no picker. */
  defaultEndpointId?: string;
  defaultNetworkId?: string;
  defaultHostname?: string;
};

export function CreateServeDialog({
  orgId,
  open,
  onOpenChange,
  defaultEndpointId,
  defaultNetworkId,
  defaultHostname,
}: CreateServeDialogProps) {
  const { create } = useServeMutations(orgId);
  const { data: machines } = useMachines(orgId);
  const locked = Boolean(defaultEndpointId);
  const [endpointId, setEndpointId] = useState(defaultEndpointId ?? "");
  const [port, setPort] = useState("3000");
  const [protocol, setProtocol] = useState<"https" | "tcp">("https");
  const [accessMode, setAccessMode] = useState<
    "all_peers" | "tags" | "machines"
  >("all_peers");
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [createdHostname, setCreatedHostname] = useState<string | null>(null);

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

  const peerMachines = useMemo(() => {
    const network = networkId || selectedMachine?.networkId;
    if (!network) return [];
    return onlineMachines.filter(
      (m) => m.networkId === network && m.endpointId !== targetEndpointId,
    );
  }, [onlineMachines, networkId, selectedMachine, targetEndpointId]);

  const canSubmit = locked
    ? Boolean(targetEndpointId && networkId)
    : onlineMachines.length > 0;

  function reset() {
    setEndpointId(defaultEndpointId ?? "");
    setPort("3000");
    setProtocol("https");
    setAccessMode("all_peers");
    setTags([]);
    setTagInput("");
    setSelectedEndpoints([]);
    setCreatedHostname(null);
  }

  function handleClose(next: boolean) {
    if (!next) reset();
    onOpenChange(next);
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

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    let submitEndpointId = targetEndpointId;
    let submitNetworkId = networkId;

    if (!locked) {
      const machine =
        onlineMachines.find((m) => m.endpointId === endpointId) ??
        onlineMachines[0];
      if (!machine) {
        toast.error("Select an online machine");
        return;
      }
      submitEndpointId = machine.endpointId;
      submitNetworkId = machine.networkId;
    }

    if (!submitEndpointId || !submitNetworkId) {
      toast.error("Missing machine or network");
      return;
    }
    if (accessMode === "tags" && tags.length === 0) {
      toast.error("Add at least one tag");
      return;
    }
    if (accessMode === "machines" && selectedEndpoints.length === 0) {
      toast.error("Select at least one machine");
      return;
    }
    try {
      const result = await create.mutateAsync({
        networkId: submitNetworkId,
        body: {
          endpointId: submitEndpointId,
          localPort: Number(port),
          protocol,
          accessMode,
          allowedTags: accessMode === "tags" ? tags : [],
          allowedEndpointIds:
            accessMode === "machines" ? selectedEndpoints : [],
        },
      });
      setCreatedHostname(result.serve.internalHostname);
      toast.success("Serve created");
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to create serve",
      );
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-lg">
        {createdHostname ? (
          <>
            <DialogHeader>
              <DialogTitle>Serve ready</DialogTitle>
              <DialogDescription>
                Peers on the network can reach this service at the internal
                hostname.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <CopyField label="Internal hostname" value={createdHostname} />
              <CopyField
                label="CLI equivalent"
                value={`tuntun serve ${port}${protocol !== "https" ? ` --protocol ${protocol}` : ""}`}
              />
            </div>
            <DialogFooter>
              <Button onClick={() => handleClose(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)}>
            <DialogHeader>
              <DialogTitle>Create serve</DialogTitle>
              <DialogDescription>
                {locked
                  ? `Publish a local port on ${machineLabel} to other machines on the mesh.`
                  : "Publish a local port to other machines on the mesh with an internal hostname."}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
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
                </div>
              )}
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="serve-port">Port</Label>
                  <Input
                    id="serve-port"
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
                <Label>Access</Label>
                <Select
                  value={accessMode}
                  onValueChange={(value) =>
                    setAccessMode(
                      (value as "all_peers" | "tags" | "machines") ??
                        "all_peers",
                    )
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all_peers">All peers</SelectItem>
                    <SelectItem value="tags">Tags</SelectItem>
                    <SelectItem value="machines">Specific machines</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {accessMode === "tags" ? (
                <div className="space-y-2">
                  <Label>Tags</Label>
                  <div className="flex flex-wrap gap-1.5">
                    {tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="gap-1">
                        {tag}
                        <button
                          type="button"
                          onClick={() => setTags(tags.filter((t) => t !== tag))}
                        >
                          <XIcon className="size-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <Input
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      placeholder="production"
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
                </div>
              ) : null}

              {accessMode === "machines" ? (
                <div className="space-y-2">
                  <Label>Machines</Label>
                  <div className="max-h-40 space-y-2 overflow-y-auto rounded-lg border border-border/60 p-3">
                    {peerMachines.length === 0 ? (
                      <p className="text-muted-foreground text-sm">
                        No other online machines in this network.
                      </p>
                    ) : (
                      peerMachines.map((machine) => {
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
                {create.isPending ? "Creating..." : "Create serve"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
