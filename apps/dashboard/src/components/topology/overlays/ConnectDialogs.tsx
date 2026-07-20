import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { CreatePolicyBody } from "@tunnet/api/management";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { CreateServeDialog } from "@/components/app/create-serve-dialog";
import { CreateTunnelDialog } from "@/components/app/create-tunnel-dialog";
import { EnrollmentTokenDialog } from "@/components/app/enrollment-token-dialog";
import {
  applyPolicyExtraFields,
  buildPolicySelector,
} from "@/components/app/policy-selector-fields";
import { useTopologyUi } from "@/components/topology/TopologyProvider";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
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
import { createManagementClient } from "@/lib/management-client";
import { queryKeys } from "@/lib/query-keys";

export function ConnectDialogs({
  orgId,
  networkId,
}: {
  orgId: string;
  networkId: string;
}) {
  const { connectIntent, setConnectIntent } = useTopologyUi();

  const policyOpen = connectIntent?.type === "policy";
  const serveOpen = connectIntent?.type === "serve";
  const tunnelOpen = connectIntent?.type === "tunnel";
  const enrollOpen = connectIntent?.type === "enroll";

  return (
    <>
      <CreatePolicyFromPeersDialog
        orgId={orgId}
        networkId={networkId}
        open={policyOpen}
        onOpenChange={(open) => {
          if (!open) setConnectIntent(null);
        }}
        sourceEndpointId={
          connectIntent?.type === "policy" ? connectIntent.sourceEndpointId : ""
        }
        targetEndpointId={
          connectIntent?.type === "policy" ? connectIntent.targetEndpointId : ""
        }
        sourceLabel={
          connectIntent?.type === "policy" ? connectIntent.sourceLabel : ""
        }
        targetLabel={
          connectIntent?.type === "policy" ? connectIntent.targetLabel : ""
        }
      />
      <CreateServeDialog
        orgId={orgId}
        open={serveOpen}
        onOpenChange={(open) => {
          if (!open) setConnectIntent(null);
        }}
        defaultEndpointId={
          connectIntent?.type === "serve" ? connectIntent.endpointId : undefined
        }
        defaultNetworkId={networkId}
      />
      <CreateTunnelDialog
        orgId={orgId}
        open={tunnelOpen}
        onOpenChange={(open) => {
          if (!open) setConnectIntent(null);
        }}
        defaultEndpointId={
          connectIntent?.type === "tunnel"
            ? connectIntent.endpointId
            : undefined
        }
        defaultNetworkId={networkId}
      />
      <EnrollmentTokenDialog
        orgId={orgId}
        open={enrollOpen}
        onOpenChange={(open) => {
          if (!open) setConnectIntent(null);
        }}
        defaultNetworkId={networkId}
      />
    </>
  );
}

function CreatePolicyFromPeersDialog({
  orgId,
  networkId,
  open,
  onOpenChange,
  sourceEndpointId,
  targetEndpointId,
  sourceLabel,
  targetLabel,
}: {
  orgId: string;
  networkId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sourceEndpointId: string;
  targetEndpointId: string;
  sourceLabel: string;
  targetLabel: string;
}) {
  const queryClient = useQueryClient();
  const [action, setAction] = useState<"allow" | "deny">("allow");
  const [protocol, setProtocol] = useState<"tcp" | "udp" | "icmp" | "any">(
    "any",
  );
  const [ports, setPorts] = useState("");
  const [slug, setSlug] = useState("");

  useEffect(() => {
    if (open) {
      setAction("allow");
      setProtocol("any");
      setPorts("");
      setSlug("");
    }
  }, [open]);

  const create = useMutation({
    mutationFn: async (body: CreatePolicyBody) => {
      const client = createManagementClient(orgId);
      return client.createPolicy(networkId, body);
    },
    onSuccess: async () => {
      toast.success("Policy created");
      await queryClient.invalidateQueries({
        queryKey: queryKeys.policies(orgId, networkId),
      });
      await queryClient.invalidateQueries({
        queryKey: queryKeys.topology(orgId, networkId),
      });
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error(
        err instanceof Error ? err.message : "Failed to create policy",
      );
    },
  });

  function submit() {
    const portRanges =
      ports.trim().length === 0
        ? []
        : ports.split(",").map((part) => {
            const [startRaw, endRaw] = part.trim().split("-");
            const start = Number(startRaw);
            const end = endRaw != null ? Number(endRaw) : start;
            return { start, end };
          });

    const body = applyPolicyExtraFields(
      {
        srcSelector: buildPolicySelector("endpoint", sourceEndpointId),
        dstSelector: buildPolicySelector("endpoint", targetEndpointId),
        action,
        protocol: protocol === "any" ? null : protocol,
        ports: portRanges,
        priority: 0,
      },
      { slug, srcPosture: "" },
    );
    create.mutate(body);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-[15px]">Create ACL rule</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-1">
          <p className="text-muted-foreground text-[12px]">
            From{" "}
            <span className="text-foreground font-medium">{sourceLabel}</span>{" "}
            to{" "}
            <span className="text-foreground font-medium">{targetLabel}</span>
          </p>
          <div className="space-y-1.5">
            <Label className="text-[12px]">Source endpoint</Label>
            <Input
              value={sourceEndpointId}
              readOnly
              className="h-8 font-mono text-[11px]"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-[12px]">Destination endpoint</Label>
            <Input
              value={targetEndpointId}
              readOnly
              className="h-8 font-mono text-[11px]"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-[12px]">Action</Label>
              <Select
                value={action}
                onValueChange={(v) => {
                  if (v) setAction(v as "allow" | "deny");
                }}
              >
                <SelectTrigger className="h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">Allow</SelectItem>
                  <SelectItem value="deny">Deny</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-[12px]">Protocol</Label>
              <Select
                value={protocol}
                onValueChange={(v) => {
                  if (v) setProtocol(v as "tcp" | "udp" | "icmp" | "any");
                }}
              >
                <SelectTrigger className="h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-[12px]">Ports (optional)</Label>
            <Input
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="80, 443, 8000-8010"
              className="h-8 font-mono text-[12px]"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-[12px]">Slug (optional)</Label>
            <Input
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="peer-to-peer"
              className="h-8 font-mono text-[12px]"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={create.isPending}>
            Create policy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
