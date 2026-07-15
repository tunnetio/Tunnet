import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
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
import { getControlPlaneUrl } from "@/lib/env";
import { createManagementClient } from "@/lib/management-client";
import { useNetworks } from "@/lib/queries/management";
import { queryKeys } from "@/lib/query-keys";

type EnrollmentTokenDialogProps = {
  orgId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  defaultNetworkId?: string;
};

export function EnrollmentTokenDialog({
  orgId,
  open,
  onOpenChange,
  defaultNetworkId,
}: EnrollmentTokenDialogProps) {
  const queryClient = useQueryClient();
  const { data: networks } = useNetworks(orgId);
  const [networkId, setNetworkId] = useState(defaultNetworkId ?? "");
  const [ttlMinutes, setTtlMinutes] = useState("15");
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState<string | null>(null);

  const selectedNetworkId = networkId || networks?.[0]?.id || "";

  async function generate() {
    if (!selectedNetworkId) {
      toast.error("Create a network first");
      return;
    }
    setLoading(true);
    try {
      const client = createManagementClient(orgId);
      const result = await client.createEnrollmentToken(selectedNetworkId, {
        ttlMinutes: Number(ttlMinutes) || 15,
      });
      setToken(result.token);
      void queryClient.invalidateQueries({
        queryKey: queryKeys.enrollmentTokens(orgId, selectedNetworkId),
      });
      toast.success("Enrollment token created");
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to create token",
      );
    } finally {
      setLoading(false);
    }
  }

  function handleClose(next: boolean) {
    if (!next) {
      setToken(null);
      setNetworkId(defaultNetworkId ?? "");
    }
    onOpenChange(next);
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Generate enrollment token</DialogTitle>
          <DialogDescription>
            Primary path: one-time token. Machines can also quick enroll with
            your org slug and wait for approval.
          </DialogDescription>
        </DialogHeader>

        {token ? (
          <div className="space-y-4">
            <CopyField label="Enrollment token" value={token} />
            <CopyField
              label="Install command"
              value={`tuntun enroll --token ${token} --control-url ${getControlPlaneUrl()}`}
            />
            <p className="text-muted-foreground text-xs">
              This token is shown only once. Copy it before closing.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Network</Label>
              <Select
                value={selectedNetworkId}
                onValueChange={(value) => setNetworkId(value ?? "")}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select network" />
                </SelectTrigger>
                <SelectContent>
                  {(networks ?? []).map((network) => (
                    <SelectItem key={network.id} value={network.id}>
                      {network.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {(networks?.length ?? 0) === 0 ? (
                <p className="text-muted-foreground text-xs">
                  Create a network before enrolling machines.
                </p>
              ) : null}
            </div>
            <div className="space-y-2">
              <Label htmlFor="ttl">Expires in (minutes)</Label>
              <Input
                id="ttl"
                type="number"
                min={1}
                max={10080}
                value={ttlMinutes}
                onChange={(e) => setTtlMinutes(e.target.value)}
              />
            </div>
          </div>
        )}

        <DialogFooter>
          {token ? (
            <Button onClick={() => handleClose(false)}>Done</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => handleClose(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => void generate()}
                disabled={loading || (networks?.length ?? 0) === 0}
              >
                {loading ? "Generating..." : "Generate token"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
