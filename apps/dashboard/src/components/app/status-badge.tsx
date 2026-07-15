import type { Device } from "@tuntun/api/management";
import { memo } from "react";
import { Badge } from "@/components/ui/badge";
import { useLivePresence } from "@/hooks/use-live-presence";
import { getMachinePresence, type MachinePresence } from "@/lib/machine-utils";
import { usePresenceClock } from "@/lib/presence-clock";
import { cn } from "@/lib/utils";

const labels: Record<MachinePresence, string> = {
  online: "Online",
  stale: "Stale",
  offline: "Offline",
  suspended: "Suspended",
  pending: "Pending",
  expired: "Expired",
};

const variants: Record<
  MachinePresence,
  "default" | "secondary" | "destructive" | "outline"
> = {
  online: "default",
  stale: "secondary",
  offline: "outline",
  suspended: "destructive",
  pending: "secondary",
  expired: "destructive",
};

const dotClass: Record<MachinePresence, string> = {
  online: "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]",
  stale: "bg-amber-400",
  offline: "bg-muted-foreground/40",
  suspended: "bg-destructive",
  pending: "bg-amber-400",
  expired: "bg-destructive",
};

export const StatusBadge = memo(function StatusBadge({
  orgId,
  device,
  showDot = true,
}: {
  orgId?: string;
  device: Pick<
    Device,
    | "endpointId"
    | "networkId"
    | "status"
    | "agentConnected"
    | "connectedAt"
    | "disconnectedAt"
    | "lastHeartbeatAt"
    | "publicIp"
    | "lastSeen"
  >;
  showDot?: boolean;
}) {
  const live = useLivePresence(orgId, device);
  const now = usePresenceClock();
  const presence = getMachinePresence(live, now);

  return (
    <Badge variant={variants[presence]} className="gap-1.5">
      {showDot ? (
        <span
          className={cn("size-1.5 rounded-full", dotClass[presence])}
          aria-hidden
        />
      ) : null}
      {labels[presence]}
    </Badge>
  );
});
