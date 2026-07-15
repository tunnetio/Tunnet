import { format } from "date-fns";
import { useEffect, useState } from "react";

import {
  type ExpiryDevice,
  formatExpiryCountdown,
  formatInactivityLimit,
  formatInactivityLimitCompact,
  getExpiryUrgency,
  inactivityWindowSecs,
  resolveExpiresAtMs,
} from "@/lib/machine-expiry";
import { cn } from "@/lib/utils";

function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);

  return now;
}

function expiryTextClass(urgency: ReturnType<typeof getExpiryUrgency>) {
  return cn(
    urgency === "warning" && "text-amber-600 dark:text-amber-400",
    urgency === "critical" && "text-destructive",
  );
}

export function MachineExpiryCountdown({
  device,
  className,
}: {
  device: ExpiryDevice;
  className?: string;
}) {
  const now = useNow();
  const urgency = getExpiryUrgency(device, now);

  if (device.status === "expired" || device.expiredAt) {
    return <span className={cn("text-destructive", className)}>Expired</span>;
  }

  const expiresAtMs = resolveExpiresAtMs(device);
  if (expiresAtMs === null) {
    return (
      <span className={cn("text-muted-foreground", className)}>Never</span>
    );
  }

  const remaining = expiresAtMs - now;

  return (
    <span
      className={cn(
        "font-mono tabular-nums",
        expiryTextClass(urgency),
        className,
      )}
    >
      {formatExpiryCountdown(remaining)}
    </span>
  );
}

export function MachineExpirySettings({ device }: { device: ExpiryDevice }) {
  const now = useNow();
  const urgency = getExpiryUrgency(device, now);

  if (device.status === "expired" || device.expiredAt) {
    return (
      <div className="border-destructive/25 bg-destructive/5 rounded-lg border px-3.5 py-3">
        <p className="text-destructive text-sm font-medium">Machine expired</p>
        <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
          It cannot connect until re-enrolled or its inactivity TTL is cleared.
        </p>
      </div>
    );
  }

  const expiresAtMs = resolveExpiresAtMs(device);
  const remaining = expiresAtMs === null ? null : expiresAtMs - now;
  const windowSecs = inactivityWindowSecs(device);

  if (expiresAtMs === null) {
    return (
      <p className="text-muted-foreground text-sm leading-relaxed">
        No inactivity TTL. This machine will not be auto-cleaned unless org
        policy or a per-machine expiry is set.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        {windowSecs !== null ? (
          <div className="rounded-lg border border-border/70 px-3 py-2.5">
            <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
              Limit
            </p>
            <p className="mt-1 text-sm font-medium">
              {formatInactivityLimitCompact(windowSecs)}
            </p>
            <p className="text-muted-foreground mt-0.5 text-xs">
              {formatInactivityLimit(windowSecs)}
            </p>
          </div>
        ) : null}
        <div className="rounded-lg border border-border/70 px-3 py-2.5">
          <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
            Remaining
          </p>
          <p
            className={cn(
              "mt-1 font-mono text-sm font-medium tabular-nums",
              expiryTextClass(urgency),
            )}
          >
            {remaining === null ? "—" : formatExpiryCountdown(remaining)}
          </p>
        </div>
        <div className="rounded-lg border border-border/70 px-3 py-2.5 sm:col-span-1">
          <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
            Deadline
          </p>
          <p className="mt-1 text-sm font-medium">
            {format(new Date(expiresAtMs), "MMM d, HH:mm")}
          </p>
          <p className="text-muted-foreground mt-0.5 text-xs">
            {format(new Date(expiresAtMs), "yyyy")}
          </p>
        </div>
      </div>
      <p className="text-muted-foreground text-xs leading-relaxed">
        Deadline is last seen plus the inactivity TTL. Any control-plane contact
        resets the clock.
      </p>
    </div>
  );
}
