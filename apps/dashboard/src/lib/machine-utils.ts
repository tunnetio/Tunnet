import type { Device, Network } from "@tuntun/api/management";
import { formatDistanceToNow } from "date-fns";

import type { LivePresenceDevice } from "@/hooks/use-live-presence";

export type AggregatedMachine = Device & {
  networkName: string;
};

export function aggregateMachines(
  networks: Network[],
  devicesByNetwork: Map<string, Device[]>,
): AggregatedMachine[] {
  const machines: AggregatedMachine[] = [];

  for (const network of networks) {
    const devices = devicesByNetwork.get(network.id) ?? [];
    for (const device of devices) {
      machines.push({ ...device, networkName: network.name });
    }
  }

  return machines.sort(
    (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime(),
  );
}

export type MachinePresence =
  | "online"
  | "stale"
  | "offline"
  | "suspended"
  | "pending"
  | "expired";

/** Agent heartbeats arrive every ~30s; allow one missed beat. */
export const HEARTBEAT_ONLINE_MS = 45_000;

export function getMachinePresence(
  device: Pick<Device, "status" | "agentConnected" | "lastHeartbeatAt">,
  now = Date.now(),
): MachinePresence {
  if (device.status === "expired") return "expired";
  if (device.status === "suspended") return "suspended";
  if (device.status === "pending") return "pending";

  if (device.agentConnected && device.lastHeartbeatAt) {
    const heartbeatAge = now - new Date(device.lastHeartbeatAt).getTime();
    if (heartbeatAge < HEARTBEAT_ONLINE_MS) return "online";
    return "stale";
  }

  return "offline";
}

export function formatLastSeenLabel(
  device: Pick<
    LivePresenceDevice,
    | "status"
    | "lastSeen"
    | "agentConnected"
    | "lastHeartbeatAt"
    | "disconnectedAt"
  >,
  now = Date.now(),
): string {
  if (getMachinePresence(device, now) === "online") {
    return "Now";
  }

  const at = device.disconnectedAt ?? device.lastHeartbeatAt ?? device.lastSeen;

  return formatDistanceToNow(new Date(at), { addSuffix: true });
}
