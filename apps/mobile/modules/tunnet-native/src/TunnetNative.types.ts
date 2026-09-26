export type TunnetLocalNetworkAccess = "not_required" | "granted" | "denied";

export type TunnetPlatformState = {
  readonly supported: boolean;
  readonly vpnPermissionGranted: boolean;
  readonly localNetworkAccess: TunnetLocalNetworkAccess;
  readonly notificationPermissionGranted: boolean;
  /** True only after the native runtime has attached successfully. */
  readonly serviceRunning: boolean;
};

export type TunnetRuntimeSnapshotEvent = {
  readonly snapshot: Uint8Array;
};

export type TunnetNativeEvents = {
  onRuntimeSnapshot: (event: TunnetRuntimeSnapshotEvent) => void;
};

export type TunnetNativeModule = {
  start(invite?: string): Promise<void>;
  stop(): Promise<void>;
  /** Rejects until the native runtime is ready. Use `start(inviteCode)` for the initial join. */
  joinNetwork(inviteCode: string): Promise<void>;
  getPlatformState(): Promise<TunnetPlatformState>;
  requestVpnPermission(): Promise<boolean>;
  requestLocalNetworkPermission(): Promise<boolean>;
  requestNotificationPermission(): Promise<boolean>;
  addListener(
    eventName: "onRuntimeSnapshot",
    listener: TunnetNativeEvents["onRuntimeSnapshot"],
  ): { remove(): void };
};
