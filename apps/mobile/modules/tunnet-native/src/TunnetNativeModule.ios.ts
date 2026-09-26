import { Platform } from "react-native";

import type {
  TunnetNativeEvents,
  TunnetNativeModule,
  TunnetPlatformState,
} from "./TunnetNative.types";

const unsupportedOperation = async (operation: string): Promise<never> => {
  throw new Error(
    `Tunnet native operation "${operation}" is not supported on ${Platform.OS}.`,
  );
};

const module: TunnetNativeModule = {
  start: () => unsupportedOperation("start"),
  stop: () => unsupportedOperation("stop"),
  joinNetwork: () => unsupportedOperation("joinNetwork"),
  getPlatformState: async (): Promise<TunnetPlatformState> => ({
    supported: false,
    vpnPermissionGranted: false,
    localNetworkAccess: "not_required",
    notificationPermissionGranted: false,
    serviceRunning: false,
  }),
  requestVpnPermission: () => unsupportedOperation("requestVpnPermission"),
  requestLocalNetworkPermission: () =>
    unsupportedOperation("requestLocalNetworkPermission"),
  requestNotificationPermission: () =>
    unsupportedOperation("requestNotificationPermission"),
  addListener(
    _eventName: "onRuntimeSnapshot",
    _listener: TunnetNativeEvents["onRuntimeSnapshot"],
  ) {
    return { remove() {} };
  },
};

export default module;
