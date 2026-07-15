import {
  getControlPlaneUrl as getControlPlaneUrlFromEnv,
  getManagementUrl as getManagementUrlFromEnv,
} from "@tuntun/env";

function stripTrailingSlash(url: string): string {
  return url.replace(/\/$/, "");
}

function readBinding(
  key: "MANAGEMENT_URL" | "CONTROL_PLANE_URL" | "DASHBOARD_URL",
  fallback: string,
): string {
  const fromClient = import.meta.env[key];
  if (typeof fromClient === "string" && fromClient.trim()) {
    return stripTrailingSlash(fromClient.trim());
  }

  if (typeof process !== "undefined") {
    const fromProcess = process.env[key]?.trim();
    if (fromProcess) {
      return stripTrailingSlash(fromProcess);
    }
  }

  return fallback;
}

export function getManagementApiUrl(): string {
  const configured = readBinding("MANAGEMENT_URL", "");
  if (configured) {
    return configured;
  }

  if (typeof window !== "undefined") {
    return window.location.origin;
  }

  return getManagementUrlFromEnv();
}

export function getControlPlaneUrl(): string {
  const configured = readBinding("CONTROL_PLANE_URL", "");
  if (configured) {
    return configured;
  }

  return getControlPlaneUrlFromEnv();
}

export function getDashboardUrl(): string {
  return readBinding("DASHBOARD_URL", "http://localhost:5173");
}
