const DEFAULT_DASHBOARD_URL = "http://localhost:5173";
const DEFAULT_MANAGEMENT_URL = "http://localhost:3000";
const DEFAULT_CONTROL_PLANE_URL = "http://localhost:8080";

/** Control plane internal admin API port (management → control HMAC API). */
export const CONTROL_PLANE_ADMIN_PORT = 9091;

export function stripTrailingSlash(url: string): string {
  return url.replace(/\/$/, "");
}

export function getDashboardUrl(env: NodeJS.ProcessEnv = process.env): string {
  return stripTrailingSlash(env.DASHBOARD_URL?.trim() || DEFAULT_DASHBOARD_URL);
}

export function getManagementUrl(env: NodeJS.ProcessEnv = process.env): string {
  return stripTrailingSlash(
    env.MANAGEMENT_URL?.trim() || DEFAULT_MANAGEMENT_URL,
  );
}

export function getControlPlaneUrl(
  env: NodeJS.ProcessEnv = process.env,
): string {
  return stripTrailingSlash(
    env.CONTROL_PLANE_URL?.trim() || DEFAULT_CONTROL_PLANE_URL,
  );
}

export function getManagementPort(
  env: NodeJS.ProcessEnv = process.env,
): number {
  const url = new URL(getManagementUrl(env));
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

/** Same host as `CONTROL_PLANE_URL`, admin bind port (default 9091). */
export function getControlPlaneAdminUrl(
  env: NodeJS.ProcessEnv = process.env,
): string {
  const url = new URL(getControlPlaneUrl(env));
  url.port = String(CONTROL_PLANE_ADMIN_PORT);
  return stripTrailingSlash(url.toString());
}
