import { getDashboardUrl, getManagementUrl } from "@tuntun/env";
import { Elysia } from "elysia";

import { OAUTH_CLIENT_CLI } from "../auth";

/** Public CLI auth discovery (device authorization / RFC 8628). */
export const cliAuthRoutes = new Elysia().get("/auth/cli/config", () => {
  const base = getManagementUrl();
  const web = getDashboardUrl();
  return {
    clientId: process.env.TUNTUN_OAUTH_CLI_CLIENT_ID || OAUTH_CLIENT_CLI,
    issuer: `${base}/api/auth`,
    deviceCodeEndpoint: `${base}/api/auth/device/code`,
    deviceTokenEndpoint: `${base}/api/auth/device/token`,
    verificationUri: `${web}/app/settings/account`,
    scopes: ["openid", "profile", "email", "offline_access", "mesh:connect"],
  };
});
