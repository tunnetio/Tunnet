import { Elysia } from "elysia";

import { apiKeysRoutes } from "./api-keys";
import { auditRoutes } from "./audit";
import { deviceProfilesRoutes } from "./device-profiles";
import { devicesRoutes } from "./devices";
import { enrollmentTokensRoutes } from "./enrollment-tokens";
import { entitlementsRoutes } from "./entitlements";
import { hostnameRoutesRoutes } from "./hostname-routes";
import { internalCaRoutes } from "./internal-ca";
import { networksRoutes } from "./networks";
import { nodeGroupsRoutes } from "./node-groups";
import { orgSettingsRoutes } from "./org-settings";
import { policiesRoutes } from "./policies";
import { presenceRoutes } from "./presence";
import { relaysRoutes } from "./relays";
import { sdkNodesRoutes } from "./sdk-nodes";
import { servesRoutes } from "./serves";
import { sshPoliciesRoutes } from "./ssh-policies";
import { sshSessionsRoutes } from "./ssh-sessions";
import { ssoSettingsRoutes } from "./sso-settings";
import { subnetRoutesRoutes } from "./subnet-routes";
import { topologyRoutes } from "./topology";
import { transfersRoutes } from "./transfers";
import { tunnelSettingsRoutes } from "./tunnel-settings";
import { tunnelsRoutes } from "./tunnels";

export const apiV1 = new Elysia({ prefix: "/api/v1" })
  .use(entitlementsRoutes)
  .use(networksRoutes)
  .use(devicesRoutes)
  .use(presenceRoutes)
  .use(policiesRoutes)
  .use(sshPoliciesRoutes)
  .use(sshSessionsRoutes)
  .use(subnetRoutesRoutes)
  .use(hostnameRoutesRoutes)
  .use(deviceProfilesRoutes)
  .use(nodeGroupsRoutes)
  .use(topologyRoutes)
  .use(enrollmentTokensRoutes)
  .use(sdkNodesRoutes)
  .use(apiKeysRoutes)
  .use(auditRoutes)
  .use(relaysRoutes)
  .use(tunnelsRoutes)
  .use(tunnelSettingsRoutes)
  .use(orgSettingsRoutes)
  .use(ssoSettingsRoutes)
  .use(internalCaRoutes)
  .use(servesRoutes)
  .use(transfersRoutes);
