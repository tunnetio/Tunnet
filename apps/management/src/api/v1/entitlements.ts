import { Elysia } from "elysia";

import { getEntitlements } from "../../lib/entitlements";

export const entitlementsRoutes = new Elysia({ prefix: "/entitlements" }).get(
  "/",
  async () => {
    const entitlements = await getEntitlements();
    return entitlements;
  },
);
