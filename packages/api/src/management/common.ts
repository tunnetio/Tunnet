import { z } from "zod";

export const orgIdParam = z.object({
  orgId: z.string().min(1),
});

export const networkIdParam = orgIdParam.extend({
  networkId: z.string().uuid(),
});

export const deviceIdParam = networkIdParam.extend({
  endpointId: z
    .string()
    .length(64)
    .regex(/^[0-9a-fA-F]+$/),
});

export const policyIdParam = networkIdParam.extend({
  policyId: z.string().uuid(),
});

export const tokenHashParam = networkIdParam.extend({
  tokenHash: z.string().min(1),
});

export const apiKeyIdParam = orgIdParam.extend({
  keyId: z.string().uuid(),
});

export const subnetRouteIdParam = networkIdParam.extend({
  routeId: z.string().uuid(),
});

export const deviceStatusSchema = z.enum([
  "active",
  "suspended",
  "pending",
  "expired",
]);

export const orgRoleSchema = z.enum(["owner", "admin", "member"]);

export const paginationQuery = z.object({
  cursor: z.coerce.number().int().nonnegative().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

export const errorResponse = z.object({
  error: z.string(),
});
