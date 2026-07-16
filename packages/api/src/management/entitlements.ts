import { z } from "zod";

export const entitlementsSchema = z.object({
  tier: z.enum(["community", "cloud", "commercial"]),
  multiOrganization: z.boolean(),
  cloudLanding: z.boolean(),
});

export type EntitlementsResponse = z.infer<typeof entitlementsSchema>;
