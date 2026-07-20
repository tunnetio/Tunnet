import { z } from "zod";

export const entitlementsSchema = z.object({
  tier: z.enum(["community", "cloud", "enterprise"]),
  multiOrganization: z.boolean(),
  cloudLanding: z.boolean(),
  openSignUp: z.boolean(),
  clickhouseAudit: z.boolean(),
  auditEnterpriseStreams: z.boolean(),
  complianceExport: z.boolean(),
  licenseExpiresAt: z.number().nullable(),
});

export type EntitlementsResponse = z.infer<typeof entitlementsSchema>;
