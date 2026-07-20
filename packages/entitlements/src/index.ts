export type LicenseTier = "community" | "cloud" | "enterprise";

export type PaidTier = Exclude<LicenseTier, "community">;

export type Feature =
  | "multiOrganization"
  | "cloudLanding"
  | "openSignUp"
  | "clickhouseAudit"
  | "auditEnterpriseStreams"
  | "complianceExport";

export type Entitlements = {
  tier: LicenseTier;
  multiOrganization: boolean;
  cloudLanding: boolean;
  openSignUp: boolean;
  clickhouseAudit: boolean;
  auditEnterpriseStreams: boolean;
  complianceExport: boolean;
  licenseExpiresAt: number | null;
};

const FEATURES = {
  community: {
    tier: "community",
    multiOrganization: false,
    cloudLanding: false,
    openSignUp: false,
    clickhouseAudit: false,
    auditEnterpriseStreams: false,
    complianceExport: false,
  },
  cloud: {
    tier: "cloud",
    multiOrganization: true,
    cloudLanding: true,
    openSignUp: true,
    clickhouseAudit: true,
    auditEnterpriseStreams: true,
    complianceExport: true,
  },
  enterprise: {
    tier: "enterprise",
    multiOrganization: false,
    cloudLanding: false,
    openSignUp: false,
    clickhouseAudit: true,
    auditEnterpriseStreams: true,
    complianceExport: true,
  },
} as const satisfies Record<
  LicenseTier,
  Omit<Entitlements, "licenseExpiresAt">
>;

export const COMMUNITY_ENTITLEMENTS: Entitlements = {
  ...FEATURES.community,
  licenseExpiresAt: null,
};

export function parseLicenseTier(value: unknown): LicenseTier | null {
  if (value === "community" || value === "cloud" || value === "enterprise") {
    return value;
  }
  return null;
}

export function isPaidTier(value: unknown): value is PaidTier {
  return value === "cloud" || value === "enterprise";
}

export function entitlementsForTier(
  tier: LicenseTier,
  licenseExpiresAt: number | null = null,
): Entitlements {
  return {
    ...FEATURES[tier],
    licenseExpiresAt: tier === "community" ? null : licenseExpiresAt,
  };
}
