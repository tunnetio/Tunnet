export type LicenseTier = "community" | "cloud" | "enterprise";

/** Tiers that require a signed license certificate. */
export type PaidTier = Exclude<LicenseTier, "community">;

export type Entitlements = {
  tier: LicenseTier;
  multiOrganization: boolean;
  /** SaaS marketing landing (needs private `cloud/` packages). */
  cloudLanding: boolean;
  /** Public signup + org invitations. */
  openSignUp: boolean;
  /** Unix seconds; null when community / no active license. */
  licenseExpiresAt: number | null;
};

const FEATURES = {
  community: {
    tier: "community",
    multiOrganization: false,
    cloudLanding: false,
    openSignUp: false,
  },
  cloud: {
    tier: "cloud",
    multiOrganization: true,
    cloudLanding: true,
    openSignUp: true,
  },
  enterprise: {
    tier: "enterprise",
    multiOrganization: false,
    cloudLanding: false,
    openSignUp: false,
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
