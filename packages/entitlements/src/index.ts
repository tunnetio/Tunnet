export type LicenseTier = "community" | "cloud" | "commercial";

export type Entitlements = {
  tier: LicenseTier;
  /** Allow creating and switching between multiple organizations. */
  multiOrganization: boolean;
  /** SaaS marketing landing at `/` (requires cloud/ dashboard package). */
  cloudLanding: boolean;
};

export type EntitlementOverrides = Partial<Entitlements> & {
  tier?: LicenseTier;
};

export const COMMUNITY_ENTITLEMENTS: Entitlements = {
  tier: "community",
  multiOrganization: false,
  cloudLanding: false,
};

export const CLOUD_ENTITLEMENTS: Entitlements = {
  tier: "cloud",
  multiOrganization: true,
  cloudLanding: true,
};

export const COMMERCIAL_ENTITLEMENTS: Entitlements = {
  tier: "commercial",
  multiOrganization: true,
  cloudLanding: false,
};

export function entitlementsForTier(tier: LicenseTier): Entitlements {
  switch (tier) {
    case "cloud":
      return { ...CLOUD_ENTITLEMENTS };
    case "commercial":
      return { ...COMMERCIAL_ENTITLEMENTS };
    default:
      return { ...COMMUNITY_ENTITLEMENTS };
  }
}

export function mergeEntitlements(
  base: Entitlements,
  overrides: EntitlementOverrides | null | undefined,
): Entitlements {
  if (!overrides) return base;
  return {
    ...base,
    ...overrides,
    tier: overrides.tier ?? base.tier,
  };
}
