/** SaaS deploy: full multi-org + cloud landing entitlements. */
export function getEntitlementOverrides(): {
  tier: "cloud";
  multiOrganization: true;
  cloudLanding: true;
} {
  return {
    tier: "cloud",
    multiOrganization: true,
    cloudLanding: true,
  };
}
