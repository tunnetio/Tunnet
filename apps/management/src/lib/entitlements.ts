import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  COMMUNITY_ENTITLEMENTS,
  type EntitlementOverrides,
  type Entitlements,
  entitlementsForTier,
  type LicenseTier,
  mergeEntitlements,
} from "@tuntun/entitlements";
import {
  getRepoRoot,
  hasCloudPackages,
  resolveCloudManagementRoot,
} from "@tuntun/env";

type LicenseFile = {
  tier?: LicenseTier;
  multiOrganization?: boolean;
  cloudLanding?: boolean;
};

let cached: Entitlements | null = null;

function parseTier(value: string | undefined): LicenseTier | null {
  if (value === "community" || value === "cloud" || value === "commercial") {
    return value;
  }
  return null;
}

async function loadLicenseFile(
  env: NodeJS.ProcessEnv,
): Promise<EntitlementOverrides | null> {
  const path = env.TUNTUN_LICENSE_FILE?.trim();
  if (!path || !existsSync(path)) return null;
  try {
    const raw = (await Bun.file(path).json()) as LicenseFile;
    return {
      tier: raw.tier,
      multiOrganization: raw.multiOrganization,
      cloudLanding: raw.cloudLanding,
    };
  } catch (err) {
    console.warn(
      "[entitlements] failed to read TUNTUN_LICENSE_FILE:",
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}

async function loadCloudOverrides(): Promise<EntitlementOverrides | null> {
  if (!hasCloudPackages()) return null;
  try {
    const mod = (await import(
      join(resolveCloudManagementRoot(), "src", "index.ts")
    )) as {
      getEntitlementOverrides?: () => EntitlementOverrides | null;
    };
    return mod.getEntitlementOverrides?.() ?? null;
  } catch (err) {
    console.warn(
      "[entitlements] failed to load cloud management overrides:",
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}

/**
 * Resolve product entitlements for this management process.
 *
 * Priority: TUNTUN_LICENSE_FILE → TUNTUN_LICENSE_TIER / TUNTUN_DEPLOYMENT=cloud
 * → cloud package overrides (when tier is cloud) → community default.
 */
export async function resolveEntitlements(
  env: NodeJS.ProcessEnv = process.env,
): Promise<Entitlements> {
  const fileOverrides = await loadLicenseFile(env);
  const tierFromEnv =
    parseTier(env.TUNTUN_LICENSE_TIER?.trim()) ??
    (env.TUNTUN_DEPLOYMENT?.trim() === "cloud" ? "cloud" : null);

  let base = entitlementsForTier(tierFromEnv ?? "community");

  if (base.tier === "cloud") {
    const cloudOverrides = await loadCloudOverrides();
    base = mergeEntitlements(base, cloudOverrides);
  }

  base = mergeEntitlements(base, fileOverrides);

  if (base.cloudLanding && !hasCloudPackages(getRepoRoot())) {
    base = { ...base, cloudLanding: false };
  }

  return base;
}

export async function getEntitlements(): Promise<Entitlements> {
  if (!cached) {
    cached = await resolveEntitlements();
  }
  return cached;
}

/** Test helper / hot-reload. */
export function clearEntitlementsCache(): void {
  cached = null;
}

export function assertCanCreateOrganization(
  entitlements: Entitlements,
  existingOrgCount: number,
): void {
  if (entitlements.multiOrganization) return;
  if (existingOrgCount >= 1) {
    throw new Error(
      "Community license allows a single organization. Upgrade to enable multi-organization.",
    );
  }
}

export { COMMUNITY_ENTITLEMENTS };
