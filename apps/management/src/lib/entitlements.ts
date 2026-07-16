import { existsSync } from "node:fs";
import { getDb } from "@tuntun/db";
import {
  COMMUNITY_ENTITLEMENTS,
  type Entitlements,
  entitlementsForTier,
} from "@tuntun/entitlements";
import { verifyLicense } from "@tuntun/entitlements/license";
import { getRepoRoot, hasCloudPackages } from "@tuntun/env/cloud-paths";

type Cache = {
  entitlements: Entitlements;
  /** Drop cache at this time (ms) when a paid license is active. */
  refreshAtMs: number | null;
};

let cache: Cache | null = null;

async function loadLicenseText(env: NodeJS.ProcessEnv): Promise<string | null> {
  const ref = env.TUNTUN_LICENSE?.trim();
  if (!ref) return null;

  try {
    if (ref.startsWith("{")) return ref;

    if (/^https?:\/\//i.test(ref)) {
      const response = await fetch(ref);
      if (!response.ok) {
        console.warn(
          `[entitlements] TUNTUN_LICENSE fetch failed: ${response.status}`,
        );
        return null;
      }
      return await response.text();
    }

    if (!existsSync(ref)) {
      console.warn(`[entitlements] TUNTUN_LICENSE file not found: ${ref}`);
      return null;
    }
    return await Bun.file(ref).text();
  } catch (err) {
    console.warn(
      "[entitlements] failed to load TUNTUN_LICENSE:",
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}

function applyCloudPackageGuard(entitlements: Entitlements): Entitlements {
  if (entitlements.cloudLanding && !hasCloudPackages(getRepoRoot())) {
    return { ...entitlements, cloudLanding: false };
  }
  return entitlements;
}

export async function hasAnyUsers(): Promise<boolean> {
  const row = await getDb().query.user.findFirst({ columns: { id: true } });
  return row != null;
}

/** Missing / invalid / expired certificate → community. */
export async function resolveEntitlements(
  env: NodeJS.ProcessEnv = process.env,
  nowMs: number = Date.now(),
): Promise<Entitlements> {
  const text = await loadLicenseText(env);
  if (!text) return applyCloudPackageGuard(COMMUNITY_ENTITLEMENTS);

  const verified = verifyLicense(text, Math.floor(nowMs / 1000));
  if (!verified) {
    console.warn(
      "[entitlements] TUNTUN_LICENSE invalid or malformed; using community",
    );
    return applyCloudPackageGuard(COMMUNITY_ENTITLEMENTS);
  }

  if (verified.expired) {
    console.warn(
      `[entitlements] license expired at ${new Date(verified.payload.exp * 1000).toISOString()}; using community`,
    );
    return applyCloudPackageGuard(COMMUNITY_ENTITLEMENTS);
  }

  return applyCloudPackageGuard(
    entitlementsForTier(verified.payload.tier, verified.payload.exp),
  );
}

export async function getEntitlements(): Promise<Entitlements> {
  const now = Date.now();
  if (cache && (cache.refreshAtMs === null || now < cache.refreshAtMs)) {
    return cache.entitlements;
  }

  const entitlements = await resolveEntitlements(process.env, now);
  cache = {
    entitlements,
    refreshAtMs:
      entitlements.licenseExpiresAt != null
        ? entitlements.licenseExpiresAt * 1000
        : null,
  };
  return entitlements;
}

export function clearEntitlementsCache(): void {
  cache = null;
}

export { COMMUNITY_ENTITLEMENTS };
