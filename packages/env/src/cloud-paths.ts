import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

function findRepoRoot(start = import.meta.dirname): string {
  let dir = start;
  for (let i = 0; i < 10; i++) {
    if (
      existsSync(join(dir, "packages", "env", "package.json")) &&
      existsSync(join(dir, "apps", "management", "package.json"))
    ) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // Fallback: packages/env/src → ../../..
  return join(start, "../../..");
}

/** Repo root (TunTun/). */
export function getRepoRoot(from = import.meta.dirname): string {
  return findRepoRoot(from);
}

export function cloudDashboardPath(repoRoot = getRepoRoot()): string {
  return join(repoRoot, "cloud", "dashboard");
}

export function cloudManagementPath(repoRoot = getRepoRoot()): string {
  return join(repoRoot, "cloud", "management");
}

export function stubDashboardPath(repoRoot = getRepoRoot()): string {
  return join(repoRoot, "packages", "cloud-stubs", "dashboard");
}

export function stubManagementPath(repoRoot = getRepoRoot()): string {
  return join(repoRoot, "packages", "cloud-stubs", "management");
}

/** True when the private SaaS tree is present. */
export function hasCloudPackages(repoRoot = getRepoRoot()): boolean {
  return (
    existsSync(join(cloudDashboardPath(repoRoot), "package.json")) &&
    existsSync(join(cloudManagementPath(repoRoot), "package.json"))
  );
}

export function resolveCloudDashboardRoot(repoRoot = getRepoRoot()): string {
  return hasCloudPackages(repoRoot)
    ? cloudDashboardPath(repoRoot)
    : stubDashboardPath(repoRoot);
}

export function resolveCloudManagementRoot(repoRoot = getRepoRoot()): string {
  return hasCloudPackages(repoRoot)
    ? cloudManagementPath(repoRoot)
    : stubManagementPath(repoRoot);
}
