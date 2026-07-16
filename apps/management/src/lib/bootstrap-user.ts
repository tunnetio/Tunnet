import { auth } from "../auth";
import {
  clearEntitlementsCache,
  getEntitlements,
  hasAnyUsers,
} from "./entitlements";

/**
 * If the user table is empty (community/enterprise), seed the owner via
 * Better Auth admin `createUser` (bypasses disableSignUp).
 *
 * Cloud keeps open signup and skips seeding.
 */
export async function ensureBootstrapUser(): Promise<void> {
  const entitlements = await getEntitlements();
  if (entitlements.tier === "cloud") {
    return;
  }

  if (await hasAnyUsers()) {
    return;
  }

  const email = process.env.TUNTUN_BOOTSTRAP_EMAIL?.trim();
  const password = process.env.TUNTUN_BOOTSTRAP_PASSWORD?.trim();
  const name = process.env.TUNTUN_BOOTSTRAP_NAME?.trim() || "Admin";

  if (!email || !password) {
    console.error(
      "[bootstrap] Set TUNTUN_BOOTSTRAP_EMAIL and TUNTUN_BOOTSTRAP_PASSWORD to seed the owner.",
    );
    return;
  }

  if (password.length < 8) {
    console.error(
      "[bootstrap] TUNTUN_BOOTSTRAP_PASSWORD must be at least 8 characters",
    );
    return;
  }

  await auth.api.createUser({
    body: {
      email,
      password,
      name,
      role: "admin",
    },
  });

  clearEntitlementsCache();
  console.log(`[bootstrap] Seeded owner account ${email} (admin)`);
}
