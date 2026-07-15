import {
  autoCleanupSettingsSchema,
  DEFAULT_ORGANIZATION_SETTINGS,
  normalizeOrganizationSettings,
  type OrganizationSettings,
  parseHumanDuration,
  patchOrganizationSettingsBody,
  secondsToPgInterval,
} from "@tuntun/api/management";
import { schema } from "@tuntun/db";
import { eq } from "drizzle-orm";
import { Elysia } from "elysia";

import { writeAudit } from "../../lib/audit";
import { db } from "../../lib/db";
import { getAuth, requireAdmin, requireAuth } from "./middleware/authz";
import { badRequest, sessionPlugin } from "./middleware/session";

/** Store durations as PG-parseable interval text (`N seconds`). */
function toStoredDuration(raw: string | null): string | null {
  if (raw === null) return null;
  const secs = parseHumanDuration(raw);
  if (secs === null) return raw;
  return secondsToPgInterval(secs);
}

function mergeSettings(
  current: OrganizationSettings,
  patch: ReturnType<typeof patchOrganizationSettingsBody.parse>,
): OrganizationSettings {
  const next: OrganizationSettings = {
    machines: {
      autoCleanup: { ...current.machines.autoCleanup },
    },
  };

  if (patch.machines?.autoCleanup) {
    const ac = patch.machines.autoCleanup;
    if (ac.enabled !== undefined)
      next.machines.autoCleanup.enabled = ac.enabled;
    if (ac.inactivityAfter !== undefined) {
      next.machines.autoCleanup.inactivityAfter = toStoredDuration(
        ac.inactivityAfter,
      );
    }
    if (ac.mode !== undefined) next.machines.autoCleanup.mode = ac.mode;
    if (ac.hardDeleteAfter !== undefined) {
      next.machines.autoCleanup.hardDeleteAfter = toStoredDuration(
        ac.hardDeleteAfter,
      );
    }
  }

  const validated = autoCleanupSettingsSchema.safeParse(
    next.machines.autoCleanup,
  );
  if (!validated.success) {
    throw new Error(validated.error.issues[0]?.message ?? "Invalid settings");
  }
  next.machines.autoCleanup = validated.data;
  return next;
}

export const orgSettingsRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .get("/organizations/:orgId/settings", async ({ authContext }) => {
    const auth = getAuth({ authContext });
    const org = await db.query.organization.findFirst({
      where: eq(schema.organization.id, auth.organizationId),
      columns: { id: true, settings: true },
    });

    const settings = normalizeOrganizationSettings(
      org?.settings ?? DEFAULT_ORGANIZATION_SETTINGS,
    );

    return {
      organizationId: auth.organizationId,
      settings,
    };
  })
  .group("", (app) =>
    app
      .use(requireAdmin)
      .patch(
        "/organizations/:orgId/settings",
        async ({ authContext, body }) => {
          const auth = getAuth({ authContext });
          const parsed = patchOrganizationSettingsBody.parse(body);

          const org = await db.query.organization.findFirst({
            where: eq(schema.organization.id, auth.organizationId),
            columns: { id: true, settings: true },
          });

          const current = normalizeOrganizationSettings(
            org?.settings ?? DEFAULT_ORGANIZATION_SETTINGS,
          );
          let settings: OrganizationSettings;
          try {
            settings = mergeSettings(current, parsed);
          } catch (err) {
            return badRequest(
              err instanceof Error ? err.message : "Invalid settings",
            );
          }

          await db
            .update(schema.organization)
            .set({ settings })
            .where(eq(schema.organization.id, auth.organizationId));

          await writeAudit(db, {
            organizationId: auth.organizationId,
            actor: auth.user.id,
            action: "organization.settings.update",
            target: auth.organizationId,
            metadata: parsed,
          });

          return {
            organizationId: auth.organizationId,
            settings,
          };
        },
      ),
  );
