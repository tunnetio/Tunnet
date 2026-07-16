import { Elysia } from "elysia";
import { z } from "zod";

import { auth } from "../../auth";
import { writeAudit } from "../../lib/audit";
import { db } from "../../lib/db";
import { getEntitlements } from "../../lib/entitlements";
import { getAuth, requireAdmin, requireAuth } from "./middleware/authz";
import { badRequest, sessionPlugin } from "./middleware/session";

const createOrgUserBody = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1),
  role: z.enum(["member", "admin"]).default("member"),
});

export const orgUsersRoutes = new Elysia()
  .use(sessionPlugin)
  .use(requireAuth)
  .use(requireAdmin)
  .post(
    "/organizations/:orgId/users",
    async ({ authContext, body, request }) => {
      const ctx = getAuth({ authContext });
      const parsed = createOrgUserBody.safeParse(body);
      if (!parsed.success) {
        return badRequest(parsed.error.issues[0]?.message ?? "Invalid body");
      }

      const { email, password, name, role } = parsed.data;

      const entitlements = await getEntitlements();
      if (entitlements.openSignUp) {
        return badRequest(
          "Use invitations to add users when public signup is enabled",
        );
      }

      let created: { user: { id: string; email: string; name: string } };
      try {
        created = (await auth.api.createUser({
          body: {
            email,
            password,
            name,
            role: "user",
          },
        })) as { user: { id: string; email: string; name: string } };
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Failed to create user";
        return badRequest(message);
      }

      try {
        await auth.api.addMember({
          body: {
            userId: created.user.id,
            organizationId: ctx.organizationId,
            role,
          },
          headers: request.headers,
        });
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Failed to add member";
        return badRequest(message);
      }

      await writeAudit(db, {
        organizationId: ctx.organizationId,
        actor: ctx.user.id,
        action: "user.create",
        target: created.user.id,
        metadata: { email, role },
      });

      return {
        id: created.user.id,
        email: created.user.email,
        name: created.user.name,
        role,
      };
    },
  );
