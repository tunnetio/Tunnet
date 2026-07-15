import { randomBytes } from "node:crypto";
import { schema } from "@tuntun/db";
import { getDashboardUrl, getManagementUrl } from "@tuntun/env";
import { and, eq } from "drizzle-orm";
import { Elysia } from "elysia";

import { auth } from "../auth";
import { db } from "../lib/db";

const webOrigin = () => getDashboardUrl();
const apiOrigin = () => getManagementUrl();

function htmlPage(title: string, body: string) {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0f1115; color: #e8eaed;
      display: grid; place-items: center; min-height: 100vh; margin: 0; }
    main { max-width: 28rem; padding: 2rem; text-align: center; }
    h1 { font-size: 1.25rem; margin: 0 0 0.75rem; }
    p { color: #9aa0a6; line-height: 1.5; }
    a { color: #8ab4f8; }
  </style>
</head>
<body><main>${body}</main></body>
</html>`,
    {
      headers: { "content-type": "text/html; charset=utf-8" },
    },
  );
}

async function completeChallenge(args: {
  token: string;
  email: string | null;
  method: "oidc" | "saml" | "session";
}) {
  const challenge = await db.query.sshAuthChallenges.findFirst({
    where: eq(schema.sshAuthChallenges.token, args.token),
  });
  if (!challenge) throw new Error("Challenge not found");
  if (challenge.status !== "pending") throw new Error("Challenge already used");
  if (challenge.expiresAt.getTime() < Date.now()) {
    await db
      .update(schema.sshAuthChallenges)
      .set({ status: "expired" })
      .where(eq(schema.sshAuthChallenges.token, args.token));
    throw new Error("Challenge expired");
  }

  const proofToken = randomBytes(32).toString("hex");
  const proofExpiresAt = new Date(Date.now() + 2 * 60 * 1000);

  await db.transaction(async (tx) => {
    await tx
      .insert(schema.sshAuthChecks)
      .values({
        endpointId: challenge.endpointId,
        organizationId: challenge.organizationId,
        authenticatedAt: new Date(),
        method: args.method,
        identityEmail: args.email,
        updatedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: schema.sshAuthChecks.endpointId,
        set: {
          authenticatedAt: new Date(),
          method: args.method,
          identityEmail: args.email,
          updatedAt: new Date(),
          organizationId: challenge.organizationId,
        },
      });

    await tx
      .update(schema.sshAuthChallenges)
      .set({
        status: "completed",
        proofToken,
        proofExpiresAt,
        completedAt: new Date(),
      })
      .where(eq(schema.sshAuthChallenges.token, args.token));
  });

  return { proofToken };
}

async function finishWithSession(args: {
  token: string;
  organizationId: string;
  request: Request;
}) {
  const session = await auth.api.getSession({ headers: args.request.headers });
  if (!session?.user) {
    return null;
  }

  const membership = await db.query.member.findFirst({
    where: and(
      eq(schema.member.organizationId, args.organizationId),
      eq(schema.member.userId, session.user.id),
    ),
  });
  if (!membership) {
    return htmlPage(
      "Unauthorized",
      "<h1>Not a member</h1><p>Sign in with an account that belongs to this organization.</p>",
    );
  }

  const provider = await db.query.ssoProvider.findFirst({
    where: eq(schema.ssoProvider.organizationId, args.organizationId),
  });
  const method: "oidc" | "saml" | "session" = provider?.samlConfig
    ? "saml"
    : provider?.oidcConfig
      ? "oidc"
      : "session";

  await completeChallenge({
    token: args.token,
    email: session.user.email ?? null,
    method,
  });
  return htmlPage(
    "Authenticated",
    "<h1>✓ Authenticated</h1><p>Return to your terminal. TunTun will continue automatically.</p>",
  );
}

/** Public browser routes for SSH check-mode re-authentication. */
export const sshAuthBrowserRoutes = new Elysia()
  .get("/auth/ssh", async ({ request, query, redirect }) => {
    const token = typeof query.token === "string" ? query.token.trim() : "";
    if (!token) {
      return htmlPage(
        "Invalid link",
        "<h1>Invalid re-auth link</h1><p>Missing challenge token.</p>",
      );
    }

    const challenge = await db.query.sshAuthChallenges.findFirst({
      where: eq(schema.sshAuthChallenges.token, token),
    });
    if (!challenge) {
      return htmlPage(
        "Not found",
        "<h1>Challenge not found</h1><p>This link is invalid or has already been used.</p>",
      );
    }
    if (challenge.status !== "pending") {
      return htmlPage(
        "Already completed",
        "<h1>Already authenticated</h1><p>Return to your terminal.</p>",
      );
    }
    if (challenge.expiresAt.getTime() < Date.now()) {
      await db
        .update(schema.sshAuthChallenges)
        .set({ status: "expired" })
        .where(eq(schema.sshAuthChallenges.token, token));
      return htmlPage(
        "Expired",
        "<h1>Link expired</h1><p>Run <code>tuntun ssh</code> again to get a new link.</p>",
      );
    }

    const org = await db.query.organization.findFirst({
      where: eq(schema.organization.id, challenge.organizationId),
    });
    if (!org) {
      return htmlPage(
        "Not found",
        "<h1>Organization not found</h1><p>This challenge is invalid.</p>",
      );
    }

    const provider = await db.query.ssoProvider.findFirst({
      where: eq(schema.ssoProvider.organizationId, challenge.organizationId),
    });

    if (provider) {
      try {
        const callbackURL = `${apiOrigin()}/auth/ssh/complete?token=${encodeURIComponent(token)}`;
        const result = await auth.api.signInSSO({
          body: {
            providerId: provider.providerId,
            organizationSlug: org.slug,
            callbackURL,
          },
        });
        const url =
          result &&
          typeof result === "object" &&
          "url" in result &&
          typeof (result as { url?: unknown }).url === "string"
            ? (result as { url: string }).url
            : null;
        if (url) {
          return redirect(url);
        }
        return htmlPage(
          "SSO error",
          "<h1>SSO configuration error</h1><p>No authorization URL returned.</p>",
        );
      } catch (e) {
        return htmlPage(
          "SSO error",
          `<h1>SSO configuration error</h1><p>${e instanceof Error ? e.message : "Unknown error"}</p>`,
        );
      }
    }

    // Fallback: Better Auth session for org members.
    const finished = await finishWithSession({
      token,
      organizationId: challenge.organizationId,
      request,
    });
    if (finished) return finished;

    const login = new URL(`${webOrigin()}/login`);
    login.searchParams.set(
      "redirect",
      `${apiOrigin()}/auth/ssh?token=${token}`,
    );
    return redirect(login.toString());
  })
  .get("/auth/ssh/complete", async ({ request, query }) => {
    const token = typeof query.token === "string" ? query.token.trim() : "";
    if (!token) {
      return htmlPage(
        "Invalid callback",
        "<h1>Invalid SSO callback</h1><p>Missing challenge token.</p>",
      );
    }

    const challenge = await db.query.sshAuthChallenges.findFirst({
      where: eq(schema.sshAuthChallenges.token, token),
    });
    if (challenge?.status !== "pending") {
      return htmlPage(
        "Invalid challenge",
        "<h1>Challenge invalid</h1><p>Return to the terminal and try again.</p>",
      );
    }
    if (challenge.expiresAt.getTime() < Date.now()) {
      await db
        .update(schema.sshAuthChallenges)
        .set({ status: "expired" })
        .where(eq(schema.sshAuthChallenges.token, token));
      return htmlPage(
        "Expired",
        "<h1>Link expired</h1><p>Run <code>tuntun ssh</code> again to get a new link.</p>",
      );
    }

    try {
      const finished = await finishWithSession({
        token,
        organizationId: challenge.organizationId,
        request,
      });
      if (finished) return finished;

      const login = new URL(`${webOrigin()}/login`);
      login.searchParams.set(
        "redirect",
        `${apiOrigin()}/auth/ssh/complete?token=${token}`,
      );
      return Response.redirect(login.toString(), 302);
    } catch (e) {
      await db
        .update(schema.sshAuthChallenges)
        .set({ status: "failed" })
        .where(eq(schema.sshAuthChallenges.token, token));
      return htmlPage(
        "SSO failed",
        `<h1>SSO authentication failed</h1><p>${e instanceof Error ? e.message : "Unknown error"}</p>`,
      );
    }
  });
