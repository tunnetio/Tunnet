import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { stripe } from "@better-auth/stripe";
import {
  ac,
  adminPluginAc,
  adminPluginAdminRole,
  adminPluginUserRole,
  member,
  admin as orgAdmin,
  owner,
} from "@tunnet/api/auth";
import { type BillablePlanId, getPlan } from "@tunnet/api/billing";
import { getDb, schema } from "@tunnet/db";
import { getDashboardUrl, getManagementUrl } from "@tunnet/env";
import type { LicenseManager } from "@tunnet/license/server";
import { createLicenseManager } from "@tunnet/license/server";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import {
  APIError,
  createAuthMiddleware,
  getSessionFromCtx,
} from "better-auth/api";
import {
  admin,
  bearer,
  deviceAuthorization,
  jwt,
  organization,
} from "better-auth/plugins";
import { eq } from "drizzle-orm";
import Stripe from "stripe";
import { hierarchyBeforeHook } from "./auth/hierarchy-hooks";
import { createDefaultNetwork } from "./lib/default-network";
import {
  assertSeatCapacity,
  countOwnedOrganizationsTowardQuota,
  getEffectiveOrgPlan,
  isAdminOrOwnerRole,
  isOwnerRole,
  memberRoleInOrg,
  ownershipCapForUser,
  parseCreatablePlan,
  setCloudBillingEnabled,
  softDeleteOrganization,
} from "./lib/org-billing";

const db = getDb();

const dashboardOrigin = getDashboardUrl();
const managementOrigin = getManagementUrl();

function getSharedCookieDomain(): string | undefined {
  const configured = process.env.BETTER_AUTH_COOKIE_DOMAIN?.trim();
  if (configured) return configured;

  try {
    const dashboardHost = new URL(dashboardOrigin).hostname.toLowerCase();
    const managementHost = new URL(managementOrigin).hostname.toLowerCase();
    if (
      dashboardHost.endsWith(".localhost") &&
      managementHost.endsWith(".localhost")
    ) {
      const dashboardRoot = dashboardHost.split(".").slice(-2).join(".");
      const managementRoot = managementHost.split(".").slice(-2).join(".");
      if (dashboardRoot === managementRoot) return dashboardRoot;
    }
  } catch {
    // Invalid URL configuration is reported by the individual URL helpers.
  }

  return undefined;
}

const sharedCookieDomain = getSharedCookieDomain();

export const OAUTH_CLIENT_DASHBOARD = "tunnet-dashboard";
export const OAUTH_CLIENT_CLI = "tunnet-cli";

export const TRUSTED_OAUTH_CLIENT_IDS = new Set<string>([
  OAUTH_CLIENT_DASHBOARD,
  OAUTH_CLIENT_CLI,
  ...(process.env.TUNNET_OAUTH_CLI_CLIENT_ID
    ? [process.env.TUNNET_OAUTH_CLI_CLIENT_ID]
    : []),
  ...(process.env.TUNNET_OAUTH_DASHBOARD_CLIENT_ID
    ? [process.env.TUNNET_OAUTH_DASHBOARD_CLIENT_ID]
    : []),
]);

export let license!: LicenseManager;
export let auth!: ReturnType<typeof buildAuth>;

function buildStripePlans() {
  const personalPrice = process.env.STRIPE_PRICE_PERSONAL?.trim();
  const teamPrice = process.env.STRIPE_PRICE_TEAM?.trim();
  const businessPrice = process.env.STRIPE_PRICE_BUSINESS?.trim();
  const personalAnnual = process.env.STRIPE_PRICE_PERSONAL_ANNUAL?.trim();
  const teamAnnual = process.env.STRIPE_PRICE_TEAM_ANNUAL?.trim();
  const businessAnnual = process.env.STRIPE_PRICE_BUSINESS_ANNUAL?.trim();

  const plans: Array<{
    name: BillablePlanId;
    priceId: string;
    annualDiscountPriceId?: string;
    limits: { seats: number; resources: number };
    freeTrial: { days: number };
  }> = [];

  const personal = getPlan("personal");
  const team = getPlan("team");
  const business = getPlan("business");

  if (personalPrice && personal) {
    plans.push({
      name: "personal",
      priceId: personalPrice,
      ...(personalAnnual ? { annualDiscountPriceId: personalAnnual } : {}),
      limits: {
        seats: personal.limits.maxSeats ?? 1,
        resources: personal.limits.baseResources ?? 100,
      },
      freeTrial: { days: personal.trialDays ?? 14 },
    });
  }
  if (teamPrice && team) {
    plans.push({
      name: "team",
      priceId: teamPrice,
      ...(teamAnnual ? { annualDiscountPriceId: teamAnnual } : {}),
      limits: {
        seats: team.limits.minSeats ?? 2,
        resources: team.limits.baseResources ?? 100,
      },
      freeTrial: { days: team.trialDays ?? 14 },
    });
  }
  if (businessPrice && business) {
    plans.push({
      name: "business",
      priceId: businessPrice,
      ...(businessAnnual ? { annualDiscountPriceId: businessAnnual } : {}),
      limits: {
        seats: business.limits.minSeats ?? 5,
        resources: business.limits.baseResources ?? 500,
      },
      freeTrial: { days: business.trialDays ?? 14 },
    });
  }
  return plans;
}

function logStripeConfig(opts: {
  isCloudBilling: boolean;
  stripeSecret: string | undefined;
  stripeWebhookSecret: string | undefined;
  planCount: number;
  enabled: boolean;
}) {
  if (!opts.isCloudBilling) {
    console.info("[stripe] skipped (license tier is not cloud)");
    return;
  }
  if (opts.enabled) {
    console.info(`[stripe] enabled (${opts.planCount} plan(s))`);
    return;
  }
  const missing: string[] = [];
  if (!opts.stripeSecret) missing.push("STRIPE_SECRET_KEY");
  if (!opts.stripeWebhookSecret) missing.push("STRIPE_WEBHOOK_SECRET");
  if (opts.planCount === 0) {
    missing.push(
      "STRIPE_PRICE_PERSONAL and/or STRIPE_PRICE_TEAM and/or STRIPE_PRICE_BUSINESS",
    );
  }
  console.warn(
    `[stripe] disabled - /api/auth/subscription/* will 404. Missing: ${missing.join(", ")}`,
  );
}

function buildAuth(license: LicenseManager) {
  const disablePublicSignUp = !license.has("openSignUp");
  const isCloudBilling = license.snapshot().tier === "cloud";
  setCloudBillingEnabled(isCloudBilling);

  async function countActiveMemberships(userId: string) {
    const memberships = await db.query.member.findMany({
      where: eq(schema.member.userId, userId),
      with: { organization: true },
    });
    return memberships.filter((m) => !m.organization?.deletedAt);
  }

  async function canUserCreateOrganization(user: {
    id: string;
    emailVerified?: boolean | null;
  }): Promise<boolean> {
    if (isCloudBilling) {
      const owned = await countOwnedOrganizationsTowardQuota(user.id);
      const cap = ownershipCapForUser(Boolean(user.emailVerified));
      return owned < cap;
    }
    const active = await countActiveMemberships(user.id);
    // Non-cloud fresh install: the first organization must always be
    // creatable so the onboarding name prompt can never be blocked,
    // even if license limits are misconfigured (e.g. 0).
    if (active.length === 0) return true;
    return active.length + 1 <= license.limit("organizations");
  }

  async function hasReachedOrganizationLimit(user: {
    id: string;
    emailVerified?: boolean | null;
  }): Promise<boolean> {
    if (isCloudBilling) {
      const owned = await countOwnedOrganizationsTowardQuota(user.id);
      const cap = ownershipCapForUser(Boolean(user.emailVerified));
      return owned >= cap;
    }
    const active = await countActiveMemberships(user.id);
    if (active.length === 0) return false;
    return active.length >= license.limit("organizations");
  }

  async function ssoTrustedOrigins(): Promise<string[]> {
    const origins = new Set<string>([dashboardOrigin]);
    try {
      const providers = await db.query.ssoProvider.findMany();
      for (const provider of providers) {
        try {
          origins.add(new URL(provider.issuer).origin);
        } catch {
          /* ignore invalid issuer */
        }
        if (provider.oidcConfig) {
          try {
            const cfg = JSON.parse(provider.oidcConfig) as {
              discoveryEndpoint?: string;
              authorizationEndpoint?: string;
              tokenEndpoint?: string;
              jwksEndpoint?: string;
              userInfoEndpoint?: string;
            };
            for (const url of [
              cfg.discoveryEndpoint,
              cfg.authorizationEndpoint,
              cfg.tokenEndpoint,
              cfg.jwksEndpoint,
              cfg.userInfoEndpoint,
            ]) {
              if (!url) continue;
              try {
                origins.add(new URL(url).origin);
              } catch {
                /* ignore */
              }
            }
          } catch {
            /* ignore */
          }
        }
      }
    } catch {
      /* table may not exist until migrations run */
    }
    return [...origins];
  }

  const stripeSecret = process.env.STRIPE_SECRET_KEY?.trim();
  const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET?.trim();
  const stripePlans = isCloudBilling ? buildStripePlans() : [];
  const stripeEnabled =
    isCloudBilling &&
    Boolean(stripeSecret) &&
    Boolean(stripeWebhookSecret) &&
    stripePlans.length > 0;

  logStripeConfig({
    isCloudBilling,
    stripeSecret,
    stripeWebhookSecret,
    planCount: stripePlans.length,
    enabled: stripeEnabled,
  });

  const stripeClient =
    stripeEnabled && stripeSecret
      ? new Stripe(stripeSecret, {
          apiVersion: "2026-08-26.dahlia",
        })
      : null;

  const authBeforeHook = createAuthMiddleware(async (ctx) => {
    if (ctx.path === "/organization/delete") {
      const organizationId =
        typeof ctx.body?.organizationId === "string"
          ? ctx.body.organizationId
          : null;
      if (!organizationId) {
        throw new APIError("BAD_REQUEST", {
          message: "organizationId is required",
        });
      }
      const session = await getSessionFromCtx(ctx);
      const userId = session?.user?.id;
      if (!userId) {
        throw new APIError("UNAUTHORIZED", { message: "Not authenticated" });
      }
      const role = await memberRoleInOrg(userId, organizationId);
      if (!role || !isOwnerRole(role)) {
        throw new APIError("FORBIDDEN", {
          message: "Only owners can delete an organization",
        });
      }
      try {
        await softDeleteOrganization(organizationId);
      } catch (error) {
        throw new APIError("BAD_REQUEST", {
          message:
            error instanceof Error
              ? error.message
              : "Failed to delete organization",
        });
      }
      return ctx.json({ success: true, organizationId });
    }

    if (ctx.path === "/organization/set-active") {
      const organizationId =
        typeof ctx.body?.organizationId === "string"
          ? ctx.body.organizationId
          : null;
      if (organizationId) {
        const org = await db.query.organization.findFirst({
          where: eq(schema.organization.id, organizationId),
        });
        if (!org || org.deletedAt) {
          throw new APIError("BAD_REQUEST", {
            message: "Organization not found",
          });
        }
      }
    }

    await hierarchyBeforeHook(ctx);
  });

  return betterAuth({
    appName: "Tunnet Management",
    baseURL: getManagementUrl(),
    advanced: {
      database: {
        joins: true,
      },
      ...(sharedCookieDomain
        ? {
            crossSubDomainCookies: {
              enabled: true,
              domain: sharedCookieDomain,
            },
          }
        : {}),
      useSecureCookies: managementOrigin.startsWith("https://"),
    },
    database: drizzleAdapter(db, {
      provider: "pg",
      transaction: true,
      schema: {
        user: schema.user,
        session: schema.session,
        account: schema.account,
        verification: schema.verification,
        organization: schema.organization,
        member: schema.member,
        invitation: schema.invitation,
        organizationRole: schema.organizationRole,
        ssoProvider: schema.ssoProvider,
        jwks: schema.jwks,
        oauthClient: schema.oauthClient,
        oauthRefreshToken: schema.oauthRefreshToken,
        oauthAccessToken: schema.oauthAccessToken,
        oauthConsent: schema.oauthConsent,
        deviceCode: schema.deviceCode,
        ...(stripeEnabled ? { subscription: schema.subscription } : {}),
      },
    }),
    emailAndPassword: {
      enabled: true,
      disableSignUp: disablePublicSignUp,
    },
    disabledPaths: ["/token"],
    trustedOrigins: async (request) => {
      const base = [dashboardOrigin];
      if (!request) {
        return [...base, ...(await ssoTrustedOrigins())];
      }
      const path = new URL(request.url).pathname;
      if (
        path.endsWith("/sso/register") ||
        path.includes("/sso/") ||
        path.includes("/sign-in/sso")
      ) {
        return [...base, ...(await ssoTrustedOrigins())];
      }
      return base;
    },
    hooks: {
      before: authBeforeHook,
    },
    plugins: [
      admin({
        ac: adminPluginAc,
        roles: {
          admin: adminPluginAdminRole,
          user: adminPluginUserRole,
        },
        defaultRole: "user",
        adminRoles: ["admin"],
      }),
      organization({
        ac,
        roles: {
          owner,
          admin: orgAdmin,
          member,
        },
        dynamicAccessControl: {
          enabled: true,
          maximumRolesPerOrganization: 50,
        },
        allowUserToCreateOrganization: async (user) =>
          canUserCreateOrganization(user),
        organizationLimit: async (user) => hasReachedOrganizationLimit(user),
        membershipLimit: async (_user, org) => {
          if (!isCloudBilling) return 100;
          const plan = await getEffectiveOrgPlan(org.id);
          if (plan.seats === null) return 500;
          return plan.seats;
        },
        schema: {
          organization: {
            additionalFields: {
              quickEnrollEnabled: {
                type: "boolean",
                required: false,
                defaultValue: true,
                input: true,
              },
              deletedAt: {
                type: "date",
                required: false,
                input: false,
              },
            },
          },
          organizationRole: {
            additionalFields: {
              position: {
                type: "number",
                required: true,
                defaultValue: 101,
                input: true,
              },
              color: {
                type: "string",
                required: false,
                input: true,
              },
            },
          },
        },
        organizationHooks: {
          beforeCreateOrganization: async ({ organization: orgData, user }) => {
            if (isCloudBilling) {
              const plan = parseCreatablePlan(orgData.metadata);
              if (!plan) {
                throw new APIError("BAD_REQUEST", {
                  message:
                    'Organization plan is required. Choose "free", "personal", "team", or "business".',
                });
              }
              const allowed = await canUserCreateOrganization(user);
              if (!allowed) {
                const cap = ownershipCapForUser(Boolean(user.emailVerified));
                throw new APIError("BAD_REQUEST", {
                  message: user.emailVerified
                    ? `You can own at most ${cap} organizations.`
                    : "Verify your email to own more than one organization.",
                });
              }
              return {
                data: {
                  ...orgData,
                  metadata: {
                    ...(typeof orgData.metadata === "object" && orgData.metadata
                      ? orgData.metadata
                      : {}),
                    plan,
                  },
                },
              };
            }
            return { data: orgData };
          },
          beforeCreateInvitation: async ({ organization: org }) => {
            if (!license.has("openSignUp")) {
              throw new APIError("BAD_REQUEST", {
                message:
                  "Invitations require cloud signup. Create users from the admin panel instead.",
              });
            }
            if (isCloudBilling) {
              try {
                await assertSeatCapacity(org.id, 1);
              } catch (error) {
                throw new APIError("BAD_REQUEST", {
                  message:
                    error instanceof Error
                      ? error.message
                      : "Seat limit reached",
                });
              }
            }
          },
          beforeAddMember: async ({ organization: org }) => {
            if (isCloudBilling) {
              try {
                await assertSeatCapacity(org.id, 1);
              } catch (error) {
                throw new APIError("BAD_REQUEST", {
                  message:
                    error instanceof Error
                      ? error.message
                      : "Seat limit reached",
                });
              }
            }
          },
          beforeAcceptInvitation: async ({ organization: org }) => {
            if (isCloudBilling) {
              try {
                await assertSeatCapacity(org.id, 1);
              } catch (error) {
                throw new APIError("BAD_REQUEST", {
                  message:
                    error instanceof Error
                      ? error.message
                      : "Seat limit reached",
                });
              }
            }
          },
          afterCreateOrganization: async ({ organization: org, user }) => {
            await createDefaultNetwork(org.id, user.id);
          },
        },
      }),
      ...(stripeEnabled && stripeClient && stripeWebhookSecret
        ? [
            stripe({
              stripeClient,
              stripeWebhookSecret,
              createCustomerOnSignUp: false,
              organization: { enabled: true },
              subscription: {
                enabled: true,
                plans: stripePlans,
                authorizeReference: async ({ user, referenceId, action }) => {
                  const role = await memberRoleInOrg(user.id, referenceId);
                  if (!role) return false;
                  if (action === "list-subscription") {
                    return true;
                  }
                  return isAdminOrOwnerRole(role);
                },
              },
            }),
          ]
        : []),
      sso({
        organizationProvisioning: {
          disabled: false,
          defaultRole: "member",
        },
      }),
      jwt(),
      bearer(),
      deviceAuthorization({
        verificationUri: `${dashboardOrigin}/app/settings/account`,
        validateClient: async (clientId) => {
          const client = await db.query.oauthClient.findFirst({
            where: eq(schema.oauthClient.clientId, clientId),
          });
          return Boolean(client && !client.disabled);
        },
      }),
      oauthProvider({
        loginPage: `${dashboardOrigin}/login`,
        consentPage: `${dashboardOrigin}/consent`,
        scopes: [
          "openid",
          "profile",
          "email",
          "offline_access",
          "mesh:connect",
          "tunnel:create",
          "serve:create",
          "admin:read",
          "admin:write",
        ],
        cachedTrustedClients: TRUSTED_OAUTH_CLIENT_IDS,
        clientReference: ({ session }) =>
          (session?.activeOrganizationId as string | undefined) ?? undefined,
      }),
    ],
  });
}

export async function initAuth(): Promise<LicenseManager> {
  license = await createLicenseManager();
  auth = buildAuth(license);
  return license;
}

export async function ensureTrustedOAuthClients() {
  const apiOrigin = getManagementUrl();

  const desired = [
    {
      clientId:
        process.env.TUNNET_OAUTH_DASHBOARD_CLIENT_ID || OAUTH_CLIENT_DASHBOARD,
      name: "Tunnet Dashboard",
      redirectUris: [
        `${dashboardOrigin}/api/auth/callback/tunnet`,
        `${dashboardOrigin}/consent`,
      ],
      applicationType: "web" as const,
    },
    {
      clientId: process.env.TUNNET_OAUTH_CLI_CLIENT_ID || OAUTH_CLIENT_CLI,
      name: "Tunnet CLI",
      redirectUris: [
        `${apiOrigin}/auth/cli/callback`,
        "http://127.0.0.1:3847/callback",
        "http://localhost:3847/callback",
      ],
      applicationType: "native" as const,
    },
  ];

  for (const client of desired) {
    try {
      TRUSTED_OAUTH_CLIENT_IDS.add(client.clientId);
      const existing = await db.query.oauthClient.findFirst({
        where: eq(schema.oauthClient.clientId, client.clientId),
      });
      if (existing) {
        continue;
      }

      await db.insert(schema.oauthClient).values({
        id: crypto.randomUUID(),
        clientId: client.clientId,
        clientSecret: null,
        disabled: false,
        skipConsent: true,
        enableEndSession: true,
        name: client.name,
        redirectUris: client.redirectUris,
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        tokenEndpointAuthMethod: "none",
        applicationType: client.applicationType,
        clientCredentialsScopes: [],
        requirePKCE: true,
        scopes: [
          "openid",
          "profile",
          "email",
          "offline_access",
          "mesh:connect",
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      console.log(
        `[oauth] created trusted client "${client.name}" (${client.clientId})`,
      );
    } catch (err) {
      console.warn(
        `[oauth] failed to bootstrap client "${client.name}":`,
        err instanceof Error ? err.message : err,
      );
    }
  }
}
