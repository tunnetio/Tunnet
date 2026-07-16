import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { getDb, schema } from "@tuntun/db";
import { getDashboardUrl, getManagementUrl } from "@tuntun/env";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import {
  bearer,
  deviceAuthorization,
  jwt,
  organization,
} from "better-auth/plugins";
import { eq } from "drizzle-orm";

import { createDefaultNetwork } from "./lib/default-network";
import { getEntitlements } from "./lib/entitlements";

const db = getDb();

const dashboardOrigin = getDashboardUrl();

export const OAUTH_CLIENT_DASHBOARD = "tuntun-dashboard";
export const OAUTH_CLIENT_CLI = "tuntun-cli";

export const TRUSTED_OAUTH_CLIENT_IDS = new Set<string>([
  OAUTH_CLIENT_DASHBOARD,
  OAUTH_CLIENT_CLI,
  ...(process.env.TUNTUN_OAUTH_CLI_CLIENT_ID
    ? [process.env.TUNTUN_OAUTH_CLI_CLIENT_ID]
    : []),
  ...(process.env.TUNTUN_OAUTH_DASHBOARD_CLIENT_ID
    ? [process.env.TUNTUN_OAUTH_DASHBOARD_CLIENT_ID]
    : []),
]);

async function canUserCreateOrganization(user: {
  id: string;
}): Promise<boolean> {
  const entitlements = await getEntitlements();
  if (entitlements.multiOrganization) return true;

  const memberships = await db.query.member.findMany({
    where: eq(schema.member.userId, user.id),
  });
  return memberships.length === 0;
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

export const auth = betterAuth({
  appName: "TunTun Management",
  baseURL: getManagementUrl(),
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.account,
      verification: schema.verification,
      organization: schema.organization,
      member: schema.member,
      invitation: schema.invitation,
      ssoProvider: schema.ssoProvider,
      jwks: schema.jwks,
      oauthClient: schema.oauthClient,
      oauthRefreshToken: schema.oauthRefreshToken,
      oauthAccessToken: schema.oauthAccessToken,
      oauthConsent: schema.oauthConsent,
      deviceCode: schema.deviceCode,
    },
  }),
  experimental: {
    joins: true,
  },
  emailAndPassword: {
    enabled: true,
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
  plugins: [
    organization({
      allowUserToCreateOrganization: async (user) =>
        canUserCreateOrganization(user),
      schema: {
        organization: {
          additionalFields: {
            quickEnrollEnabled: {
              type: "boolean",
              required: false,
              defaultValue: true,
              input: true,
            },
          },
        },
      },
      organizationHooks: {
        afterCreateOrganization: async ({ organization, user }) => {
          await createDefaultNetwork(organization.id, user.id);
        },
      },
    }),
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
      silenceWarnings: {
        oauthAuthServerConfig: true,
      },
    }),
  ],
});

/** Ensure first-party OAuth clients exist (CLI + dashboard). */
export async function ensureTrustedOAuthClients() {
  const apiOrigin = getManagementUrl();

  const desired = [
    {
      clientId:
        process.env.TUNTUN_OAUTH_DASHBOARD_CLIENT_ID || OAUTH_CLIENT_DASHBOARD,
      name: "TunTun Dashboard",
      redirectUris: [
        `${dashboardOrigin}/api/auth/callback/tuntun`,
        `${dashboardOrigin}/consent`,
      ],
      type: "web" as const,
    },
    {
      clientId: process.env.TUNTUN_OAUTH_CLI_CLIENT_ID || OAUTH_CLIENT_CLI,
      name: "TunTun CLI",
      redirectUris: [
        `${apiOrigin}/auth/cli/callback`,
        "http://127.0.0.1:3847/callback",
        "http://localhost:3847/callback",
      ],
      type: "native" as const,
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
        public: true,
        type: client.type,
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
