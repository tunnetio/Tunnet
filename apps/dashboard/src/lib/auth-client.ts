import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { ssoClient } from "@better-auth/sso/client";
import {
  adminClient,
  deviceAuthorizationClient,
  inferOrgAdditionalFields,
  organizationClient,
} from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

import { getManagementApiUrl } from "@/lib/env";

export const authClient = createAuthClient({
  baseURL: getManagementApiUrl(),
  fetchOptions: {
    credentials: "include",
  },
  plugins: [
    adminClient(),
    organizationClient({
      schema: inferOrgAdditionalFields({
        organization: {
          additionalFields: {
            quickEnrollEnabled: {
              type: "boolean",
              defaultValue: true,
            },
          },
        },
      }),
    }),
    ssoClient(),
    oauthProviderClient(),
    deviceAuthorizationClient(),
  ],
});

export const {
  signIn,
  signUp,
  signOut,
  useSession,
  getSession,
  organization,
  useListOrganizations,
  useActiveOrganization,
} = authClient;

export type Session = typeof authClient.$Infer.Session;
