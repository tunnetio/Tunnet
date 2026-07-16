import { useQuery } from "@tanstack/react-query";
import { entitlementsSchema } from "@tuntun/api/management";
import {
  COMMUNITY_ENTITLEMENTS,
  type Entitlements,
} from "@tuntun/entitlements";

import { getManagementApiUrl } from "@/lib/env";

async function fetchEntitlements(): Promise<Entitlements> {
  const response = await fetch(`${getManagementApiUrl()}/api/v1/entitlements`, {
    credentials: "include",
  });
  if (!response.ok) {
    return COMMUNITY_ENTITLEMENTS;
  }
  const data: unknown = await response.json();
  const parsed = entitlementsSchema.safeParse(data);
  return parsed.success ? parsed.data : COMMUNITY_ENTITLEMENTS;
}

export function useEntitlements() {
  return useQuery({
    queryKey: ["entitlements"],
    queryFn: fetchEntitlements,
    staleTime: 60_000,
  });
}
