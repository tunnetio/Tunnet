import { createFileRoute, redirect } from "@tanstack/react-router";
import { HomePage, hasMarketingLanding } from "@tuntun/cloud-dashboard";

import { getSession } from "@/lib/auth.functions";

function showCloudLanding(): boolean {
  if (!hasMarketingLanding) return false;
  return (
    import.meta.env.TUNTUN_DEPLOYMENT === "cloud" ||
    import.meta.env.TUNTUN_LICENSE_TIER === "cloud"
  );
}

export const Route = createFileRoute("/")({
  beforeLoad: async () => {
    if (showCloudLanding()) return;
    const session = await getSession();
    throw redirect({ to: session ? "/app" : "/login" });
  },
  component: showCloudLanding() ? HomePage : undefined,
});
