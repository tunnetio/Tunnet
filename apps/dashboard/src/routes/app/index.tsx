import { createFileRoute } from "@tanstack/react-router";

import { OverviewCanvas } from "@/components/topology/OverviewCanvas";
import { TopologyProvider } from "@/components/topology/TopologyProvider";
import { useActiveOrganization } from "@/lib/auth-client";

export const Route = createFileRoute("/app/")({
  component: OverviewPage,
});

function OverviewPage() {
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;

  if (!orgId) {
    return (
      <div className="text-muted-foreground flex h-full items-center justify-center text-sm">
        Select an organization.
      </div>
    );
  }

  return (
    <TopologyProvider>
      <div className="flex h-full min-h-0 flex-1 flex-col">
        <OverviewCanvas orgId={orgId} />
      </div>
    </TopologyProvider>
  );
}
