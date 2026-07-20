import { useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { useEffect } from "react";

import { NetworkCanvas } from "@/components/topology/NetworkCanvas";
import {
  TopologyProvider,
  useTopologyUi,
} from "@/components/topology/TopologyProvider";
import type { MeshKindFilter } from "@/components/topology/types";
import { useActiveOrganization } from "@/lib/auth-client";

function NetworkMeshBody({
  orgId,
  networkId,
}: {
  orgId: string;
  networkId: string;
}) {
  const search = useSearch({ from: "/app/networks/$networkId/" });
  const navigate = useNavigate({ from: "/app/networks/$networkId/" });
  const { kindFilter, setKindFilter } = useTopologyUi();

  useEffect(() => {
    const kind = (search.kind ?? "all") as MeshKindFilter;
    setKindFilter(kind);
  }, [search.kind, setKindFilter]);

  useEffect(() => {
    const urlKind = search.kind ?? "all";
    if (kindFilter === urlKind) return;
    void navigate({
      search: (prev) => {
        if (kindFilter === "all") {
          const { kind: _k, ...rest } = prev as { kind?: string };
          return rest;
        }
        return { ...prev, kind: kindFilter };
      },
      replace: true,
    });
  }, [kindFilter, navigate, search.kind]);

  return <NetworkCanvas orgId={orgId} networkId={networkId} />;
}

export function NetworkOverviewPage() {
  const { networkId } = useParams({ from: "/app/networks/$networkId/" });
  const search = useSearch({ from: "/app/networks/$networkId/" });
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const initialKind = (search.kind ?? "all") as MeshKindFilter;

  if (!orgId) {
    return (
      <div className="text-muted-foreground flex h-full items-center justify-center text-sm">
        Select an organization.
      </div>
    );
  }

  return (
    <TopologyProvider initialKind={initialKind}>
      <div className="flex h-full min-h-0 flex-1 flex-col">
        <NetworkMeshBody orgId={orgId} networkId={networkId} />
      </div>
    </TopologyProvider>
  );
}
