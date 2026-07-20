import { createFileRoute } from "@tanstack/react-router";

import { NetworkOverviewPage } from "@/components/app/network-overview";

const KIND_VALUES = [
  "all",
  "machine",
  "k8s",
  "subnet",
  "hostname",
  "exit",
  "relay",
] as const;

export type MeshKindFilter = (typeof KIND_VALUES)[number];

function parseKind(value: unknown): MeshKindFilter | undefined {
  if (typeof value !== "string") return undefined;
  return (KIND_VALUES as readonly string[]).includes(value)
    ? (value as MeshKindFilter)
    : undefined;
}

export const Route = createFileRoute("/app/networks/$networkId/")({
  validateSearch: (search: Record<string, unknown>) => {
    const kind = parseKind(search.kind);
    return kind && kind !== "all" ? { kind } : {};
  },
  component: NetworkOverviewPage,
});
