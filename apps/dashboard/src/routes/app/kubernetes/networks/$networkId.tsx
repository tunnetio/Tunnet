import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/app/kubernetes/networks/$networkId")({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/app/networks/$networkId",
      params: { networkId: params.networkId },
      search: { kind: "k8s" },
    });
  },
});
