import { useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { useTopologyUi } from "@/components/topology/TopologyProvider";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

type MenuState = {
  x: number;
  y: number;
  endpointId?: string;
  networkId?: string;
  label: string;
  kind: "peer" | "network";
};

export function TopologyContextMenus({
  networkId,
}: {
  orgId: string;
  networkId?: string;
}) {
  const navigate = useNavigate();
  const { setSelected, setConnectIntent } = useTopologyUi();
  const [menu, setMenu] = useState<MenuState | null>(null);

  useEffect(() => {
    function onOpen(event: Event) {
      const detail = (event as CustomEvent<MenuState>).detail;
      if (!detail) return;
      setMenu(detail);
    }
    window.addEventListener("tunnet-topology-context", onOpen);
    return () => window.removeEventListener("tunnet-topology-context", onOpen);
  }, []);

  if (!menu) return null;

  return (
    <DropdownMenu
      open
      onOpenChange={(open) => {
        if (!open) setMenu(null);
      }}
    >
      <DropdownMenuTrigger
        className="fixed size-0 opacity-0"
        style={{ left: menu.x, top: menu.y }}
      />
      <DropdownMenuContent className="w-48" align="start">
        {menu.kind === "peer" && menu.endpointId ? (
          <>
            <DropdownMenuItem
              onClick={() =>
                setSelected({
                  kind: "topology",
                  node: {
                    id: menu.endpointId!,
                    kind: "machine",
                    label: menu.label,
                    endpointId: menu.endpointId,
                  },
                })
              }
            >
              View details
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                void navigate({
                  to: "/app/machines/$endpointId",
                  params: { endpointId: menu.endpointId! },
                });
              }}
            >
              Open machine
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() =>
                setConnectIntent({
                  type: "serve",
                  endpointId: menu.endpointId!,
                  networkId: networkId ?? menu.networkId ?? "",
                })
              }
            >
              Create serve
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() =>
                setConnectIntent({
                  type: "tunnel",
                  endpointId: menu.endpointId!,
                  networkId: networkId ?? menu.networkId ?? "",
                })
              }
            >
              Create tunnel
            </DropdownMenuItem>
          </>
        ) : null}
        {menu.kind === "network" && menu.networkId ? (
          <>
            <DropdownMenuItem
              onClick={() => {
                void navigate({
                  to: "/app/networks/$networkId",
                  params: { networkId: menu.networkId! },
                });
              }}
            >
              Open mesh
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                void navigate({
                  to: "/app/networks/$networkId/access",
                  params: { networkId: menu.networkId! },
                });
              }}
            >
              View ACLs
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() =>
                setConnectIntent({
                  type: "enroll",
                  networkId: menu.networkId!,
                })
              }
            >
              Add peer
            </DropdownMenuItem>
          </>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function openTopologyContextMenu(
  event: React.MouseEvent,
  payload: {
    kind: "peer" | "network";
    label: string;
    endpointId?: string;
    networkId?: string;
  },
) {
  event.preventDefault();
  window.dispatchEvent(
    new CustomEvent("tunnet-topology-context", {
      detail: {
        x: event.clientX,
        y: event.clientY,
        ...payload,
      } satisfies MenuState,
    }),
  );
}
