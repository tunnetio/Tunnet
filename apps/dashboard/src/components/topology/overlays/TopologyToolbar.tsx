import { useReactFlow } from "@xyflow/react";
import { toPng } from "html-to-image";
import {
  DownloadIcon,
  LayoutGridIcon,
  RouteIcon,
  SearchIcon,
} from "lucide-react";

import { useTopologyUi } from "@/components/topology/TopologyProvider";
import type {
  MeshKindFilter,
  MeshStatusFilter,
} from "@/components/topology/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

type TopologyToolbarProps = {
  mode: "overview" | "network";
  className?: string;
  actions?: React.ReactNode;
};

export function TopologyToolbar({
  mode,
  className,
  actions,
}: TopologyToolbarProps) {
  const {
    overviewMode,
    statusFilter,
    setStatusFilter,
    kindFilter,
    setKindFilter,
    heatmap,
    setHeatmap,
    searchQuery,
    setSearchQuery,
    pathPickMode,
    setPathPickMode,
    setPathEndpoints,
    setHighlightedPath,
    requestRelayout,
  } = useTopologyUi();
  const rf = useReactFlow();

  async function exportPng() {
    const el = document.querySelector(".react-flow") as HTMLElement | null;
    if (!el) return;
    const dataUrl = await toPng(el, {
      backgroundColor: "transparent",
      pixelRatio: 2,
      filter: (node) => {
        if (!(node instanceof HTMLElement)) return true;
        return !node.classList.contains("react-flow__panel");
      },
    });
    const a = document.createElement("a");
    a.href = dataUrl;
    a.download = `tunnet-topology-${Date.now()}.png`;
    a.click();
  }

  const showSearch =
    mode === "network" || (mode === "overview" && overviewMode === "topology");

  return (
    <div
      className={cn(
        "pointer-events-auto flex flex-wrap items-center gap-2 rounded-lg border border-border/70 bg-card/95 px-2.5 py-2 shadow-sm backdrop-blur",
        className,
      )}
    >
      {showSearch ? (
        <div className="relative min-w-[140px] flex-1">
          <SearchIcon className="text-muted-foreground pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search nodes…"
            className="h-8 pl-7 text-[12px]"
          />
        </div>
      ) : null}

      {mode === "network" ? (
        <>
          <Select
            value={statusFilter}
            onValueChange={(v) => {
              if (v) setStatusFilter(v as MeshStatusFilter);
            }}
          >
            <SelectTrigger className="h-8 w-[110px] text-[12px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All status</SelectItem>
              <SelectItem value="online">Online</SelectItem>
              <SelectItem value="offline">Offline</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={kindFilter}
            onValueChange={(v) => {
              if (v) setKindFilter(v as MeshKindFilter);
            }}
          >
            <SelectTrigger className="h-8 w-[120px] text-[12px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All kinds</SelectItem>
              <SelectItem value="machine">Machines</SelectItem>
              <SelectItem value="k8s">Kubernetes</SelectItem>
              <SelectItem value="subnet">Subnets</SelectItem>
              <SelectItem value="hostname">Hostnames</SelectItem>
              <SelectItem value="exit">Exit</SelectItem>
              <SelectItem value="relay">Relays</SelectItem>
            </SelectContent>
          </Select>
          <Button
            type="button"
            size="sm"
            variant={heatmap ? "secondary" : "ghost"}
            className="h-8 text-[12px]"
            onClick={() => setHeatmap(!heatmap)}
          >
            Heatmap
          </Button>
          <Button
            type="button"
            size="sm"
            variant={pathPickMode ? "secondary" : "ghost"}
            className="h-8 text-[12px]"
            onClick={() => {
              const next = !pathPickMode;
              setPathPickMode(next);
              setPathEndpoints([]);
              setHighlightedPath(new Set());
            }}
          >
            <RouteIcon className="size-3.5" />
            Path
          </Button>
        </>
      ) : null}

      {showSearch ? (
        <>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-8 text-[12px]"
            onClick={() => requestRelayout()}
          >
            <LayoutGridIcon className="size-3.5" />
            Layout
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-8 text-[12px]"
            onClick={() => void exportPng()}
            disabled={rf.getNodes().length === 0}
          >
            <DownloadIcon className="size-3.5" />
            PNG
          </Button>
        </>
      ) : null}
      {actions}
    </div>
  );
}
