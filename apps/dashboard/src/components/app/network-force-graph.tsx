import type { TopologyEdge, TopologyNode } from "@tuntun/api/management";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, {
  type ForceGraphMethods,
  type LinkObject,
  type NodeObject,
} from "react-force-graph-2d";

import { cn } from "@/lib/utils";

type GraphKind = TopologyNode["kind"] | "hub";

type GraphNode = NodeObject &
  Omit<TopologyNode, "kind"> & {
    kind: GraphKind;
    val: number;
  };

type GraphLink = LinkObject &
  TopologyEdge & {
    curvature?: number;
  };

const HUB_COLOR = "#5b6cff";
const ONLINE_GREEN = "#22c55e";
const OFFLINE_SLATE = "#94a3b8";

const KIND_COLOR: Record<Exclude<GraphKind, "hub" | "machine">, string> = {
  subnet: "#34d399",
  hostname: "#0ea5e9",
  exit: "#f59e0b",
  relay: "#ef4444",
};

const EDGE_COLOR: Record<TopologyEdge["kind"] | "hub", string> = {
  hub: "rgba(91, 108, 255, 0.45)",
  peer: "#22c55e",
  subnet: "rgba(52, 211, 153, 0.55)",
  hostname: "rgba(14, 165, 233, 0.55)",
  exit: "rgba(245, 158, 11, 0.55)",
  tunnel: "rgba(239, 68, 68, 0.75)",
};

function nodeRadius(node: GraphNode): number {
  if (node.kind === "hub") return 14;
  if (node.kind === "relay") return 7;
  if (node.kind === "machine") return 20;
  if (node.kind === "exit") return 7;
  return 5;
}

function pinStaticLayout(nodes: GraphNode[]) {
  const hub = nodes.find((n) => n.kind === "hub");
  if (hub) {
    hub.x = 0;
    hub.y = 0;
    hub.fx = 0;
    hub.fy = 0;
  }

  const machines = nodes.filter((n) => n.kind === "machine");
  const others = nodes.filter((n) => n.kind !== "hub" && n.kind !== "machine");
  const ring = 110;

  machines.forEach((machine, i) => {
    const angle =
      machines.length === 1
        ? -Math.PI / 2
        : (2 * Math.PI * i) / machines.length - Math.PI / 2;
    const x = Math.cos(angle) * ring;
    const y = Math.sin(angle) * ring;
    machine.x = x;
    machine.y = y;
    machine.fx = x;
    machine.fy = y;
  });

  const outer = 170;
  others.forEach((node, i) => {
    const count = Math.max(others.length, 1);
    const angle = (2 * Math.PI * i) / count + Math.PI / count;
    const x = Math.cos(angle) * outer;
    const y = Math.sin(angle) * outer;
    node.x = x;
    node.y = y;
    node.fx = x;
    node.fy = y;
  });
}

function linkEndId(end: GraphLink["source"] | GraphLink["target"]): string {
  if (end == null) return "";
  if (typeof end === "object") {
    return String((end as { id?: string | number }).id ?? "");
  }
  return String(end);
}

function isHubLink(link: GraphLink): boolean {
  return (
    linkEndId(link.source).startsWith("hub:") ||
    linkEndId(link.target).startsWith("hub:")
  );
}

function linkMachineOnline(link: GraphLink): boolean {
  const ends = [link.source, link.target];
  for (const end of ends) {
    if (typeof end === "object" && end != null) {
      const node = end as GraphNode;
      if (node.kind === "machine") return Boolean(node.online);
    }
  }
  return false;
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  const radius = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + w, y, x + w, y + h, radius);
  ctx.arcTo(x + w, y + h, x, y + h, radius);
  ctx.arcTo(x, y + h, x, y, radius);
  ctx.arcTo(x, y, x + w, y, radius);
  ctx.closePath();
}

export function NetworkForceGraph({
  nodes,
  edges,
  onSelect,
  className,
  heightClassName,
  showHub = true,
  statusFilter = "all",
  kindFilter = "all",
  heatmap = false,
}: {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  onSelect?: (node: TopologyNode | null) => void;
  className?: string;
  heightClassName?: string;
  showHub?: boolean;
  statusFilter?: "all" | "online" | "offline";
  kindFilter?: "all" | TopologyNode["kind"];
  /** When true, edge thickness scales more strongly with intensity. */
  heatmap?: boolean;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<ForceGraphMethods<GraphNode, GraphLink> | undefined>(
    undefined,
  );
  const logoRef = useRef<HTMLImageElement | null>(null);
  const [logoReady, setLogoReady] = useState(false);
  const [size, setSize] = useState<{ w: number; h: number } | null>(null);

  useEffect(() => {
    const img = new Image();
    img.src = "/logo.png";
    img.onload = () => {
      logoRef.current = img;
      setLogoReady(true);
    };
    img.onerror = () => {
      logoRef.current = null;
      setLogoReady(false);
    };
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = () => {
      const { width, height } = el.getBoundingClientRect();
      if (width < 2 || height < 2) return;
      setSize({
        w: Math.max(320, Math.floor(width)),
        h: Math.max(260, Math.floor(height)),
      });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (kindFilter !== "all" && n.kind !== kindFilter) return false;
      if (n.kind === "machine") {
        if (statusFilter === "online" && !n.online) return false;
        if (statusFilter === "offline" && n.online) return false;
      }
      return true;
    });
  }, [nodes, statusFilter, kindFilter]);

  const visibleIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes],
  );

  const graphData = useMemo(() => {
    const gNodes: GraphNode[] = filteredNodes.map((n) => ({
      ...n,
      val: 1,
    }));

    const gLinks: GraphLink[] = edges
      .filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target))
      .map((e) => ({
        ...e,
        curvature: 0,
      }));

    if (showHub) {
      const hubId = "hub:tuntun";
      gNodes.unshift({
        id: hubId,
        kind: "hub",
        label: "TunTun",
        secondary: "Edge",
        val: 1,
        online: true,
      });
      for (const n of filteredNodes) {
        if (n.kind !== "machine") continue;
        gLinks.push({
          id: `hub-edge:${n.id}`,
          source: hubId,
          target: n.id,
          kind: "peer",
          intensity: n.online ? 0.7 : 0.25,
          curvature: 0,
          direct: true,
        });
      }
    }

    pinStaticLayout(gNodes);
    return { nodes: gNodes, links: gLinks };
  }, [filteredNodes, edges, visibleIds, showHub]);

  const [viewReady, setViewReady] = useState(false);

  const fitViewport = useCallback(() => {
    const fg = fgRef.current;
    if (!fg) return;
    fg.d3Force("charge", null);
    fg.d3Force("center", null);
    fg.d3Force("link", null);
    fg.zoomToFit(0, 96);
    setViewReady(true);
  }, []);

  const topologyKey = `${graphData.nodes.length}:${graphData.links.length}`;

  useEffect(() => {
    void topologyKey;
    setViewReady(false);
  }, [topologyKey]);

  useEffect(() => {
    void topologyKey;
    if (!size) return;
    const id = window.requestAnimationFrame(fitViewport);
    return () => window.cancelAnimationFrame(id);
  }, [size, topologyKey, fitViewport]);

  const paintNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const r = nodeRadius(node);
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const scale = Math.max(globalScale, 0.85);

      if (node.kind === "hub") {
        const logo = logoRef.current;
        if (logo && logoReady) {
          ctx.save();
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.clip();
          ctx.drawImage(logo, x - r, y - r, r * 2, r * 2);
          ctx.restore();
        } else {
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = HUB_COLOR;
          ctx.fill();
          const fontSize = Math.max(11 / scale, 4);
          ctx.font = `700 ${fontSize}px Geist Variable, ui-sans-serif, system-ui`;
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillStyle = "#fff";
          ctx.fillText("T", x, y + 0.5);
        }

        const labelSize = Math.max(10 / scale, 3.2);
        ctx.font = `500 ${labelSize}px Geist Variable, ui-sans-serif, system-ui`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillStyle = "rgba(71, 85, 105, 0.9)";
        // ctx.fillText("TunTun", x, y + r + 5);
        return;
      }

      if (node.kind === "machine") {
        const online = Boolean(node.online);
        const name = node.label || "machine";
        const ip = node.secondary ?? node.assignedIp ?? "—";
        const nameSize = Math.max(12 / scale, 3.6);
        const ipSize = Math.max(10 / scale, 3);
        ctx.font = `600 ${nameSize}px Geist Variable, ui-sans-serif, system-ui`;
        const nameW = ctx.measureText(name).width;
        ctx.font = `${ipSize}px Geist Mono Variable, ui-monospace, monospace`;
        const ipW = ctx.measureText(ip).width;

        const padX = 12 / scale;
        const padY = 10 / scale;
        const pip = 5 / scale;
        const gap = 8 / scale;
        const cardW = Math.max(nameW, ipW) + pip + gap + padX * 2;
        const cardH = nameSize + ipSize + 4 / scale + padY * 2;
        const cardX = x - cardW / 2;
        const cardY = y - cardH / 2;

        roundRect(ctx, cardX, cardY, cardW, cardH, 6 / scale);
        ctx.fillStyle = online ? "#ffffff" : "rgba(248, 250, 252, 0.95)";
        ctx.fill();
        ctx.strokeStyle = online
          ? "rgba(15, 23, 42, 0.12)"
          : "rgba(148, 163, 184, 0.45)";
        ctx.lineWidth = 1 / scale;
        ctx.stroke();

        const textTop = cardY + padY;
        ctx.beginPath();
        ctx.arc(
          cardX + padX + pip / 2,
          textTop + nameSize / 2,
          pip / 2,
          0,
          Math.PI * 2,
        );
        ctx.fillStyle = online ? ONLINE_GREEN : OFFLINE_SLATE;
        ctx.fill();

        const textX = cardX + padX + pip + gap;
        ctx.textAlign = "left";
        ctx.textBaseline = "top";
        ctx.font = `600 ${nameSize}px Geist Variable, ui-sans-serif, system-ui`;
        ctx.fillStyle = online
          ? "rgba(15, 23, 42, 0.95)"
          : "rgba(100, 116, 139, 0.95)";
        ctx.fillText(name, textX, textTop);

        ctx.font = `${ipSize}px Geist Mono Variable, ui-monospace, monospace`;
        ctx.fillStyle = "rgba(100, 116, 139, 0.95)";
        ctx.fillText(ip, textX, textTop + nameSize + 4 / scale);
        return;
      }

      ctx.beginPath();
      if (node.kind === "subnet") {
        ctx.rect(x - r, y - r, r * 2, r * 2);
      } else if (node.kind === "hostname") {
        ctx.moveTo(x, y - r);
        ctx.lineTo(x + r, y);
        ctx.lineTo(x, y + r);
        ctx.lineTo(x - r, y);
        ctx.closePath();
      } else if (node.kind === "exit") {
        for (let i = 0; i < 6; i++) {
          const a = (Math.PI / 3) * i - Math.PI / 6;
          const px = x + Math.cos(a) * r;
          const py = y + Math.sin(a) * r;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
      } else {
        ctx.moveTo(x, y - r);
        ctx.lineTo(x + r * 0.85, y);
        ctx.lineTo(x, y + r);
        ctx.lineTo(x - r * 0.85, y);
        ctx.closePath();
      }

      ctx.fillStyle = KIND_COLOR[node.kind];
      ctx.fill();
      ctx.strokeStyle = "rgba(255, 255, 255, 0.7)";
      ctx.lineWidth = 1 / scale;
      ctx.stroke();

      const fontSize = Math.max(10 / scale, 3.2);
      ctx.font = `${fontSize}px Geist Variable, ui-sans-serif, system-ui`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillStyle = "rgba(71, 85, 105, 0.9)";
      ctx.fillText(node.label, x, y + r + 3);
    },
    [logoReady],
  );

  const paintLink = useCallback(
    (link: GraphLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      if (link.kind !== "tunnel") return;
      const source = link.source as GraphNode | string | number | undefined;
      const target = link.target as GraphNode | string | number | undefined;
      if (
        typeof source !== "object" ||
        source == null ||
        typeof target !== "object" ||
        target == null
      ) {
        return;
      }
      const hostname =
        (source as GraphNode).publicHostname ??
        (target as GraphNode).publicHostname;
      if (!hostname) return;
      const x =
        (((source as GraphNode).x ?? 0) + ((target as GraphNode).x ?? 0)) / 2;
      const y =
        (((source as GraphNode).y ?? 0) + ((target as GraphNode).y ?? 0)) / 2;
      const fontSize = Math.max(8 / globalScale, 2.4);
      ctx.font = `${fontSize}px Geist Mono Variable, ui-monospace, monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = "rgba(220, 38, 38, 0.8)";
      ctx.fillText(hostname, x, y - 4);
    },
    [],
  );

  const linkColor = useCallback((link: GraphLink) => {
    if (isHubLink(link)) {
      return linkMachineOnline(link)
        ? "rgba(34, 197, 94, 0.55)"
        : "rgba(148, 163, 184, 0.45)";
    }
    if (link.kind === "peer") {
      return link.direct === false ? "#eab308" : EDGE_COLOR.peer;
    }
    return EDGE_COLOR[link.kind];
  }, []);

  const linkWidth = useCallback(
    (link: GraphLink) => {
      if (isHubLink(link)) return linkMachineOnline(link) ? 1.4 : 1.1;
      const intensity = link.intensity ?? 0.35;
      if (heatmap) {
        return 0.5 + intensity * 4.5;
      }
      if (link.kind === "tunnel") return 1.4;
      return 0.6 + intensity * 1.8;
    },
    [heatmap],
  );

  const linkLineDash = useCallback((link: GraphLink) => {
    if (isHubLink(link)) return [5, 4];
    if (link.kind === "tunnel") return [4, 3];
    return null;
  }, []);

  const linkParticles = useCallback((link: GraphLink) => {
    if (isHubLink(link)) {
      return linkMachineOnline(link) ? 3 : 0;
    }
    if (link.kind === "tunnel") return 3;
    if (link.kind !== "peer") {
      return Math.round(1 + (link.intensity ?? 0.3) * 2);
    }
    // Peer traffic animation only when intensity suggests activity
    if ((link.intensity ?? 0) < 0.15) return 0;
    return Math.max(1, Math.round((link.intensity ?? 0.35) * 5));
  }, []);

  const linkParticleSpeed = useCallback((link: GraphLink) => {
    if (isHubLink(link)) return 0.006;
    return 0.004 + (link.intensity ?? 0.35) * 0.012;
  }, []);

  return (
    <div
      ref={containerRef}
      className={cn(
        "mesh-surface relative w-full overflow-hidden rounded-lg border border-border/60",
        heightClassName ?? "h-[360px] sm:h-[440px]",
        className,
      )}
    >
      {size ? (
        <div
          className={cn("size-full", viewReady ? "opacity-100" : "opacity-0")}
        >
          <ForceGraph2D
            ref={fgRef}
            width={size.w}
            height={size.h}
            graphData={graphData}
            backgroundColor="rgba(0,0,0,0)"
            nodeId="id"
            linkSource="source"
            linkTarget="target"
            nodeCanvasObject={paintNode}
            linkCanvasObjectMode={() => "after"}
            linkCanvasObject={paintLink}
            nodePointerAreaPaint={(node, color, ctx) => {
              const n = node as GraphNode;
              const r = nodeRadius(n) + 4;
              ctx.beginPath();
              ctx.arc(node.x ?? 0, node.y ?? 0, r, 0, Math.PI * 2);
              ctx.fillStyle = color;
              ctx.fill();
            }}
            linkColor={linkColor}
            linkWidth={linkWidth}
            linkLineDash={linkLineDash}
            linkCurvature="curvature"
            linkDirectionalParticles={linkParticles}
            linkDirectionalParticleSpeed={linkParticleSpeed}
            linkDirectionalParticleWidth={(link) =>
              isHubLink(link as GraphLink)
                ? 2.2
                : 1.2 + ((link as GraphLink).intensity ?? 0.3) * 2
            }
            linkDirectionalParticleColor={(link) =>
              isHubLink(link as GraphLink)
                ? ONLINE_GREEN
                : linkColor(link as GraphLink)
            }
            warmupTicks={0}
            cooldownTicks={0}
            d3AlphaDecay={1}
            d3VelocityDecay={1}
            enableNodeDrag={false}
            enableZoomInteraction={false}
            enablePanInteraction={false}
            onEngineStop={fitViewport}
            onNodeClick={(node) => {
              const n = node as GraphNode;
              if (n.kind === "hub") {
                onSelect?.(null);
                return;
              }
              onSelect?.(n as TopologyNode);
            }}
            onBackgroundClick={() => onSelect?.(null)}
          />
        </div>
      ) : null}
    </div>
  );
}
