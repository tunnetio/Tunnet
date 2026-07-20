import {
  BaseEdge,
  EdgeLabelRenderer,
  type EdgeProps,
  getBezierPath,
} from "@xyflow/react";

import type { MeshEdgeData } from "@/components/topology/types";
import { cn } from "@/lib/utils";

export function MeshEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
  selected,
}: EdgeProps) {
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });
  const edgeData = data as MeshEdgeData | undefined;
  const highlighted = edgeData?.highlighted || selected;

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{
          ...style,
          strokeWidth: highlighted
            ? Number(style?.strokeWidth ?? 1.5) + 1
            : style?.strokeWidth,
          opacity: highlighted ? 1 : 0.85,
        }}
      />
      {edgeData?.label ? (
        <EdgeLabelRenderer>
          <div
            className={cn(
              "nodrag nopan pointer-events-none absolute rounded bg-card/90 px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground shadow-sm",
              highlighted && "text-foreground",
            )}
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            }}
          >
            {edgeData.label}
          </div>
        </EdgeLabelRenderer>
      ) : null}
    </>
  );
}

export function SubnetRouteEdge(props: EdgeProps) {
  return <MeshEdge {...props} />;
}

export function PolicyEdge(props: EdgeProps) {
  return (
    <MeshEdge
      {...props}
      style={{
        ...props.style,
        stroke: "#3b82f6",
        strokeDasharray: "4 3",
      }}
    />
  );
}
