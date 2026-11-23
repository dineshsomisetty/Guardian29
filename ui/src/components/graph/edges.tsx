import { memo } from "react";
import { getSmoothStepPath, type Edge, type EdgeProps } from "@xyflow/react";

export interface CustodyEdgeData {
  /** hop index on the highlighted path, or -1 when off-path */
  hop: number;
  /** changes with every selection, restarts the draw */
  drawKey: string;
  dim: boolean;
  via?: { x: number; y: number }[];
  [key: string]: unknown;
}

export type CustodyEdgeT = Edge<CustodyEdgeData>;

/** Per-hop draw time; the next hop starts as the previous one lands. */
export const HOP_MS = 420;
const HOP_STAGGER = 360;

export const CustodyEdge = memo(function CustodyEdge(p: EdgeProps<CustodyEdgeT>) {
  const via = p.data?.via;
  const d = via?.length
    ? orthThrough([{ x: p.sourceX, y: p.sourceY }, ...via, { x: p.targetX, y: p.targetY }])
    : getSmoothStepPath({
        sourceX: p.sourceX,
        sourceY: p.sourceY,
        targetX: p.targetX,
        targetY: p.targetY,
        sourcePosition: p.sourcePosition,
        targetPosition: p.targetPosition,
        borderRadius: 0,
        offset: 18,
      })[0];
  const hop = p.data?.hop ?? -1;
  if (hop < 0) {
    return <path d={d} className={`g-edge${p.data?.dim ? " is-dim" : ""}`} fill="none" />;
  }
  return (
    <g className="g-edge-path-group">
      <path d={d} className="g-edge g-edge-under" fill="none" />
      <path
        key={p.data!.drawKey}
        d={d}
        pathLength={1}
        className="g-edge-path"
        fill="none"
        style={{ animationDelay: `${hop * HOP_STAGGER}ms`, animationDuration: `${HOP_MS}ms` }}
      />
    </g>
  );
});

/** Square-cornered route through dagre's lane points: horizontal, vertical at the midpoint, horizontal. */
function orthThrough(pts: { x: number; y: number }[]) {
  let d = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 1; i < pts.length; i++) {
    const a = pts[i - 1];
    const b = pts[i];
    if (Math.abs(a.y - b.y) < 0.5) d += ` H ${b.x}`;
    else {
      const mx = (a.x + b.x) / 2;
      d += ` H ${mx} V ${b.y} H ${b.x}`;
    }
  }
  return d;
}

export const edgeTypes = { custody: CustodyEdge };
