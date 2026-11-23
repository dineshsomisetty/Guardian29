import { useEffect, useMemo, useState } from "react";
import {
  Background, BackgroundVariant, MiniMap, Panel, ReactFlow, ReactFlowProvider, useReactFlow,
  type Edge, type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Maximize2 } from "lucide-react";
import { buildVisible } from "../lib/layout";
import { useStore } from "../store";
import { nodeTypes, type GNode } from "./graphNodes";

const RISK_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#3b82f6",
  low: "#52525b",
};

export default function GraphView() {
  const { data } = useStore();
  const [onlyRisk, setOnlyRisk] = useState(false);
  const vis = useMemo(() => buildVisible(data.graph, data.findings, onlyRisk), [data.graph, data.findings, onlyRisk]);
  if (data.graph.nodes.length === 0)
    return (
      <div className="empty">
        <strong>No dependency graph recorded</strong>
        <span>Discovery did not produce a graph for this run.</span>
      </div>
    );
  return (
    <ReactFlowProvider>
      <Canvas vis={vis} onlyRisk={onlyRisk} setOnlyRisk={setOnlyRisk} />
    </ReactFlowProvider>
  );
}

function Canvas({
  vis, onlyRisk, setOnlyRisk,
}: {
  vis: ReturnType<typeof buildVisible>;
  onlyRisk: boolean;
  setOnlyRisk: (b: boolean) => void;
}) {
  const { data, findingsById, selectedFindingId, selectedNodeId, focusIds, openNode } = useStore();
  const rf = useReactFlow();

  // edges that lie on a vulnerable transitive path
  const riskEdges = useMemo(() => {
    const s = new Set<string>();
    for (const f of data.findings)
      for (const p of f.dependency_paths) for (let i = 0; i + 1 < p.length; i++) s.add(`${p[i]}>${p[i + 1]}`);
    return s;
  }, [data.findings]);
  const focusEdges = useMemo(() => {
    const s = new Set<string>();
    const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;
    if (f) for (const p of f.dependency_paths) for (let i = 0; i + 1 < p.length; i++) s.add(`${p[i]}>${p[i + 1]}`);
    return s;
  }, [selectedFindingId, findingsById]);

  const base = useMemo<GNode[]>(
    () =>
      vis.nodes.map((n) => {
        const k = n.data.kind;
        return {
          id: n.id,
          type: k === "project" || k === "package" || k === "tray" ? k : "pseudo",
          position: { x: n.x, y: n.y },
          data: n.data,
          width: n.w,
          height: n.h,
          draggable: false,
          connectable: false,
          selectable: k !== "tray",
        } as GNode;
      }),
    [vis],
  );

  const nodes = useMemo<GNode[]>(
    () =>
      base.map((n) => {
        const dim = focusIds && !focusIds.has(n.id);
        const cls = [dim ? "is-dim" : "", n.id === selectedNodeId ? "is-sel" : ""].filter(Boolean).join(" ");
        return cls === (n.className ?? "") ? n : { ...n, className: cls };
      }),
    [base, focusIds, selectedNodeId],
  );

  const edges = useMemo<Edge[]>(
    () =>
      vis.edges.map((e) => {
        const risk = riskEdges.has(e.id);
        const onFocus = focusEdges.has(e.id);
        const dim = focusIds && !(focusIds.has(e.source) && focusIds.has(e.target));
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          pathOptions: { borderRadius: 8 },
          selectable: false,
          focusable: false,
          className: [risk ? "e-risk" : "e-base", onFocus ? "e-focus" : "", dim ? "e-dim" : ""].filter(Boolean).join(" "),
        } as Edge;
      }),
    [vis.edges, riskEdges, focusEdges, focusIds],
  );

  // zoom to the selected node
  useEffect(() => {
    if (!selectedNodeId || !vis.nodes.some((n) => n.id === selectedNodeId)) return;
    const t = window.setTimeout(
      () => void rf.fitView({ nodes: [{ id: selectedNodeId }], duration: 220, maxZoom: 1.15, padding: 1.4 }),
      30,
    );
    return () => window.clearTimeout(t);
  }, [selectedNodeId, rf, vis.nodes]);

  const fitOpts = useMemo(
    () => ({
      padding: 0.1,
      maxZoom: 0.9,
      nodes: vis.nodes.filter((n) => !n.data.plain && n.data.kind !== "tray").map((n) => ({ id: n.id })),
    }),
    [vis.nodes],
  );

  useEffect(() => {
    const t = window.setTimeout(() => void rf.fitView({ ...fitOpts, duration: 220 }), 60);
    return () => window.clearTimeout(t);
  }, [fitOpts, rf]);

  const onNodeClick: NodeMouseHandler = (_, node) => {
    if (node.type !== "tray") openNode(node.id);
  };

  return (
    <div className="graph" aria-label="Dependency graph">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        fitView
        fitViewOptions={fitOpts}
        minZoom={0.04}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable
        edgesFocusable={false}
        onlyRenderVisibleElements
        colorMode="dark"
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="rgba(255,255,255,0.09)" />
        <MiniMap
          pannable
          zoomable
          position="bottom-left"
          nodeStrokeWidth={0}
          nodeColor={(n) => {
            const d = n.data as GNode["data"];
            if (d.kind === "tray") return "#27272a";
            if (d.findings > 0) return RISK_COLOR[d.risk ?? "low"];
            return d.kind === "project" ? "#a1a1aa" : "#3f3f46";
          }}
          maskColor="rgba(9,9,11,0.72)"
        />
        <Panel position="top-left" className="gpanel">
          <label className="switch">
            <input type="checkbox" checked={onlyRisk} onChange={(e) => setOnlyRisk(e.target.checked)} />
            <span className="switch-track" aria-hidden />
            <span>Risk Paths Only</span>
          </label>
          <span className="gstat mono">
            {vis.visiblePackages.toLocaleString()} of {vis.totalPackages.toLocaleString()} packages
          </span>
          <button type="button" className="btn ghost icon" aria-label="Fit graph to view" onClick={() => void rf.fitView({ ...fitOpts, duration: 220 })}>
            <Maximize2 size={15} aria-hidden />
          </button>
        </Panel>
        <Panel position="bottom-right" className="glegend">
          <span><i className="lg lg-edge" aria-hidden /> vulnerable path</span>
          <span><i className="lg lg-crit" aria-hidden /> critical</span>
          <span><i className="lg lg-high" aria-hidden /> high</span>
          <span><i className="lg lg-med" aria-hidden /> medium</span>
        </Panel>
      </ReactFlow>
    </div>
  );
}
