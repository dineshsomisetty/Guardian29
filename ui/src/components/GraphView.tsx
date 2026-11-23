import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  Controls,
  ReactFlow,
  ReactFlowProvider,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "../styles/graph.css";
import { Container, FileCog, Workflow } from "lucide-react";
import { useSel } from "../state";
import { buildVisible, pathHops, type VisNodeData } from "./graph/layout";
import { nodeTypes, type CustodyNode } from "./graph/nodes";
import { edgeTypes, type CustodyEdgeT } from "./graph/edges";

function useReducedMotion() {
  const q = "(prefers-reduced-motion: reduce)";
  const [reduce, setReduce] = useState(() => typeof window !== "undefined" && window.matchMedia(q).matches);
  useEffect(() => {
    const m = window.matchMedia(q);
    const on = () => setReduce(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return reduce;
}

export default function GraphView() {
  const { run } = useSel();
  const [onlyRisk, setOnlyRisk] = useState(false);
  const vis = useMemo(() => buildVisible(run.graph, run.findings, onlyRisk), [run, onlyRisk]);
  const roots = run.graph.roots;

  return (
    <section className="g-panel" aria-label="Dependency graph">
      <header className="panelhead g-head">
        <div className="g-title">
          <h2>Dependency graph</h2>
          <p className="meta">
            {roots.join(" + ")} · {vis.totalPackages.toLocaleString()} packages · showing{" "}
            {vis.nodes.length.toLocaleString()}{" "}
            {onlyRisk ? "(on a risk path, with findings, CI/image/config)" : "(direct, on a risk path, CI/image/config)"}
          </p>
        </div>
        <Legend />
        <label className="g-toggle">
          <input type="checkbox" checked={onlyRisk} onChange={(e) => setOnlyRisk(e.target.checked)} />
          <span className="g-toggle-box" aria-hidden />
          <span className="g-toggle-text">Show only risk paths</span>
        </label>
      </header>
      {run.graph.nodes.length === 0 ? (
        <div className="g-empty">
          <p className="g-empty-title">No graph recorded</p>
          <p>Discovery did not produce a dependency graph for this run, so there is nothing to trace yet.</p>
        </div>
      ) : (
        <ReactFlowProvider>
          <Canvas vis={vis} drawSalt={onlyRisk ? "r" : "a"} />
        </ReactFlowProvider>
      )}
    </section>
  );
}

function Legend() {
  return (
    <ul className="g-legend" aria-label="Legend">
      {(["critical", "high", "medium", "low"] as const).map((r) => (
        <li key={r}>
          <span className={`g-sw r-${r}`} aria-hidden />
          {r}
        </li>
      ))}
      <li className="g-legend-gap">
        <span className="g-shape g-shape-project" aria-hidden />
        project
      </li>
      <li>
        <span className="g-shape g-shape-pkg" aria-hidden />
        package
      </li>
      <li>
        <span className="g-shape g-shape-dev" aria-hidden />
        dev
      </li>
      <li>
        <Workflow size={13} strokeWidth={1.75} aria-hidden />
        CI
      </li>
      <li>
        <Container size={13} strokeWidth={1.75} aria-hidden />
        image
      </li>
      <li>
        <FileCog size={13} strokeWidth={1.75} aria-hidden />
        config
      </li>
    </ul>
  );
}

function Canvas({ vis, drawSalt }: { vis: ReturnType<typeof buildVisible>; drawSalt: string }) {
  const { run, pathIds, selectedNodeId, selectedFindingId, selectNode } = useSel();
  const reduce = useReducedMotion();
  const rf = useReactFlow();
  const initialized = useNodesInitialized();

  // positions: computed once per visible set
  const base = useMemo<CustodyNode[]>(
    () =>
      vis.nodes.map((n) => {
        const k = n.data.kind;
        const tray = k === "tray";
        return {
          id: n.id,
          type: k === "project" || k === "package" || tray ? k : "pseudo",
          position: { x: n.x, y: n.y },
          data: n.data,
          draggable: false,
          connectable: false,
          selectable: !tray,
          focusable: !tray,
          ariaLabel: tray ? undefined : ariaFor(n.data),
        };
      }),
    [vis],
  );
  const visibleSet = useMemo(() => new Set(vis.nodes.map((n) => n.id)), [vis]);

  const hasPath = pathIds.size > 0;
  const [nodes, setNodes, onNodesChange] = useNodesState<CustodyNode>([]);

  // styles only: keep measured sizes, never re-run layout on selection
  useEffect(() => {
    setNodes((prev) => {
      const prevById = new Map(prev.map((p) => [p.id, p]));
      return base.map((n) => {
        const on = pathIds.has(n.id);
        const cls = [hasPath && !on ? "is-dim" : "", on ? "is-path" : "", n.id === selectedNodeId ? "is-sel" : ""]
          .filter(Boolean)
          .join(" ");
        const old = prevById.get(n.id);
        return { ...n, measured: old?.measured, className: cls };
      });
    });
  }, [base, pathIds, selectedNodeId, hasPath, setNodes]);

  const drawKey = `${selectedFindingId ?? ""}|${selectedNodeId ?? ""}|${drawSalt}`;
  const edges = useMemo<CustodyEdgeT[]>(() => {
    const hops = pathHops(vis.edges, pathIds, run.graph.roots);
    return vis.edges.map((e) => {
      const hop = hops.get(e.id) ?? -1;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "custody",
        zIndex: hop >= 0 ? 2 : 0,
        focusable: false,
        selectable: false,
        data: { hop, drawKey, dim: hasPath && hop < 0, via: e.via },
      };
    });
  }, [vis, pathIds, run.graph.roots, drawKey, hasPath]);

  // pan/zoom to the highlighted path whenever it changes (and on first render)
  const pathKey = useMemo(() => [...pathIds].sort().join("|"), [pathIds]);
  const [ready, setReady] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);
  // real canvas size (not the window): the path is re-centred whenever the canvas is resized
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      setSize((p) => (Math.abs(p.w - r.width) < 1 && Math.abs(p.h - r.height) < 1 ? p : { w: r.width, h: r.height }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    if (!initialized) return;
    const ids = [...pathIds].filter((id) => visibleSet.has(id));
    // first fit is instant (no sweep in from the origin); later ones glide
    const duration = reduce || !ready ? 0 : 600;
    const id = requestAnimationFrame(() => {
      if (ids.length) {
        // centre the highlighted path with even padding on every side (room for the finding chips on the
        // node corners). Zoom fits the path, capped at 1.4; floor 0.8 so text stays legible when a path is
        // physically wider than the canvas (the 3-node default path fits at ~0.95 at 1440x900)
        const rect = canvasRef.current?.getBoundingClientRect();
        const w = rect?.width ?? 0;
        const h = rect?.height ?? 0;
        const b = rf.getNodesBounds(ids);
        const chip = 12;
        const bw = b.width + 2 * chip;
        const bh = b.height + 2 * chip;
        const padX = 40; // clear space beyond the chips, every side
        const padY = 40;
        const fit = w && h ? Math.min((w - 2 * padX) / bw, (h - 2 * padY) / bh) : 1;
        const zoom = Math.min(1.4, Math.max(fit, 0.8));
        const cx = b.x + b.width / 2;
        const cy = b.y + b.height / 2;
        rf.setViewport({ x: w / 2 - cx * zoom, y: h / 2 - cy * zoom, zoom }, { duration });
      }
      else rf.fitView({ duration, padding: 0.05 });
      // QA hook (plan D3-08: real graph renders < 2 s): ms since navigation start, read via performance.getEntriesByName
      if (!performance.getEntriesByName("guardian:graph-ready").length) performance.mark("guardian:graph-ready");
      setReady(true);
    });
    return () => cancelAnimationFrame(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialized, pathKey, visibleSet, size]);

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const el = (e.target as HTMLElement).closest?.(".react-flow__node");
      const id = el?.getAttribute("data-id");
      if (id && !id.startsWith("tray:")) {
        e.preventDefault();
        selectNode(id);
      }
    },
    [selectNode],
  );

  return (
    <div ref={canvasRef} className={`g-canvas${reduce ? " no-motion" : ""}${ready ? " is-ready" : ""}`} onKeyDown={onKeyDown}>
      <ReactFlow<CustodyNode, CustodyEdgeT>
        proOptions={{ hideAttribution: true }}
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={(_, n) => {
          if (n.type !== "tray") selectNode(n.id);
        }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        minZoom={0.05}
        maxZoom={2}
        onlyRenderVisibleElements={false}
        zoomOnDoubleClick={false}
      >
        <Controls showInteractive={false} position="top-left" />
      </ReactFlow>
    </div>
  );
}

function ariaFor(d: VisNodeData) {
  const kind = d.kind === "project" ? "Project" : d.kind === "package" ? "Package" : d.kind.toUpperCase();
  const parts = [`${kind} ${d.label}${d.version ? ` ${d.version}` : ""}`];
  if (d.direct) parts.push("direct dependency");
  if (d.dev) parts.push("dev scope");
  if (d.findings) parts.push(`${d.findings} finding${d.findings === 1 ? "" : "s"}, ${d.risk ?? "low"} risk`);
  if (d.hidden) parts.push(`${d.hidden} collapsed dependencies`);
  return parts.join(", ");
}
