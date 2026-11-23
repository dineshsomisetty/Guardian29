import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background, BackgroundVariant, MiniMap, Panel, ReactFlow, ReactFlowProvider, useReactFlow, useStore as useRFStore,
  type Edge, type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ChevronDown, ChevronUp, LocateFixed, Maximize2, Minus, Plus, Search, X } from "lucide-react";
import { buildVisible } from "../lib/layout";
import { useStore } from "../store";
import { typingTarget } from "./hooks";
import { nodeTypes, type GNode } from "./graphNodes";
import { EmptyState, Tip } from "./ui";

const RISK_COLOR: Record<string, string> = { critical: "#ef4444", high: "#f59e0b", medium: "#3b82f6", low: "#52525b" };
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 1.75;
const READABLE_ZOOM = 0.7;
const ANIM = 220;

export default function GraphView() {
  const { data } = useStore();
  const hasFindings = data.findings.length > 0;
  const [onlyRisk, setOnlyRisk] = useState(hasFindings);
  const vis = useMemo(() => buildVisible(data.graph, data.findings, onlyRisk), [data.graph, data.findings, onlyRisk]);
  if (data.graph.nodes.length === 0)
    return (
      <EmptyState title="No dependency map was recorded" center>
        Guardian did not produce a map of the dependencies for this scan, so there is nothing to draw yet.
      </EmptyState>
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
  const { data, findingsById, order, selectedFindingId, selectedNodeId, focusIds, openNode, graphTarget, clearGraphTarget } = useStore();
  const rf = useReactFlow();
  const [hover, setHover] = useState<string | null>(null);
  const hoverRaf = useRef(0);
  const visIds = useMemo(() => new Map(vis.nodes.map((n) => [n.id, n])), [vis.nodes]);

  // ---------------------------------------------------------------- derived edge sets
  const riskEdges = useMemo(() => {
    const s = new Set<string>();
    for (const f of data.findings)
      for (const p of f.dependency_paths) for (let i = 0; i + 1 < p.length; i++) s.add(`${p[i]}>${p[i + 1]}`);
    return s;
  }, [data.findings]);

  const parents = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of vis.edges) (m.get(e.target) ?? m.set(e.target, []).get(e.target)!).push(e.source);
    return m;
  }, [vis.edges]);

  // hovering a package lights up every way it is reached from a root, and dims the rest
  const hoverSet = useMemo(() => {
    if (!hover) return null;
    const seen = new Set<string>([hover]);
    const stack = [hover];
    while (stack.length) {
      const id = stack.pop()!;
      for (const p of parents.get(id) ?? []) if (!seen.has(p)) (seen.add(p), stack.push(p));
    }
    return seen;
  }, [hover, parents]);

  const focusEdges = useMemo(() => {
    const s = new Set<string>();
    const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;
    if (f) for (const p of f.dependency_paths) for (let i = 0; i + 1 < p.length; i++) s.add(`${p[i]}>${p[i + 1]}`);
    return s;
  }, [selectedFindingId, findingsById]);

  const active = hoverSet ?? focusIds;

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
        const dim = active && !active.has(n.id);
        const cls = [dim ? "is-dim" : "", n.id === selectedNodeId ? "is-sel" : "", n.id === hover ? "is-hover" : ""].filter(Boolean).join(" ");
        return cls === (n.className ?? "") ? n : { ...n, className: cls };
      }),
    [base, active, selectedNodeId, hover],
  );

  const edges = useMemo<Edge[]>(
    () =>
      vis.edges.map((e) => {
        const risk = riskEdges.has(e.id);
        const lit = hoverSet ? hoverSet.has(e.source) && hoverSet.has(e.target) : focusEdges.has(e.id);
        const dim = active && !(active.has(e.source) && active.has(e.target));
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          pathOptions: { borderRadius: 10 },
          selectable: false,
          focusable: false,
          className: [risk ? "e-risk" : "e-base", lit ? "e-focus" : "", dim ? "e-dim" : ""].filter(Boolean).join(" "),
        } as Edge;
      }),
    [vis.edges, riskEdges, focusEdges, hoverSet, active],
  );

  // ---------------------------------------------------------------- viewport
  const bounds = useMemo(() => {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of vis.nodes) {
      x0 = Math.min(x0, n.x);
      y0 = Math.min(y0, n.y);
      x1 = Math.max(x1, n.x + n.w);
      y1 = Math.max(y1, n.y + n.h);
    }
    return Number.isFinite(x0) ? { x0, y0, x1, y1 } : null;
  }, [vis.nodes]);
  const extent = useMemo<[[number, number], [number, number]] | undefined>(
    () => (bounds ? [[bounds.x0 - 600, bounds.y0 - 400], [bounds.x1 + 600, bounds.y1 + 400]] : undefined),
    [bounds],
  );

  /** The riskiest path: where the first look should land. */
  const focusNodes = useMemo(() => {
    if (!onlyRisk) return [];
    for (const id of order) {
      const f = findingsById.get(id);
      const p = f?.dependency_paths.find((path) => path.length > 1 && path.every((n) => visIds.has(n)));
      if (p) return p.map((n) => ({ id: n }));
    }
    return [];
  }, [order, findingsById, visIds, onlyRisk]);

  const overviewNodes = useMemo(
    () => vis.nodes.filter((n) => !n.data.plain && n.data.kind !== "tray").map((n) => ({ id: n.id })),
    [vis.nodes],
  );

  const focusRisk = useCallback(
    (duration: number) => {
      if (focusNodes.length)
        void rf.fitView({ nodes: focusNodes, padding: FIT_PAD, minZoom: READABLE_ZOOM, maxZoom: 1, duration });
      else void rf.fitView({ nodes: overviewNodes, padding: FIT_PAD, minZoom: MIN_ZOOM, maxZoom: 1, duration });
    },
    [rf, focusNodes, overviewNodes],
  );
  const fitAll = useCallback(
    () => void rf.fitView({ nodes: overviewNodes, padding: FIT_PAD, minZoom: MIN_ZOOM, maxZoom: 1, duration: ANIM }),
    [rf, overviewNodes],
  );

  // first look, and again whenever the set of drawn nodes changes (Risk paths only toggled)
  const firstDraw = useRef(true);
  useEffect(() => {
    const t = window.setTimeout(() => {
      focusRisk(firstDraw.current ? 0 : ANIM);
      firstDraw.current = false;
    }, 60);
    return () => window.clearTimeout(t);
  }, [vis, focusRisk]);

  const centerOn = useCallback(
    (id: string, zoom = 1) => {
      const n = visIds.get(id);
      if (!n) return false;
      void rf.setCenter(n.x + n.w / 2, n.y + n.h / 2, { zoom, duration: ANIM });
      return true;
    },
    [rf, visIds],
  );

  // a package picked in search or "Show in map" from the inspector, possibly not drawn yet
  const [pending, setPending] = useState<string | null>(null);
  const goTo = useCallback(
    (id: string) => {
      if (visIds.has(id)) {
        centerOn(id, 1);
        return;
      }
      if (onlyRisk) {
        setPending(id);
        setOnlyRisk(false);
      } else openNode(id);
    },
    [visIds, centerOn, onlyRisk, setOnlyRisk, openNode],
  );
  useEffect(() => {
    if (!pending || !visIds.has(pending)) return;
    const t = window.setTimeout(() => {
      centerOn(pending, 1);
      setPending(null);
    }, 120);
    return () => window.clearTimeout(t);
  }, [pending, visIds, centerOn]);
  useEffect(() => {
    if (!graphTarget) return;
    const id = graphTarget;
    clearGraphTarget();
    const t = window.setTimeout(() => goTo(id), 120);
    return () => window.clearTimeout(t);
  }, [graphTarget, clearGraphTarget, goTo]);

  // keyboard zoom
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typingTarget(e.target)) return;
      if (e.key === "+" || e.key === "=") void rf.zoomIn({ duration: ANIM });
      else if (e.key === "-" || e.key === "_") void rf.zoomOut({ duration: ANIM });
      else if (e.key === "0") fitAll();
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [rf, fitAll]);

  const onNodeClick: NodeMouseHandler = (_, node) => {
    if (node.type !== "tray") openNode(node.id);
  };
  const onNodeDoubleClick: NodeMouseHandler = (_, node) => {
    if (node.type !== "tray") centerOn(node.id, 1.3);
  };
  const setHoverSoon = (id: string | null) => {
    cancelAnimationFrame(hoverRaf.current);
    hoverRaf.current = requestAnimationFrame(() => setHover(id));
  };

  return (
    <div className="graph" aria-label="Dependency map">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onNodeDoubleClick={onNodeDoubleClick}
        onNodeMouseEnter={(_, n) => n.type !== "tray" && setHoverSoon(n.id)}
        onNodeMouseLeave={() => setHoverSoon(null)}
        minZoom={MIN_ZOOM}
        maxZoom={MAX_ZOOM}
        translateExtent={extent}
        panOnScroll
        zoomOnScroll={false}
        zoomOnPinch
        zoomOnDoubleClick={false}
        panOnDrag
        preventScrolling
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable
        edgesFocusable={false}
        elementsSelectable
        onlyRenderVisibleElements
        attributionPosition="bottom-right"
        colorMode="dark"
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1.2} color="rgba(255,255,255,0.08)" />
        <MiniMap
          pannable
          zoomable
          position="bottom-right"
          style={{ width: 168, height: 112 }}
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
          <GraphSearch onPick={goTo} />
          <Tip text="Show only the packages that lead to a finding, plus your direct dependencies in a compact group. Turn off to draw every direct dependency." side="bottom">
            <label className="switch">
              <input type="checkbox" checked={onlyRisk} onChange={(e) => setOnlyRisk(e.target.checked)} />
              <span className="switch-track" aria-hidden />
              <span>Risk paths only</span>
            </label>
          </Tip>
          <span className="gstat">
            {vis.visiblePackages.toLocaleString()} of {vis.totalPackages.toLocaleString()} packages drawn
          </span>
        </Panel>

        <Legend />

        <Panel position="bottom-left" className="gctl">
          <Tip text="Zoom in (+)" side="right"><button type="button" className="gbtn" aria-label="Zoom in" onClick={() => void rf.zoomIn({ duration: ANIM })}><Plus size={16} aria-hidden /></button></Tip>
          <ZoomReadout />
          <Tip text="Zoom out (-)" side="right"><button type="button" className="gbtn" aria-label="Zoom out" onClick={() => void rf.zoomOut({ duration: ANIM })}><Minus size={16} aria-hidden /></button></Tip>
          <span className="gsep" aria-hidden />
          <Tip text="Fit the whole map (0)" side="right"><button type="button" className="gbtn" aria-label="Fit the whole map" onClick={fitAll}><Maximize2 size={16} aria-hidden /></button></Tip>
          <Tip text="Back to the riskiest path" side="right"><button type="button" className="gbtn" aria-label="Back to the riskiest path" onClick={() => focusRisk(ANIM)}><LocateFixed size={16} aria-hidden /></button></Tip>
        </Panel>

        <Panel position="bottom-center" className="ghint">
          Scroll to move around · Ctrl + scroll or pinch to zoom · double-click a package to zoom in
        </Panel>
      </ReactFlow>
    </div>
  );
}

function ZoomReadout() {
  const z = useRFStore((s) => s.transform[2]);
  return <span className="gzoom num" aria-live="off">{Math.round(z * 100)}%</span>;
}

// keep fitted nodes clear of the search/toggle bar on top and the hint line + controls at the bottom
const FIT_PAD = { top: "76px", right: "48px", bottom: "64px", left: "72px" } as const;

function Legend() {
  // collapsed by default so it never covers nodes on first look; a reader who opens it keeps it open
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem("guardian.legend") === "open";
    } catch {
      return false;
    }
  });
  const toggle = () => {
    setOpen(!open);
    try {
      localStorage.setItem("guardian.legend", open ? "closed" : "open");
    } catch {
      /* ignore */
    }
  };
  return (
    <Panel position="top-right" className="glegend">
      <button type="button" className="glegend-head" aria-expanded={open} onClick={toggle}>
        How to read this map {open ? <ChevronUp size={14} aria-hidden /> : <ChevronDown size={14} aria-hidden />}
      </button>
      {open && (
        <ul>
          <li><i className="lg lg-edge" aria-hidden />Dashed red line: the route from your code to a vulnerable package</li>
          <li><i className="lg lg-box r-critical" aria-hidden /><i className="lg lg-box r-high" aria-hidden /><i className="lg lg-box r-medium" aria-hidden />Outline colour: how severe its worst finding is</li>
          <li><i className="lg lg-badge num" aria-hidden>3</i>Number of findings on that package</li>
          <li><i className="lg lg-more num" aria-hidden>+4</i>Direct dependencies not drawn (hidden to keep the map readable)</li>
          <li><i className="lg lg-dev" aria-hidden />Dashed tag: development-only package</li>
        </ul>
      )}
    </Panel>
  );
}

function GraphSearch({ onPick }: { onPick: (id: string) => void }) {
  const { data } = useStore();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (t.length < 2) return [];
    const hits: { id: string; label: string; version?: string; findings: number; rank: number }[] = [];
    for (const n of data.graph.nodes) {
      const l = n.label.toLowerCase();
      const i = l.indexOf(t);
      if (i < 0) continue;
      hits.push({ id: n.id, label: n.label, version: n.version, findings: n.finding_ids?.length ?? 0, rank: (i === 0 ? 0 : 2) - (n.finding_ids?.length ? 1 : 0) });
    }
    return hits.sort((a, b) => a.rank - b.rank || a.label.localeCompare(b.label)).slice(0, 8);
  }, [q, data.graph.nodes]);
  useEffect(() => setCur(0), [q]);
  useEffect(() => {
    const off = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", off);
    return () => document.removeEventListener("mousedown", off);
  }, []);
  const pick = (id: string) => {
    onPick(id);
    setOpen(false);
  };
  return (
    <div className="gsearch" ref={box}>
      <span className="searchbox">
        <Search size={16} aria-hidden />
        <input
          data-search
          type="search"
          placeholder="Find a package"
          aria-label="Find a package in the map"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setCur((c) => Math.min(results.length - 1, c + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setCur((c) => Math.max(0, c - 1));
            } else if (e.key === "Enter" && results[cur]) pick(results[cur].id);
            else if (e.key === "Escape") {
              setOpen(false);
              (e.target as HTMLInputElement).blur();
            }
          }}
        />
        {q && (
          <button type="button" className="sbox-clear" aria-label="Clear search" onClick={() => setQ("")}>
            <X size={14} aria-hidden />
          </button>
        )}
      </span>
      {open && q.trim().length >= 2 && (
        <ul className="gresults" role="listbox">
          {results.length === 0 && <li className="gres-empty">No package matches "{q}".</li>}
          {results.map((r, i) => (
            <li key={r.id} role="option" aria-selected={i === cur}>
              <button type="button" className={i === cur ? "on" : ""} onMouseEnter={() => setCur(i)} onClick={() => pick(r.id)}>
                <span className="gres-name">{r.label}</span>
                <span className="mono faint">{r.version ?? ""}</span>
                {r.findings > 0 && <span className="pill sev-high">{r.findings}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
