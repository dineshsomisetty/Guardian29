import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background, BackgroundVariant, MiniMap, Panel, ReactFlow, ReactFlowProvider, useReactFlow, useStore as useRFStore,
  type Edge, type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CheckCheck, ChevronDown, ChevronRight, ChevronUp, CircleHelp, FlaskConical, ListChecks, LocateFixed, Maximize2, Minus, PanelLeftClose, PanelLeftOpen, Plus, Search, X } from "lucide-react";
import type { Risk } from "../api/types";
import { RISK_LABEL, bandOf, riskRank } from "../lib/format";
import { plainTitle } from "../lib/labels";
import { buildVisible } from "../lib/layout";
import { useStore } from "../store";
import { typingTarget, useStoredState } from "./hooks";
import { nodeTypes, type GNode } from "./graphNodes";
import { EmptyState, Tip } from "./ui";

const RISK_COLOR: Record<string, string> = { critical: "#ef4444", high: "#f59e0b", medium: "#3b82f6", low: "#71717a" };
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 1.75;
const READABLE_ZOOM = 0.7;
const ANIM = 220;

type Level = "all" | "high" | "critical";
const LEVELS: { id: Level; label: string; tip: string }[] = [
  { id: "all", label: "All", tip: "Draw the route to every finding" },
  { id: "high", label: "High and up", tip: "Only draw routes to High and Critical findings" },
  { id: "critical", label: "Critical", tip: "Only draw routes to Critical findings" },
];
const passes = (b: Risk | null, level: Level) => level === "all" || (b != null && riskRank(b) <= (level === "critical" ? 0 : 1));

export interface NodeRisk {
  band: Risk;
  score: number | null;
  count: number;
}

export default function GraphView() {
  const { data, riskById } = useStore();
  const hasFindings = data.findings.length > 0;
  const [onlyRisk, setOnlyRisk] = useState(hasFindings);
  const [level, setLevel] = useStoredState<Level>("guardian.map.level", "all");
  const shown = useMemo(() => data.findings.filter((f) => passes(bandOf(f, riskById), level)), [data.findings, riskById, level]);
  const allowed = useMemo(() => (level === "all" ? null : new Set(shown.map((f) => f.finding_id))), [level, shown]);
  const vis = useMemo(() => buildVisible(data.graph, shown, onlyRisk, allowed), [data.graph, shown, onlyRisk, allowed]);
  if (data.graph.nodes.length === 0)
    return (
      <EmptyState title="No dependency map was recorded" center>
        Guardian did not produce a map of the dependencies for this scan, so there is nothing to draw yet.
      </EmptyState>
    );
  return (
    <ReactFlowProvider>
      <Canvas vis={vis} onlyRisk={onlyRisk} setOnlyRisk={setOnlyRisk} level={level} setLevel={setLevel} shown={shown} />
    </ReactFlowProvider>
  );
}

function Canvas({
  vis, onlyRisk, setOnlyRisk, level, setLevel, shown,
}: {
  vis: ReturnType<typeof buildVisible>;
  onlyRisk: boolean;
  setOnlyRisk: (b: boolean) => void;
  level: Level;
  setLevel: (l: Level) => void;
  shown: ReturnType<typeof useStore>["data"]["findings"];
}) {
  const { data, findingsById, riskById, order, selectedFindingId, selectedNodeId, focusIds, openNode, graphTarget, clearGraphTarget } = useStore();
  const rf = useReactFlow();
  const [hover, setHover] = useState<string | null>(null);
  const [pinned, setPinned] = useState<string | null>(null);
  const [listOpen, setListOpen] = useStoredState<"open" | "closed">("guardian.map.list", "open");
  const hoverRaf = useRef(0);
  const visIds = useMemo(() => new Map(vis.nodes.map((n) => [n.id, n])), [vis.nodes]);

  // ---------------------------------------------------------------- Guardian's level and top score per node
  const nodeRisk = useMemo(() => {
    const m = new Map<string, NodeRisk>();
    for (const n of data.graph.nodes) {
      let band: Risk | null = null;
      let score: number | null = null;
      let count = 0;
      for (const id of n.finding_ids ?? []) {
        const f = findingsById.get(id);
        if (!f) continue;
        count++;
        const b = bandOf(f, riskById);
        const s = riskById.get(id)?.score ?? null;
        if (b && (!band || riskRank(b) < riskRank(band))) band = b;
        if (s != null && (score == null || s > score)) score = s;
      }
      if (count && band) m.set(n.id, { band, score, count });
    }
    return m;
  }, [data.graph.nodes, findingsById, riskById]);

  const allowedIds = useMemo(() => new Set(shown.map((f) => f.finding_id)), [shown]);
  /** what the "N of M drawn" count is made of, said in words */
  const countWhy = useMemo(() => {
    const byId = new Map(data.graph.nodes.map((n) => [n.id, n]));
    let withF = 0;
    let route = 0;
    let plain = 0;
    for (const n of vis.nodes) {
      if (n.data.kind !== "package") continue;
      if ((byId.get(n.id)?.finding_ids ?? []).some((id) => allowedIds.has(id))) withF++;
      else if (n.data.plain) plain++;
      else route++;
    }
    const hidden = vis.totalPackages - vis.visiblePackages;
    return [
      `${withF} package${withF === 1 ? " has" : "s have"} a finding${level === "all" ? "" : " at this level"}.`,
      route ? `${route} more sit on a route between your project and one of them.` : "",
      plain ? `${plain} are direct dependencies with no findings, grouped below the map.` : "",
      `The other ${hidden.toLocaleString()} have no findings and are not on any route, so they are hidden.`,
      onlyRisk ? 'Turning off "Routes only" also draws every direct dependency.' : 'Turn on "Routes only" to hide direct dependencies that have no findings.',
    ].filter(Boolean).join(" ");
  }, [vis, data.graph.nodes, allowedIds, level, onlyRisk]);

  // ---------------------------------------------------------------- derived edge sets
  /** each link on a route, coloured by the worst finding reached through it */
  const edgeBand = useMemo(() => {
    const m = new Map<string, Risk>();
    for (const f of shown) {
      const b = bandOf(f, riskById) ?? "low";
      for (const p of f.dependency_paths)
        for (let i = 0; i + 1 < p.length; i++) {
          const id = `${p[i]}>${p[i + 1]}`;
          const cur = m.get(id);
          if (!cur || riskRank(b) < riskRank(cur)) m.set(id, b);
        }
    }
    return m;
  }, [shown, riskById]);

  const parents = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of vis.edges) (m.get(e.target) ?? m.set(e.target, []).get(e.target)!).push(e.source);
    return m;
  }, [vis.edges]);

  /** a package plus every package above it, up to the project: all the ways it gets in */
  const upstream = useCallback(
    (start: string | null) => {
      if (!start) return null;
      const seen = new Set<string>([start]);
      const stack = [start];
      while (stack.length) {
        const id = stack.pop()!;
        for (const p of parents.get(id) ?? []) if (!seen.has(p)) (seen.add(p), stack.push(p));
      }
      return seen;
    },
    [parents],
  );
  const hoverSet = useMemo(() => upstream(hover), [hover, upstream]);
  const pinSet = useMemo(() => upstream(pinned), [pinned, upstream]);

  const focusEdges = useMemo(() => {
    const s = new Set<string>();
    const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;
    if (f) for (const p of f.dependency_paths) for (let i = 0; i + 1 < p.length; i++) s.add(`${p[i]}>${p[i + 1]}`);
    return s;
  }, [selectedFindingId, findingsById]);

  const trace = hoverSet ?? pinSet;
  const active = trace ?? focusIds;

  const base = useMemo<GNode[]>(
    () =>
      vis.nodes.map((n) => {
        const k = n.data.kind;
        const r = nodeRisk.get(n.id);
        return {
          id: n.id,
          type: k === "project" || k === "package" || k === "tray" ? k : "pseudo",
          position: { x: n.x, y: n.y },
          data: { ...n.data, risk: r?.band ?? null, score: r?.score ?? null, findings: r?.count ?? 0 },
          width: n.w,
          height: n.h,
          draggable: false,
          connectable: false,
          selectable: k !== "tray",
        } as GNode;
      }),
    [vis, nodeRisk],
  );

  const nodes = useMemo<GNode[]>(
    () =>
      base.map((n) => {
        const dim = active && !active.has(n.id);
        const sel = n.id === selectedNodeId || n.id === pinned;
        const cls = [dim ? "is-dim" : "", sel ? "is-sel" : "", n.id === hover ? "is-hover" : ""].filter(Boolean).join(" ");
        return cls === (n.className ?? "") ? n : { ...n, className: cls };
      }),
    [base, active, selectedNodeId, pinned, hover],
  );

  const edges = useMemo<Edge[]>(
    () =>
      vis.edges.map((e) => {
        const band = edgeBand.get(e.id);
        const lit = trace ? trace.has(e.source) && trace.has(e.target) : focusEdges.has(e.id);
        const dim = active && !(active.has(e.source) && active.has(e.target));
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          pathOptions: { borderRadius: 10 },
          selectable: false,
          focusable: false,
          className: [band ? `e-risk e-${band}` : "e-base", lit ? "e-focus" : "", dim ? "e-dim" : ""].filter(Boolean).join(" "),
        } as Edge;
      }),
    [vis.edges, edgeBand, focusEdges, trace, active],
  );

  // ---------------------------------------------------------------- ranked list: the way into the map
  const ranked = useMemo(() => {
    const out: { id: string; label: string; version?: string; risk: NodeRisk; drawn: boolean }[] = [];
    for (const n of data.graph.nodes) {
      const r = nodeRisk.get(n.id);
      if (!r || !passes(r.band, level) || n.kind === "project") continue;
      out.push({ id: n.id, label: n.label, version: n.version, risk: r, drawn: visIds.has(n.id) });
    }
    return out.sort((a, b) => riskRank(a.risk.band) - riskRank(b.risk.band) || (b.risk.score ?? 0) - (a.risk.score ?? 0) || b.risk.count - a.risk.count);
  }, [data.graph.nodes, nodeRisk, level, visIds]);

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
    () => (bounds ? [[bounds.x0 - 800, bounds.y0 - 400], [bounds.x1 + 600, bounds.y1 + 400]] : undefined),
    [bounds],
  );
  const pad = useMemo(() => ({ ...FIT_PAD, left: (listOpen === "open" ? "380px" : FIT_PAD.left) as `${number}px` }), [listOpen]);

  /** The riskiest path: where the first look should land. */
  const focusNodes = useMemo(() => {
    if (!onlyRisk) return [];
    const allowedIds = new Set(shown.map((f) => f.finding_id));
    for (const id of order) {
      if (!allowedIds.has(id)) continue;
      const f = findingsById.get(id);
      const p = f?.dependency_paths.find((path) => path.length > 1 && path.every((n) => visIds.has(n)));
      if (p) return p.map((n) => ({ id: n }));
    }
    return [];
  }, [order, findingsById, visIds, onlyRisk, shown]);

  const overviewNodes = useMemo(
    () => vis.nodes.filter((n) => !n.data.plain && n.data.kind !== "tray").map((n) => ({ id: n.id })),
    [vis.nodes],
  );

  const focusRisk = useCallback(
    (duration: number) => {
      if (focusNodes.length)
        void rf.fitView({ nodes: focusNodes, padding: pad, minZoom: READABLE_ZOOM, maxZoom: 1, duration });
      else void rf.fitView({ nodes: overviewNodes, padding: pad, minZoom: MIN_ZOOM, maxZoom: 1, duration });
    },
    [rf, focusNodes, overviewNodes, pad],
  );
  const fitAll = useCallback(
    () => void rf.fitView({ nodes: overviewNodes, padding: pad, minZoom: MIN_ZOOM, maxZoom: 1, duration: ANIM }),
    [rf, overviewNodes, pad],
  );

  // first look, and again whenever the set of drawn nodes changes (filters toggled)
  const firstDraw = useRef(true);
  useEffect(() => {
    const t = window.setTimeout(() => {
      focusRisk(firstDraw.current ? 0 : ANIM);
      firstDraw.current = false;
    }, 60);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vis]);

  const centerOn = useCallback(
    (id: string, zoom = 1) => {
      const n = visIds.get(id);
      if (!n) return false;
      // keep the package clear of the list on the left
      const shift = listOpen === "open" ? 160 / zoom : 0;
      void rf.setCenter(n.x + n.w / 2 - shift, n.y + n.h / 2, { zoom, duration: ANIM });
      return true;
    },
    [rf, visIds, listOpen],
  );

  // a package picked in search, the list, or "Show in map" from the inspector, possibly not drawn yet
  const [pending, setPending] = useState<string | null>(null);
  const goTo = useCallback(
    (id: string) => {
      setPinned(id);
      if (visIds.has(id)) {
        centerOn(id, 1);
        return;
      }
      if (onlyRisk || level !== "all") {
        setPending(id);
        setOnlyRisk(false);
        setLevel("all");
      } else openNode(id);
    },
    [visIds, centerOn, onlyRisk, level, setOnlyRisk, setLevel, openNode],
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
  useEffect(() => {
    if (pinned && !data.graph.nodes.some((n) => n.id === pinned)) setPinned(null);
  }, [pinned, data.graph.nodes]);

  // keyboard: zoom, fit, and Escape to let go of a traced package
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typingTarget(e.target)) return;
      if (e.key === "+" || e.key === "=") void rf.zoomIn({ duration: ANIM });
      else if (e.key === "-" || e.key === "_") void rf.zoomOut({ duration: ANIM });
      else if (e.key === "0") fitAll();
      else if (e.key === "Escape" && pinned && !document.querySelector(".insp.open")) setPinned(null);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [rf, fitAll, pinned]);

  const onNodeClick: NodeMouseHandler = (_, node) => {
    if (node.type === "tray") return;
    setPinned(node.id);
    openNode(node.id);
  };
  const onNodeDoubleClick: NodeMouseHandler = (_, node) => {
    if (node.type !== "tray") centerOn(node.id, 1.3);
  };
  const setHoverSoon = (id: string | null) => {
    cancelAnimationFrame(hoverRaf.current);
    hoverRaf.current = requestAnimationFrame(() => setHover(id));
  };

  const pinnedRisk = pinned ? nodeRisk.get(pinned) : undefined;
  const pinnedNode = pinned ? data.graph.nodes.find((n) => n.id === pinned) : undefined;

  return (
    <div className={`graph${listOpen === "open" ? " with-list" : ""}`} aria-label="Dependency map">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onNodeDoubleClick={onNodeDoubleClick}
        onNodeMouseEnter={(_, n) => n.type !== "tray" && setHoverSoon(n.id)}
        onNodeMouseLeave={() => setHoverSoon(null)}
        onPaneClick={() => setPinned(null)}
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
        <Background variant={BackgroundVariant.Dots} gap={24} size={1.2} color="rgba(255,255,255,0.07)" />
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
          <Tip text={listOpen === "open" ? "Hide the list of risky packages" : "Show the list of risky packages"} side="bottom">
            <button
              type="button"
              className="gbtn"
              aria-label={listOpen === "open" ? "Hide risky packages list" : "Show risky packages list"}
              aria-pressed={listOpen === "open"}
              onClick={() => setListOpen(listOpen === "open" ? "closed" : "open")}
            >
              {listOpen === "open" ? <PanelLeftClose size={16} aria-hidden /> : <PanelLeftOpen size={16} aria-hidden />}
            </button>
          </Tip>
          <GraphSearch onPick={goTo} />
          <div className="seg-tabs gseg" role="group" aria-label="Which risk levels to draw">
            {LEVELS.map((l) => (
              <Tip key={l.id} text={l.tip} side="bottom">
                <button type="button" className={level === l.id ? "on" : ""} aria-pressed={level === l.id} onClick={() => setLevel(l.id)}>
                  {l.label}
                </button>
              </Tip>
            ))}
          </div>
          <Tip text="On: draw only packages that have a finding or lead to one, so the map stays readable. Off: also draw every package your project depends on directly, even with no findings. Nothing about the findings changes, only what is drawn." side="bottom">
            <label className="switch">
              <input type="checkbox" checked={onlyRisk} onChange={(e) => setOnlyRisk(e.target.checked)} />
              <span className="switch-track" aria-hidden />
              <span>Routes only</span>
            </label>
          </Tip>
          <Tip text={countWhy} side="bottom">
            <span className="gstat num" tabIndex={0}>
              {vis.visiblePackages.toLocaleString()} of {vis.totalPackages.toLocaleString()} packages drawn <CircleHelp size={13} aria-hidden className="faint" />
            </span>
          </Tip>
          <Legend />
        </Panel>

        {pinned && pinnedNode && (
          <Panel position="bottom-center" className="gtrace">
            <span>
              Tracing <b>{pinnedNode.label}</b>
              {pinnedNode.version ? <span className="mono faint"> {pinnedNode.version}</span> : null}
              {pinnedRisk ? <span className="faint"> · every route from your project is lit</span> : null}
            </span>
            <button type="button" className="btn ghost sm" onClick={() => openNode(pinned)}>
              Details
            </button>
            <Tip text="Stop tracing (Esc)" side="bottom">
              <button type="button" className="btn ghost icon sm" aria-label="Stop tracing" onClick={() => setPinned(null)}>
                <X size={14} aria-hidden />
              </button>
            </Tip>
          </Panel>
        )}

        <Panel position="bottom-left" className="gctl">
          <Tip text="Zoom in (+)" side="right"><button type="button" className="gbtn" aria-label="Zoom in" onClick={() => void rf.zoomIn({ duration: ANIM })}><Plus size={16} aria-hidden /></button></Tip>
          <ZoomReadout />
          <Tip text="Zoom out (-)" side="right"><button type="button" className="gbtn" aria-label="Zoom out" onClick={() => void rf.zoomOut({ duration: ANIM })}><Minus size={16} aria-hidden /></button></Tip>
          <span className="gsep" aria-hidden />
          <Tip text="Fit the whole map (0)" side="right"><button type="button" className="gbtn" aria-label="Fit the whole map" onClick={fitAll}><Maximize2 size={16} aria-hidden /></button></Tip>
          <Tip text="Back to the riskiest route" side="right"><button type="button" className="gbtn" aria-label="Back to the riskiest route" onClick={() => focusRisk(ANIM)}><LocateFixed size={16} aria-hidden /></button></Tip>
        </Panel>
      </ReactFlow>

      {listOpen === "open" && (
        <RiskList items={ranked} pinned={pinned} level={level} onPick={goTo} onHover={setHoverSoon} />
      )}
    </div>
  );
}

function RiskList({
  items, pinned, level, onPick, onHover,
}: {
  items: { id: string; label: string; version?: string; risk: NodeRisk; drawn: boolean }[];
  pinned: string | null;
  level: Level;
  onPick: (id: string) => void;
  onHover: (id: string | null) => void;
}) {
  const ref = useRef<HTMLOListElement>(null);
  useEffect(() => {
    if (pinned) ref.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(pinned)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [pinned]);
  return (
    <aside className="glist" aria-label="Risky packages">
      <header className="glist-head">
        <h2>Riskiest packages</h2>
        <p className="faint">
          {items.length} {level === "all" ? "with findings" : level === "high" ? "at High or Critical" : "at Critical"}, worst first. Select one to trace how it gets in.
        </p>
      </header>
      {items.length === 0 ? (
        <p className="glist-empty muted">No package has a finding at this level.</p>
      ) : (
        <ol className="glist-items" ref={ref}>
          {items.map((it) => (
            <li key={it.id}>
              <button
                type="button"
                data-id={it.id}
                className={`glist-item${pinned === it.id ? " on" : ""}`}
                aria-current={pinned === it.id ? "true" : undefined}
                onClick={() => onPick(it.id)}
                onMouseEnter={() => it.drawn && onHover(it.id)}
                onMouseLeave={() => onHover(null)}
              >
                <span className={`glist-score num t-${it.risk.band}`}>{it.risk.score != null ? it.risk.score.toFixed(0) : "–"}</span>
                <span className="glist-text">
                  <span className="glist-name">
                    {it.label}
                    {it.version ? <span className="mono faint"> {it.version}</span> : null}
                  </span>
                  <span className="glist-meta">
                    <span className={`t-${it.risk.band}`}>{RISK_LABEL[it.risk.band]}</span>
                    <span className="faint"> · {it.risk.count} finding{it.risk.count === 1 ? "" : "s"}</span>
                    {!it.drawn && <span className="faint"> · not drawn yet</span>}
                  </span>
                </span>
              </button>
              {pinned === it.id && <PackageDetail id={it.id} label={it.label} />}
            </li>
          ))}
        </ol>
      )}
    </aside>
  );
}

/** A selected package, inline in the list: its findings with their scores, and the way on to every other page. */
function PackageDetail({ id, label }: { id: string; label: string }) {
  const { data, nodesById, findingsById, riskById, openFinding, setView, setFindingFilter } = useStore();
  const fs = (nodesById.get(id)?.finding_ids ?? [])
    .map((x) => findingsById.get(x))
    .filter((f): f is NonNullable<typeof f> => !!f)
    .sort((a, b) => (riskById.get(b.finding_id)?.score ?? 0) - (riskById.get(a.finding_id)?.score ?? 0));
  const ids = new Set(fs.map((f) => f.finding_id));
  const plans = data.plans.filter((p) => ids.has(p.finding_id));
  const validated = data.validation.some((v) => ids.has(v.finding_id));
  const shown = fs.slice(0, 6);
  return (
    <div className="glist-detail">
      <ul className="plain">
        {shown.map((f) => {
          const r = riskById.get(f.finding_id);
          const b = bandOf(f, riskById);
          return (
            <li key={f.finding_id}>
              <button type="button" className="glist-finding" onClick={() => openFinding(f.finding_id)}>
                <span className={`num t-${b ?? "low"}`}>{r ? r.score.toFixed(0) : "–"}</span>
                <span>{f.vuln_id ?? plainTitle(f, b)}</span>
                <ChevronRight size={14} aria-hidden className="faint" />
              </button>
            </li>
          );
        })}
      </ul>
      {fs.length > shown.length && <p className="faint glist-more">and {fs.length - shown.length} more</p>}
      <p className="faint glist-hint">Select a finding for its full risk assessment: the score, each factor and the evidence.</p>
      <div className="glist-actions">
        <button
          type="button"
          className="btn sm"
          onClick={() => {
            setFindingFilter({ risk: null, cat: null, q: label });
            setView("findings");
          }}
        >
          <ListChecks size={14} aria-hidden /> All in Findings
        </button>
        {plans.length > 0 && (
          <button type="button" className="btn sm" onClick={() => setView("gate")}>
            <CheckCheck size={14} aria-hidden /> Proposed fix
          </button>
        )}
        {validated && (
          <button type="button" className="btn sm" onClick={() => setView("validation")}>
            <FlaskConical size={14} aria-hidden /> Validation
          </button>
        )}
      </div>
      {plans.length === 0 && <p className="faint glist-hint">No fix has been proposed for this package yet.</p>}
    </div>
  );
}

function ZoomReadout() {
  const z = useRFStore((s) => s.transform[2]);
  return <span className="gzoom num" aria-live="off">{Math.round(z * 100)}%</span>;
}

// keep fitted nodes clear of the toolbar on top and the controls at the bottom
const FIT_PAD = { top: "84px", right: "48px", bottom: "48px", left: "72px" } as const;

function Legend() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const off = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", off);
    window.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", off);
      window.removeEventListener("keydown", esc);
    };
  }, [open]);
  return (
    <div className="glegend" ref={box}>
      <button type="button" className="btn ghost sm" aria-expanded={open} onClick={() => setOpen(!open)}>
        <CircleHelp size={14} aria-hidden /> How to read {open ? <ChevronUp size={14} aria-hidden /> : <ChevronDown size={14} aria-hidden />}
      </button>
      {open && (
        <div className="glegend-pop" role="dialog" aria-label="How to read this map">
          <p className="faint">Your project is on the left. Each line is "depends on", so a route runs left to right from your code to the package with the problem.</p>
          <ul>
            <li><i className="lg lg-edge e-critical" aria-hidden /><i className="lg lg-edge e-high" aria-hidden />Route colour: the worst finding reached through that link</li>
            <li><i className="lg lg-chip num" aria-hidden>High 72</i>The package's risk level and its highest score (0 to 100)</li>
            <li><i className="lg lg-more num" aria-hidden>+4</i>Its own dependencies that are not drawn, to keep the map readable</li>
            <li><i className="lg lg-dev" aria-hidden />Dashed tag: only used while developing</li>
          </ul>
          <p className="faint">Hover a package to light up every way it gets in. Select it to keep the routes lit and open its findings. Scroll to move; Ctrl + scroll or pinch to zoom.</p>
        </div>
      )}
    </div>
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
                {r.findings > 0 && <span className="pill">{r.findings} finding{r.findings === 1 ? "" : "s"}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
