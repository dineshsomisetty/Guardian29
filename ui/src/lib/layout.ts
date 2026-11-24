// Collapse rule (plan §4.3) + dagre layout for the dependency graph.
import dagre from "@dagrejs/dagre";
import type { Finding, GraphData, GraphNode, NodeKind, Risk } from "../api/types";

export interface VisNodeData {
  /** "tray" = caption over the grid of plain direct dependencies of one root */
  kind: NodeKind | "tray";
  label: string;
  version?: string;
  direct: boolean;
  dev: boolean;
  risk: Risk | null;
  findings: number;
  /** hidden direct children (collapsed) */
  hidden: number;
  /** package count for a project root */
  packages: number;
  /** plain direct dependency shown in a tray */
  plain?: boolean;
  [key: string]: unknown;
}

export interface VisNode {
  id: string;
  data: VisNodeData;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface VisEdge {
  id: string;
  source: string;
  target: string;
}

export interface VisibleGraph {
  nodes: VisNode[];
  edges: VisEdge[];
  totalPackages: number;
  visiblePackages: number;
}

export const SIZE: Record<NodeKind, { w: number; h: number }> = {
  project: { w: 168, h: 76 },
  package: { w: 240, h: 66 },
  ci: { w: 240, h: 52 },
  image: { w: 240, h: 52 },
  config: { w: 240, h: 52 },
};

const isPseudo = (k: NodeKind) => k === "ci" || k === "image" || k === "config";

/** Which node ids survive the collapse rule. */
export function visibleIds(graph: GraphData, findings: Finding[], onlyRisk: boolean, allowed: Set<string> | null = null): Set<string> {
  const roots = new Set(graph.roots);
  const counts = (n: GraphNode) => (n.finding_ids ?? []).some((id) => !allowed || allowed.has(id));
  const onPath = new Set<string>();
  for (const f of findings) for (const p of f.dependency_paths) for (const id of p) onPath.add(id);

  const directOf = new Set<string>();
  for (const e of graph.edges) if (roots.has(e.source)) directOf.add(e.target);

  const keep = new Set<string>();
  for (const n of graph.nodes) {
    const hasFindings = counts(n);
    if (n.kind === "project" || roots.has(n.id)) keep.add(n.id);
    else if (isPseudo(n.kind)) {
      // a level filter hides CI/image/config items whose findings are all below it
      if (!allowed || hasFindings || !(n.finding_ids?.length)) keep.add(n.id);
    }
    else if (onPath.has(n.id) || hasFindings) keep.add(n.id);
    else if (!onlyRisk && (n.direct || directOf.has(n.id))) keep.add(n.id);
  }
  return keep;
}

/**
 * `findings` are the findings whose routes are drawn; pass `allowed` (their ids) when they are a filtered subset,
 * so packages whose findings are all filtered out drop back to plain dependencies.
 */
export function buildVisible(graph: GraphData, findings: Finding[], onlyRisk: boolean, allowed: Set<string> | null = null): VisibleGraph {
  const keep = visibleIds(graph, findings, onlyRisk, allowed);
  const counts = (n: GraphNode) => (n.finding_ids ?? []).some((id) => !allowed || allowed.has(id));
  const byId = new Map<string, GraphNode>(graph.nodes.map((n) => [n.id, n]));
  const roots = new Set(graph.roots);

  // hidden direct children per visible node
  const hiddenKids = new Map<string, Set<string>>();
  const edges: VisEdge[] = [];
  const seen = new Set<string>();
  for (const e of graph.edges) {
    if (!keep.has(e.source)) continue;
    if (keep.has(e.target)) {
      const id = `${e.source}>${e.target}`;
      if (seen.has(id) || e.source === e.target) continue;
      seen.add(id);
      edges.push({ id, source: e.source, target: e.target });
    } else if (byId.has(e.target)) {
      let s = hiddenKids.get(e.source);
      if (!s) hiddenKids.set(e.source, (s = new Set()));
      s.add(e.target);
    }
  }

  const pkgCount = new Map<string, number>();
  let totalPackages = 0;
  for (const n of graph.nodes) {
    if (n.kind !== "package") continue;
    totalPackages++;
    const ps = n.projects?.length ? n.projects : n.project ? [n.project] : [];
    for (const p of ps) pkgCount.set(p, (pkgCount.get(p) ?? 0) + 1);
  }

  // "Plain" direct deps: no findings, not on a path, nothing visible below them, only reached from a root.
  // They go into a per-root tray under the evidence cluster instead of a 150-row dagre column,
  // which keeps every risk path compact enough to read at a useful zoom.
  const onPath = new Set<string>();
  for (const f of findings) for (const p of f.dependency_paths) for (const id of p) onPath.add(id);
  const parents = new Map<string, string[]>();
  for (const e of edges) (parents.get(e.target) ?? parents.set(e.target, []).get(e.target)!).push(e.source);
  // evidence = findings, risk paths, pseudo-nodes; structural = evidence + everything above it
  const structural = new Set<string>();
  const stack: string[] = [];
  for (const id of keep) {
    const n = byId.get(id);
    if (!n) continue;
    if (roots.has(id) || n.kind !== "package" || onPath.has(id) || counts(n)) stack.push(id);
  }
  while (stack.length) {
    const id = stack.pop()!;
    if (structural.has(id)) continue;
    structural.add(id);
    for (const p of parents.get(id) ?? []) if (!structural.has(p)) stack.push(p);
  }
  const trayOf = new Map<string, string>();
  for (const id of keep) {
    if (structural.has(id)) continue;
    const rootParent = (parents.get(id) ?? []).find((p) => roots.has(p));
    if (rootParent) trayOf.set(id, rootParent);
    else structural.add(id); // unreachable from a root: keep it in the layout rather than lose it
  }
  const dagEdges: VisEdge[] = edges
    .filter((e) => structural.has(e.source) && structural.has(e.target))
    .map((e) => ({ ...e }));

  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 20, ranksep: 44, marginx: 24, marginy: 24, ranker: "network-simplex" });
  g.setDefaultEdgeLabel(() => ({}));

  const out: VisNode[] = [];
  const tray: VisNode[] = [];
  let visiblePackages = 0;
  // roots first so dagre keeps them in declared order
  const ordered = [...keep].sort((a, b) => Number(roots.has(b)) - Number(roots.has(a)));
  for (const id of ordered) {
    const n = byId.get(id);
    if (!n) continue;
    const kind: NodeKind = roots.has(id) ? "project" : n.kind;
    if (kind === "package") visiblePackages++;
    const { w, h } = SIZE[kind];
    (trayOf.has(id) ? tray : out).push({
      id,
      x: 0,
      y: 0,
      w,
      h,
      data: {
        kind,
        label: n.label,
        version: n.version,
        direct: !!n.direct,
        dev: n.scope === "dev",
        risk: n.risk ?? null,
        findings: n.finding_ids?.length ?? 0,
        hidden: hiddenKids.get(id)?.size ?? 0,
        packages: pkgCount.get(id) ?? 0,
        plain: trayOf.has(id),
      },
    });
  }
  for (const n of out) g.setNode(n.id, { width: n.w, height: n.h });
  for (const e of dagEdges) g.setEdge(e.source, e.target);
  dagre.layout(g);
  let bottom = 0;
  for (const n of out) {
    const p = g.node(n.id);
    n.x = p.x - n.w / 2;
    n.y = p.y - n.h / 2;
    bottom = Math.max(bottom, n.y + n.h);
  }
  // Pull each root level with the middle of its risk-bearing direct children (edges are orthogonal,
  // so this only shortens the trunk); keeps root -> first hop short for every highlighted path.
  const pos = new Map(out.map((n) => [n.id, n]));
  for (const r of out) {
    if (!roots.has(r.id)) continue;
    const ys = dagEdges
      .filter((e) => e.source === r.id)
      .map((e) => pos.get(e.target))
      .filter((c): c is VisNode => !!c && (c.data.findings > 0 || onPath.has(c.id)))
      .map((c) => c.y + c.h / 2)
      .sort((a, b) => a - b);
    if (ys.length) r.y = ys[Math.floor(ys.length / 2)] - r.h / 2;
  }
  const rs = out.filter((n) => roots.has(n.id)).sort((a, b) => a.y - b.y);
  for (let i = 1; i < rs.length; i++) rs[i].y = Math.max(rs[i].y, rs[i - 1].y + rs[i - 1].h + 32);

  // trays: a captioned grid of plain direct deps per root, one hairline edge root -> tray caption
  const rootNodes = out.filter((n) => roots.has(n.id));
  const colX = rootNodes.length ? Math.max(...rootNodes.map((r) => r.x + r.w)) + 80 : 24;
  const cols = 4;
  const gap = 12;
  const pw = SIZE.package.w;
  const ph = SIZE.package.h;
  let y = bottom + 72;
  const trayEdges: VisEdge[] = [];
  for (const r of graph.roots) {
    const members = tray
      .filter((n) => trayOf.get(n.id) === r)
      .sort((a, b) => a.data.label.localeCompare(b.data.label));
    if (!members.length) continue;
    const id = `tray:${r}`;
    const w = cols * pw + (cols - 1) * gap;
    out.push({
      id,
      x: colX,
      y,
      w,
      h: TRAY_H,
      data: {
        kind: "tray",
        label: r,
        direct: false,
        dev: false,
        risk: null,
        findings: 0,
        hidden: 0,
        packages: members.length,
      },
    });
    trayEdges.push({ id: `${r}>${id}`, source: r, target: id });
    y += TRAY_H + gap;
    members.forEach((m, i) => {
      m.x = colX + (i % cols) * (pw + gap);
      m.y = y + Math.floor(i / cols) * (ph + gap);
      out.push(m);
    });
    y += Math.ceil(members.length / cols) * (ph + gap) + 48;
  }
  return { nodes: out, edges: [...dagEdges, ...trayEdges], totalPackages, visiblePackages };
}

export const TRAY_H = 38;
