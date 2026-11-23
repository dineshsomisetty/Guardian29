import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import type { Finding, GraphNode, RunData } from "./api/types";

export type Section = "graph" | "exhibits" | "changes" | "custody";

interface Selection {
  run: RunData;
  findingsById: Map<string, Finding>;
  nodesById: Map<string, GraphNode>;
  /** finding shown on the exhibit sheet */
  selectedFindingId: string | null;
  selectFinding: (id: string | null) => void;
  /** graph node in focus (package or pseudo-node) */
  selectedNodeId: string | null;
  selectNode: (id: string | null) => void;
  /** node ids on the highlighted path (selected finding's first dependency path, or path to selected node) */
  pathIds: Set<string>;
  section: Section;
  setSection: (s: Section) => void;
}

const Ctx = createContext<Selection | null>(null);

export const RISK_ORDER = ["critical", "high", "medium", "low"] as const;
const rank = (r: string | null) => (r ? RISK_ORDER.indexOf(r as (typeof RISK_ORDER)[number]) : 9);

export function sortFindings(fs: Finding[]): Finding[] {
  return [...fs].sort((a, b) => rank(a.initial_risk) - rank(b.initial_risk) || (b.cvss ?? 0) - (a.cvss ?? 0));
}

export function pseudoNodeFor(f: Finding, nodes: Map<string, GraphNode>): string | null {
  for (const n of nodes.values()) if (n.finding_ids?.includes(f.finding_id)) return n.id;
  return null;
}

export function SelectionProvider({ run, children }: { run: RunData; children: ReactNode }) {
  const findingsById = useMemo(() => new Map(run.findings.map((f) => [f.finding_id, f])), [run]);
  const nodesById = useMemo(() => new Map(run.graph.nodes.map((n) => [n.id, n])), [run]);
  const first = useMemo(() => sortFindings(run.findings).find((f) => f.dependency_paths.length > 0), [run]);
  const [selectedFindingId, setFinding] = useState<string | null>(first?.finding_id ?? null);
  const [selectedNodeId, setNode] = useState<string | null>(first?.component_purl ?? null);
  // deep link: ?section=graph|exhibits|changes|custody (used for screenshots and to share a view)
  const [section, setSectionState] = useState<Section>(() => {
    const s = new URLSearchParams(window.location.search).get("section");
    return (["graph", "exhibits", "changes", "custody"] as string[]).includes(s ?? "") ? (s as Section) : "graph";
  });
  const setSection = (s: Section) => {
    setSectionState(s);
    const u = new URL(window.location.href);
    u.searchParams.set("section", s);
    window.history.replaceState(null, "", u);
  };

  const pathIds = useMemo(() => {
    const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;
    if (f?.dependency_paths.length) return new Set(f.dependency_paths.flat());
    if (f) {
      const p = pseudoNodeFor(f, nodesById);
      const root = f.project && nodesById.has(f.project) ? f.project : run.graph.roots[0];
      return new Set([root, p].filter(Boolean) as string[]);
    }
    return new Set<string>(selectedNodeId ? [selectedNodeId] : []);
  }, [selectedFindingId, selectedNodeId, findingsById, nodesById, run]);

  const value: Selection = {
    run,
    findingsById,
    nodesById,
    selectedFindingId,
    selectFinding: (id) => {
      setFinding(id);
      const f = id ? findingsById.get(id) : undefined;
      if (f) setNode(f.component_purl && nodesById.has(f.component_purl) ? f.component_purl : pseudoNodeFor(f, nodesById));
    },
    selectedNodeId,
    selectNode: (id) => {
      setNode(id);
      const n = id ? nodesById.get(id) : undefined;
      const fid = n?.finding_ids?.length
        ? sortFindings(n.finding_ids.map((x) => findingsById.get(x)!).filter(Boolean))[0]?.finding_id
        : null;
      if (fid) setFinding(fid);
    },
    pathIds,
    section,
    setSection,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSel(): Selection {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSel outside SelectionProvider");
  return v;
}
