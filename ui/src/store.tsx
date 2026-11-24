import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  LOCAL_ME, getMe, getToken, setToken, type Me,
  detectSource, eventsUrl, fetchTrace, initialRunId, listRuns, loadDynamic, loadRun, type Src,
} from "./api/client";
import type {
  AgentEvent, Finding, GraphNode, RemediationPlan, Risk, RiskAssessment, RunData, RunListItem, SourceKind,
} from "./api/types";
import { BootError, BootSkeleton, SignIn } from "./components/Boot";
import { bandOf, isCve, riskRank } from "./lib/format";
import { derivePipeline, type Pipeline } from "./lib/pipeline";

export type View = "overview" | "graph" | "findings" | "gate" | "validation" | "report";
export const VIEWS: View[] = ["overview", "graph", "findings", "gate", "validation", "report"];

export interface FindingFilter {
  risk: Risk | null;
  cat: string | null;
  /** search text to start the Findings page with, e.g. a package name picked in the map */
  q?: string;
}

export type InspectorTarget = { kind: "finding" | "evidence" | "node"; id: string } | null;
export type LiveState = "connecting" | "live" | "poll" | "idle";

interface Store {
  me: Me;
  signOut: () => void;
  kind: SourceKind;
  src: Src;
  runs: RunListItem[];
  switchRun: (id: string) => void;
  data: RunData;
  status: string;
  replay: boolean;
  events: AgentEvent[];
  live: LiveState;
  pipeline: Pipeline;
  refresh: () => Promise<void>;

  view: View;
  setView: (v: View) => void;
  drawerOpen: boolean;
  setDrawerOpen: (b: boolean) => void;
  drawerAgent: string | null;
  setDrawerAgent: (a: string | null) => void;

  findingsById: Map<string, Finding>;
  nodesById: Map<string, GraphNode>;
  riskById: Map<string, RiskAssessment>;
  plansById: Map<string, RemediationPlan>;
  order: string[];
  anomaliesFirst: boolean;
  setAnomaliesFirst: (b: boolean) => void;
  findingFilter: FindingFilter;
  setFindingFilter: (f: Partial<FindingFilter>) => void;
  helpOpen: boolean;
  setHelpOpen: (b: boolean) => void;
  /** Show a finding's risk path in the graph. */
  showInGraph: (nodeId: string) => void;
  graphTarget: string | null;
  clearGraphTarget: () => void;

  selectedFindingId: string | null;
  selectedNodeId: string | null;
  focusIds: Set<string> | null;
  inspector: InspectorTarget;
  openFinding: (id: string) => void;
  openEvidence: (id: string) => void;
  openNode: (id: string) => void;
  selectNodeOnly: (id: string | null) => void;
  closeInspector: () => void;
  stepFinding: (delta: number) => void;
}

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const v = useContext(Ctx);
  if (!v) throw new Error("useStore outside provider");
  return v;
}

function initialView(): View {
  const v = new URLSearchParams(window.location.search).get("view");
  return (VIEWS as string[]).includes(v ?? "") ? (v as View) : "overview";
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

type Boot =
  | { phase: "loading" }
  | { phase: "error"; message: string; kind: SourceKind | null; runs: RunListItem[] }
  | { phase: "signin"; bad: boolean }
  | { phase: "ready"; kind: SourceKind; data: RunData; me: Me };

export function Provider({ children }: { children: ReactNode }) {
  const [boot, setBoot] = useState<Boot>({ phase: "loading" });
  const [runs, setRuns] = useState<RunListItem[]>([]);
  const [runKey, setRunKey] = useState<string | null>(null); // null -> initial
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let dead = false;
    setBoot({ phase: "loading" });
    (async () => {
      let kind: SourceKind | null = null;
      try {
        kind = await detectSource();
        const me = kind === "api" ? await getMe() : LOCAL_ME;
        const id = runKey ?? initialRunId(kind);
        const data = await loadRun({ kind, runId: id });
        if (dead) return;
        setBoot({ phase: "ready", kind, data, me });
        listRuns(kind).then((r) => !dead && setRuns(r)).catch(() => undefined);
      } catch (e) {
        if (dead) return;
        if (String((e as Error).message ?? e).startsWith("401")) {
          setBoot({ phase: "signin", bad: !!getToken() });
          return;
        }
        const found = kind ? await listRuns(kind).catch(() => [] as RunListItem[]) : [];
        setBoot({ phase: "error", message: String((e as Error).message ?? e), kind, runs: found });
      }
    })();
    return () => {
      dead = true;
    };
  }, [runKey, attempt]);

  const switchRun = useCallback((id: string) => {
    const u = new URL(window.location.href);
    u.searchParams.set("run", id);
    window.history.replaceState(null, "", u);
    setRunKey(id);
  }, []);

  if (boot.phase === "loading") return <BootSkeleton />;
  if (boot.phase === "signin")
    return (
      <SignIn
        bad={boot.bad}
        onSubmit={(t) => {
          setToken(t);
          setAttempt((n) => n + 1);
        }}
      />
    );
  if (boot.phase === "error")
    return (
      <BootError
        message={boot.message}
        runs={boot.runs}
        onRetry={() => setAttempt((n) => n + 1)}
        onPick={(id) => switchRun(id)}
      />
    );
  return (
    <Inner key={`${boot.kind}|${boot.data.runId}`} kind={boot.kind} me={boot.me} first={boot.data} runs={runs} switchRun={switchRun}>
      {children}
    </Inner>
  );
}

function Inner({
  kind, me, first, runs, switchRun, children,
}: {
  kind: SourceKind;
  me: Me;
  first: RunData;
  runs: RunListItem[];
  switchRun: (id: string) => void;
  children: ReactNode;
}) {
  const [data, setData] = useState<RunData>(first);
  const src = useMemo<Src>(() => ({ kind, runId: kind === "sample" ? "sample" : first.runId }), [kind, first.runId]);
  const status = data.summary.status;
  const terminal = status === "done" || status === "failed";
  const statusRef = useRef(status);
  statusRef.current = status;

  // ------------------------------------------------ refresh (poll while the run is live)
  const refresh = useCallback(async () => {
    try {
      const dyn = await loadDynamic(src);
      setData((prev) => {
        const next = { ...prev };
        let changed = false;
        for (const k of ["summary", "findings", "risk", "plans", "validation", "approvals"] as const) {
          if (!same(prev[k], dyn[k])) {
            (next as Record<string, unknown>)[k] = dyn[k];
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    } catch {
      /* keep what we have */
    }
  }, [src]);

  useEffect(() => {
    if (kind === "sample" || terminal) return;
    const t = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(t);
  }, [kind, terminal, refresh]);

  // ------------------------------------------------ events: SSE with trace.jsonl fallback
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [live, setLive] = useState<LiveState>("connecting");
  useEffect(() => {
    let closed = false;
    let es: EventSource | null = null;
    let pollT: number | undefined;
    let flushT: number | undefined;
    let count = 0;
    const buf: AgentEvent[] = [];
    setEvents([]);
    setLive("connecting");
    const flush = () => {
      flushT = undefined;
      if (buf.length) {
        const add = buf.splice(0);
        setEvents((p) => p.concat(add));
      }
    };
    const push = (e: AgentEvent) => {
      buf.push(e);
      if (flushT === undefined) flushT = window.setTimeout(flush, 80);
    };
    const poll = async () => {
      const all = await fetchTrace(src);
      if (closed) return;
      setEvents((p) => (p.length === all.length ? p : all));
      setLive(all.length || kind === "sample" ? "poll" : "idle");
      const t = statusRef.current;
      if (t !== "done" && t !== "failed" && kind !== "sample") pollT = window.setTimeout(poll, 2500);
    };
    if (kind === "api") {
      es = new EventSource(eventsUrl(src));
      let opened = false;
      const guard = window.setTimeout(() => {
        if (!opened && es) {
          es.close();
          void poll();
        }
      }, 2500);
      es.onopen = () => {
        opened = true;
        window.clearTimeout(guard);
        setLive("live");
      };
      es.onmessage = (m) => {
        const idx = Number(m.lastEventId);
        if (Number.isFinite(idx) && idx < count) return;
        count = Number.isFinite(idx) ? idx + 1 : count + 1;
        try {
          push(JSON.parse(m.data) as AgentEvent);
        } catch {
          /* ignore a malformed line */
        }
      };
      es.onerror = () => {
        if (!opened) {
          window.clearTimeout(guard);
          es?.close();
          void poll();
          return;
        }
        const t = statusRef.current;
        if (t === "done" || t === "failed") {
          es?.close();
          setLive("idle");
        }
      };
    } else {
      void poll();
    }
    return () => {
      closed = true;
      es?.close();
      window.clearTimeout(pollT);
      window.clearTimeout(flushT);
    };
  }, [src, kind]);

  // after a terminal status arrives over polling, close an open stream's reconnect loop is handled in onerror

  // ------------------------------------------------ derived maps
  const findingsById = useMemo(() => new Map(data.findings.map((f) => [f.finding_id, f])), [data.findings]);
  const nodesById = useMemo(() => new Map(data.graph.nodes.map((n) => [n.id, n])), [data.graph.nodes]);
  const riskById = useMemo(() => new Map(data.risk.map((r) => [r.finding_id, r])), [data.risk]);
  const plansById = useMemo(() => new Map(data.plans.map((p) => [p.plan_id, p])), [data.plans]);
  const pipeline = useMemo(() => derivePipeline(events, status), [events, status]);

  const [anomaliesFirst, setAnomaliesFirst] = useState(false);
  const [findingFilter, setFilterState] = useState<FindingFilter>({ risk: null, cat: null });
  const setFindingFilter = useCallback((f: Partial<FindingFilter>) => setFilterState((p) => ({ ...p, ...f })), []);
  const [helpOpen, setHelpOpen] = useState(false);
  const [graphTarget, setGraphTarget] = useState<string | null>(null);
  const clearGraphTarget = useCallback(() => setGraphTarget(null), []);
  const order = useMemo(() => {
    const score = (f: Finding) => riskById.get(f.finding_id)?.score ?? (f.cvss ?? 0) * 10;
    return [...data.findings]
      .sort(
        (a, b) =>
          (anomaliesFirst ? Number(isCve(a)) - Number(isCve(b)) : 0) ||
          riskRank(bandOf(a, riskById)) - riskRank(bandOf(b, riskById)) ||
          score(b) - score(a) ||
          a.finding_id.localeCompare(b.finding_id),
      )
      .map((f) => f.finding_id);
  }, [data.findings, riskById, anomaliesFirst]);

  // ------------------------------------------------ view + selection
  const [view, setViewState] = useState<View>(initialView);
  const setView = useCallback((v: View) => {
    setViewState(v);
    const u = new URL(window.location.href);
    u.searchParams.set("view", v);
    window.history.replaceState(null, "", u);
  }, []);
  const showInGraph = useCallback(
    (nodeId: string) => {
      setGraphTarget(nodeId);
      setView("graph");
    },
    [setView],
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerAgent, setDrawerAgent] = useState<string | null>(null);
  const [selectedFindingId, setSelF] = useState<string | null>(null);
  const [selectedNodeId, setSelN] = useState<string | null>(null);
  const [inspector, setInspector] = useState<InspectorTarget>(null);

  const nodeOf = useCallback(
    (f: Finding): string | null => {
      if (f.component_purl && nodesById.has(f.component_purl)) return f.component_purl;
      for (const n of nodesById.values()) if (n.finding_ids?.includes(f.finding_id)) return n.id;
      return null;
    },
    [nodesById],
  );

  const openFinding = useCallback(
    (id: string) => {
      const f = findingsById.get(id);
      setSelF(id);
      if (f) setSelN(nodeOf(f));
      setInspector({ kind: "finding", id });
    },
    [findingsById, nodeOf],
  );
  const openEvidence = useCallback((id: string) => setInspector({ kind: "evidence", id }), []);
  const openNode = useCallback(
    (id: string) => {
      setSelN(id);
      const n = nodesById.get(id);
      const fs = (n?.finding_ids ?? []).map((x) => findingsById.get(x)).filter((x): x is Finding => !!x);
      fs.sort((a, b) => riskRank(bandOf(a, riskById)) - riskRank(bandOf(b, riskById)));
      if (fs.length) {
        setSelF(fs[0].finding_id);
        setInspector({ kind: "finding", id: fs[0].finding_id });
      } else {
        setSelF(null);
        setInspector({ kind: "node", id });
      }
    },
    [nodesById, findingsById, riskById],
  );
  const selectNodeOnly = useCallback((id: string | null) => setSelN(id), []);
  const closeInspector = useCallback(() => setInspector(null), []);
  const stepFinding = useCallback(
    (delta: number) => {
      if (!inspector || inspector.kind !== "finding") return;
      const i = order.indexOf(inspector.id);
      const j = Math.min(order.length - 1, Math.max(0, (i < 0 ? 0 : i) + delta));
      if (order[j]) openFinding(order[j]);
    },
    [inspector, order, openFinding],
  );

  const focusIds = useMemo(() => {
    const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;
    if (f && f.dependency_paths.length) return new Set(f.dependency_paths.flat());
    if (selectedNodeId) return new Set([selectedNodeId]);
    return null;
  }, [selectedFindingId, selectedNodeId, findingsById]);

  const signOut = useCallback(() => {
    setToken(null);
    window.location.reload();
  }, []);
  const value: Store = {
    me, signOut, kind, src, runs, switchRun, data, status, replay: data.summary.llm?.mode === "replay", events, live, pipeline,
    refresh, view, setView, drawerOpen, setDrawerOpen, drawerAgent, setDrawerAgent, findingsById, nodesById, riskById, plansById, order,
    anomaliesFirst, setAnomaliesFirst, findingFilter, setFindingFilter, helpOpen, setHelpOpen, showInGraph, graphTarget,
    clearGraphTarget, selectedFindingId, selectedNodeId, focusIds, inspector, openFinding,
    openEvidence, openNode, selectNodeOnly, closeInspector, stepFinding,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
