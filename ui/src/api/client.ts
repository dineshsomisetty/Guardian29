import type {
  AgentEvent, Approval, Changes, Evidence, Finding, GraphData, RemediationPlan, ReportJson, RiskAssessment,
  RunData, RunListItem, RunSummary, SourceKind, ValidationResult,
} from "./types";

export const API_BASE = ((import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000").replace(/\/$/, "");
export const RUNS_BASE = ((import.meta.env.VITE_RUNS_BASE as string | undefined) ?? "http://localhost:8001").replace(/\/$/, "");
const SAMPLE = "/sample-run";

export interface Src {
  kind: SourceKind;
  runId: string;
}

async function timedFetch(url: string, init?: RequestInit, ms = 2000): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { cache: "no-store", ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return (await r.json()) as T;
}

async function optJson<T>(url: string, fallback: T): Promise<T> {
  try {
    const r = await fetch(url, { cache: "no-store" });
    return r.ok ? ((await r.json()) as T) : fallback;
  } catch {
    return fallback;
  }
}

/** Where a run's files live for this source. */
function root(src: Src): string {
  if (src.kind === "api") return `${API_BASE}/runs/${src.runId}`;
  if (src.kind === "static") return `${RUNS_BASE}/${src.runId}`;
  return SAMPLE;
}

const ROUTE = {
  summary: ["summary", "run_summary.json"],
  graph: ["graph", "graph.json"],
  findings: ["findings", "findings.json"],
  changes: ["changes", "changes.json"],
  risk: ["risk", "risk.json"],
} as const;

export function resUrl(src: Src, res: keyof typeof ROUTE): string {
  return `${root(src)}/${src.kind === "api" ? ROUTE[res][0] : ROUTE[res][1]}`;
}

export function reportUrl(src: Src, kind: "json" | "html"): string {
  return `${root(src)}/report.${kind}`;
}

/** Candidate locations for an exported report, API first, then the static run server. */
export function reportCandidates(src: Src, kind: "json" | "html"): string[] {
  if (src.kind === "api") return [reportUrl(src, kind), `${RUNS_BASE}/${src.runId}/report.${kind}`];
  return [reportUrl(src, kind)];
}

export async function firstAvailable(urls: string[]): Promise<string | null> {
  for (const u of urls) {
    try {
      const ctl = new AbortController();
      const r = await fetch(u, { cache: "no-store", signal: ctl.signal });
      ctl.abort();
      if (r.ok) return u;
    } catch {
      /* try next */
    }
  }
  return null;
}

export function traceFallbackUrl(src: Src): string {
  return src.kind === "api" ? `${RUNS_BASE}/${src.runId}/trace.jsonl` : `${root(src)}/trace.jsonl`;
}

export function eventsUrl(src: Src): string {
  return `${API_BASE}/runs/${src.runId}/events`;
}

// ---------------------------------------------------------------- source + run list

export async function detectSource(): Promise<SourceKind> {
  if (new URLSearchParams(window.location.search).get("source") === "sample") return "sample";
  try {
    const r = await timedFetch(`${API_BASE}/runs`);
    if (r.ok) return "api";
  } catch {
    /* fall through */
  }
  try {
    const r = await timedFetch(`${RUNS_BASE}/index.json`);
    if (r.ok) return "static";
  } catch {
    /* fall through */
  }
  return "sample";
}

function itemOf(id: string, s: Partial<RunSummary> | null | undefined): RunListItem {
  return {
    id,
    target: s?.target ?? id,
    status: s?.status ?? "running",
    mode: s?.llm?.mode ?? null,
    commit: s?.commit ?? null,
  };
}

export async function listRuns(kind: SourceKind): Promise<RunListItem[]> {
  if (kind === "sample") {
    const s = await optJson<RunSummary | null>(`${SAMPLE}/run_summary.json`, null);
    return [itemOf("sample", s)];
  }
  let ids: string[];
  if (kind === "api") ids = await optJson<string[]>(`${API_BASE}/runs`, []);
  else ids = (await optJson<{ runs: string[] }>(`${RUNS_BASE}/index.json`, { runs: [] })).runs;
  ids = ids.slice(0, 14);
  return Promise.all(
    ids.map(async (id) => {
      const s = await optJson<RunSummary | null>(resUrl({ kind, runId: id }, "summary"), null);
      return itemOf(id, s);
    }),
  );
}

export function initialRunId(kind: SourceKind): string {
  if (kind === "sample") return "sample";
  return new URLSearchParams(window.location.search).get("run") ?? "latest";
}

// ---------------------------------------------------------------- run bundle

async function jsonLines<T>(url: string): Promise<T[]> {
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) return [];
    return (await r.text())
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as T);
  } catch {
    return [];
  }
}

type Dynamic = Pick<RunData, "summary" | "findings" | "risk" | "plans" | "validation" | "approvals">;

/** Mutable, cheap-to-refresh part of a run. */
export async function loadDynamic(src: Src): Promise<Dynamic> {
  const [summary, findings, risk] = await Promise.all([
    getJson<RunSummary>(resUrl(src, "summary")),
    getJson<Finding[]>(resUrl(src, "findings")).catch(() => [] as Finding[]),
    optJson<RiskAssessment[]>(resUrl(src, "risk"), []),
  ]);
  let plans: RemediationPlan[];
  let validation: ValidationResult[];
  let approvals: Approval[];
  if (src.kind === "api") {
    [plans, validation, approvals] = await Promise.all([
      optJson<RemediationPlan[]>(`${root(src)}/plans`, []),
      optJson<ValidationResult[]>(`${root(src)}/validation`, []),
      optJson<Approval[]>(`${root(src)}/approvals`, []),
    ]);
  } else {
    // static servers cannot list directories: plan and attempt ids come from the run summary
    const planIds = new Set<string>();
    const attemptIds = new Set<string>();
    for (const r of summary.remediation ?? [])
      for (const a of r.attempts) {
        planIds.add(a.plan_id);
        if (a.attempt_id) attemptIds.add(a.attempt_id);
      }
    if (summary.pending_plan) planIds.add(summary.pending_plan.plan_id);
    const base = root(src);
    [plans, validation, approvals] = await Promise.all([
      Promise.all([...planIds].map((id) => optJson<RemediationPlan | null>(`${base}/plans/${id}.json`, null))).then(
        (a) => a.filter((x): x is RemediationPlan => !!x),
      ),
      Promise.all(
        [...attemptIds].map((id) => optJson<ValidationResult | null>(`${base}/validation/${id}.json`, null)),
      ).then((a) => a.filter((x): x is ValidationResult => !!x)),
      planIds.size ? jsonLines<Approval>(`${base}/approvals.jsonl`) : Promise.resolve([] as Approval[]),
    ]);
  }
  plans.sort((a, b) => a.attempt - b.attempt);
  return { summary, findings, risk, plans, validation, approvals };
}

export async function loadRun(src: Src): Promise<RunData> {
  const [graph, changes, dyn] = await Promise.all([
    getJson<GraphData>(resUrl(src, "graph")).catch(() => ({ nodes: [], edges: [], roots: [] }) as GraphData),
    optJson<Changes | null>(resUrl(src, "changes"), null),
    loadDynamic(src),
  ]);
  return { runId: dyn.summary.run_id ?? src.runId, graph, changes, ...dyn };
}

export async function loadReport(src: Src): Promise<ReportJson | null> {
  return optJson<ReportJson | null>(reportUrl(src, "json"), null);
}

// ---------------------------------------------------------------- evidence

const evCache = new Map<string, Promise<Evidence | null>>();

export function loadEvidence(src: Src, id: string): Promise<Evidence | null> {
  const key = `${src.kind}|${src.runId}|${id}`;
  let p = evCache.get(key);
  if (!p) {
    const url = src.kind === "api" ? `${root(src)}/evidence/${id}` : `${root(src)}/evidence/${id}.json`;
    p = optJson<Evidence | null>(url, null);
    evCache.set(key, p);
  }
  return p;
}

export async function fetchTrace(src: Src): Promise<AgentEvent[]> {
  return jsonLines<AgentEvent>(traceFallbackUrl(src));
}

// ---------------------------------------------------------------- decision

export interface DecisionResult {
  ok: boolean;
  message: string;
}

export async function postDecision(
  src: Src,
  planId: string,
  body: { plan_hash: string; decision: string; comment: string | null; decided_by: string },
): Promise<DecisionResult> {
  try {
    const r = await fetch(`${API_BASE}/runs/${src.runId}/plans/${planId}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) return { ok: true, message: "Decision recorded. The run is resuming." };
    let detail = `${r.status}`;
    try {
      const j = (await r.json()) as { detail?: unknown };
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail ?? j);
    } catch {
      /* keep status */
    }
    return { ok: false, message: `${r.status}: ${detail}` };
  } catch (e) {
    return { ok: false, message: `Could not reach the API (${(e as Error).message}).` };
  }
}
