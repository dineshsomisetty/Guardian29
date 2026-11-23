import type {
  AgentEvent, Approval, Evidence, Finding, GraphData, RemediationPlan, ReportJson, RiskAssessment,
  RunData, RunListItem, RunSummary, SourceKind, ValidationResult,
} from "./types";

export const API_BASE = ((import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000").replace(/\/$/, "");
export const RUNS_BASE = ((import.meta.env.VITE_RUNS_BASE as string | undefined) ?? "http://localhost:8001").replace(/\/$/, "");
const SAMPLE = "/sample-run";

// ---------------------------------------------------------------- auth (token lives in sessionStorage only)

const TOKEN_KEY = "guardian.token";
export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
export function setToken(t: string | null) {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the token is kept for this page load only */
    memToken = t;
  }
}
let memToken: string | null = null;
const token = () => getToken() ?? memToken;

/** fetch that adds the bearer token when one is set (and only then, to avoid needless CORS preflights). */
function afetch(url: string, init: RequestInit = {}): Promise<Response> {
  const t = token();
  if (!t || !url.startsWith(API_BASE)) return fetch(url, init);
  return fetch(url, { ...init, headers: { ...(init.headers as Record<string, string> | undefined), Authorization: `Bearer ${t}` } });
}

export interface Me {
  name: string;
  role: "viewer" | "operator" | "approver";
  mode: "token" | "local-dev";
  can_start_runs: boolean;
  can_decide: boolean;
}
export const LOCAL_ME: Me = { name: "Local dev", role: "approver", mode: "local-dev", can_start_runs: true, can_decide: true };

export async function getMe(): Promise<Me> {
  try {
    const r = await afetch(`${API_BASE}/auth/me`, { cache: "no-store" });
    if (r.status === 401) throw new Error("401 sign-in required");
    if (r.ok) return (await r.json()) as Me;
  } catch (e) {
    if (String((e as Error).message).startsWith("401")) throw e;
  }
  return LOCAL_ME;
}

export interface Src {
  kind: SourceKind;
  runId: string;
}

async function timedFetch(url: string, init?: RequestInit, ms = 2000): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await afetch(url, { cache: "no-store", ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function getJson<T>(url: string): Promise<T> {
  const r = await afetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return (await r.json()) as T;
}

async function optJson<T>(url: string, fallback: T): Promise<T> {
  try {
    const r = await afetch(url, { cache: "no-store" });
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

/** Where an exported report lives. The API is the only place checked when it is the data source. */
export function reportCandidates(src: Src, kind: "json" | "html"): string[] {
  return [reportUrl(src, kind)];
}

export async function firstAvailable(urls: string[]): Promise<string | null> {
  for (const u of urls) {
    try {
      const ctl = new AbortController();
      const r = await afetch(u, { cache: "no-store", signal: ctl.signal });
      ctl.abort();
      if (r.ok) return u;
    } catch {
      /* try next */
    }
  }
  return null;
}

export function traceFallbackUrl(src: Src): string | null {
  return src.kind === "api" ? null : `${root(src)}/trace.jsonl`;
}

export function eventsUrl(src: Src): string {
  const t = token();
  return `${API_BASE}/runs/${src.runId}/events${t ? `?access_token=${encodeURIComponent(t)}` : ""}`;
}

// ---------------------------------------------------------------- source + run list

export async function detectSource(): Promise<SourceKind> {
  if (new URLSearchParams(window.location.search).get("source") === "sample") return "sample";
  try {
    const r = await timedFetch(`${API_BASE}/runs`);
    if (r.ok || r.status === 401) return "api";
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
    const r = await afetch(url, { cache: "no-store" });
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
  const [graph, dyn] = await Promise.all([
    getJson<GraphData>(resUrl(src, "graph")).catch(() => ({ nodes: [], edges: [], roots: [] }) as GraphData),
    loadDynamic(src),
  ]);
  return { runId: dyn.summary.run_id ?? src.runId, graph, changes: null, ...dyn };
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
  const u = traceFallbackUrl(src);
  return u ? jsonLines<AgentEvent>(u) : [];
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
    const r = await afetch(`${API_BASE}/runs/${src.runId}/plans/${planId}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) return { ok: true, message: "Decision recorded." };
    let detail = "";
    try {
      const j = (await r.json()) as { detail?: unknown };
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail ?? j);
    } catch {
      /* keep status */
    }
    const friendly =
      r.status === 401
        ? "Your sign-in has expired or is not valid. Sign in again and retry."
        : r.status === 403
          ? "Your role cannot do this. Only approvers can decide on a fix."
          : r.status === 429
            ? "Guardian is busy with other runs right now. Wait a moment and try again."
            : r.status === 409
        ? "This run is not waiting for a decision any more. It may already have been answered."
        : r.status === 400
          ? "Guardian rejected the decision because it does not match the plan that is waiting. Reload the page and try again."
          : "Guardian could not record the decision.";
    return { ok: false, message: `${friendly}${detail ? ` (${detail})` : ""}` };
  } catch {
    return { ok: false, message: "Could not reach the Guardian API. Check that it is running and try again." };
  }
}
