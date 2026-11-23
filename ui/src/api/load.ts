import type { AgentEvent, Changes, Evidence, Finding, GraphData, RunData, RunSummary } from "./types";

// `make serve-runs` (§4.2). Falls back to the bundled sample run so the UI works with no server.
const SERVER = (import.meta.env.VITE_RUNS_BASE as string | undefined) ?? "http://localhost:8001";
const SAMPLE = "/sample-run";

async function json<T>(url: string): Promise<T> {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return (await r.json()) as T;
}

async function text(url: string): Promise<string> {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.text();
}

export function runBaseFromLocation(): string {
  const run = new URLSearchParams(window.location.search).get("run");
  return `${SERVER}/${run ?? "latest"}`;
}

async function loadFrom(base: string): Promise<RunData> {
  const [summary, graph, findings, traceText] = await Promise.all([
    json<RunSummary>(`${base}/run_summary.json`),
    json<GraphData>(`${base}/graph.json`),
    json<Finding[]>(`${base}/findings.json`),
    text(`${base}/trace.jsonl`),
  ]);
  const changes = await json<Changes>(`${base}/changes.json`).catch(() => null);
  const trace = traceText
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as AgentEvent);
  return { base, summary, graph, findings, changes, trace };
}

export async function loadRun(): Promise<RunData & { source: "server" | "sample" }> {
  try {
    return { ...(await loadFrom(runBaseFromLocation())), source: "server" };
  } catch {
    return { ...(await loadFrom(SAMPLE)), source: "sample" };
  }
}

const evidenceCache = new Map<string, Promise<Evidence | null>>();

export function loadEvidence(base: string, id: string): Promise<Evidence | null> {
  const key = `${base}|${id}`;
  if (!evidenceCache.has(key)) {
    evidenceCache.set(key, json<Evidence>(`${base}/evidence/${id}.json`).catch(() => null));
  }
  return evidenceCache.get(key)!;
}
