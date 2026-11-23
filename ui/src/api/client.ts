import type {
  AgentEvent,
  Changes,
  Evidence,
  Finding,
  GraphData,
  ReportAvailability,
  RemediationPlan,
  RunSummary,
  ValidationResult,
} from "./types";

const API_BASE = (import.meta.env.VITE_GUARDIAN_API_BASE || "http://127.0.0.1:8000").replace(/\/+$/, "");

export interface RunData {
  summary: RunSummary;
  graph: GraphData;
  findings: Finding[];
  changes: Changes;
  plans: RemediationPlan[];
  validation: ValidationResult[];
  report: ReportAvailability;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch (error) {
    throw new Error(`Guardian API is unavailable at ${API_BASE}: ${String(error)}`);
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json() as { detail?: string };
      detail = body.detail ?? detail;
    } catch {
      detail = `${detail} ${response.statusText}`.trim();
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export async function fetchRun(runId: string): Promise<RunData> {
  const encodedId = encodeURIComponent(runId);
  const [summary, graph, findings, changes, plans, validation, report] = await Promise.all([
    requestJson<RunSummary>(`/runs/${encodedId}/summary`),
    requestJson<GraphData>(`/runs/${encodedId}/graph`),
    requestJson<Finding[]>(`/runs/${encodedId}/findings`),
    requestJson<Changes>(`/runs/${encodedId}/changes`),
    requestJson<RemediationPlan[]>(`/runs/${encodedId}/plans`),
    requestJson<ValidationResult[]>(`/runs/${encodedId}/validation`),
    requestJson<ReportAvailability>(`/runs/${encodedId}/report`),
  ]);
  return { summary, graph, findings, changes, plans, validation, report };
}

export async function fetchLatestRun(): Promise<RunData> {
  const summary = await requestJson<RunSummary>("/runs/latest");
  return fetchRun(summary.run_id);
}

export function fetchRunHistory(): Promise<RunSummary[]> {
  return requestJson<RunSummary[]>("/runs");
}

export function fetchRunFindings(runId: string): Promise<Finding[]> {
  return requestJson<Finding[]>(`/runs/${encodeURIComponent(runId)}/findings`);
}

export function fetchEvidence(runId: string, evidenceId: string): Promise<Evidence> {
  return requestJson<Evidence>(
    `/runs/${encodeURIComponent(runId)}/evidence/${encodeURIComponent(evidenceId)}`,
  );
}

export function getEventsUrl(runId: string): string {
  return `${API_BASE}/runs/${encodeURIComponent(runId)}/events`;
}

export function startRun(repo: string): Promise<{ run_id: string }> {
  return requestJson<{ run_id: string }>("/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo }),
  });
}

export function submitDecision(
  runId: string,
  plan: RemediationPlan,
  decision: "approve" | "reject" | "accept_risk",
  comment: string,
): Promise<{ recorded: boolean; gate_resumed: boolean; detail?: string }> {
  return requestJson(`/runs/${encodeURIComponent(runId)}/plans/${encodeURIComponent(plan.plan_id)}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision, plan_hash: plan.plan_hash, comment: comment || undefined }),
  });
}

export function reportUrl(runId: string): string {
  return `${API_BASE}/runs/${encodeURIComponent(runId)}/report.json`;
}

export type { AgentEvent };
