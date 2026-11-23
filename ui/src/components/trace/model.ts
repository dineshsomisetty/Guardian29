import type { AgentEvent } from "../../api/types";

/* Agent identities: ink + muted tones; the LLM agent carries the rail's amber accent. */
export type AgentId = "supervisor" | "discovery" | "detection" | "evidence_analyst" | "guardrail";

export interface AgentMeta {
  id: string;
  mono: string;
  no: string;
  role: string;
  kind: string;
  tone: "tool" | "llm" | "router" | "guard";
}

const KNOWN: Record<AgentId, AgentMeta> = {
  supervisor: { id: "supervisor", mono: "SV", no: "0", role: "Supervisor", kind: "router", tone: "router" },
  discovery: { id: "discovery", mono: "DI", no: "1", role: "Discovery", kind: "tool agent", tone: "tool" },
  detection: { id: "detection", mono: "DE", no: "2", role: "Detection", kind: "tool agent", tone: "tool" },
  evidence_analyst: { id: "evidence_analyst", mono: "EA", no: "3", role: "Evidence analyst", kind: "LLM agent", tone: "llm" },
  guardrail: { id: "guardrail", mono: "GR", no: "G", role: "Guardrail", kind: "code check", tone: "guard" },
};

/** pipeline order of the worker agents (lanes) */
export const WORKERS = ["discovery", "detection", "evidence_analyst"] as const;

export function agentMeta(id: string): AgentMeta {
  const k = KNOWN[id as AgentId];
  if (k) return k;
  const words = id.split(/[_\s-]+/).filter(Boolean);
  const mono = (words.length > 1 ? words[0][0] + words[1][0] : id.slice(0, 2)).toUpperCase();
  const role = words.map((w) => w[0].toUpperCase() + w.slice(1)).join(" ");
  return { id, mono, no: "·", role, kind: "agent", tone: "tool" };
}

export const TYPE_LABEL: Record<string, string> = {
  agent_start: "start",
  agent_end: "end",
  tool_call: "tool call",
  tool_result: "tool result",
  llm_call: "LLM call",
  llm_result: "LLM result",
  handoff: "hand-off",
  decision: "decision",
  guardrail: "guardrail",
  error: "error",
};

export const KEY_TYPES = new Set(["agent_start", "handoff", "decision", "guardrail", "error", "agent_end"]);

/** ISO timestamp with microseconds -> epoch milliseconds (fractional) */
export function parseTs(ts: string): number {
  const m = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?(.*)$/.exec(ts);
  if (!m) return Date.parse(ts);
  const frac = (m[2] ?? "0").padEnd(6, "0").slice(0, 6);
  const base = Date.parse(`${m[1]}${m[3] || "Z"}`);
  return base + Number(frac) / 1000;
}

export function fmtOffset(ms: number): string {
  const s = ms / 1000;
  return `+${s < 10 ? s.toFixed(2) : s.toFixed(1)}s`;
}

export function fmtDur(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  return `${s < 10 ? s.toFixed(2) : s.toFixed(1)}s`;
}

/** "SBOM + dependency graph -> detection" -> "detection" */
export function handoffTarget(e: AgentEvent): string | null {
  const d = e.data as Record<string, unknown>;
  for (const k of ["to", "next", "target", "next_agent"]) if (typeof d?.[k] === "string") return d[k] as string;
  const m = /->\s*([a-z_]+)/i.exec(e.summary);
  return m ? m[1] : null;
}

export interface TEvent extends AgentEvent {
  i: number;
  t: number; // ms offset from run start
}

export interface Span {
  agent: string;
  start: number;
  end: number;
}

export interface ToolSpan {
  agent: string;
  tool: string;
  start: number;
  end: number;
}

export interface Hand {
  from: string;
  to: string;
  t: number;
  evidence: number;
  summary: string;
}

export interface TraceModel {
  events: TEvent[];
  total: number;
  spans: Map<string, Span>;
  run: Span | null; // supervisor span
  tools: ToolSpan[];
  hands: Hand[];
  decisions: (TEvent & { dno: number })[];
  lanes: string[];
  /** tool_call index -> matching tool_result index (and back) */
  pairOf: Map<number, number>;
}

export function buildModel(trace: AgentEvent[]): TraceModel {
  const abs = trace.map((e) => parseTs(e.ts));
  const t0 = abs.length ? Math.min(...abs) : 0;
  const events: TEvent[] = trace.map((e, i) => ({ ...e, i, t: abs[i] - t0 }));
  const total = events.length ? Math.max(...events.map((e) => e.t)) : 0;

  const spans = new Map<string, Span>();
  for (const e of events) {
    if (e.type === "agent_start" && !spans.has(e.agent)) spans.set(e.agent, { agent: e.agent, start: e.t, end: e.t });
    if (e.type === "agent_end") {
      const s = spans.get(e.agent);
      if (s) s.end = Math.max(s.end, e.t);
      else spans.set(e.agent, { agent: e.agent, start: e.t, end: e.t });
    }
  }
  // an agent that never logged agent_end runs until its last event
  for (const e of events) {
    const s = spans.get(e.agent);
    if (s && e.t > s.end && !events.some((x) => x.agent === e.agent && x.type === "agent_end")) s.end = e.t;
  }

  const pairOf = new Map<number, number>();
  const tools: ToolSpan[] = [];
  const open = new Map<string, TEvent>();
  for (const e of events) {
    const tool = String((e.data as Record<string, unknown>)?.tool ?? "");
    if (e.type === "tool_call") open.set(`${e.agent}|${tool}`, e);
    if (e.type === "tool_result") {
      const c = open.get(`${e.agent}|${tool}`);
      if (c) {
        open.delete(`${e.agent}|${tool}`);
        pairOf.set(c.i, e.i);
        pairOf.set(e.i, c.i);
        tools.push({ agent: e.agent, tool: tool || "tool", start: c.t, end: e.t });
      }
    }
  }

  const hands: Hand[] = events
    .filter((e) => e.type === "handoff")
    .map((e) => ({ from: e.agent, to: handoffTarget(e) ?? "", t: e.t, evidence: e.evidence_ids.length, summary: e.summary }));

  let dno = 0;
  const decisions = events.filter((e) => e.type === "decision").map((e) => ({ ...e, dno: ++dno }));

  const seen = [...spans.keys()].filter((a) => a !== "supervisor" && a !== "guardrail");
  const lanes = [
    ...WORKERS.filter((w) => seen.includes(w)),
    ...seen.filter((a) => !(WORKERS as readonly string[]).includes(a)),
  ];

  return { events, total, spans, run: spans.get("supervisor") ?? null, tools, hands, decisions, lanes, pairOf };
}

/**
 * Piecewise-linear time axis: each interval between agent start/end times keeps its real
 * proportion, but an interval where an agent is active never drops below a legible share.
 * Tick labels show real offsets, so the compression is visible, not hidden.
 */
export function buildScale(m: TraceModel) {
  const pts = new Set<number>([0, m.total]);
  for (const s of m.spans.values()) { pts.add(s.start); pts.add(s.end); }
  const bp = [...pts].sort((a, b) => a - b);
  const total = m.total || 1;
  const workers = [...m.spans.values()].filter((s) => s.agent !== "supervisor");
  const weights: number[] = [];
  for (let i = 0; i < bp.length - 1; i++) {
    const a = bp[i], b = bp[i + 1];
    const d = b - a;
    const active = workers.some((s) => s.start <= a && s.end >= b && s.end > s.start);
    weights.push(d <= 0 ? 0 : Math.max(d / total, active ? 0.16 : 0.012));
  }
  const sum = weights.reduce((x, y) => x + y, 0) || 1;
  const acc = [0];
  for (const w of weights) acc.push(acc[acc.length - 1] + w / sum);
  const compressed = weights.some((w, i) => Math.abs(w / sum - (bp[i + 1] - bp[i]) / total) > 0.02);

  const frac = (t: number) => {
    if (t <= bp[0]) return 0;
    for (let i = 0; i < bp.length - 1; i++) {
      if (t <= bp[i + 1]) {
        const d = bp[i + 1] - bp[i];
        return acc[i] + (d > 0 ? ((t - bp[i]) / d) * (acc[i + 1] - acc[i]) : 0);
      }
    }
    return 1;
  };
  return { frac, ticks: bp, compressed };
}
