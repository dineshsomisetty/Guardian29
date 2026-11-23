import type { AgentEvent } from "../api/types";

export const AGENTS = [
  "discovery",
  "detection",
  "evidence_analyst",
  "investigator",
  "risk_analyst",
  "remediation",
  "human_gate",
  "validator",
  "reporter",
] as const;
export type AgentId = (typeof AGENTS)[number];

export const AGENT_LABEL: Record<AgentId, string> = {
  discovery: "Discovery",
  detection: "Detection",
  evidence_analyst: "Evidence",
  investigator: "Investigator",
  risk_analyst: "Risk",
  remediation: "Remediation",
  human_gate: "Human gate",
  validator: "Validator",
  reporter: "Reporter",
};

export type NodeState = "idle" | "active" | "done" | "waiting" | "error";

export interface PipeNode {
  id: AgentId;
  state: NodeState;
  runs: number;
  events: number;
  last: string;
}

export interface Pipeline {
  nodes: PipeNode[];
  /** index of the node the beam flows into, or -1 */
  beamTo: number;
  /** event index -> D-number */
  decisions: Map<number, number>;
  guardrails: [string, number][];
}

const isAgent = (a: string): a is AgentId => (AGENTS as readonly string[]).includes(a);

export function derivePipeline(events: AgentEvent[], status: string): Pipeline {
  const nodes: PipeNode[] = AGENTS.map((id) => ({ id, state: "idle", runs: 0, events: 0, last: "" }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const decisions = new Map<number, number>();
  const rules = new Map<string, number>();
  let d = 0;
  let lastAgent = null as AgentId | null;
  events.forEach((e, i) => {
    if (e.type === "decision") decisions.set(i, ++d);
    if (e.type === "guardrail" || e.agent === "guardrail") {
      const r = String((e.data as { rule?: unknown }).rule ?? "unknown");
      rules.set(r, (rules.get(r) ?? 0) + 1);
    }
    if (!isAgent(e.agent)) return;
    const n = byId.get(e.agent)!;
    n.events++;
    n.last = e.summary;
    lastAgent = n.id;
    if (e.type === "agent_start") {
      n.state = "active";
      n.runs++;
    } else if (e.type === "agent_end") n.state = "done";
    else if (e.type === "error") n.state = "error";
    else if (e.type === "gate_wait") n.state = "waiting";
    else if (e.type === "gate_resume") n.state = "active";
    else if (n.state === "idle") n.state = "active";
  });
  const terminal = status === "done" || status === "failed";
  if (terminal) for (const n of nodes) if (n.state === "active" || n.state === "waiting") n.state = "done";
  const gate = byId.get("human_gate")!;
  if (status === "awaiting_human") {
    gate.state = "waiting";
    for (const n of nodes) if (n !== gate && n.state === "active") n.state = "done";
  } else if (gate.state === "waiting") gate.state = "active";

  let beamTo = -1;
  if (!terminal && status !== "awaiting_human") {
    let act = -1;
    nodes.forEach((n, i) => {
      if (n.state === "active") act = i;
    });
    if (act < 0 && lastAgent) act = AGENTS.indexOf(lastAgent);
    beamTo = act > 0 ? act : -1;
  }
  return { nodes, beamTo, decisions, guardrails: [...rules.entries()].sort((a, b) => b[1] - a[1]) };
}
