import { useEffect, useState } from "react";
import { loadEvidence } from "../../api/load";
import type { AgentEvent, Evidence, Finding, Risk } from "../../api/types";
import { evidenceLine, toolName } from "./format";

export type StampKind = "fact" | "verified" | "inferred" | "rejected" | "rule" | Risk;

export interface CustodyRow {
  key: string;
  /** tool or agent that signed, rendered in condensed caps */
  who: string;
  /** what they did, one line */
  what: string;
  /** a mono detail line (scanner facts, claim field=value) */
  detail?: string;
  evidenceIds: string[];
  stamp: StampKind;
  stampText: string;
}

export type EvidenceState =
  | { status: "loading"; forId: string }
  | { status: "ready"; forId: string; byId: Map<string, Evidence | null> };

/** Loads every evidence record cited by a finding (its own ids plus ids cited by claims / guardrail events). */
export function useFindingEvidence(base: string, findingId: string | null, ids: string[]): EvidenceState | null {
  const [state, setState] = useState<EvidenceState | null>(null);
  const key = ids.join("|");
  useEffect(() => {
    if (!findingId) {
      setState(null);
      return;
    }
    let live = true;
    setState({ status: "loading", forId: findingId });
    Promise.all(ids.map((id) => loadEvidence(base, id).then((ev) => [id, ev] as const))).then((pairs) => {
      if (live) setState({ status: "ready", forId: findingId, byId: new Map(pairs) });
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, findingId, key]);
  return state;
}

export function guardrailEvents(trace: AgentEvent[], findingId: string): AgentEvent[] {
  return trace.filter((e) => e.type === "guardrail" && e.finding_id === findingId);
}

export function citedEvidenceIds(f: Finding, guards: AgentEvent[]): string[] {
  const ids = new Set(f.evidence_ids);
  for (const c of f.claims) c.evidence_ids.forEach((e) => ids.add(e));
  for (const g of guards) g.evidence_ids.forEach((e) => ids.add(e));
  return [...ids];
}

function ruleBasis(f: Finding): string {
  if (f.cvss != null) return `CVSS ${f.cvss} band`;
  if (f.severity) return `scanner severity ${f.severity}`;
  return "category default";
}

/**
 * Ordered custody signatures for one exhibit:
 *   1. each evidence record on the finding (FACT)
 *   2. initial-risk assignment (RULE, or the analyst's risk stamp)
 *   3. each analyst claim (VERIFIED / INFERRED / REJECTED when labelled unsupported)
 *   4. each guardrail event for this finding (REJECTED)
 */
export function buildCustodyRows(
  f: Finding,
  evidence: Map<string, Evidence | null>,
  guards: AgentEvent[],
  model: string | null,
  analystReached: boolean,
): CustodyRow[] {
  const rows: CustodyRow[] = [];

  for (const id of f.evidence_ids) {
    const ev = evidence.get(id);
    if (!ev) {
      rows.push({ key: `ev:${id}`, who: "Evidence store", what: "Record not present in this run's evidence folder", evidenceIds: [id], stamp: "fact", stampText: "Fact" });
      continue;
    }
    const { verb, detail } = evidenceLine(ev);
    rows.push({
      key: `ev:${id}`,
      who: toolName(ev.source_tool),
      what: verb,
      detail: detail.join(" · ") || undefined,
      evidenceIds: [id],
      stamp: "fact",
      stampText: "Fact",
    });
  }

  const risk = f.initial_risk;
  if (f.initial_risk_source === "llm") {
    rows.push({
      key: "risk",
      who: `Evidence analyst${model ? ` ${model}` : ""}`,
      what: `Assessed initial risk ${risk ?? "unrated"} from the cited evidence`,
      evidenceIds: [],
      stamp: risk ?? "inferred",
      stampText: risk ?? "Unrated",
    });
  } else {
    const why = guards.length ? "analyst output rejected" : analystReached ? "no analyst assessment" : "analyst not reached";
    rows.push({
      key: "risk",
      who: "Scoring rule",
      what: `Initial risk ${risk ?? "unrated"} by rule (${ruleBasis(f)}); ${why}`,
      evidenceIds: [],
      stamp: "rule",
      stampText: "Rule",
    });
  }

  f.claims.forEach((c, i) => {
    const rejected = c.label !== "verified" && c.label !== "inferred";
    rows.push({
      key: `claim:${i}`,
      who: rejected ? "Guardrail" : "Evidence analyst",
      what: rejected ? `Claim rejected, not supported by evidence: ${c.text}` : c.text,
      detail: c.field ? `${c.field} = ${c.value ?? "null"}` : undefined,
      evidenceIds: c.evidence_ids,
      stamp: c.label === "verified" || c.label === "inferred" ? c.label : "rejected",
      stampText: rejected ? "Rejected" : c.label,
    });
  });

  guards.forEach((g, i) => {
    const rule = typeof g.data?.rule === "string" ? g.data.rule : null;
    const what = rule && g.summary.startsWith(rule) ? g.summary.slice(rule.length).replace(/^[:\s]+/, "") : g.summary;
    rows.push({
      key: `guard:${i}`,
      who: rule ? `Guardrail ${rule}` : "Guardrail",
      what,
      evidenceIds: g.evidence_ids,
      stamp: "rejected",
      stampText: "Rejected",
    });
  });

  return rows;
}
