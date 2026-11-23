import { ArrowRight, ChevronDown, ChevronRight, ShieldAlert, Split, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { agentMeta, fmtDur, fmtOffset, handoffTarget, TYPE_LABEL, type TEvent } from "./model";
import Summary from "./Summary";

export interface LedgerProps {
  events: TEvent[];
  pairOf: Map<number, number>;
  dnoOf: Map<number, number>;
  selectedFindingId: string | null;
  onFinding: (id: string) => void;
}

/** Full custody ledger: one dense row per event. */
export default function Ledger({ events, pairOf, dnoOf, selectedFindingId, onFinding }: LedgerProps) {
  const [open, setOpen] = useState<Set<number>>(new Set());
  const shown = new Set(events.map((e) => e.i));
  const toggle = (i: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });

  return (
    <ol className="lg" aria-label="Custody log events">
      {events.map((e) => {
        const m = agentMeta(e.agent);
        const p = pairOf.get(e.i);
        const pairTop = e.type === "tool_call" && p !== undefined && shown.has(p);
        const pairBottom = e.type === "tool_result" && p !== undefined && shown.has(p);
        const alarm = e.type === "error" || e.type === "guardrail" || e.agent === "guardrail";
        const cls = [
          "lg-row",
          `t-${e.type}`,
          alarm && "alarm",
          pairTop && "pair-top",
          pairBottom && "pair-bottom",
          e.finding_id && "has-finding",
          e.finding_id && e.finding_id === selectedFindingId && "is-selected",
        ].filter(Boolean).join(" ");
        const isOpen = open.has(e.i);
        const d = e.data as Record<string, unknown>;
        const target = e.type === "handoff" ? handoffTarget(e) : null;

        return (
          <li key={e.i} className={cls} onClick={e.finding_id ? () => onFinding(e.finding_id!) : undefined}>
            <span className="lg-t value">{fmtOffset(e.t)}</span>
            <span className="lg-agent">
              <span className={`mono-chip ${m.tone}`} aria-hidden>{m.mono}</span>
              <span className="lg-role">{m.role}</span>
            </span>
            <span className="lg-type">
              <span className={`lg-tag t-${e.type}${alarm ? " alarm" : ""}`}>
                {e.type === "decision" && <Split size={12} strokeWidth={2.25} aria-hidden />}
                {e.type === "error" && <TriangleAlert size={12} strokeWidth={2.25} aria-hidden />}
                {e.type === "guardrail" && <ShieldAlert size={12} strokeWidth={2.25} aria-hidden />}
                {TYPE_LABEL[e.type] ?? e.type.replace(/_/g, " ")}
                {e.type === "decision" && dnoOf.has(e.i) && <span className="lg-dno">D{dnoOf.get(e.i)}</span>}
              </span>
            </span>
            <span className="lg-sum">
              <span className="lg-text"><Summary text={e.summary} /></span>
              {target && (
                <span className="lg-next">
                  <ArrowRight size={13} strokeWidth={2.25} aria-hidden />
                  <span className={`mono-chip ${agentMeta(target).tone}`} aria-hidden>{agentMeta(target).mono}</span>
                  {agentMeta(target).role}
                </span>
              )}
              {e.type === "tool_result" && typeof d.ms === "number" && (
                <span className="lg-aside value">{fmtDur(d.ms)}</span>
              )}
              {(e.type === "llm_call" || e.type === "llm_result") && typeof d.model === "string" && (
                <span className="lg-aside value">{d.model}{typeof d.mode === "string" ? ` · ${d.mode}` : ""}</span>
              )}
              {e.finding_id && (
                <button
                  type="button"
                  className="lg-finding value"
                  aria-pressed={e.finding_id === selectedFindingId}
                  onClick={(ev) => { ev.stopPropagation(); onFinding(e.finding_id!); }}
                >
                  {e.finding_id}
                </button>
              )}
            </span>
            <span className="lg-ev">
              {e.evidence_ids.length > 0 && (
                <button
                  type="button"
                  className="lg-evbtn"
                  aria-expanded={isOpen}
                  onClick={(ev) => { ev.stopPropagation(); toggle(e.i); }}
                >
                  {isOpen ? <ChevronDown size={13} aria-hidden /> : <ChevronRight size={13} aria-hidden />}
                  <span className="value">{e.evidence_ids.length}</span>
                  <span className="lg-evword">evidence</span>
                </button>
              )}
            </span>
            {isOpen && (
              <ul className="lg-evlist" onClick={(ev) => ev.stopPropagation()}>
                {e.evidence_ids.map((id) => <li key={id} className="value">{id}</li>)}
              </ul>
            )}
          </li>
        );
      })}
    </ol>
  );
}
