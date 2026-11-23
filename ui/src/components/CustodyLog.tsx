import { useMemo, useState } from "react";
import { useSel } from "../state";
import "../styles/trace.css";
import Ledger from "./trace/Ledger";
import RelayBand from "./trace/RelayBand";
import Segmented, { type SegOption } from "./trace/Segmented";
import { buildModel, fmtDur, KEY_TYPES, WORKERS, agentMeta } from "./trace/model";

export default function CustodyLog() {
  const { run, selectFinding, selectedFindingId } = useSel();
  const model = useMemo(() => buildModel(run.trace), [run.trace]);
  const [agent, setAgent] = useState<string>("all");
  const [keyOnly, setKeyOnly] = useState(true);

  const guardHits = model.events.filter((e) => e.type === "guardrail").length;
  const dnoOf = useMemo(() => new Map(model.decisions.map((d) => [d.i, d.dno])), [model]);

  const agentOpts: SegOption<string>[] = useMemo(() => {
    const present = new Set(model.events.map((e) => e.agent));
    const order = [...WORKERS, "supervisor", "guardrail", ...[...present].filter((a) => !["supervisor", "guardrail", ...WORKERS].includes(a))];
    const base = keyOnly ? model.events.filter((e) => KEY_TYPES.has(e.type)) : model.events;
    return [
      { id: "all", label: "All", count: base.length },
      ...order
        .filter((a) => present.has(a) || a === "guardrail")
        .map((a) => ({ id: a, label: agentMeta(a).role, count: base.filter((e) => e.agent === a || (a === "guardrail" && e.type === "guardrail")).length })),
    ];
  }, [model, keyOnly]);

  const shown = model.events.filter(
    (e) =>
      (!keyOnly || KEY_TYPES.has(e.type)) &&
      (agent === "all" || e.agent === agent || (agent === "guardrail" && e.type === "guardrail")),
  );

  const meta = [
    `${model.events.length} events`,
    `${model.lanes.length} agents`,
    `${model.decisions.length} decisions`,
    `${guardHits} guardrail hit${guardHits === 1 ? "" : "s"}`,
    `total duration ${fmtDur(model.total)}`,
  ].join(" · ");

  if (!model.events.length) {
    return (
      <div className="cl">
        <div className="panelhead"><h2>Custody log</h2><span className="meta">no events</span></div>
        <div className="cl-empty">
          <p className="cl-empty-title">No agent trace for this run</p>
          <p>The run did not write <span className="value">trace.jsonl</span>. Re-run the pipeline to record the custody log.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="cl">
      <div className="panelhead"><h2>Custody log</h2><span className="meta">{meta}</span></div>
      <section className="cl-band" aria-label="Agent relay">
        <RelayBand model={model} />
      </section>
      <div className="cl-tools">
        <Segmented label="Filter by agent" options={agentOpts} value={agent} onChange={setAgent} />
        <button type="button" className="cl-toggle" aria-pressed={keyOnly} onClick={() => setKeyOnly((k) => !k)}>
          <span className="cl-switch" aria-hidden><span /></span>
          Key events only
        </button>
        <span className="cl-count label">Showing {shown.length} of {model.events.length}</span>
      </div>
      <div className="cl-scroll">
        <div className="lg-head" aria-hidden>
          <span className="label">Time</span>
          <span className="label">Agent</span>
          <span className="label">Event</span>
          <span className="label">Record</span>
          <span className="label">Evidence</span>
        </div>
        {shown.length ? (
          <Ledger events={shown} pairOf={model.pairOf} dnoOf={dnoOf} selectedFindingId={selectedFindingId} onFinding={selectFinding} />
        ) : (
          <p className="cl-none">No {keyOnly ? "key " : ""}events from this agent. {keyOnly && "Turn off “Key events only” to see its tool calls."}</p>
        )}
      </div>
    </div>
  );
}
