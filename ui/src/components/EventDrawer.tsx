import { X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { clock } from "../lib/format";
import { AGENTS, AGENT_LABEL, type AgentId } from "../lib/pipeline";
import { useStore } from "../store";
import { inertProps } from "./hooks";
import { EvChip } from "./ui";

const CAP = 400;

export default function EventDrawer() {
  const { drawerOpen, setDrawerOpen, events, pipeline, drawerAgent, setDrawerAgent, openFinding } = useStore();
  const [showAll, setShowAll] = useState(false);
  const [follow, setFollow] = useState(true);
  const body = useRef<HTMLDivElement>(null);
  const rows = useMemo(() => {
    const out: { e: (typeof events)[number]; i: number }[] = [];
    events.forEach((e, i) => {
      if (!drawerAgent || e.agent === drawerAgent) out.push({ e, i });
    });
    return out;
  }, [events, drawerAgent]);
  const shown = showAll ? rows : rows.slice(-CAP);

  useEffect(() => {
    if (drawerOpen && follow && body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [drawerOpen, follow, shown.length]);

  return (
    <aside
      className={`drawer${drawerOpen ? " open" : ""}`}
      aria-label="Event drawer"
      aria-hidden={!drawerOpen}
      {...(drawerOpen ? {} : inertProps)}
    >
      <header className="drawer-head">
        <h2>Activity log</h2>
        <span className="num muted">
          {rows.length}
          {drawerAgent ? ` of ${events.length}` : ""}
        </span>
        <div className="drawer-filters" role="group" aria-label="Filter by agent">
          <button type="button" className={`chip${!drawerAgent ? " on" : ""}`} onClick={() => setDrawerAgent(null)}>
            Everything
          </button>
          {[...AGENTS, "supervisor", "guardrail"].map((a) => (
            <button
              key={a}
              type="button"
              className={`chip${drawerAgent === a ? " on" : ""}`}
              onClick={() => setDrawerAgent(drawerAgent === a ? null : a)}
            >
              {AGENT_LABEL[a as AgentId] ?? a}
            </button>
          ))}
        </div>
        <div className="drawer-rules" aria-label="Guardrail counters">
          {pipeline.guardrails.length === 0 ? (
            <span className="muted">No safety rules triggered</span>
          ) : (
            pipeline.guardrails.map(([r, n]) => (
              <span key={r} className="pill gate mono">
                {r} <span className="num">×{n}</span>
              </span>
            ))
          )}
        </div>
        <button type="button" className="btn ghost icon" onClick={() => setDrawerOpen(false)} aria-label="Close activity log">
          <X size={16} aria-hidden />
        </button>
      </header>
      <div
        className="drawer-body"
        ref={body}
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
        }}
      >
        {rows.length > shown.length && (
          <button type="button" className="btn ghost sm" onClick={() => setShowAll(true)}>
            Show {rows.length - shown.length} earlier events
          </button>
        )}
        {shown.length === 0 && <p className="empty">Nothing has happened yet. Steps appear here as Guardian works.</p>}
        <ol className="evlist">
          {shown.map(({ e, i }) => {
            const d = pipeline.decisions.get(i);
            return (
              <li key={i} className={`ev ty-${e.type}${d ? " is-decision" : ""}`}>
                <span className="ev-t mono">{clock(e.ts)}</span>
                <span className="ev-a">{AGENT_LABEL[e.agent as AgentId] ?? e.agent}</span>
                <span className="ev-ty mono">{e.type}</span>
                <span className="ev-s">
                  {d && <span className="dmark mono">D{d}</span>}
                  {e.type === "guardrail" && (
                    <span className="pill gate mono">{String((e.data as { rule?: unknown }).rule ?? "")}</span>
                  )}
                  {e.summary}
                  {e.finding_id && (
                    <button type="button" className="evchip fid" onClick={() => openFinding(e.finding_id!)}>
                      {e.finding_id.slice(0, 7)}…{e.finding_id.slice(-4)}
                    </button>
                  )}
                  {e.evidence_ids.slice(0, 4).map((id) => (
                    <EvChip key={id} id={id} />
                  ))}
                  {e.evidence_ids.length > 4 && <span className="muted"> +{e.evidence_ids.length - 4}</span>}
                </span>
              </li>
            );
          })}
        </ol>
      </div>
    </aside>
  );
}
