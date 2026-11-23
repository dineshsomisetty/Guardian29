import { Fragment } from "react";
import { AGENT_LABEL } from "../lib/pipeline";
import { useStore } from "../store";

export default function Pipeline() {
  const { pipeline, events, live, drawerOpen, setDrawerOpen, setDrawerAgent } = useStore();
  const rules = pipeline.guardrails.reduce((a, [, n]) => a + n, 0);
  return (
    <section className="pipe" aria-label="Agent pipeline">
      <ol className="pipe-nodes">
        {pipeline.nodes.map((n, i) => (
          <Fragment key={n.id}>
            {i > 0 && (
              <li
                aria-hidden
                className={`pe${pipeline.beamTo === i ? " beam" : ""}${n.id === "human_gate" ? " to-gate" : ""}`}
              />
            )}
            <li className="pn-li">
              <button
                type="button"
                className={`pn st-${n.state}`}
                onClick={() => {
                  setDrawerAgent(n.id);
                  setDrawerOpen(true);
                }}
                title={n.last || AGENT_LABEL[n.id]}
              >
                <span className="pn-dot" aria-hidden />
                <span className="pn-name">{AGENT_LABEL[n.id]}</span>
                <span className="pn-sub">
                  {n.state === "waiting"
                    ? "awaiting human"
                    : n.state === "idle" || n.state === "error"
                      ? n.state
                      : n.runs > 1
                        ? `${n.runs} runs`
                        : n.state}
                </span>
              </button>
            </li>
          </Fragment>
        ))}
      </ol>
      <button
        type="button"
        className="pipe-ev btn"
        aria-expanded={drawerOpen}
        onClick={() => {
          setDrawerAgent(null);
          setDrawerOpen(!drawerOpen);
        }}
      >
        <span className={`live-dot ${live}`} aria-hidden />
        <span>Events</span>
        <span className="num">{events.length}</span>
        {rules > 0 && <span className="pill gate mono">{rules} guard</span>}
      </button>
    </section>
  );
}
