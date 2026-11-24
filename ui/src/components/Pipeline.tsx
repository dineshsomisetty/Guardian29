import { AlertTriangle, Check, Circle, Hourglass, Loader2, type LucideIcon } from "lucide-react";
import { Fragment } from "react";
import { AGENT_LABEL, STATE_WORD, type NodeState } from "../lib/pipeline";
import { STEP_DOING } from "../lib/labels";
import { useStore } from "../store";
import { Tip } from "./ui";

const ICON: Record<NodeState, LucideIcon> = {
  idle: Circle,
  active: Loader2,
  done: Check,
  waiting: Hourglass,
  error: AlertTriangle,
};

export default function Pipeline() {
  const { pipeline, setDrawerAgent, setDrawerOpen, setView } = useStore();
  return (
    <nav className="pipe" aria-label="What Guardian has done so far">
      <ol className="pipe-nodes">
        {pipeline.nodes.map((n, i) => {
          const Icon = ICON[n.state];
          const label = AGENT_LABEL[n.id];
          const tip = (
            <>
              <b>{label}</b> · {STATE_WORD[n.state]}
              <br />
              {n.last || STEP_DOING[n.id]}
              {n.runs > 1 ? ` (ran ${n.runs} times)` : ""}
            </>
          );
          return (
            <Fragment key={n.id}>
              {i > 0 && <li aria-hidden className={`pe${pipeline.beamTo === i ? " beam" : ""}${n.state !== "idle" ? " lit" : ""}`} />}
              <li className="pn-li">
                <Tip text={tip} side="bottom" block>
                  <button
                    type="button"
                    className={`pn st-${n.state}`}
                    aria-label={`${label}: ${STATE_WORD[n.state]}`}
                    onClick={() => {
                      if (n.id === "human_gate") return setView("gate");
                      if (n.id === "validator") return setView("validation");
                      if (n.id === "reporter") return setView("report");
                      setDrawerAgent(n.id);
                      setDrawerOpen(true);
                    }}
                  >
                    <Icon size={16} aria-hidden className={n.state === "active" ? "spin" : ""} />
                    <span className="pn-name">{label}</span>
                  </button>
                </Tip>
              </li>
            </Fragment>
          );
        })}
      </ol>
    </nav>
  );
}
