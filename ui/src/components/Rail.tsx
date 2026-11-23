import { ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSel, type Section } from "../state";

const NAV: { id: Section; name: string }[] = [
  { id: "graph", name: "Dependency graph" },
  { id: "exhibits", name: "Exhibits" },
  { id: "changes", name: "What changed" },
  { id: "custody", name: "Custody log" },
];

/** true on the stacked (narrow) layout, where the case and chain collapse into a disclosure */
function useNarrow() {
  const q = "(max-width: 1100px)";
  const [narrow, setNarrow] = useState(() => typeof window !== "undefined" && window.matchMedia(q).matches);
  useEffect(() => {
    const m = window.matchMedia(q);
    const on = () => setNarrow(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return narrow;
}

function endSummary(trace: { agent: string; type: string; summary: string }[], agent: string) {
  return [...trace].reverse().find((e) => e.agent === agent && e.type === "agent_end")?.summary ?? null;
}

export default function Rail({ source }: { source: "server" | "sample" }) {
  const { run, section, setSection } = useSel();
  const { summary, trace, findings, changes } = run;
  const narrow = useNarrow();
  const [caseOpen, setCaseOpen] = useState(false);

  const chain = useMemo(() => {
    const guard = trace.filter((e) => e.type === "guardrail").length;
    const llm = findings.filter((f) => f.initial_risk_source === "llm").length;
    const claims = findings.reduce((n, f) => n + f.claims.length, 0);
    const disc = endSummary(trace, "discovery");
    const det = endSummary(trace, "detection");
    return [
      { no: "1", role: "Discovery", kind: "tool", llm: false,
        res: disc ? <><b>{(summary.sbom.components ?? 0).toLocaleString()}</b> components, {summary.projects.length} projects</> : "not run" },
      { no: "2", role: "Detection", kind: "tool", llm: false,
        res: det ? <><b>{summary.findings.total}</b> findings from scanners + detectors</> : "not run" },
      { no: "3", role: "Evidence analyst", kind: "LLM", llm: true,
        res: llm ? <><b>{llm}</b> explained · <b>{claims}</b> claims · <b>{guard}</b> guardrail hits</>
                 : <>LLM not reached · rule-based risk · <b>{guard}</b> guardrail hits</> },
    ];
  }, [summary, trace, findings]);

  const counts: Record<Section, string> = {
    graph: `${run.graph.nodes.length.toLocaleString()}`,
    exhibits: `${findings.length}`,
    changes: changes ? `${changes.added.length + changes.removed.length + changes.changed.length}` : "–",
    custody: `${trace.length}`,
  };

  return (
    <aside className="rail" aria-label="Case and navigation">
      <div className="rail-brand">
        <div className="word"><ShieldCheck size={26} strokeWidth={1.75} aria-hidden />GUARDIAN</div>
        <div className="sub">Supply-chain custody</div>
      </div>

      {/* desktop: always open, summary hidden. narrow: a collapsed-by-default disclosure */}
      <details
        className="rail-case"
        open={narrow ? caseOpen : true}
        onToggle={(e) => { if (narrow) setCaseOpen(e.currentTarget.open); }}
      >
        <summary>Case and custody chain</summary>
      <div className="rail-block">
        <span className="label">Case</span>
        <div className="case-id">{summary.run_id}</div>
        <div className="case-meta">
          {summary.target}{summary.commit ? ` @ ${summary.commit.slice(0, 9)}` : ""}
          <br />LLM {summary.llm.model ?? "none"} · {summary.llm.mode}
        </div>
        {source === "sample" && <div className="case-src"><b>Bundled sample run</b> · run server not reachable</div>}
      </div>

      <div className="rail-block">
        <span className="label">Custody chain</span>
        <ol className="chain">
          {chain.map((c) => (
            <li key={c.no}>
              <span className={`box${c.llm ? " llm" : ""}`}>{c.no}</span>
              <div>
                <div><span className="role">{c.role}</span><span className="kind">{c.kind}</span></div>
                <div className="res">{c.res}</div>
              </div>
            </li>
          ))}
        </ol>
      </div>
      </details>

      <nav aria-label="Sections">
        <ul className="nav">
          {NAV.map((n) => (
            <li key={n.id}>
              <button aria-current={section === n.id} onClick={() => setSection(n.id)}>
                <span className="name">{n.name}</span>
                <span className="count">{counts[n.id]}</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <div className="rail-foot">
        Tools produce facts. Agents explain them. Every claim cites evidence and is labelled by code, not by the model.
      </div>
    </aside>
  );
}
