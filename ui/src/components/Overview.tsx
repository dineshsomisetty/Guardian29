import { ArrowRight, CheckCircle2, ChevronRight, FileText, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import type { Finding, Risk } from "../api/types";
import { RISKS, bandOf, fmtDate, groupKey, plural, shortCommit } from "../lib/format";
import { BAND_COPY, BAND_RANGE, CATEGORY_WHY, STEP_DOING, categoryLabel, findingRef, plainTitle, whyItMatters } from "../lib/labels";
import { planSummary } from "../lib/plan";
import { AGENTS } from "../lib/pipeline";
import { useStore } from "../store";
import { EmptyState, SevPill, Tip } from "./ui";

export default function Overview() {
  const { data, order, findingsById, riskById, status, pipeline, setView, setFindingFilter, openFinding, plansById } = useStore();
  const s = data.summary;

  const counts = useMemo(() => {
    const c: Record<Risk, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of data.findings) {
      const b = bandOf(f, riskById);
      if (b) c[b]++;
    }
    return c;
  }, [data.findings, riskById]);

  const top = useMemo(() => {
    const seen = new Map<string, { f: Finding; n: number }>();
    for (const id of order) {
      const f = findingsById.get(id)!;
      const k = groupKey(f);
      const hit = seen.get(k);
      if (hit) hit.n++;
      else seen.set(k, { f, n: 1 });
    }
    return [...seen.values()].slice(0, 5);
  }, [order, findingsById]);

  const anomalies = useMemo(() => {
    const by = new Map<string, Finding[]>();
    for (const id of order) {
      const f = findingsById.get(id)!;
      if (f.category === "cve") continue;
      (by.get(f.category) ?? by.set(f.category, []).get(f.category)!).push(f);
    }
    return [...by.entries()];
  }, [order, findingsById]);

  const pending = s.pending_plan ?? null;
  const plan = pending ? plansById.get(pending.plan_id) : undefined;
  const pf = plan ? findingsById.get(plan.finding_id) : undefined;
  const sum = plan ? planSummary(plan, pf, pf ? bandOf(pf, riskById) : null) : null;

  const active = pipeline.nodes.find((n) => n.state === "active");
  const stepsDone = pipeline.nodes.filter((n) => n.state === "done").length;

  const gotoFindings = (risk: Risk | null, cat: string | null) => {
    setFindingFilter({ risk, cat });
    setView("findings");
  };

  if (!data.findings.length && status === "done")
    return (
      <div className="page">
        <EmptyState icon={<ShieldCheck size={32} aria-hidden />} title="No findings" center>
          Guardian scanned {s.target} and found no known vulnerabilities or suspicious packages.
        </EmptyState>
      </div>
    );

  return (
    <div className="page" aria-label="Overview">
      <div className="page-in">
        <header className="page-head">
          <h1>Security overview</h1>
          <p className="muted">
            What Guardian found in <b>{s.target}</b>, what matters most, and what it needs from you.
          </p>
        </header>

        {/* ---- next step */}
        {status === "awaiting_human" && plan && sum ? (
          <section className="nextstep gate" aria-label="Next step">
            <ShieldAlert size={22} aria-hidden className="ns-ico" />
            <div className="ns-text">
              <p className="ns-title">1 fix is waiting for your approval</p>
              <p className="ns-sub">{sum.sentence}</p>
              <p className="ns-small">Nothing is changed in your repository until you approve, and even then the fix is tried on a sandbox copy first.</p>
            </div>
            <button type="button" className="btn amber lg" onClick={() => setView("gate")}>
              Review proposed fix <ArrowRight size={16} aria-hidden />
            </button>
          </section>
        ) : status === "done" ? (
          <section className="nextstep ok" aria-label="Next step">
            <CheckCircle2 size={22} aria-hidden className="ns-ico" />
            <div className="ns-text">
              <p className="ns-title">The scan is complete</p>
              <p className="ns-sub">
                {data.validation.some((v) => v.verdict === "verified")
                  ? "A fix was approved and verified in a sandbox. The full report is ready."
                  : "Guardian has finished. The full report is ready."}
              </p>
            </div>
            <button type="button" className="btn lg" onClick={() => setView("report")}>
              <FileText size={16} aria-hidden /> Open the report
            </button>
          </section>
        ) : status === "failed" ? (
          <section className="nextstep bad" aria-label="Next step">
            <ShieldAlert size={22} aria-hidden className="ns-ico" />
            <div className="ns-text">
              <p className="ns-title">The scan stopped with an error</p>
              <p className="ns-sub">Open the activity log to see which step failed and why.</p>
            </div>
          </section>
        ) : (
          <section className="nextstep info" aria-label="Next step">
            <Loader2 size={22} aria-hidden className="ns-ico spin" />
            <div className="ns-text">
              <p className="ns-title">Guardian is working</p>
              <p className="ns-sub">
                {active ? STEP_DOING[active.id] : STEP_DOING[AGENTS[Math.min(stepsDone, AGENTS.length - 1)]]}
                {" "}
                <span className="faint">
                  (step {Math.min(stepsDone + 1, AGENTS.length)} of {AGENTS.length})
                </span>
              </p>
            </div>
          </section>
        )}

        {/* ---- what was scanned */}
        <section className="scanned" aria-label="What was scanned">
          <div className="stat">
            <span className="stat-k">Scanned</span>
            <span className="stat-v">{s.target}</span>
          </div>
          <div className="stat">
            <span className="stat-k">Commit</span>
            <span className="stat-v mono">{shortCommit(s.commit)}</span>
          </div>
          <div className="stat">
            <span className="stat-k">Packages</span>
            <span className="stat-v">
              <span className="num">{(s.sbom?.components ?? data.graph.nodes.filter((n) => n.kind === "package").length).toLocaleString()}</span>
              <span className="stat-sub">
                {s.sbom?.direct != null && s.sbom?.transitive != null
                  ? `${s.sbom.direct.toLocaleString()} you chose, ${s.sbom.transitive.toLocaleString()} pulled in by them`
                  : ""}
              </span>
            </span>
          </div>
          <div className="stat">
            <span className="stat-k">Projects</span>
            <span className="stat-v">
              {s.projects?.length ?? 0}
              <span className="stat-sub">{(s.projects ?? []).join(", ")}</span>
            </span>
          </div>
          <div className="stat">
            <span className="stat-k">Scanned on</span>
            <span className="stat-v">{fmtDate(s.finished_at ?? s.started_at)}</span>
          </div>
        </section>

        {/* ---- severity */}
        <section aria-label="How risky is it">
          <h2 className="h2">How risky is it?</h2>
          <p className="sec-lead">
            {plural(data.findings.length, "finding")} in total. Each gets a risk score from 0 to 100: the advisory's severity, adjusted for
            how likely it is to be exploited, whether your code uses it, whether it ships to production and whether the service is exposed.
            The score sets the level, so a level can be higher or lower than the advisory's own rating.
          </p>
          <div className="bands">
            {RISKS.map((r) => (
              <button
                key={r}
                type="button"
                className={`band-card b-${r}`}
                disabled={!counts[r]}
                onClick={() => gotoFindings(r, null)}
              >
                <span className="band-top">
                  <span className="band-name">
                    {BAND_COPY[r].name} <span className="band-range num faint">{BAND_RANGE[r][0]}–{BAND_RANGE[r][1]}</span>
                  </span>
                  <span className="band-n num">{counts[r]}</span>
                </span>
                <span className="band-line">{BAND_COPY[r].line}</span>
              </button>
            ))}
          </div>
        </section>

        {/* ---- top risks */}
        <section aria-label="Top risks">
          <div className="h2-row">
            <h2 className="h2">What to look at first</h2>
            <button type="button" className="btn ghost sm" onClick={() => gotoFindings(null, null)}>
              All findings <ArrowRight size={14} aria-hidden />
            </button>
          </div>
          <p className="sec-lead">The highest-scoring risks, ranked. Select one to see the evidence behind the score.</p>
          {top.length === 0 ? (
            <EmptyState title="Nothing scored yet">Risks appear here once Guardian has analysed the findings.</EmptyState>
          ) : (
            <ol className="toplist">
              {top.map(({ f, n }, i) => {
                const risk = riskById.get(f.finding_id);
                const band = bandOf(f, riskById);
                return (
                  <li key={f.finding_id}>
                    <button type="button" className="top-row" onClick={() => openFinding(f.finding_id)}>
                      <span className="top-rank num">{i + 1}</span>
                      <span className="top-main">
                        <span className="top-title">
                          {plainTitle(f, band)}
                          {n > 1 && <span className="pill dashed">{n} versions</span>}
                        </span>
                        <span className="top-why">{whyItMatters(f, risk)}</span>
                        <span className="top-ref mono">{findingRef(f)}</span>
                      </span>
                      <span className="top-side">
                        <SevPill risk={band} />
                        {risk && (
                          <Tip text="Risk score out of 100. Open the finding to see how it was calculated." side="left">
                            <span className="top-score num">
                              {risk.score.toFixed(0)}
                              <span className="faint">/100</span>
                            </span>
                          </Tip>
                        )}
                      </span>
                      <ChevronRight size={16} aria-hidden className="faint" />
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        {/* ---- anomalies */}
        {anomalies.length > 0 && (
          <section aria-label="Suspicious packages and unsafe setup">
            <h2 className="h2">Suspicious packages and unsafe setup</h2>
            <p className="sec-lead">
              These are not published CVEs. They are warning signs in how the project is built and what it installs, the kind of thing supply-chain attacks rely on.
            </p>
            <ul className="anoms">
              {anomalies.map(([cat, fs]) => {
                const worst = fs.map((f) => bandOf(f, riskById)).sort((a, b) => RISKS.indexOf(a ?? "low") - RISKS.indexOf(b ?? "low"))[0];
                return (
                  <li key={cat}>
                    <button type="button" className="anom-row" onClick={() => gotoFindings(null, cat)}>
                      <span className="anom-n num">{fs.length}</span>
                      <span className="anom-main">
                        <span className="anom-title">{categoryLabel(cat)}</span>
                        <span className="anom-why">{CATEGORY_WHY[cat] ?? ""}</span>
                        <span className="anom-ex">
                          {fs.slice(0, 2).map((f) => plainTitle(f, bandOf(f, riskById))).join("  ·  ")}
                          {fs.length > 2 ? `  ·  and ${fs.length - 2} more` : ""}
                        </span>
                      </span>
                      <SevPill risk={worst} />
                      <ChevronRight size={16} aria-hidden className="faint" />
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}
