import { AlertTriangle, Check, CheckCircle2, ChevronDown, ChevronRight, Circle, Search, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { Evidence, Finding, RemediationPlan, ValidationResult } from "../api/types";
import { bandOf } from "../lib/format";
import { evidenceTitle, plainTitle, verdictFail } from "../lib/labels";
import { planSummary } from "../lib/plan";
import { useStore } from "../store";
import { useCountTween, useEvidence, useEvidenceMany } from "./hooks";
import { Callout, EmptyState, Json, Section, Skeleton } from "./ui";

interface Attempt {
  plan: RemediationPlan;
  val: ValidationResult | undefined;
}

const failWord = verdictFail;

export default function ValidationView() {
  const { data, findingsById, riskById } = useStore();
  const ids = useMemo(() => [...new Set(data.plans.map((p) => p.finding_id))], [data.plans]);
  const [fid, setFid] = useState<string | null>(null);
  const current = fid && ids.includes(fid) ? fid : (ids.find((i) => data.validation.some((v) => v.finding_id === i)) ?? ids[0]);

  if (!ids.length)
    return (
      <EmptyState title="Nothing has been validated yet" center>
        After you approve a fix, Guardian applies it to a sandbox copy, builds, tests and re-scans it. The result appears here.
      </EmptyState>
    );

  const attempts: Attempt[] = data.plans
    .filter((p) => p.finding_id === current)
    .map((plan) => ({ plan, val: data.validation.find((v) => v.plan_id === plan.plan_id) }));
  const f = findingsById.get(current);

  return (
    <div className="val">
      <div className="val-in">
        <header className="page-head">
          <h1>Validation</h1>
          <p className="muted">Did the fix work? Guardian tries every fix on a sandbox copy before anyone relies on it.</p>
          {ids.length > 1 && (
            <label className="select-row">
              <span className="muted">Finding</span>
              <select value={current} onChange={(e) => setFid(e.target.value)}>
                {ids.map((i) => {
                  const g = findingsById.get(i);
                  return (
                    <option key={i} value={i}>
                      {g ? plainTitle(g, bandOf(g, riskById)) : i}
                    </option>
                  );
                })}
              </select>
            </label>
          )}
        </header>
        <Verdict attempts={attempts} title={f ? plainTitle(f, bandOf(f, riskById)) : ""} finding={f} />
        <Timeline attempts={attempts} />
        <AttemptDetail key={current} attempts={attempts} />
      </div>
    </div>
  );
}

function Verdict({ attempts, title, finding }: { attempts: Attempt[]; title: string; finding: Finding | undefined }) {
  const { riskById } = useStore();
  const last = attempts[attempts.length - 1];
  const failed = attempts.filter((a) => a.val && a.val.verdict !== "verified");
  const ok = attempts.find((a) => a.val?.verdict === "verified");
  if (ok?.val) {
    const sm = planSummary(ok.plan, finding, finding ? bandOf(finding, riskById) : null);
    return (
      <Callout tone="ok" title="Verified: the vulnerability is gone, and the build and tests passed in the sandbox" icon={<CheckCircle2 size={20} aria-hidden />}>
        To {sm.verb} {sm.pkg}
        {sm.to ? ` to ${sm.to}` : ""} fixes: {title}.
        {failed.length ? ` It took ${attempts.length} attempts; ${failed.length} earlier ${failed.length === 1 ? "attempt" : "attempts"} did not work and Guardian re-planned.` : ""}
      </Callout>
    );
  }
  if (last && !last.val)
    return (
      <Callout tone="gate" title="Waiting for validation" icon={<Circle size={20} aria-hidden />}>
        The fix has not been tried in the sandbox yet. It runs after the plan is approved.
      </Callout>
    );
  if (last?.val)
    return (
      <Callout tone="bad" title={`Failed attempt ${last.plan.attempt}: ${failWord(last.val.verdict)}`} icon={<XCircle size={20} aria-hidden />}>
        Guardian re-plans after a failure, up to three attempts, and then hands the finding to a person. Nothing was changed in your repository.
      </Callout>
    );
  return null;
}

function Timeline({ attempts }: { attempts: Attempt[] }) {
  const steps: { key: string; title: string; sub: string; cls: string }[] = [];
  attempts.forEach((a, i) => {
    const sm = planSummary(a.plan, undefined, null);
    const what = `${sm.verb} ${sm.pkg}${sm.to ? ` to ${sm.to}` : ""}`;
    const s = !a.val
      ? { cls: "gate", label: "Waiting for validation" }
      : a.val.verdict === "verified"
        ? { cls: "ok", label: "Verified" }
        : { cls: "bad", label: `Failed: ${failWord(a.val.verdict)}` };
    steps.push({ key: a.plan.plan_id, title: `Attempt ${a.plan.attempt}: ${what}`, sub: s.label, cls: s.cls });
    const next = attempts[i + 1];
    if (next && a.val && a.val.verdict !== "verified") steps.push({ key: `re-${i}`, title: "Guardian re-plans", sub: "Tries a different version", cls: "" });
  });
  return (
    <ol className="timeline" aria-label="Attempts in order">
      {steps.map((s) => (
        <li key={s.key} className={`tl ${s.cls}`}>
          <span className="tl-dot" aria-hidden>
            {s.cls === "ok" ? <Check size={12} /> : s.cls === "bad" ? <XCircle size={12} /> : null}
          </span>
          <span className="tl-title">{s.title}</span>
          <span className="tl-sub">{s.sub}</span>
        </li>
      ))}
    </ol>
  );
}

function AttemptDetail({ attempts }: { attempts: Attempt[] }) {
  const validated = attempts.filter((a) => a.val);
  const [idx, setIdx] = useState(Math.max(0, validated.length - 1));
  const a = validated[Math.min(idx, validated.length - 1)];
  if (!a || !a.val) return null;
  const v = a.val;
  return (
    <>
      {validated.length > 1 && (
        <div className="seg-tabs" role="tablist" aria-label="Attempt">
          {validated.map((x, i) => (
            <button key={x.plan.plan_id} role="tab" aria-selected={i === idx} className={i === idx ? "on" : ""} type="button" onClick={() => setIdx(i)}>
              Attempt {x.plan.attempt}
            </button>
          ))}
        </div>
      )}
      <div className="val-grid">
        <div className="val-col">
          <ScoreDrop key={v.attempt_id} v={v} />
          <Checks v={v} />
        </div>
        <div className="val-col">
          <SbomDiff id={v.sbom_diff_evidence_id} />
        </div>
      </div>
      <LogViewer ids={v.log_evidence_ids} />
    </>
  );
}

function ScoreDrop({ v }: { v: ValidationResult }) {
  const [now, setNow] = useState(v.risk_before);
  useEffect(() => {
    const id = requestAnimationFrame(() => setNow(v.risk_after));
    return () => cancelAnimationFrame(id);
  }, [v.risk_after]);
  const shown = useCountTween(now);
  // the sentence uses the same rounded numbers the reader sees, so "68 to 8" always says "down 60"
  const dropped = Math.round(v.risk_before) - Math.round(v.risk_after);
  return (
    <Section title="Risk score before and after">
      <div className="drop-nums">
        <span className="num drop-before">{v.risk_before.toFixed(0)}</span>
        <span aria-hidden className="faint">to</span>
        <span className={`num drop-after ${dropped > 0 ? "good" : "bad"}`}>{shown.toFixed(0)}</span>
        <span className="muted">{dropped > 0 ? `down ${dropped.toFixed(0)} points` : dropped < 0 ? `up ${(-dropped).toFixed(0)} points` : "no change"}</span>
      </div>
      <div className="drop-track" role="img" aria-label={`Risk before ${v.risk_before}, after ${v.risk_after}`}>
        <span className="drop-ghost" style={{ width: `${v.risk_before}%` }} />
        <span className="drop-fill" style={{ width: `${now}%` }} />
      </div>
      <div className="drop-scale mono"><span>0</span><span>50</span><span>100</span></div>
    </Section>
  );
}

const tests = (t: Record<string, number>) => {
  const e = Object.entries(t);
  return e.length ? e.map(([k, n]) => `${n} ${k}`).join(", ") : "not run";
};

interface SandboxTestFacts {
  failing_tests?: Record<string, string[]>;
  baseline?: { unit_tests?: Record<string, number>; integration_tests?: Record<string, number> } | null;
  notes?: string[];
}

/** Test rows judged against the unpatched project: failures that happen without the fix are not the fix's. */
function testRow(counts: Record<string, number>, phase: "test" | "integration", f: SandboxTestFacts | null) {
  if (!Object.keys(counts).length) return { text: "Not run", ok: null as boolean | null };
  const base = phase === "test" ? f?.baseline?.unit_tests : f?.baseline?.integration_tests;
  const label = phase === "test" ? "unit" : "integration";
  if (f?.notes?.some((n) => n.startsWith(phase === "test" ? "test suite" : "integration suite")))
    return { text: `Not runnable in the sandbox (fails the same way without the fix)`, ok: null };
  const failed = counts.failed ?? 0;
  if (!failed) return { text: tests(counts), ok: true };
  const newOnes = f?.failing_tests?.new_vs_baseline ?? null;
  if (base && newOnes && newOnes.length === 0)
    return { text: `${tests(counts)}: all ${failed} already fail without the fix, none caused by it`, ok: true };
  return { text: `${tests(counts)}${newOnes?.length ? ` (${newOnes.length} new ${label} failure${newOnes.length === 1 ? "" : "s"})` : ""}`, ok: false };
}

function Checks({ v }: { v: ValidationResult }) {
  const ev = useEvidenceMany(v.log_evidence_ids);
  const facts = (ev.items.find((e) => e.kind === "test_result" && e.source_tool === "sandbox:docker")?.facts ??
    null) as SandboxTestFacts | null;
  const unit = testRow(v.unit_tests, "test", facts);
  const integ = testRow(v.integration_tests, "integration", facts);
  const row = (k: string, val: string, ok?: boolean | null) => (
    <div>
      <dt>{k}</dt>
      <dd className={ok === true ? "good" : ok === false ? "bad" : ""}>
        {ok === true && <Check size={14} aria-hidden />}
        {ok === false && <AlertTriangle size={14} aria-hidden />} {val}
      </dd>
    </div>
  );
  return (
    <Section title="What was checked">
      <dl className="facts">
        {row("Build", v.build_ok == null ? "Not run" : v.build_ok ? "Passed" : "Failed", v.build_ok)}
        {row("Unit tests", unit.text, unit.ok)}
        {row("Integration tests", integ.text, integ.ok)}
        {row("Vulnerability gone after re-scan", v.target_finding_resolved ? "Yes" : "No", v.target_finding_resolved)}
        {row("New findings introduced", v.new_findings.length ? String(v.new_findings.length) : "None", v.new_findings.length === 0)}
        {row("Guardian's confidence", v.final_confidence)}
      </dl>
      {facts?.notes?.length ? (
        <ul className="muted check-notes">
          {facts.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      ) : null}
    </Section>
  );
}

interface SbomFacts {
  added?: string[];
  removed?: string[];
  changed?: { name: string; from: string; to: string }[];
  components_before?: number;
  components_after?: number;
}

function SbomDiff({ id }: { id: string | null }) {
  const st = useEvidence(id);
  const head = "Packages before and after";
  if (!id)
    return (
      <Section title={head}>
        <p className="muted">No comparison was recorded, because the build or re-scan did not run.</p>
      </Section>
    );
  if (st.status === "loading")
    return (
      <Section title={head}>
        <Skeleton h={120} />
      </Section>
    );
  if (st.status !== "ok")
    return (
      <Section title={head}>
        <p className="muted">The comparison record is not available.</p>
      </Section>
    );
  const f = st.ev.facts as SbomFacts;
  const rows: { kind: string; name: string; from: string; to: string }[] = [];
  const split = (p: string) => {
    const l = p.replace(/^pkg:[^/]+\//, "");
    const i = l.lastIndexOf("@");
    return i > 0 ? [decodeURIComponent(l.slice(0, i)), l.slice(i + 1)] : [l, ""];
  };
  for (const c of f.changed ?? []) rows.push({ kind: "changed", name: c.name, from: c.from, to: c.to });
  for (const p of f.removed ?? []) {
    const [n, ver] = split(p);
    rows.push({ kind: "removed", name: n, from: ver, to: "" });
  }
  for (const p of f.added ?? []) {
    const [n, ver] = split(p);
    rows.push({ kind: "added", name: n, from: "", to: ver });
  }
  const WORD: Record<string, string> = { changed: "Updated", removed: "Removed", added: "Added" };
  return (
    <Section title={head}>
      <p className="muted sbom-count">
        <span className="num">{f.components_before ?? "?"}</span> packages before, <span className="num">{f.components_after ?? "?"}</span> after.
      </p>
      <div className="sbom-scroll">
        <table className="sbom">
          <thead>
            <tr><th>Change</th><th>Package</th><th>Before</th><th>After</th></tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={4} className="muted">No packages changed.</td></tr>
            )}
            {rows.slice(0, 300).map((r, i) => (
              <tr key={`${r.kind}-${r.name}-${i}`} className={`sb-${r.kind}`}>
                <td>{WORD[r.kind]}</td>
                <td className="mono">{r.name}</td>
                <td className="mono">{r.from}</td>
                <td className="mono">{r.to}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

function LogViewer({ ids }: { ids: string[] }) {
  const ev = useEvidenceMany(ids);
  const logs = ev.items.filter((e) => e.kind === "build_log" || e.kind === "test_result" || e.excerpt);
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState(0);
  const [q, setQ] = useState("");
  const cur: Evidence | undefined = logs[Math.min(tab, logs.length - 1)];
  const lines = useMemo(() => (cur?.excerpt ?? "").replace(/\r/g, "").split("\n"), [cur]);
  const t = q.trim().toLowerCase();
  const hits = t ? lines.filter((l) => l.toLowerCase().includes(t)).length : 0;
  return (
    <section className="sec logs">
      <button type="button" className="logs-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
        <h3>Build and test logs</h3>
        <span className="faint">{ev.loaded ? `${logs.length} ${logs.length === 1 ? "log" : "logs"}` : "loading"}. For engineers: open to read the raw output.</span>
      </button>
      {open &&
        (!ev.loaded ? (
          <Skeleton h={160} />
        ) : !cur ? (
          <p className="muted">No logs were recorded for this attempt.</p>
        ) : (
          <>
            <div className="log-tools">
              <div className="seg-tabs" role="tablist" aria-label="Log">
                {logs.map((l, i) => (
                  <button key={l.evidence_id} role="tab" type="button" aria-selected={i === tab} className={i === tab ? "on" : ""} onClick={() => setTab(i)}>
                    {evidenceTitle(l)}
                  </button>
                ))}
              </div>
              <span className="searchbox">
                <Search size={16} aria-hidden />
                <input type="search" placeholder="Search this log" aria-label="Search this log" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} />
              </span>
              {t && <span className="muted">{hits} matching {hits === 1 ? "line" : "lines"}</span>}
            </div>
            {cur.excerpt ? (
              <pre className="log" tabIndex={0}>
                {lines.map((ln, i) => {
                  const hit = t && ln.toLowerCase().includes(t);
                  return (
                    <span key={i} className={`ll${hit ? " hit" : ""}${/\b(error|fail(ed|ure)?|fatal)\b/i.test(ln) ? " err" : /\bwarn(ing)?\b/i.test(ln) ? " warn" : ""}`}>
                      <span className="ln num">{i + 1}</span>
                      {ln || " "}
                    </span>
                  );
                })}
              </pre>
            ) : (
              <Json value={cur.facts} collapsedLines={14} />
            )}
            <p className="faint mono">Produced by {cur.source_tool}</p>
          </>
        ))}
    </section>
  );
}
