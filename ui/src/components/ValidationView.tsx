import { useEffect, useMemo, useState } from "react";
import type { Evidence, RemediationPlan, ValidationResult } from "../api/types";
import { findingHeadline } from "../lib/format";
import { useStore } from "../store";
import { useCountTween, useEvidence, useEvidenceMany } from "./hooks";
import { EvChip, Json, Section } from "./ui";

const VERDICT_CLASS: Record<string, string> = { verified: "ok" };

interface Attempt {
  plan: RemediationPlan;
  val: ValidationResult | undefined;
}

export default function ValidationView() {
  const { data, findingsById } = useStore();
  const ids = useMemo(() => [...new Set(data.plans.map((p) => p.finding_id))], [data.plans]);
  const [fid, setFid] = useState<string | null>(null);
  const current = fid && ids.includes(fid) ? fid : (ids.find((i) => data.validation.some((v) => v.finding_id === i)) ?? ids[0]);

  if (!ids.length)
    return (
      <div className="empty">
        <strong>Nothing validated yet</strong>
        <span>Validation results appear after a plan is approved and the validator re-checks a patched copy.</span>
      </div>
    );

  const attempts: Attempt[] = data.plans
    .filter((p) => p.finding_id === current)
    .map((plan) => ({ plan, val: data.validation.find((v) => v.plan_id === plan.plan_id) }));
  const f = findingsById.get(current);

  return (
    <div className="val">
      <header className="val-head">
        <h2>Validation</h2>
        <label className="select-row">
          <span className="muted">Finding</span>
          <select value={current} onChange={(e) => setFid(e.target.value)}>
            {ids.map((i) => {
              const g = findingsById.get(i);
              return (
                <option key={i} value={i}>
                  {g ? `${findingHeadline(g)} (${g.category})` : i}
                </option>
              );
            })}
          </select>
        </label>
        {f && <span className="muted val-title">{f.title}</span>}
      </header>
      <Timeline attempts={attempts} />
      <AttemptDetail key={current} attempts={attempts} />
    </div>
  );
}

function stepOf(a: Attempt) {
  if (!a.val) return { cls: "gate", label: "Awaiting validation" };
  if (a.val.verdict === "verified") return { cls: "ok", label: "Verified" };
  return { cls: "bad", label: `Failed (${a.val.verdict.replace(/_/g, " ")})` };
}

function Timeline({ attempts }: { attempts: Attempt[] }) {
  const steps: { key: string; title: string; sub: string; cls: string }[] = [];
  attempts.forEach((a, i) => {
    const s = stepOf(a);
    steps.push({ key: a.plan.plan_id, title: `Attempt ${a.plan.attempt}`, sub: s.label, cls: s.cls });
    const next = attempts[i + 1];
    if (next) steps.push({ key: `re-${i}`, title: "Re-plan", sub: `${next.plan.action}${next.plan.target_version ? ` ${next.plan.target_version}` : ""}`, cls: "" });
  });
  return (
    <ol className="timeline" aria-label="Attempt timeline">
      {steps.map((s) => (
        <li key={s.key} className={`tl ${s.cls}`}>
          <span className="tl-dot" aria-hidden />
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
  if (!a || !a.val)
    return (
      <div className="empty">
        <strong>No validation result for this finding yet</strong>
        <span>The latest plan has not been validated.</span>
      </div>
    );
  const v = a.val;
  return (
    <div className="val-grid">
      <div className="val-col">
        {validated.length > 1 && (
          <div className="seg-tabs" role="tablist" aria-label="Attempt">
            {validated.map((x, i) => (
              <button
                key={x.plan.plan_id}
                role="tab"
                aria-selected={i === idx}
                className={i === idx ? "on" : ""}
                type="button"
                onClick={() => setIdx(i)}
              >
                Attempt {x.plan.attempt}
              </button>
            ))}
          </div>
        )}
        <ScoreDrop key={v.attempt_id} v={v} />
        <Checks v={v} />
        <SbomDiff id={v.sbom_diff_evidence_id} />
      </div>
      <div className="val-col">
        <LogViewer ids={v.log_evidence_ids} />
      </div>
    </div>
  );
}

function ScoreDrop({ v }: { v: ValidationResult }) {
  const [now, setNow] = useState(v.risk_before);
  useEffect(() => {
    const id = requestAnimationFrame(() => setNow(v.risk_after));
    return () => cancelAnimationFrame(id);
  }, [v.risk_after]);
  const shown = useCountTween(now);
  const dropped = v.risk_before - v.risk_after;
  return (
    <Section title="Risk score" aside={<span className={`pill ${VERDICT_CLASS[v.verdict] ?? "bad"}`}>{v.verdict.replace(/_/g, " ")}</span>}>
      <div className="drop">
        <div className="drop-nums">
          <span className="num drop-before">{v.risk_before.toFixed(1)}</span>
          <span aria-hidden className="drop-arrow">to</span>
          <span className={`num drop-after ${v.risk_after < v.risk_before ? "good" : "bad"}`}>{shown.toFixed(1)}</span>
          <span className="muted">{dropped > 0 ? `down ${dropped.toFixed(1)} points` : dropped < 0 ? `up ${(-dropped).toFixed(1)} points` : "unchanged"}</span>
        </div>
        <div className="drop-track" role="img" aria-label={`Risk before ${v.risk_before}, after ${v.risk_after}`}>
          <span className="drop-ghost" style={{ width: `${v.risk_before}%` }} />
          <span className="drop-fill" style={{ width: `${now}%` }} />
        </div>
        <div className="drop-scale mono">
          <span>0</span>
          <span>40</span>
          <span>60</span>
          <span>80</span>
          <span>100</span>
        </div>
      </div>
    </Section>
  );
}

function tests(t: Record<string, number>): string {
  const e = Object.entries(t);
  return e.length ? e.map(([k, n]) => `${n} ${k}`).join(", ") : "not run";
}

function Checks({ v }: { v: ValidationResult }) {
  const row = (k: string, val: string, cls?: string) => (
    <div>
      <dt>{k}</dt>
      <dd className={cls}>{val}</dd>
    </div>
  );
  return (
    <Section title="Checks">
      <dl className="facts">
        {row("Build", v.build_ok == null ? "not run" : v.build_ok ? "passed" : "failed", v.build_ok === false ? "bad" : v.build_ok ? "good" : "")}
        {row("Unit tests", tests(v.unit_tests), "mono")}
        {row("Integration tests", tests(v.integration_tests), "mono")}
        {row("Target finding resolved", v.target_finding_resolved ? "yes" : "no", v.target_finding_resolved ? "good" : "bad")}
        {row("New findings", v.new_findings.length ? String(v.new_findings.length) : "none", v.new_findings.length ? "bad" : "")}
        {row("Final confidence", v.final_confidence)}
        {v.artifact_rescanned && row("Artifact rescanned", v.artifact_rescanned, "mono")}
      </dl>
      {v.detector_evidence_ids.length > 0 && (
        <p className="muted detectors">
          Detector re-runs:{" "}
          {v.detector_evidence_ids.slice(0, 4).map((e) => (
            <EvChip key={e} id={e} />
          ))}
          {v.detector_evidence_ids.length > 4 && ` +${v.detector_evidence_ids.length - 4}`}
        </p>
      )}
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
  if (!id)
    return (
      <Section title="SBOM before and after">
        <p className="muted">No SBOM diff recorded for this attempt (build and rescan were not run).</p>
      </Section>
    );
  if (st.status !== "ok")
    return (
      <Section title="SBOM before and after">
        <p className="muted">{st.status === "loading" ? "Loading" : "SBOM diff evidence is not available."}</p>
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
  return (
    <Section title="SBOM before and after" aside={<EvChip id={st.ev.evidence_id} />}>
      <p className="muted sbom-count">
        Components <span className="num">{f.components_before ?? "?"}</span> to <span className="num">{f.components_after ?? "?"}</span>
      </p>
      <div className="sbom-scroll">
        <table className="sbom">
          <thead>
            <tr>
              <th>Change</th>
              <th>Package</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No component changes.
                </td>
              </tr>
            )}
            {rows.slice(0, 300).map((r, i) => (
              <tr key={`${r.kind}-${r.name}-${i}`} className={`sb-${r.kind}`}>
                <td>{r.kind}</td>
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
  const [tab, setTab] = useState(0);
  const cur: Evidence | undefined = logs[Math.min(tab, logs.length - 1)];
  return (
    <Section title="Build and test logs">
      {!ev.loaded ? (
        <p className="muted">Loading</p>
      ) : !cur ? (
        <p className="muted">No log evidence for this attempt.</p>
      ) : (
        <>
          <div className="seg-tabs" role="tablist" aria-label="Log">
            {logs.map((l, i) => (
              <button key={l.evidence_id} role="tab" type="button" aria-selected={i === tab} className={i === tab ? "on" : ""} onClick={() => setTab(i)}>
                {l.kind}
              </button>
            ))}
          </div>
          {cur.excerpt ? (
            <pre className="log" tabIndex={0}>
              {cur.excerpt.replace(/\r/g, "").split("\n").map((ln, i) => (
                <span key={i} className={`ll${/\b(error|fail(ed|ure)?|fatal)\b/i.test(ln) ? " err" : /\b(warn(ing)?)\b/i.test(ln) ? " warn" : /\b(pass(ed)?|ok|success)\b/i.test(ln) ? " pass" : ""}`}>
                  <span className="ln num">{i + 1}</span>
                  {ln || " "}
                </span>
              ))}
            </pre>
          ) : (
            <Json value={cur.facts} collapsedLines={14} />
          )}
          <p className="muted mono">
            {cur.source_tool} · <EvChip id={cur.evidence_id} />
          </p>
        </>
      )}
    </Section>
  );
}
