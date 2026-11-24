import { ChevronDown, ChevronUp, MapPin, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Finding } from "../api/types";
import { bandOf, purlLabel, purlName, purlVersion } from "../lib/format";
import { BAND_COPY, CATEGORY_WHY, categoryLabel, evidenceTitle, findingRef, isMachineSummary, plainTitle, scoreExplainer, statusText } from "../lib/labels";
import { planSummary } from "../lib/plan";
import { useStore } from "../store";
import { inertProps, typingTarget, useEvidence } from "./hooks";
import { BandScale, FactorTable } from "./RiskTable";
import { ClaimList, EmptyState, EvidenceById, Section, SevPill, Tip } from "./ui";

export default function Inspector() {
  const { inspector, closeInspector, stepFinding } = useStore();
  const open = !!inspector;
  const panel = useRef<HTMLElement>(null);
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeInspector();
      } else if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !typingTarget(e.target) && inspector?.kind === "finding") {
        e.preventDefault();
        e.stopPropagation();
        stepFinding(e.key === "ArrowDown" ? 1 : -1);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [open, inspector, closeInspector, stepFinding]);

  useEffect(() => {
    if (open) {
      if (!panel.current?.contains(document.activeElement)) opener.current = document.activeElement;
      panel.current?.focus({ preventScroll: true });
    } else if (opener.current instanceof HTMLElement) {
      opener.current.focus({ preventScroll: true });
      opener.current = null;
    }
  }, [open]);

  useEffect(() => {
    if (open) panel.current?.querySelector(".insp-body")?.scrollTo({ top: 0 });
  }, [inspector?.id, inspector?.kind, open]);

  return (
    <>
      <div className={`scrim${open ? " on" : ""}`} onClick={closeInspector} aria-hidden />
      <aside
        ref={panel}
        tabIndex={-1}
        className={`insp${open ? " open" : ""}`}
        aria-label="Finding details"
        aria-hidden={!open}
        {...(open ? {} : inertProps)}
      >
        {inspector?.kind === "finding" && <FindingPane key={inspector.id} id={inspector.id} />}
        {inspector?.kind === "evidence" && <EvidencePane key={inspector.id} id={inspector.id} />}
        {inspector?.kind === "node" && <NodePane key={inspector.id} id={inspector.id} />}
      </aside>
    </>
  );
}

function Head({ children, onPrev, onNext }: { children: ReactNode; onPrev?: () => void; onNext?: () => void }) {
  const { closeInspector } = useStore();
  return (
    <header className="insp-head">
      <div className="insp-title">{children}</div>
      <div className="insp-actions">
        {onPrev && (
          <>
            <Tip text="Previous finding (Up arrow)" side="bottom">
              <button type="button" className="btn ghost icon" onClick={onPrev} aria-label="Previous finding">
                <ChevronUp size={16} aria-hidden />
              </button>
            </Tip>
            <Tip text="Next finding (Down arrow)" side="bottom">
              <button type="button" className="btn ghost icon" onClick={onNext} aria-label="Next finding">
                <ChevronDown size={16} aria-hidden />
              </button>
            </Tip>
          </>
        )}
        <Tip text="Close (Esc)" side="bottom">
          <button type="button" className="btn ghost icon" onClick={closeInspector} aria-label="Close details">
            <X size={16} aria-hidden />
          </button>
        </Tip>
      </div>
    </header>
  );
}

function HowItGetsIn({ finding }: { finding: Finding }) {
  const { selectNodeOnly, nodesById, showInGraph, closeInspector } = useStore();
  const paths = finding.dependency_paths;
  const [all, setAll] = useState(false);
  if (!paths.length)
    return (
      <p className="muted">
        This is not a package dependency.{" "}
        {finding.file_path && (
          <>
            It was found in <span className="mono">{finding.file_path}{finding.line ? `:${finding.line}` : ""}</span>.
          </>
        )}
      </p>
    );
  const shown = all ? paths : paths.slice(0, 1);
  const last = paths[0][paths[0].length - 1];
  return (
    <div className="howin">
      <p className="sec-lead">
        {paths[0].length > 2
          ? "Your project does not use this package directly. It arrives through other packages, in this order:"
          : "Your project depends on this package directly:"}
      </p>
      {shown.map((p, k) => (
        <ol key={k} className="crumbs" aria-label="Dependency path">
          {p.map((id, i) => (
            <li key={`${id}-${i}`}>
              <button
                type="button"
                className={i === p.length - 1 ? "crumb last" : "crumb"}
                title={id}
                onClick={() => {
                  selectNodeOnly(id);
                  if (nodesById.has(id)) {
                    closeInspector();
                    showInGraph(id);
                  }
                }}
              >
                {i === 0 ? <span className="faint">project </span> : null}
                {purlName(id) === id ? purlLabel(id) : `${purlName(id)} ${purlVersion(id)}`}
              </button>
            </li>
          ))}
        </ol>
      ))}
      {paths.length > 1 && (
        <button type="button" className="btn ghost sm" onClick={() => setAll(!all)}>
          {all ? "Show only the first route" : `${paths.length - 1} more route${paths.length > 2 ? "s" : ""} to this package`}
        </button>
      )}
      <button
        type="button"
        className="btn sm"
        onClick={() => {
          closeInspector();
          showInGraph(last);
        }}
      >
        <MapPin size={14} aria-hidden /> Show in dependency map
      </button>
    </div>
  );
}

function FindingPane({ id }: { id: string }) {
  const { findingsById, riskById, stepFinding, data, setView, openFinding, nodesById, order, closeInspector } = useStore();
  const f = findingsById.get(id);
  const risk = riskById.get(id);
  const [openEv, setOpenEv] = useState<Set<string>>(new Set());
  const [showAllEv, setShowAllEv] = useState(false);

  const evidenceIds = useMemo(() => {
    if (!f) return [];
    const ids = new Set<string>(f.evidence_ids);
    if (risk) {
      for (const k of ["S", "E", "R", "P", "X"] as const) risk.factors[k].evidence_ids.forEach((e) => ids.add(e));
      risk.factors.provenance_evidence_ids.forEach((e) => ids.add(e));
      risk.claims.forEach((c) => c.evidence_ids.forEach((e) => ids.add(e)));
    }
    f.claims.forEach((c) => c.evidence_ids.forEach((e) => ids.add(e)));
    return [...ids];
  }, [f, risk]);

  const cite = useCallback(
    (evId: string) => {
      setShowAllEv(true);
      setOpenEv((p) => new Set(p).add(evId));
      window.setTimeout(() => document.getElementById(`evw-${evId}`)?.scrollIntoView({ block: "center", behavior: "smooth" }), 80);
    },
    [],
  );

  if (!f)
    return (
      <>
        <Head>
          <h2>Finding not found</h2>
        </Head>
        <div className="insp-body"><EmptyState title="This finding is no longer in the scan">Close this panel and pick another one.</EmptyState></div>
      </>
    );

  const band = bandOf(f, riskById);
  const node = f.component_purl ? nodesById.get(f.component_purl) : undefined;
  const siblings = (node?.finding_ids ?? []).filter((x) => x !== id && findingsById.has(x));
  const plans = data.plans.filter((p) => p.finding_id === id);
  const pos = order.indexOf(id);
  const name = f.component_purl ? purlName(f.component_purl) : "";
  const ver = f.component_purl ? purlVersion(f.component_purl) : "";
  const lead =
    f.explanation ??
    (risk?.summary && !isMachineSummary(risk.summary) ? risk.summary : null) ??
    (f.category === "cve" && name
      ? `${name} ${ver} is affected by ${f.vuln_id ?? "a known advisory"}.${f.fixed_versions.length ? ` A fixed version exists: ${f.fixed_versions.join(", ")}.` : " No fixed version is listed yet."}`
      : (CATEGORY_WHY[f.category] ?? f.title));
  const claims = f.claims.length ? f.claims : (risk?.claims ?? []);
  const shownEv = showAllEv ? evidenceIds : evidenceIds.slice(0, 5);
  const fromInvestigator = !!f.explanation;

  return (
    <>
      <Head onPrev={() => stepFinding(-1)} onNext={() => stepFinding(1)}>
        <div className="insp-pills">
          {risk ? (
            <Tip text="Guardian's risk level and its 0 to 100 score for your project" side="bottom">
              <span className={`pill sev-${risk.band}`}>
                {BAND_COPY[risk.band].name} risk <span className="num">· {risk.score.toFixed(0)}</span>
              </span>
            </Tip>
          ) : (
            <SevPill risk={band} />
          )}
          <span className="pill">{categoryLabel(f.category)}</span>
          <span className={`pill${f.scope === "dev" ? " dashed" : ""}`}>{f.scope === "prod" ? "Production" : f.scope === "dev" ? "Dev only" : "Scope unknown"}</span>
          {pos >= 0 && <span className="faint num">{pos + 1} of {order.length}</span>}
        </div>
        <h2>{plainTitle(f, band)}</h2>
        <p className="mono faint insp-ref">{findingRef(f)}</p>
      </Head>
      <div className="insp-body">
        {risk && <RiskVerdict finding={f} />}
        <Section title="What this means">
          {fromInvestigator && <p className="lead-src faint">The investigator's notes</p>}
          <p className="prose">{lead}</p>
          <dl className="facts">
            {f.component_purl && <Fact k="Package" v={`${name} ${ver}`.trim()} mono />}
            {f.affected_range && <Fact k="Affected versions" v={f.affected_range} mono />}
            {f.fixed_versions.length > 0 && <Fact k="Fixed in" v={f.fixed_versions.join(", ")} mono good />}
            {f.cvss != null && (
              <Fact
                k="Advisory rating"
                v={`CVSS ${f.cvss.toFixed(1)}${f.severity ? ` (${f.severity})` : ""}, before your project's context`}
                mono
              />
            )}
            {f.aliases.length > 0 && <Fact k="Also known as" v={f.aliases.join(", ")} mono />}
            {f.file_path && <Fact k="Found in" v={`${f.file_path}${f.line ? `:${f.line}` : ""}`} mono />}
          </dl>
          {claims.length > 0 && (
            <div className="claimsblock">
              <h4 className="mini-h">What Guardian concluded</h4>
              <ClaimList claims={claims} onCite={cite} />
            </div>
          )}
        </Section>

        {risk && (
          <Section
            id="score-detail"
            title={`How the score of ${risk.score.toFixed(0)} adds up`}
            lead="Each factor earns points up to its own maximum. The points add up to the score out of 100."
          >
            <FactorTable risk={risk} finding={f} onCite={cite} />
          </Section>
        )}

        <Section title="How it gets in">
          <HowItGetsIn finding={f} />
        </Section>

        <Section title={`Evidence (${evidenceIds.length})`} lead="The records behind every statement above. Open one to read the source.">
          {evidenceIds.length === 0 && <p className="muted">No evidence records are attached to this finding.</p>}
          <div className="evstack">
            {shownEv.map((e) => (
              <div key={e} id={`evw-${e}`}>
                <EvidenceById
                  id={e}
                  open={openEv.has(e)}
                  onToggle={(o) =>
                    setOpenEv((p) => {
                      const n = new Set(p);
                      if (o) n.add(e);
                      else n.delete(e);
                      return n;
                    })
                  }
                />
              </div>
            ))}
          </div>
          {evidenceIds.length > 5 && (
            <button type="button" className="btn ghost sm" onClick={() => setShowAllEv(!showAllEv)}>
              {showAllEv ? "Show fewer" : `Show all ${evidenceIds.length} records`}
            </button>
          )}
        </Section>

        <Section title="More">
          <details className="more">
            <summary>Technical details</summary>
            <dl className="facts">
              <Fact k="Finding id" v={f.finding_id} mono />
              <Fact k="Found by" v={f.detector} mono />
              {f.component_purl && <Fact k="Package URL" v={f.component_purl} mono />}
              <Fact k="Status" v={statusText(f.status)} />
              {f.initial_risk && <Fact k="First rating" v={`${f.initial_risk} (${f.initial_risk_source === "llm" ? "AI" : "rule"})`} />}
            </dl>
          </details>
          {plans.length > 0 && (
            <div className="plans-note">
              <h4 className="mini-h">Proposed fix</h4>
              <ul className="plain">
                {plans.map((p) => (
                  <li key={p.plan_id}>
                    Attempt {p.attempt}: {planSummary(p, undefined, null).change}{" "}
                    <button type="button" className="btn ghost sm" onClick={() => { closeInspector(); setView("gate"); }}>Open remediation</button>
                    <button type="button" className="btn ghost sm" onClick={() => { closeInspector(); setView("validation"); }}>Open validation</button>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {siblings.length > 0 && (
            <div className="plans-note">
              <h4 className="mini-h">Other findings on this package ({siblings.length})</h4>
              <ul className="plain">
                {siblings.slice(0, 12).map((s) => {
                  const g = findingsById.get(s)!;
                  return (
                    <li key={s}>
                      <button type="button" className="linkish" onClick={() => openFinding(s)}>
                        <SevPill risk={bandOf(g, riskById)} /> {plainTitle(g, bandOf(g, riskById))}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </Section>
      </div>
    </>
  );
}

/** The risk level up front: score, where it sits on the scale, and why it differs from the advisory's rating. */
function RiskVerdict({ finding }: { finding: Finding }) {
  const { riskById } = useStore();
  const risk = riskById.get(finding.finding_id);
  if (!risk) return null;
  const first = finding.initial_risk;
  const firstDiffers = first && first !== risk.band;
  return (
    <section className="sec verdict" aria-label="Risk level">
      <div className="verdict-top">
        <span className={`verdict-score num t-${risk.band}`}>{risk.score.toFixed(0)}</span>
        <span className="verdict-of faint">/ 100</span>
        <span className="verdict-words">
          <b className={`t-${risk.band}`}>{BAND_COPY[risk.band].name} risk</b>
          <span className="muted">{BAND_COPY[risk.band].line}</span>
        </span>
      </div>
      <BandScale score={risk.score} band={risk.band} />
      <p className="prose verdict-why">{scoreExplainer(finding, risk)}</p>
      {firstDiffers && (
        <p className="verdict-note faint">
          The investigator's first read was {BAND_COPY[first].name}, before Guardian checked how your code uses the package. This
          score replaces it.
        </p>
      )}
      <button
        type="button"
        className="linkish verdict-link"
        onClick={() => document.getElementById("score-detail")?.scrollIntoView({ behavior: "smooth", block: "start" })}
      >
        See how the score adds up
      </button>
    </section>
  );
}

function Fact({ k, v, mono, good }: { k: string; v: string; mono?: boolean; good?: boolean }) {
  return (
    <div>
      <dt>{k}</dt>
      <dd className={`${mono ? "mono" : ""}${good ? " good" : ""}`}>{v}</dd>
    </div>
  );
}

function EvidencePane({ id }: { id: string }) {
  const { data, openFinding, riskById } = useStore();
  const st = useEvidence(id);
  const refs = data.findings.filter((f) => f.evidence_ids.includes(id) || f.claims.some((c) => c.evidence_ids.includes(id)));
  const title = st.status === "ok" ? evidenceTitle(st.ev) : "Evidence";
  return (
    <>
      <Head>
        <div className="insp-pills"><span className="claim-tag v">Source record</span></div>
        <h2>{title}</h2>
        <p className="muted">The original record behind a statement Guardian made.</p>
      </Head>
      <div className="insp-body">
        <EvidenceById id={id} startOpen />
        {refs.length > 0 && (
          <Section title="Used by these findings">
            <ul className="plain">
              {refs.slice(0, 20).map((f) => (
                <li key={f.finding_id}>
                  <button type="button" className="linkish" onClick={() => openFinding(f.finding_id)}>
                    <SevPill risk={bandOf(f, riskById)} /> {plainTitle(f, bandOf(f, riskById))}
                  </button>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </div>
    </>
  );
}

const NODE_KIND: Record<string, string> = { package: "Package", project: "Project", ci: "CI workflow", image: "Container image", config: "Config file" };

function NodePane({ id }: { id: string }) {
  const { nodesById, closeInspector } = useStore();
  const n = nodesById.get(id);
  return (
    <>
      <Head>
        <div className="insp-pills">
          <span className="pill">{n ? (NODE_KIND[n.kind] ?? n.kind) : "Item"}</span>
          {n?.scope && <span className={`pill${n.scope === "dev" ? " dashed" : ""}`}>{n.scope === "prod" ? "Production" : n.scope === "dev" ? "Dev only" : "Scope unknown"}</span>}
        </div>
        <h2>{n ? `${n.label}${n.version ? ` ${n.version}` : ""}` : id}</h2>
      </Head>
      <div className="insp-body">
        <Section title="What this is">
          <p className="prose">
            {n?.kind === "project"
              ? "A project in the repository. Its dependencies are drawn to the right of it in the map."
              : "This item has no findings. It is shown so you can see how the rest of the map connects."}
          </p>
          <dl className="facts">
            {n?.ecosystem && <Fact k="Ecosystem" v={n.ecosystem} />}
            {n?.project && <Fact k="Project" v={n.project} />}
            {n?.direct != null && n.kind === "package" && <Fact k="How it is used" v={n.direct ? "Chosen directly by the project" : "Pulled in by another package"} />}
            {n?.has_install_script && <Fact k="Install script" v="Runs code when installed" />}
            {n?.deprecated && <Fact k="Deprecated" v="Yes, the maintainers recommend not using it" />}
            {n?.origin && <Fact k="Origin" v={n.origin} mono />}
          </dl>
          <button type="button" className="btn ghost sm" onClick={closeInspector}>Close</button>
        </Section>
        <Section title="Technical details">
          <dl className="facts">
            <Fact k="Id" v={id} mono />
            {n?.integrity && <Fact k="Integrity hash" v={n.integrity} mono />}
          </dl>
        </Section>
      </div>
    </>
  );
}
