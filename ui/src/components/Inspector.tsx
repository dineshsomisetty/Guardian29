import { ChevronDown, ChevronUp, X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import type { Finding } from "../api/types";
import { bandOf, purlLabel } from "../lib/format";
import { useStore } from "../store";
import { inertProps } from "./hooks";
import RiskTable from "./RiskTable";
import { CatPill, ClaimList, ClaimMark, EvidenceById, Section, SevPill } from "./ui";

export default function Inspector() {
  const { inspector, closeInspector, stepFinding } = useStore();
  const open = !!inspector;
  const panel = useRef<HTMLElement>(null);
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    const typing = (t: EventTarget | null) => t instanceof HTMLElement && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeInspector();
      } else if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !typing(e.target) && inspector?.kind === "finding") {
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
        aria-label="Forensic Inspector"
        aria-hidden={!open}
        {...(open ? {} : inertProps)}
      >
        {inspector?.kind === "finding" && <FindingPane id={inspector.id} />}
        {inspector?.kind === "evidence" && <EvidencePane id={inspector.id} />}
        {inspector?.kind === "node" && <NodePane id={inspector.id} />}
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
            <button type="button" className="btn ghost icon" onClick={onPrev} aria-label="Previous finding" title="Previous (ArrowUp)">
              <ChevronUp size={16} aria-hidden />
            </button>
            <button type="button" className="btn ghost icon" onClick={onNext} aria-label="Next finding" title="Next (ArrowDown)">
              <ChevronDown size={16} aria-hidden />
            </button>
          </>
        )}
        <button type="button" className="btn ghost icon" onClick={closeInspector} aria-label="Close inspector" title="Close (Esc)">
          <X size={16} aria-hidden />
        </button>
      </div>
    </header>
  );
}

function Breadcrumb({ paths, finding }: { paths: string[][]; finding: Finding }) {
  const { selectNodeOnly, nodesById, setView } = useStore();
  if (!paths.length)
    return (
      <p className="muted">
        No dependency path.{" "}
        {finding.file_path && (
          <span className="mono">
            {finding.file_path}
            {finding.line ? `:${finding.line}` : ""}
          </span>
        )}
      </p>
    );
  const p = paths[0];
  return (
    <div className="crumbs">
      <ol aria-label="Dependency path">
        {p.map((id, i) => (
          <li key={`${id}-${i}`}>
            <button
              type="button"
              className={i === p.length - 1 ? "crumb last" : "crumb"}
              title={id}
              onClick={() => {
                selectNodeOnly(id);
                if (nodesById.has(id)) setView("graph");
              }}
            >
              {purlLabel(id)}
            </button>
          </li>
        ))}
      </ol>
      {paths.length > 1 && <p className="muted">{paths.length - 1} more path{paths.length > 2 ? "s" : ""} to this component.</p>}
    </div>
  );
}

function FindingPane({ id }: { id: string }) {
  const { findingsById, riskById, stepFinding, data, setView, openFinding, nodesById, order } = useStore();
  const f = findingsById.get(id);
  if (!f) return <Head>Finding not found</Head>;
  const risk = riskById.get(id);
  const band = bandOf(f, riskById);
  const node = f.component_purl ? nodesById.get(f.component_purl) : undefined;
  const siblings = (node?.finding_ids ?? []).filter((x) => x !== id && findingsById.has(x));
  const plans = data.plans.filter((p) => p.finding_id === id);
  const pos = order.indexOf(id);
  return (
    <>
      <Head onPrev={() => stepFinding(-1)} onNext={() => stepFinding(1)}>
        <div className="insp-pills">
          <SevPill risk={band} />
          <CatPill cat={f.category} />
          <span className={`pill scope-${f.scope}`}>{f.scope}</span>
          {pos >= 0 && (
            <span className="muted num">
              {pos + 1} / {order.length}
            </span>
          )}
        </div>
        <h2>{f.title}</h2>
        <p className="mono muted">{f.finding_id}</p>
      </Head>
      <div className="insp-body">
        <Section title="Dependency path">
          <Breadcrumb paths={f.dependency_paths} finding={f} />
        </Section>

        <Section title="Facts">
          <dl className="facts">
            {f.component_purl && <Fact k="Component" v={purlLabel(f.component_purl)} mono />}
            {f.vuln_id && <Fact k="Advisory" v={[f.vuln_id, ...f.aliases].join(", ")} mono />}
            {f.cvss != null && <Fact k="CVSS" v={`${f.cvss.toFixed(1)}${f.severity ? ` (${f.severity})` : ""}`} mono />}
            {f.affected_range && <Fact k="Affected" v={f.affected_range} mono />}
            {f.fixed_versions.length > 0 && <Fact k="Fixed in" v={f.fixed_versions.join(", ")} mono />}
            {f.file_path && <Fact k="Location" v={`${f.file_path}${f.line ? `:${f.line}` : ""}`} mono />}
            <Fact k="Detector" v={f.detector} mono />
            <Fact k="Status" v={f.status.replace("_", " ")} />
          </dl>
        </Section>

        {f.explanation && (
          <Section title="Analyst explanation" aside={<ClaimMark label="inferred" />}>
            <p className="prose">{f.explanation}</p>
          </Section>
        )}

        {risk && (
          <Section title={`Risk ${risk.score.toFixed(1)} / 100`} aside={<SevPill risk={risk.band} />}>
            <RiskTable risk={risk} />
          </Section>
        )}

        <Section title="Claims">
          <ClaimList claims={f.claims} />
        </Section>

        <Section title={`Evidence (${f.evidence_ids.length})`} aside={<ClaimMark label="verified" />}>
          <div className="evstack">
            {f.evidence_ids.map((e) => (
              <EvidenceById key={e} id={e} />
            ))}
          </div>
        </Section>

        {plans.length > 0 && (
          <Section title="Remediation">
            <ul className="plain">
              {plans.map((p) => (
                <li key={p.plan_id}>
                  Attempt {p.attempt}: <b>{p.action}</b>
                  {p.target_version ? <span className="mono"> to {p.target_version}</span> : null}{" "}
                  <button type="button" className="btn ghost sm" onClick={() => setView("gate")}>
                    Approval gate
                  </button>
                  <button type="button" className="btn ghost sm" onClick={() => setView("validation")}>
                    Validation
                  </button>
                </li>
              ))}
            </ul>
          </Section>
        )}

        {siblings.length > 0 && (
          <Section title={`Other findings on this component (${siblings.length})`}>
            <ul className="plain">
              {siblings.slice(0, 12).map((s) => {
                const g = findingsById.get(s)!;
                return (
                  <li key={s}>
                    <button type="button" className="linkish" onClick={() => openFinding(s)}>
                      <SevPill risk={bandOf(g, riskById)} /> <span className="mono">{g.vuln_id ?? g.title}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Section>
        )}
      </div>
    </>
  );
}

function Fact({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div>
      <dt>{k}</dt>
      <dd className={mono ? "mono" : undefined}>{v}</dd>
    </div>
  );
}

function EvidencePane({ id }: { id: string }) {
  const { data } = useStore();
  const refs = data.findings.filter((f) => f.evidence_ids.includes(id));
  const { openFinding } = useStore();
  return (
    <>
      <Head>
        <div className="insp-pills">
          <span className="fact-tag">Fact</span>
        </div>
        <h2>Evidence</h2>
        <p className="mono muted">{id}</p>
      </Head>
      <div className="insp-body">
        <EvidenceById id={id} startOpen />
        {refs.length > 0 && (
          <Section title="Cited by">
            <ul className="plain">
              {refs.slice(0, 20).map((f) => (
                <li key={f.finding_id}>
                  <button type="button" className="linkish" onClick={() => openFinding(f.finding_id)}>
                    {f.vuln_id ?? f.title}
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

function NodePane({ id }: { id: string }) {
  const { nodesById } = useStore();
  const n = nodesById.get(id);
  return (
    <>
      <Head>
        <div className="insp-pills">
          <span className="pill">{n?.kind ?? "node"}</span>
          {n?.scope && <span className={`pill scope-${n.scope}`}>{n.scope}</span>}
        </div>
        <h2>{n ? n.label : id}</h2>
        {n?.version && <p className="mono muted">{n.version}</p>}
      </Head>
      <div className="insp-body">
        <Section title="Component">
          <dl className="facts">
            <Fact k="Id" v={id} mono />
            {n?.ecosystem && <Fact k="Ecosystem" v={n.ecosystem} />}
            {n?.project && <Fact k="Project" v={n.project} />}
            {n?.origin && <Fact k="Origin" v={n.origin} mono />}
            {n?.integrity && <Fact k="Integrity" v={n.integrity} mono />}
            {n?.has_install_script && <Fact k="Install script" v="declared" />}
            {n?.deprecated && <Fact k="Deprecated" v="yes" />}
          </dl>
        </Section>
        <p className="muted">No findings reference this component.</p>
      </div>
    </>
  );
}
