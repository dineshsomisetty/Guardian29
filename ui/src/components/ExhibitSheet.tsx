import { ChevronDown, ChevronRight, FileSearch, Link2 } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import type { Evidence, Finding, GraphNode } from "../api/types";
import { sortFindings, useSel } from "../state";
import EvidenceDrawer from "./exhibit/EvidenceDrawer";
import { buildCustodyRows, citedEvidenceIds, guardrailEvents, useFindingEvidence, type CustodyRow } from "./exhibit/custody";
import { categoryName, fileLine, nodeLabel } from "./exhibit/format";
import "../styles/exhibit.css";

export default function ExhibitSheet() {
  const { run, findingsById, selectedFindingId } = useSel();
  const order = useMemo(() => sortFindings(run.findings), [run]);
  const f = selectedFindingId ? findingsById.get(selectedFindingId) : undefined;

  if (!f) {
    return (
      <aside className="exhibit" aria-label="Exhibit sheet">
        <div className="exhibit-empty sheetpanel">
          <FileSearch size={28} strokeWidth={1.5} aria-hidden />
          <p className="exhibit-empty-title">No exhibit selected</p>
          <p>Choose a finding under Exhibits, or a flagged node on the dependency graph, to open its sheet and custody log.</p>
        </div>
      </aside>
    );
  }

  const idx = order.findIndex((x) => x.finding_id === f.finding_id);
  return (
    <aside className="exhibit" aria-label="Exhibit sheet">
      <ExhibitTag f={f} no={idx + 1} total={order.length} />
      <Particulars f={f} />
      <Custody key={f.finding_id} f={f} />
    </aside>
  );
}

const pad = (n: number, w: number) => String(n).padStart(w, "0");

function ExhibitTag({ f, no, total }: { f: Finding; no: number; total: number }) {
  const w = String(total).length;
  return (
    <header className="exhibit-tag">
      <h2 className="tag-title">{f.title}</h2>
      <div className="tag-meta">
        {f.initial_risk ? <span className={`stamp ${f.initial_risk}`}>{f.initial_risk}</span> : <span className="stamp rule">Unrated</span>}
        <span className="tag-cat">{categoryName(f.category)}</span>
        <span className="tag-no">Exhibit <b>{pad(no, w)}</b> of {total}</span>
        <span className="tag-id value">{f.finding_id} · {f.status}</span>
      </div>
    </header>
  );
}

/* ---- particulars ----------------------------------------------------- */

interface Field { key: string; label: string; value: ReactNode; half?: boolean; primary?: boolean }

function Particulars({ f }: { f: Finding }) {
  const { nodesById } = useSel();
  const [all, setAll] = useState(false);
  const node = f.component_purl ? nodesById.get(f.component_purl) : undefined;
  const fields: Field[] = [];
  const isCve = f.category === "cve";
  const fl = fileLine(f);

  if (f.component_purl) fields.push({ key: "component", label: "Component", primary: true, value: <span className="value">{f.component_purl}</span> });
  if (f.dependency_paths.length) fields.push({ key: "path", label: "Path", primary: true, value: <PathField f={f} nodes={nodesById} /> });
  // where the package came from and its full-length lockfile hash: always visible, never truncated
  if (node?.origin) fields.push({ key: "origin", label: "Origin", primary: true, value: <span className="value">{node.origin}</span> });
  if (node?.integrity) fields.push({ key: "integrity", label: "Integrity", primary: true, value: <span className="value hash">{node.integrity}</span> });
  if (f.fixed_versions.length || f.affected_range) {
    fields.push({
      key: "fixed", label: "Fixed in", half: true, primary: true,
      value: (
        <span className="value">
          {f.fixed_versions.length ? f.fixed_versions.join(", ") : "no fix published"}
          {f.affected_range && <span className="sub">affected {f.affected_range}</span>}
        </span>
      ),
    });
  }
  if (f.cvss != null || f.severity) {
    fields.push({
      key: "cvss", label: "CVSS", half: true, primary: true,
      value: <span className="value">{f.cvss ?? "–"}{f.severity && <span className="sub">scanner severity {f.severity}</span>}</span>,
    });
  }
  // non-CVE findings are identified by where they were seen and who saw them
  const where: Field | null = fl ? { key: "fileline", label: "File:line", half: true, primary: !isCve, value: <span className="value">{fl}</span> } : null;
  const who: Field = { key: "detector", label: "Detector", half: true, primary: !isCve, value: <span className="value">{f.detector}</span> };
  if (!isCve) {
    if (where) fields.push(where);
    fields.push(who);
  }
  fields.push({
    key: "scope", label: "Scope",
    value: <span className="value">{f.scope}{f.project ? ` · project ${f.project}` : ""}{node?.direct != null ? ` · ${node.direct ? "direct" : "transitive"}` : ""}</span>,
  });
  if (f.aliases.length) fields.push({ key: "aliases", label: "Aliases", value: <span className="value">{[f.vuln_id, ...f.aliases].filter(Boolean).join(", ")}</span> });
  else if (f.vuln_id) fields.push({ key: "advisory", label: "Advisory", value: <span className="value">{f.vuln_id}</span> });
  if (isCve) {
    if (where) fields.push(where);
    fields.push(who);
  }
  if (node?.has_install_script || node?.deprecated) {
    fields.push({
      key: "flags", label: "Flags",
      value: <span className="value">{[node.has_install_script && "install script", node.deprecated && "deprecated"].filter(Boolean).join(" · ")}</span>,
    });
  }

  // key particulars first, the rest behind the disclosure; box numbers follow display order
  const ordered = [...fields.filter((x) => x.primary), ...fields.filter((x) => !x.primary)];
  const shown = ordered.map((x, i) => ({ ...x, no: `1${String.fromCharCode(97 + i)}`, right: false })).filter((x) => all || x.primary);
  let col = 0; // 0 = next half field opens a row, 1 = it sits right of a partner
  for (const x of shown) {
    if (!x.half) { col = 0; continue; }
    x.right = col === 1;
    col = 1 - col;
  }
  const extra = ordered.length - ordered.filter((x) => x.primary).length;

  return (
    <section className="sheetpanel exhibit-sec" aria-labelledby="sec-particulars">
      <h3 className="sec-head" id="sec-particulars">Particulars</h3>
      <dl className="fields" id="particulars-more">
        {shown.map((x) => (
          <div className={`field${x.half ? " half" : ""}${x.half && !x.right ? " pair-l" : ""}`} key={x.key}>
            <span className="fieldno" aria-hidden>{x.no}</span>
            <dt className="label">{x.label}</dt>
            <dd>{x.value}</dd>
          </div>
        ))}
      </dl>
      {extra > 0 && (
        <button className="disclose" aria-expanded={all} aria-controls="particulars-more" onClick={() => setAll((v) => !v)}>
          <ChevronDown size={14} strokeWidth={2} aria-hidden className="disclose-chev" />
          {all ? "Fewer particulars" : `More particulars (${extra})`}
        </button>
      )}
    </section>
  );
}

function PathField({ f, nodes }: { f: Finding; nodes: Map<string, GraphNode> }) {
  const { selectNode } = useSel();
  const [all, setAll] = useState(false);
  const paths = all ? f.dependency_paths : f.dependency_paths.slice(0, 1);
  const more = f.dependency_paths.length - 1;
  return (
    <div className="paths">
      {paths.map((p, pi) => (
        <ol className="crumbs" key={pi} aria-label={`Dependency path ${pi + 1}`}>
          {p.map((id, i) => (
            <li key={`${id}-${i}`}>
              {i > 0 && <ChevronRight size={12} strokeWidth={2} aria-hidden className="crumb-sep" />}
              <button className={`chip${i === p.length - 1 ? " end" : ""}`} onClick={() => selectNode(id)} title={id}>
                {nodeLabel(id, nodes)}
              </button>
            </li>
          ))}
        </ol>
      ))}
      {more > 0 && (
        <button className="linkbtn" aria-expanded={all} onClick={() => setAll((v) => !v)}>
          {all ? "Show first path only" : `+${more} more path${more > 1 ? "s" : ""}`}
        </button>
      )}
    </div>
  );
}

/* ---- custody log ----------------------------------------------------- */

function Custody({ f }: { f: Finding }) {
  const { run } = useSel();
  const guards = useMemo(() => guardrailEvents(run.trace, f.finding_id), [run, f]);
  const ids = useMemo(() => citedEvidenceIds(f, guards), [f, guards]);
  const ev = useFindingEvidence(run.base, f.finding_id, ids);
  const model = run.summary.llm.model;
  const analystReached = useMemo(
    () => run.trace.some((e) => e.agent === "evidence_analyst" && e.type === "llm_result") || run.findings.some((x) => x.initial_risk_source === "llm"),
    [run],
  );

  const ready = ev?.status === "ready" && ev.forId === f.finding_id ? ev.byId : null;
  const rows = useMemo(
    () => (ready ? buildCustodyRows(f, ready, guards, model, analystReached) : null),
    [ready, f, guards, model, analystReached],
  );

  return (
    <section className="sheetpanel exhibit-sec" aria-labelledby="sec-custody">
      <h3 className="sec-head" id="sec-custody">
        Custody log
        {rows && <span className="sec-meta">{rows.length} signatures</span>}
      </h3>
      <Statement f={f} model={model} analystReached={analystReached} rejected={guards.length > 0} />
      {rows ? <CustodyList rows={rows} evidence={ready!} /> : <p className="custody-wait">Retrieving evidence records…</p>}
    </section>
  );
}

function Statement({ f, model, analystReached, rejected }: { f: Finding; model: string | null; analystReached: boolean; rejected: boolean }) {
  if (f.explanation) {
    return (
      <figure className="statement">
        <blockquote>{f.explanation}</blockquote>
        <figcaption className="label">Signed · evidence analyst{model ? ` · ${model}` : ""}</figcaption>
      </figure>
    );
  }
  const basis = f.cvss != null ? `CVSS ${f.cvss} band` : f.severity ? `scanner severity ${f.severity}` : `${categoryName(f.category)} category default`;
  const why = rejected ? "analyst output rejected by guardrails" : analystReached ? "no analyst assessment for this exhibit" : "analyst not reached";
  return (
    <div className="statement rule-note">
      <p>Initial risk by rule ({basis}); {why}. Only tool facts are on this exhibit.</p>
    </div>
  );
}

function CustodyList({ rows, evidence }: { rows: CustodyRow[]; evidence: Map<string, Evidence | null> }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <ol className="custody">
      {rows.map((r, i) => (
        <li className={`custody-row s-${r.stamp}`} key={r.key} style={{ ["--i" as string]: i }}>
          <span className="c-box" aria-hidden>{i + 1}</span>
          <div className="c-body">
            <div className="c-who">{r.who}</div>
            <p className="c-what">{r.what}</p>
            {r.detail && <p className="c-detail value">{r.detail}</p>}
            {r.evidenceIds.length > 0 && (
              <ul className="c-ev">
                {r.evidenceIds.map((id) => {
                  const k = `${r.key}|${id}`;
                  const dom = `drawer-${i}-${id}`;
                  const isOpen = open === k;
                  return (
                    <li key={id}>
                      <button className="ev-id" aria-expanded={isOpen} aria-controls={dom} onClick={() => setOpen(isOpen ? null : k)}>
                        <Link2 size={12} strokeWidth={2} aria-hidden />
                        <span>{id}</span>
                        <ChevronRight size={12} strokeWidth={2} aria-hidden className="ev-chev" />
                      </button>
                      {isOpen && <EvidenceDrawer domId={dom} id={id} ev={evidence.get(id)} />}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          <span className={`stamp ${r.stamp} c-stamp`}>{r.stampText}</span>
        </li>
      ))}
    </ol>
  );
}
