import { useState, type ReactNode } from "react";
import type { Claim, Evidence, Risk } from "../api/types";
import { RISK_LABEL, categoryLabel } from "../lib/format";
import { useStore } from "../store";
import { useEvidence } from "./hooks";

export function SevPill({ risk }: { risk: Risk | null | undefined }) {
  if (!risk) return <span className="pill">unrated</span>;
  return <span className={`pill sev-${risk}`}>{RISK_LABEL[risk]}</span>;
}

export function CatPill({ cat }: { cat: string }) {
  return <span className="pill">{categoryLabel(cat)}</span>;
}

export function EvChip({ id }: { id: string }) {
  const { openEvidence } = useStore();
  return (
    <button type="button" className="evchip" title={`Open ${id}`} onClick={() => openEvidence(id)}>
      {id.length > 18 ? `${id.slice(0, 7)}…${id.slice(-6)}` : id}
    </button>
  );
}

export function ClaimMark({ label }: { label: string }) {
  if (label === "verified") return <span className="label-v">Verified fact</span>;
  if (label === "inferred") return <span className="label-i">Inferred context</span>;
  return <span className="label-u">Unsupported</span>;
}

export function ClaimList({ claims }: { claims: Claim[] }) {
  if (!claims.length) return <p className="muted">No structured claims recorded.</p>;
  return (
    <ul className="claims">
      {claims.map((c, i) => (
        <li key={`${i}-${c.text.slice(0, 24)}`}>
          <ClaimMark label={c.label} />
          <span className="claim-text">{c.text}</span>
          {c.evidence_ids.length > 0 && (
            <span className="claim-ev">
              {c.evidence_ids.map((e) => (
                <EvChip key={e} id={e} />
              ))}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

export function Json({ value, collapsedLines = 8 }: { value: unknown; collapsedLines?: number }) {
  const text = JSON.stringify(value, null, 2) ?? "";
  const lines = text.split("\n");
  const [open, setOpen] = useState(false);
  const long = lines.length > collapsedLines;
  return (
    <div className="json">
      <pre>{long && !open ? lines.slice(0, collapsedLines).join("\n") + "\n…" : text}</pre>
      {long && (
        <button type="button" className="btn ghost sm" onClick={() => setOpen(!open)}>
          {open ? "Collapse" : `Show all ${lines.length} lines`}
        </button>
      )}
    </div>
  );
}

export function DiffView({ text }: { text: string }) {
  const lines = text.replace(/\r/g, "").split("\n");
  return (
    <pre className="diff" aria-label="Unified diff">
      {lines.map((l, i) => {
        let c = "d-ctx";
        if (l.startsWith("+++") || l.startsWith("---")) c = "d-file";
        else if (l.startsWith("@@")) c = "d-hunk";
        else if (l.startsWith("+")) c = "d-add";
        else if (l.startsWith("-")) c = "d-del";
        return (
          <span key={i} className={`d-line ${c}`}>
            {l || " "}
          </span>
        );
      })}
    </pre>
  );
}

export function EvidenceCard({ ev, startOpen = false }: { ev: Evidence; startOpen?: boolean }) {
  const [open, setOpen] = useState(startOpen);
  const isDiff = ev.kind === "patch_diff" || ev.kind === "diff";
  return (
    <div className="evcard">
      <button type="button" className="evcard-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="fact-tag">Fact</span>
        <span className="evcard-kind">{ev.kind}</span>
        <span className="evcard-src mono">{ev.source_tool}</span>
        <span className="evcard-id mono">{ev.evidence_id}</span>
        <span className="chev" aria-hidden>{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="evcard-body">
          {(ev.file_path || ev.line) && (
            <p className="mono muted">
              {ev.file_path}
              {ev.line ? `:${ev.line}` : ""}
            </p>
          )}
          {Object.keys(ev.facts ?? {}).length > 0 && <Json value={ev.facts} />}
          {ev.excerpt && (isDiff ? <DiffView text={ev.excerpt} /> : <pre className="excerpt">{ev.excerpt}</pre>)}
          {ev.sha256 && <p className="mono muted">sha256 {ev.sha256}</p>}
          <p className="mono muted">{ev.created_at}</p>
        </div>
      )}
    </div>
  );
}

export function EvidenceById({ id, startOpen }: { id: string; startOpen?: boolean }) {
  const st = useEvidence(id);
  if (st.status === "loading") return <div className="evcard skeleton mono">{id}</div>;
  if (st.status === "missing")
    return (
      <div className="evcard missing mono">
        {id} <span className="muted">not available</span>
      </div>
    );
  return <EvidenceCard ev={st.ev} startOpen={startOpen} />;
}

export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="sec">
      <header className="sec-head">
        <h3>{title}</h3>
        {aside}
      </header>
      {children}
    </section>
  );
}
