import {
  cloneElement, useEffect, useMemo, useRef, useState, type ReactElement, type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, ChevronDown, ChevronRight, Info, SearchX } from "lucide-react";
import type { Claim, Evidence, Risk } from "../api/types";
import { RISK_LABEL } from "../lib/format";
import { categoryShort, evidenceSummary, evidenceTitle } from "../lib/labels";
import { useStore } from "../store";
import { useEvidence } from "./hooks";

// ------------------------------------------------------------------ tooltip

type Side = "top" | "bottom" | "left" | "right";

/** Lightweight tooltip: hover (after a short delay) or keyboard focus. Rendered in a portal so no parent can clip it. */
export function Tip({ text, side = "bottom", children, block }: { text: ReactNode; side?: Side; children: ReactElement; block?: boolean }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const show = (delay: number) => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const r = ref.current?.getBoundingClientRect();
      if (!r) return;
      const cx = Math.min(Math.max(r.left + r.width / 2, 160), window.innerWidth - 160);
      if (side === "bottom") setPos({ x: cx, y: r.bottom + 8 });
      else if (side === "top") setPos({ x: cx, y: r.top - 8 });
      else if (side === "right") setPos({ x: r.right + 10, y: r.top + r.height / 2 });
      else setPos({ x: r.left - 10, y: r.top + r.height / 2 });
    }, delay);
  };
  const hide = () => {
    window.clearTimeout(timer.current);
    setPos(null);
  };
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <span
      ref={ref}
      className="tip-wrap"
      style={block ? { display: "flex", width: "100%" } : undefined}
      onMouseEnter={() => show(280)}
      onMouseLeave={hide}
      onMouseDown={hide}
      onFocus={() => show(0)}
      onBlur={hide}
    >
      {cloneElement(children)}
      {pos && createPortal(<div role="tooltip" className={`tip tip-${side}`} style={{ left: pos.x, top: pos.y }}>{text}</div>, document.body)}
    </span>
  );
}

/** Small "i" that explains a term on hover or focus. */
export function Hint({ text, side = "top" }: { text: ReactNode; side?: Side }) {
  return (
    <Tip text={text} side={side}>
      <span className="hint" tabIndex={0} role="img" aria-label="More information">
        <Info size={14} aria-hidden />
      </span>
    </Tip>
  );
}

// ------------------------------------------------------------------ pills

export function SevPill({ risk }: { risk: Risk | null | undefined }) {
  if (!risk) return <span className="pill">Unrated</span>;
  return <span className={`pill sev-${risk}`}>{RISK_LABEL[risk]}</span>;
}

export function CatPill({ cat }: { cat: string }) {
  return <span className="pill">{categoryShort(cat)}</span>;
}

/** Short mono evidence reference. Only used inside expanded technical details. */
export function EvChip({ id }: { id: string }) {
  const { openEvidence } = useStore();
  return (
    <button type="button" className="evchip" title="Open this evidence record" onClick={() => openEvidence(id)}>
      {id.length > 18 ? `${id.slice(0, 7)}…${id.slice(-6)}` : id}
    </button>
  );
}

const CLAIM_HELP = {
  verified: "A Verified fact is read straight from scanner output, a registry record or a file in your repository. You can open its source and check it.",
  inferred: "An AI inference is the model's reasoning about what the facts mean. It is useful context, but it is not proven by a source, so treat it as a judgement.",
  unsupported: "Guardian could not tie this statement to any evidence, so it is not relied on.",
  pending: "Guardian's own reasoning about the fix that the sources do not prove on their own yet. The sandbox build, tests and re-scan are what check it.",
};

/** Who wrote an unproven statement: the AI model, or Guardian's deterministic rules (plans). */
export type ClaimOrigin = "ai" | "rule";

export function ClaimMark({ label, help = true, origin = "ai" }: { label: string; help?: boolean; origin?: ClaimOrigin }) {
  const v = label === "verified";
  const i = label === "inferred";
  const cls = v ? "v" : i ? "i" : "u";
  const text = v ? "Verified fact" : i ? (origin === "rule" ? "Not yet proven" : "AI inference") : "Unsupported";
  const el = <span className={`claim-tag ${cls}`}>{text}</span>;
  const helpKey = v ? "verified" : i ? (origin === "rule" ? "pending" : "inferred") : "unsupported";
  return help ? (
    <Tip text={CLAIM_HELP[helpKey]} side="top">
      {el}
    </Tip>
  ) : (
    el
  );
}

// ------------------------------------------------------------------ citations

/** "source 1, 2" links that jump to the evidence rather than printing raw ids. */
export function Cites({ ids, onCite }: { ids: string[]; onCite?: (id: string) => void }) {
  const { openEvidence } = useStore();
  if (!ids.length) return null;
  const open = onCite ?? openEvidence;
  return (
    <span className="cites">
      <span className="cites-k">{ids.length === 1 ? "source" : "sources"}</span>
      {ids.slice(0, 6).map((id, n) => (
        <Tip key={id} text="Open this source" side="top">
          <button type="button" className="cite" aria-label={`Open source ${n + 1}`} onClick={() => open(id)}>
            {n + 1}
          </button>
        </Tip>
      ))}
      {ids.length > 6 && <span className="faint">+{ids.length - 6}</span>}
    </span>
  );
}

export function ClaimList({ claims, onCite, origin = "ai" }: {
  claims: Claim[];
  onCite?: (id: string) => void;
  origin?: ClaimOrigin;
}) {
  if (!claims.length) return <p className="muted">No individual claims were recorded for this finding.</p>;
  return (
    <ul className="claims">
      {claims.map((c, i) => (
        <li key={`${i}-${c.text.slice(0, 24)}`}>
          <ClaimMark label={c.label} origin={origin} />
          <p className="claim-text">{c.text}</p>
          <Cites ids={c.evidence_ids} onCite={onCite} />
        </li>
      ))}
    </ul>
  );
}

// ------------------------------------------------------------------ code-ish blocks

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
          {open ? "Show less" : `Show all ${lines.length} lines`}
        </button>
      )}
    </div>
  );
}

export function DiffView({ text }: { text: string }) {
  const lines = text.replace(/\r/g, "").split("\n");
  return (
    <pre className="diff" aria-label="Proposed change, unified diff">
      {lines.map((l, i) => {
        let c = "d-ctx";
        if (l.startsWith("+++") || l.startsWith("---")) c = "d-file";
        else if (l.startsWith("@@")) c = "d-hunk";
        else if (l.startsWith("+")) c = "d-add";
        else if (l.startsWith("-")) c = "d-del";
        return (
          <span key={i} className={`d-line ${c}`}>
            <span className="d-sign" aria-hidden>{c === "d-add" ? "+" : c === "d-del" ? "-" : " "}</span>
            {c === "d-add" || c === "d-del" ? l.slice(1) || " " : l || " "}
          </span>
        );
      })}
    </pre>
  );
}

// ------------------------------------------------------------------ evidence

export function EvidenceCard({
  ev, open: forced, onToggle, startOpen = false,
}: { ev: Evidence; open?: boolean; onToggle?: (o: boolean) => void; startOpen?: boolean }) {
  const [own, setOwn] = useState(startOpen);
  const open = forced ?? own;
  const ref = useRef<HTMLDivElement>(null);
  const isDiff = ev.kind === "patch_diff" || ev.kind === "diff";
  const summary = useMemo(() => evidenceSummary(ev), [ev]);
  return (
    <div className={`evcard${open ? " open" : ""}`} id={`ev-${ev.evidence_id}`} ref={ref}>
      <button
        type="button"
        className="evcard-head"
        aria-expanded={open}
        onClick={() => {
          setOwn(!open);
          onToggle?.(!open);
        }}
      >
        <span className="evcard-text">
          <span className="evcard-kind">{evidenceTitle(ev)}</span>
          {summary && <span className="evcard-sum">{summary}</span>}
        </span>
        {open ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
      </button>
      {open && (
        <div className="evcard-body">
          {(ev.file_path || ev.line) && (
            <p className="mono faint">
              {ev.file_path}
              {ev.line ? `:${ev.line}` : ""}
            </p>
          )}
          {ev.excerpt && (isDiff ? <DiffView text={ev.excerpt} /> : <pre className="excerpt">{ev.excerpt}</pre>)}
          {Object.keys(ev.facts ?? {}).length > 0 && (
            <div>
              <p className="mini-h">Raw data</p>
              <Json value={ev.facts} />
            </div>
          )}
          <dl className="techlist">
            <dt>Evidence id</dt>
            <dd><span className="evchip static">{ev.evidence_id}</span></dd>
            <dt>Produced by</dt>
            <dd className="mono">{ev.source_tool}</dd>
            <dt>Recorded</dt>
            <dd className="mono">{ev.created_at}</dd>
            {ev.sha256 && (<><dt>SHA-256</dt><dd className="mono">{ev.sha256}</dd></>)}
          </dl>
        </div>
      )}
    </div>
  );
}

export function EvidenceById({
  id, open, onToggle, startOpen,
}: { id: string; open?: boolean; onToggle?: (o: boolean) => void; startOpen?: boolean }) {
  const st = useEvidence(id);
  if (st.status === "loading") return <div className="evcard skel" style={{ height: 52 }} aria-busy="true" />;
  if (st.status === "missing")
    return (
      <div className="evcard missing">
        This source record is not available for this run.
      </div>
    );
  return <EvidenceCard ev={st.ev} open={open} onToggle={onToggle} startOpen={startOpen} />;
}

// ------------------------------------------------------------------ layout bits

export function Section({
  title, aside, children, id, lead,
}: { title: string; aside?: ReactNode; children: ReactNode; id?: string; lead?: string }) {
  return (
    <section className="sec" id={id}>
      <header className="sec-head">
        <h3>{title}</h3>
        {aside}
      </header>
      {lead && <p className="sec-lead">{lead}</p>}
      {children}
    </section>
  );
}

export function Skeleton({ w, h = 14, style }: { w?: number | string; h?: number; style?: React.CSSProperties }) {
  return <div className="skel" style={{ width: w ?? "100%", height: h, ...style }} aria-hidden />;
}

export function SkeletonRows({ n = 4, h = 56 }: { n?: number; h?: number }) {
  return (
    <div className="skel-rows" role="status" aria-label="Loading">
      {Array.from({ length: n }, (_, i) => (
        <Skeleton key={i} h={h} />
      ))}
    </div>
  );
}

export function EmptyState({
  title, children, action, icon, center,
}: { title: string; children?: ReactNode; action?: ReactNode; icon?: ReactNode; center?: boolean }) {
  return (
    <div className={`empty${center ? " center" : ""}`}>
      <span className="empty-ico">{icon ?? <SearchX size={28} aria-hidden />}</span>
      <strong>{title}</strong>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}

export function Callout({
  tone = "gate", title, children, icon,
}: { tone?: "gate" | "bad" | "info" | "ok"; title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className={`callout ${tone}`} role={tone === "bad" ? "alert" : undefined}>
      <span className="callout-ico">{icon ?? <AlertTriangle size={18} aria-hidden />}</span>
      <div>
        <p className="callout-title">{title}</p>
        {children && <div className="callout-body">{children}</div>}
      </div>
    </div>
  );
}
