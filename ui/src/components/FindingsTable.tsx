import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { bandOf, claimCounts, findingHeadline, fixed1, isCve, purlLabel } from "../lib/format";
import { useStore } from "../store";
import { CatPill, SevPill } from "./ui";

export default function FindingsTable() {
  const { data, order, findingsById, riskById, anomaliesFirst, setAnomaliesFirst, openFinding, inspector, selectedFindingId } =
    useStore();
  const [cursor, setCursor] = useState(0);
  const body = useRef<HTMLDivElement>(null);
  const counts = useMemo(() => claimCounts(data.findings, data.risk), [data.findings, data.risk]);
  const anomalies = useMemo(() => data.findings.filter((f) => !isCve(f)).length, [data.findings]);

  useEffect(() => {
    const i = selectedFindingId ? order.indexOf(selectedFindingId) : -1;
    if (i >= 0) setCursor(i);
  }, [selectedFindingId, order]);

  useEffect(() => {
    body.current?.querySelector<HTMLElement>(`[data-row="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "j" || e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(order.length - 1, c + 1));
    } else if (e.key === "k" || e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(0, c - 1));
    } else if (e.key === "Enter" && order[cursor]) {
      e.preventDefault();
      openFinding(order[cursor]);
    } else if (e.key === "Home") setCursor(0);
    else if (e.key === "End") setCursor(order.length - 1);
  };

  if (!data.findings.length)
    return (
      <div className="empty">
        <strong>No findings</strong>
        <span>This run recorded no findings.</span>
      </div>
    );

  return (
    <section className="ftable" aria-label="Findings">
      <header className="ftable-bar">
        <h2>
          Findings <span className="num muted">{data.findings.length}</span>
        </h2>
        <label className="switch">
          <input type="checkbox" checked={anomaliesFirst} onChange={(e) => setAnomaliesFirst(e.target.checked)} />
          <span className="switch-track" aria-hidden />
          <span>Anomalies First</span>
          <span className="muted num">({anomalies} non-CVE)</span>
        </label>
        <span className="tm-spacer" />
        <span className="claimctr" title="Claims grounded in evidence versus inferred context">
          <span className="label-v">Verified</span>
          <span className="num">{counts.verified}</span>
          <span className="label-i">Inferred</span>
          <span className="num">{counts.inferred}</span>
        </span>
        <span className="kbd-hint muted">
          <kbd>j</kbd>
          <kbd>k</kbd> move <kbd>Enter</kbd> open
        </span>
      </header>
      <div className="trow thead" aria-hidden>
        <span>Severity</span>
        <span>Category</span>
        <span>Finding</span>
        <span>Component</span>
        <span>Scope</span>
        <span className="r">Score</span>
        <span className="r">V / I</span>
        <span>Status</span>
      </div>
      <div
        className="tbody"
        ref={body}
        role="listbox"
        aria-label="Findings, sorted"
        aria-activedescendant={order[cursor] ? `row-${order[cursor]}` : undefined}
        tabIndex={0}
        onKeyDown={onKey}
      >
        {order.map((id, i) => {
          const f = findingsById.get(id)!;
          const r = riskById.get(id);
          const v = f.claims.filter((c) => c.label === "verified").length;
          const inf = f.claims.length - v;
          const open = inspector?.kind === "finding" && inspector.id === id;
          return (
            <div
              key={id}
              id={`row-${id}`}
              data-row={i}
              role="option"
              aria-selected={i === cursor}
              className={`trow${i === cursor ? " cur" : ""}${open ? " open" : ""}${isCve(f) ? "" : " anomaly"}`}
              onClick={() => {
                setCursor(i);
                openFinding(id);
              }}
            >
              <span>
                <SevPill risk={bandOf(f, riskById)} />
              </span>
              <span>
                <CatPill cat={f.category} />
              </span>
              <span className="t-title" title={f.title}>
                <span className={isCve(f) ? "mono" : ""}>{findingHeadline(f)}</span>
                {f.vuln_id && f.title !== f.vuln_id && <span className="muted"> {f.title.replace(f.vuln_id, "").replace(/^\s*in\s*/, "in ")}</span>}
              </span>
              <span className="mono t-comp" title={f.component_purl ?? f.file_path ?? ""}>
                {f.component_purl ? purlLabel(f.component_purl) : (f.file_path ?? "")}
              </span>
              <span>
                <span className={`pill scope-${f.scope}`}>{f.scope}</span>
              </span>
              <span className="r num">{r ? fixed1(Math.round(r.score * 10) / 10) : f.cvss != null ? f.cvss.toFixed(1) : "-"}</span>
              <span className="r num">
                <span className="vi-v">{v}</span> / <span className="vi-i">{inf}</span>
              </span>
              <span className="t-status">{f.status.replace("_", " ")}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
