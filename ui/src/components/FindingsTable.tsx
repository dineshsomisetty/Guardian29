import { ChevronDown, ChevronRight, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Finding, Risk } from "../api/types";
import { RISKS, RISK_LABEL, bandOf, groupKey, plural, purlLabel, purlVersion } from "../lib/format";
import { categoryLabel, categoryShort, findingRef, plainTitle } from "../lib/labels";
import { useStore } from "../store";
import { typingTarget } from "./hooks";
import { EmptyState, SevPill, Tip } from "./ui";

const STATUS_WORD: Record<string, string> = {
  open: "Open",
  assessed: "Assessed",
  planned: "Fix planned",
  awaiting_human: "Awaiting approval",
  verified: "Fixed and verified",
  escalated: "Needs attention",
  accepted: "Risk accepted",
  rejected: "Fix rejected",
};
const statusWord = (s: string) => STATUS_WORD[s] ?? s.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

interface Row {
  key: string;
  id: string;
  depth: 0 | 1;
  /** all findings of a collapsed/expandable group (length > 1 only on the header row) */
  group: string[];
}

export default function FindingsTable() {
  const {
    data, order, findingsById, riskById, anomaliesFirst, setAnomaliesFirst, openFinding, inspector, selectedFindingId,
    findingFilter, setFindingFilter, helpOpen,
  } = useStore();
  const [q, setQ] = useState(findingFilter.q ?? "");
  const [group, setGroup] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(0);
  const body = useRef<HTMLDivElement>(null);
  const { risk: fRisk, cat: fCat } = findingFilter;

  const ordered = useMemo(() => {
    if (!anomaliesFirst) return order;
    return [...order].sort((a, b) => Number(findingsById.get(a)!.category === "cve") - Number(findingsById.get(b)!.category === "cve"));
  }, [order, anomaliesFirst, findingsById]);

  // counts reflect the other active filters so the chips never promise rows that are not there
  const text = useMemo(() => {
    const m = new Map<string, string>();
    for (const f of data.findings) {
      m.set(
        f.finding_id,
        [plainTitle(f, bandOf(f, riskById)), f.vuln_id, ...f.aliases, f.component_purl ? purlLabel(f.component_purl) : "", f.file_path, categoryLabel(f.category), f.title]
          .filter(Boolean)
          .join(" ")
          .toLowerCase(),
      );
    }
    return m;
  }, [data.findings, riskById]);

  const matches = (f: Finding, ignore?: "risk" | "cat") => {
    if (ignore !== "risk" && fRisk && bandOf(f, riskById) !== fRisk) return false;
    if (ignore !== "cat" && fCat && f.category !== fCat) return false;
    const t = q.trim().toLowerCase();
    return !t || (text.get(f.finding_id) ?? "").includes(t);
  };
  const riskCounts = useMemo(() => {
    const c: Record<Risk, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of data.findings) if (matches(f, "risk")) {
      const b = bandOf(f, riskById);
      if (b) c[b]++;
    }
    return c;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data.findings, riskById, fCat, q, text]);
  const catCounts = useMemo(() => {
    const c = new Map<string, number>();
    for (const f of data.findings) if (matches(f, "cat")) c.set(f.category, (c.get(f.category) ?? 0) + 1);
    return c;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data.findings, riskById, fRisk, q, text]);
  const allCats = useMemo(() => {
    const c = new Map<string, number>();
    for (const f of data.findings) c.set(f.category, (c.get(f.category) ?? 0) + 1);
    return [...c.keys()].sort((a, b) => (c.get(b) ?? 0) - (c.get(a) ?? 0));
  }, [data.findings]);

  const filtered = useMemo(
    () => ordered.filter((id) => matches(findingsById.get(id)!)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [ordered, findingsById, fRisk, fCat, q, text, riskById],
  );

  const rows = useMemo<Row[]>(() => {
    if (!group) return filtered.map((id) => ({ key: id, id, depth: 0, group: [id] }));
    const by = new Map<string, string[]>();
    for (const id of filtered) {
      const k = groupKey(findingsById.get(id)!);
      (by.get(k) ?? by.set(k, []).get(k)!).push(id);
    }
    const out: Row[] = [];
    const done = new Set<string>();
    for (const id of filtered) {
      const k = groupKey(findingsById.get(id)!);
      if (done.has(k)) continue;
      done.add(k);
      const ids = by.get(k)!;
      out.push({ key: `g:${k}`, id: ids[0], depth: 0, group: ids });
      if (ids.length > 1 && expanded.has(k)) for (const c of ids) out.push({ key: c, id: c, depth: 1, group: [c] });
    }
    return out;
  }, [filtered, group, expanded, findingsById]);

  // keep the cursor on the finding that is open in the inspector
  useEffect(() => {
    const i = selectedFindingId ? rows.findIndex((r) => r.id === selectedFindingId || r.group.includes(selectedFindingId)) : -1;
    if (i >= 0) setCursor(i);
  }, [selectedFindingId, rows]);
  useEffect(() => setCursor((c) => Math.min(c, Math.max(0, rows.length - 1))), [rows.length]);
  useEffect(() => {
    body.current?.querySelector<HTMLElement>(`[data-row="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const toggleGroup = (r: Row, want?: boolean) => {
    if (r.group.length < 2) return;
    const k = groupKey(findingsById.get(r.id)!);
    setExpanded((p) => {
      const n = new Set(p);
      const open = want ?? !n.has(k);
      if (open) n.add(k);
      else n.delete(k);
      return n;
    });
  };

  // keyboard works from anywhere on the page unless a control that uses those keys has focus
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || helpOpen) return;
      const t = e.target as HTMLElement | null;
      if (typingTarget(t)) return;
      const onControl = t instanceof HTMLElement && /^(BUTTON|A|SUMMARY)$/.test(t.tagName) && !t.closest(".tbody");
      if (onControl && (e.key === "Enter" || e.key === " ")) return;
      const r = rows[cursor];
      if (e.key === "j" || e.key === "ArrowDown") {
        if (inspector && e.key === "ArrowDown") return; // the inspector steps through findings itself
        e.preventDefault();
        setCursor((c) => Math.min(rows.length - 1, c + 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        if (inspector && e.key === "ArrowUp") return;
        e.preventDefault();
        setCursor((c) => Math.max(0, c - 1));
      } else if (e.key === "Enter" && r && !(t instanceof HTMLButtonElement && t.closest(".tbody"))) {
        e.preventDefault();
        openFinding(r.id);
      } else if (e.key === "ArrowRight" && r) toggleGroup(r, true);
      else if (e.key === "ArrowLeft" && r) toggleGroup(r, false);
      else if (e.key === "Home") setCursor(0);
      else if (e.key === "End") setCursor(rows.length - 1);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  });

  if (!data.findings.length)
    return (
      <EmptyState title="No findings" center>
        This scan did not record any findings. If it is still running, they will appear here as Guardian finds them.
      </EmptyState>
    );

  const filtersOn = !!(fRisk || fCat || q);
  const clear = () => {
    setFindingFilter({ risk: null, cat: null, q: "" });
    setQ("");
  };

  return (
    <section className="ftable" aria-label="Findings">
      <header className="ftable-bar">
        <div className="ftable-title">
          <h1>Findings</h1>
          <span className="muted">
            {filtersOn ? `${filtered.length.toLocaleString()} of ${data.findings.length.toLocaleString()}` : data.findings.length.toLocaleString()} shown. Select a row for the plain-language explanation and evidence.
          </span>
        </div>
        <div className="ftable-tools">
          <span className="searchbox">
            <Search size={16} aria-hidden />
            <input
              data-search
              type="search"
              value={q}
              placeholder="Search package, advisory or file"
              aria-label="Search findings"
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") (e.target as HTMLInputElement).blur();
              }}
            />
            {q && (
              <button type="button" className="sbox-clear" aria-label="Clear search" onClick={() => setQ("")}>
                <X size={14} aria-hidden />
              </button>
            )}
          </span>
          <div className="chips" role="group" aria-label="Filter by risk level">
            <button type="button" className={`chip${!fRisk ? " on" : ""}`} onClick={() => setFindingFilter({ risk: null })}>
              All levels
            </button>
            {RISKS.map((r) => (
              <button key={r} type="button" className={`chip${fRisk === r ? " on" : ""}`} aria-pressed={fRisk === r} disabled={!riskCounts[r] && fRisk !== r} onClick={() => setFindingFilter({ risk: fRisk === r ? null : r })}>
                <span className={`dot ${r === "critical" ? "bad" : r === "high" ? "gate" : r === "medium" ? "info" : ""}`} aria-hidden />
                {RISK_LABEL[r]} <span className="num">{riskCounts[r]}</span>
              </button>
            ))}
          </div>
          <span className="grow" />
          <Tip text="Show the same advisory on several versions of one package as a single row you can expand." side="bottom">
            <label className="switch">
              <input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} />
              <span className="switch-track" aria-hidden />
              <span>Group duplicates</span>
            </label>
          </Tip>
          <Tip text="List suspicious packages and unsafe setup before known CVEs." side="bottom">
            <label className="switch">
              <input type="checkbox" checked={anomaliesFirst} onChange={(e) => setAnomaliesFirst(e.target.checked)} />
              <span className="switch-track" aria-hidden />
              <span>Suspicious first</span>
            </label>
          </Tip>
        </div>
        {allCats.length > 1 && (
          <div className="chips" role="group" aria-label="Filter by type">
            <button type="button" className={`chip${!fCat ? " on" : ""}`} onClick={() => setFindingFilter({ cat: null })}>
              All types
            </button>
            {allCats.map((c) => (
              <button key={c} type="button" className={`chip${fCat === c ? " on" : ""}`} aria-pressed={fCat === c} disabled={!catCounts.get(c) && fCat !== c} onClick={() => setFindingFilter({ cat: fCat === c ? null : c })}>
                {categoryShort(c)} <span className="num">{catCounts.get(c) ?? 0}</span>
              </button>
            ))}
          </div>
        )}
      </header>

      <div className="trow thead" role="row">
        <Tip text="Guardian's risk level for your project, set by the score: Critical 80+, High 60+, Medium 40+, Low under 40. It can differ from the advisory's own rating." side="top"><span>Risk level</span></Tip>
        <span>Finding</span>
        <span>Type</span>
        <Tip text="Risk score from 0 to 100. Open a finding to see how it was calculated." side="top"><span className="r">Risk score</span></Tip>
        <span>Status</span>
      </div>

      {rows.length === 0 ? (
        <EmptyState title="No findings match these filters" center action={<button type="button" className="btn" onClick={clear}>Clear filters</button>}>
          Try a different word, or remove a level or type filter.
        </EmptyState>
      ) : (
        <div className="tbody" ref={body} role="listbox" aria-label="Findings, most urgent first" tabIndex={0}
          aria-activedescendant={rows[cursor] ? `row-${rows[cursor].key}` : undefined}>
          {rows.map((r, i) => {
            const f = findingsById.get(r.id)!;
            const risk = riskById.get(r.id);
            const band = bandOf(f, riskById);
            const isGroup = r.group.length > 1 && r.depth === 0;
            const k = groupKey(f);
            const isOpen = expanded.has(k);
            const sel = inspector?.kind === "finding" && inspector.id === r.id;
            const score = risk ? risk.score : f.cvss != null ? f.cvss * 10 : null;
            const versions = isGroup ? r.group.map((g) => purlVersion(findingsById.get(g)!.component_purl ?? "")).filter(Boolean) : [];
            return (
              <div
                key={r.key}
                id={`row-${r.key}`}
                data-row={i}
                role="option"
                aria-selected={i === cursor}
                className={`trow${i === cursor ? " cur" : ""}${sel ? " open" : ""}${r.depth ? " child" : ""}`}
                onClick={() => {
                  setCursor(i);
                  openFinding(r.id);
                }}
              >
                <span className="t-sev">
                  {isGroup ? (
                    <Tip text={isOpen ? "Hide versions" : `Show all ${r.group.length} versions`} side="top">
                      <button type="button" className="t-chev" aria-label={isOpen ? "Collapse versions" : "Expand versions"} aria-expanded={isOpen}
                        onClick={(e) => { e.stopPropagation(); setCursor(i); toggleGroup(r); }}>
                        {isOpen ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
                      </button>
                    </Tip>
                  ) : r.depth ? <span className="t-indent" aria-hidden /> : null}
                  <SevPill risk={band} />
                </span>
                <span className="t-main">
                  <span className="t-title">
                    {r.depth ? `Version ${purlVersion(f.component_purl ?? "") || "unknown"}: ${findingRef(f)}` : plainTitle(f, band)}
                    {isGroup && <span className="pill dashed">{plural(r.group.length, "version")}</span>}
                  </span>
                  <span className="t-sub mono">
                    {isGroup ? `${findingRef(f)} · versions ${versions.slice(0, 4).join(", ")}${versions.length > 4 ? ", ..." : ""}` : r.depth ? (f.dependency_paths[0] ? f.dependency_paths[0].map(purlLabel).join(" > ") : f.file_path ?? "") : `${findingRef(f)} · ${f.scope === "dev" ? "dev only" : f.scope === "prod" ? "production" : "scope unknown"}`}
                  </span>
                </span>
                <span className="t-cat">{categoryShort(f.category)}</span>
                <span className="r t-score num">
                  {score != null ? (
                    <>
                      <span>{score.toFixed(1)}</span>
                      <span className="scorebar-mini" aria-hidden><i style={{ width: `${Math.min(100, score)}%` }} /></span>
                    </>
                  ) : (
                    <span className="faint">n/a</span>
                  )}
                </span>
                <span className="t-status">{statusWord(f.status)}</span>
              </div>
            );
          })}
        </div>
      )}
      <footer className="ftable-foot">
        <span className="muted">
          Showing {filtered.length.toLocaleString()} {filtered.length === 1 ? "finding" : "findings"}
          {group && rows.filter((r) => r.depth === 0).length !== filtered.length ? ` in ${rows.filter((r) => r.depth === 0).length} rows` : ""}
        </span>
        <span className="kbd-hint">
          <kbd>j</kbd><kbd>k</kbd> move · <kbd>Enter</kbd> open · <kbd>/</kbd> search · <kbd>?</kbd> all shortcuts
        </span>
      </footer>
    </section>
  );
}
