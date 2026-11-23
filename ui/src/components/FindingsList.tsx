import { ArrowDown, ArrowUp, ArrowUpDown, Search, X } from "lucide-react";
import { Fragment, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { Finding, Risk } from "../api/types";
import { RISK_ORDER, sortFindings, useSel } from "../state";
import { categoryName, fileLine, isAnomaly, labelCounts, pathDepth } from "./exhibit/format";
import "../styles/findings.css";

type SortKey = "no" | "risk" | "title" | "component" | "depth" | "label" | "evidence";
type RiskFilter = "all" | Risk;

const COLS: { key: SortKey; name: string; cls: string }[] = [
  { key: "no", name: "Exhibit no.", cls: "c-no" },
  { key: "risk", name: "Risk", cls: "c-risk" },
  { key: "title", name: "Finding", cls: "c-title" },
  { key: "component", name: "Component / file", cls: "c-comp" },
  { key: "depth", name: "Path depth", cls: "c-depth" },
  { key: "label", name: "Label", cls: "c-label" },
  { key: "evidence", name: "Evidence", cls: "c-evn" },
];

/** Allow a purl / path to wrap only at "/" and "@" boundaries, never mid-word. */
function breakable(s: string): ReactNode {
  const parts = s.split(/(?=@)|(?<=\/)/);
  return parts.map((p, i) => (
    <Fragment key={i}>
      {i > 0 && <wbr />}
      {p}
    </Fragment>
  ));
}

const riskRank = (r: Risk | null) => (r ? RISK_ORDER.indexOf(r) : 9);
const component = (f: Finding) => f.component_purl ?? fileLine(f) ?? "";
const depthRank = (f: Finding) => {
  const d = pathDepth(f);
  return d.kind === "none" ? 99 : d.hops;
};
const labelRank = (f: Finding) => {
  const c = labelCounts(f);
  return c.verified * 1000 + c.inferred;
};

export default function FindingsList() {
  const { run, selectedFindingId, selectFinding } = useSel();
  const ordered = useMemo(() => sortFindings(run.findings), [run]);
  const exhibitNo = useMemo(() => new Map(ordered.map((f, i) => [f.finding_id, i + 1])), [ordered]);

  const [risk, setRisk] = useState<RiskFilter>("all");
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [anomaliesFirst, setAnomaliesFirst] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "no", dir: 1 });

  const total = run.findings.length;
  const cve = run.findings.filter((f) => f.category === "cve").length;
  const riskCounts = useMemo(() => {
    const m: Record<string, number> = { all: total };
    for (const r of RISK_ORDER) m[r] = run.findings.filter((f) => f.initial_risk === r).length;
    return m;
  }, [run, total]);
  const categories = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of run.findings) m.set(f.category, (m.get(f.category) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => (a[0] === "cve" ? -1 : b[0] === "cve" ? 1 : a[0].localeCompare(b[0])));
  }, [run]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = ordered.filter((f) => {
      if (risk !== "all" && f.initial_risk !== risk) return false;
      if (category !== "all" && f.category !== category) return false;
      if (!q) return true;
      const hay = [f.title, f.component_purl, f.file_path, f.vuln_id, f.category, f.detector, ...f.aliases].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });
    const cmp: Record<SortKey, (a: Finding, b: Finding) => number> = {
      no: (a, b) => exhibitNo.get(a.finding_id)! - exhibitNo.get(b.finding_id)!,
      risk: (a, b) => riskRank(a.initial_risk) - riskRank(b.initial_risk),
      title: (a, b) => a.title.localeCompare(b.title),
      component: (a, b) => component(a).localeCompare(component(b)),
      depth: (a, b) => depthRank(a) - depthRank(b),
      label: (a, b) => labelRank(b) - labelRank(a),
      evidence: (a, b) => b.evidence_ids.length - a.evidence_ids.length,
    };
    const byNo = cmp.no;
    return list.sort((a, b) => {
      if (anomaliesFirst) {
        const d = Number(isAnomaly(b)) - Number(isAnomaly(a));
        if (d) return d;
      }
      return cmp[sort.key](a, b) * sort.dir || byNo(a, b);
    });
  }, [ordered, exhibitNo, risk, category, query, anomaliesFirst, sort]);

  const filtered = risk !== "all" || category !== "all" || query.trim() !== "";
  const clear = () => {
    setRisk("all");
    setCategory("all");
    setQuery("");
  };

  const toggleSort = (key: SortKey) => setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));

  // keep the selected exhibit in view when it is chosen elsewhere (graph, path chips)
  const bodyRef = useRef<HTMLTableSectionElement>(null);
  useEffect(() => {
    if (!selectedFindingId) return;
    const el = bodyRef.current?.querySelector<HTMLElement>(`[data-fid="${selectedFindingId}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [selectedFindingId]);

  const onRowKey = (e: KeyboardEvent<HTMLTableRowElement>, id: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectFinding(id);
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = (e.key === "ArrowDown" ? e.currentTarget.nextElementSibling : e.currentTarget.previousElementSibling) as HTMLElement | null;
      next?.focus();
    }
  };

  return (
    <section className="findings" aria-labelledby="findings-title">
      <div className="panelhead">
        <h2 id="findings-title">Exhibits</h2>
        <span className="meta">{total} findings · {cve} CVE · {total - cve} supply-chain anomalies</span>
      </div>

      <div className="ff-bar" role="search">
        <div className="seg" role="group" aria-label="Filter by risk">
          {(["all", ...RISK_ORDER] as RiskFilter[]).map((r) => (
            <button key={r} className={`seg-btn r-${r}`} aria-pressed={risk === r} onClick={() => setRisk(r)}>
              {r !== "all" && <span className="seg-dot" aria-hidden />}
              <span className="seg-name">{r === "all" ? "All" : r}</span>
              <span className="seg-n">{riskCounts[r]}</span>
            </button>
          ))}
        </div>

        <label className="ff-field">
          <span className="label">Category</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="all">All categories ({total})</option>
            {categories.map(([c, n]) => (
              <option key={c} value={c}>{categoryName(c)} ({n})</option>
            ))}
          </select>
        </label>

        <label className="ff-search">
          <Search size={14} strokeWidth={2} aria-hidden />
          <span className="sr-only">Search findings</span>
          <input type="search" value={query} placeholder="Search id, package, file" onChange={(e) => setQuery(e.target.value)} />
          {query && (
            <button className="ff-x" onClick={() => setQuery("")} aria-label="Clear search">
              <X size={13} strokeWidth={2} aria-hidden />
            </button>
          )}
        </label>

        <button className="ff-toggle" role="switch" aria-checked={anomaliesFirst} onClick={() => setAnomaliesFirst((v) => !v)}>
          <span className="ff-track" aria-hidden><span className="ff-knob" /></span>
          Anomalies first
        </button>
      </div>

      <div className="ff-scroll">
        {rows.length === 0 ? (
          <div className="ff-empty">
            <p className="ff-empty-title">No exhibits match these filters</p>
            <p>{total} findings are on file; the current risk, category or search excludes all of them.</p>
            <button className="ff-clear" onClick={clear}>Clear filters</button>
          </div>
        ) : (
          <table className="ff-table">
            <caption className="sr-only">
              {rows.length} of {total} findings{filtered ? " (filtered)" : ""}. Select a row to open its exhibit sheet.
            </caption>
            <thead>
              <tr>
                {COLS.map((c) => {
                  const active = sort.key === c.key;
                  const Icon = active ? (sort.dir === 1 ? ArrowUp : ArrowDown) : ArrowUpDown;
                  return (
                    <th key={c.key} className={c.cls} scope="col" aria-sort={active ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
                      <button className={`th-btn${active ? " on" : ""}`} onClick={() => toggleSort(c.key)}>
                        {c.name}
                        <Icon size={12} strokeWidth={2} aria-hidden />
                      </button>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody ref={bodyRef}>
              {rows.map((f) => (
                <Row
                  key={f.finding_id}
                  f={f}
                  no={exhibitNo.get(f.finding_id)!}
                  width={String(total).length}
                  selected={f.finding_id === selectedFindingId}
                  onSelect={() => selectFinding(f.finding_id)}
                  onKey={(e) => onRowKey(e, f.finding_id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

function Row({ f, no, width, selected, onSelect, onKey }: {
  f: Finding; no: number; width: number; selected: boolean;
  onSelect: () => void; onKey: (e: KeyboardEvent<HTMLTableRowElement>) => void;
}) {
  const d = pathDepth(f);
  const lc = labelCounts(f);
  const fl = fileLine(f);
  return (
    <tr
      data-fid={f.finding_id}
      className={selected ? "sel" : undefined}
      tabIndex={0}
      aria-selected={selected}
      onClick={onSelect}
      onKeyDown={onKey}
    >
      <td className="c-no">{String(no).padStart(width, "0")}</td>
      <td className="c-risk">
        {f.initial_risk ? <span className={`stamp sm ${f.initial_risk}`}>{f.initial_risk}</span> : <span className="stamp sm rule">Unrated</span>}
      </td>
      <td className="c-title">
        <span className={`t-main${f.vuln_id ? " is-id" : ""}`}>{f.vuln_id ?? f.title}</span>
        <span className="t-cat">{categoryName(f.category)}{f.cvss != null ? ` · CVSS ${f.cvss}` : ""}</span>
      </td>
      <td className="c-comp">
        {f.component_purl ? (
          <span className="mono">{breakable(f.component_purl)}</span>
        ) : fl ? (
          <span className="mono file">{breakable(fl)}</span>
        ) : (
          <span className="none">–</span>
        )}
        {f.component_purl && f.category !== "cve" && fl && <span className="mono sub">{breakable(fl)}</span>}
      </td>
      <td className="c-depth">
        {d.kind === "none" ? <span className="none">file</span> : d.kind === "direct" ? "direct" : <>transitive<span className="sub">{d.hops} hops</span></>}
        {d.paths > 1 && <span className="sub">{d.paths} paths</span>}
      </td>
      <td className="c-label">
        {lc.verified + lc.inferred + lc.rejected === 0 ? (
          <span className="stamp sm rule">{f.initial_risk_source === "llm" ? "Analyst" : "Rule"}</span>
        ) : (
          <span className="labels">
            {lc.verified > 0 && <span className="stamp sm verified">Verified {lc.verified}</span>}
            {lc.inferred > 0 && <span className="stamp sm inferred">Inferred {lc.inferred}</span>}
            {lc.rejected > 0 && <span className="stamp sm rejected">Rejected {lc.rejected}</span>}
          </span>
        )}
      </td>
      <td className="c-evn">{f.evidence_ids.length}</td>
    </tr>
  );
}
