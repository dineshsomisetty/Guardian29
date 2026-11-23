import { Download, Shield } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { firstAvailable, reportCandidates } from "../api/client";
import { RISKS, RISK_LABEL, shortCommit } from "../lib/format";
import { useStore } from "../store";

export default function Telemetry() {
  const { data, runs, switchRun, kind, replay, status } = useStore();
  const s = data.summary;
  const by = s.findings?.by_risk ?? ({} as Record<string, number>);
  const list = runs.some((r) => r.id === data.runId)
    ? runs
    : [{ id: data.runId, target: s.target, status, mode: s.llm?.mode ?? null, commit: s.commit }, ...runs];
  return (
    <header className="top">
      <div className="brand">
        <Shield size={16} strokeWidth={2} aria-hidden />
        <span>Guardian</span>
      </div>
      <label className="switcher">
        <span className="sr">Target run</span>
        <select value={data.runId} onChange={(e) => switchRun(e.target.value)} disabled={kind === "sample"}>
          {list.map((r) => (
            <option key={r.id} value={r.id}>
              {r.target} · {r.id.replace(/^run_/, "")} · {r.status}
            </option>
          ))}
        </select>
      </label>
      <span className="tm-item" title={s.commit ?? undefined}>
        <span className="tm-k">commit</span>
        <span className="mono">{shortCommit(s.commit)}</span>
      </span>
      <span className="tm-item">
        <span className="tm-k">llm</span>
        <span className="mono">{s.llm?.model ?? s.llm?.mode ?? "none"}</span>
        {replay ? (
          <span className="pill gate mono" title="LLM responses are replayed from a recorded run">
            REPLAY
          </span>
        ) : (
          s.llm?.mode && <span className="pill mono">{s.llm.mode.toUpperCase()}</span>
        )}
      </span>
      <span className="tm-item tm-counts" aria-label="Findings by severity">
        {RISKS.map((r) => (
          <span key={r} className={`pill sev-${r}`} title={`${RISK_LABEL[r]} findings`}>
            <span className="num">{by[r] ?? 0}</span> {RISK_LABEL[r]}
          </span>
        ))}
      </span>
      <span className="tm-spacer" />
      <span className={`pill mono src-${kind}`} title="Where this view reads its data">
        {kind === "api" ? "API" : kind === "static" ? "STATIC" : "OFFLINE SAMPLE"}
      </span>
      <span
        className={`pill ${status === "done" ? "ok" : status === "awaiting_human" ? "gate" : status === "failed" ? "bad" : ""}`}
      >
        {status.replace("_", " ")}
      </span>
      <ExportMenu />
    </header>
  );
}

function ExportMenu() {
  const { src } = useStore();
  const [open, setOpen] = useState(false);
  const [links, setLinks] = useState<{ json: string | null; html: string | null } | "probing">("probing");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    let dead = false;
    setLinks("probing");
    Promise.all([firstAvailable(reportCandidates(src, "json")), firstAvailable(reportCandidates(src, "html"))]).then(
      ([json, html]) => !dead && setLinks({ json, html }),
    );
    const off = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", off);
    document.addEventListener("keydown", esc);
    return () => {
      dead = true;
      document.removeEventListener("mousedown", off);
      document.removeEventListener("keydown", esc);
    };
  }, [open, src]);
  const href = (k: "json" | "html") => (links === "probing" ? null : links[k]);
  const item = (label: string, url: string | null, file: string) =>
    url ? (
      <a className="menu-item" href={url} download={file} target="_blank" rel="noreferrer">
        {label}
      </a>
    ) : (
      <span className="menu-item off">
        {label} <span className="muted">{links === "probing" ? "checking" : "not generated yet"}</span>
      </span>
    );
  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Download size={14} aria-hidden /> Export
      </button>
      {open && (
        <div className="menu-pop" role="menu">
          {item("report.json", href("json"), "report.json")}
          {item("report.html", href("html"), "report.html")}
        </div>
      )}
    </div>
  );
}
