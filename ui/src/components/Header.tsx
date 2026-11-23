import { Activity, ChevronDown, Download, Info, Keyboard, LogOut, Shield } from "lucide-react";
import { useCallback, useState } from "react";
import { fmtDate, shortCommit } from "../lib/format";
import { LLM_NAME, llmMode, statusText } from "../lib/labels";
import { useStore } from "../store";
import { useDismiss, useReportLinks } from "./hooks";
import { Tip } from "./ui";

const STATUS: Record<string, { text: string; cls: string }> = {
  done: { text: "Complete", cls: "ok" },
  awaiting_human: { text: "Needs your approval", cls: "gate" },
  failed: { text: "Failed", cls: "bad" },
  running: { text: "Running", cls: "info" },
};

export default function Header() {
  const { data, runs, switchRun, kind, status, events, live, drawerOpen, setDrawerOpen, setDrawerAgent, setHelpOpen, me, signOut } = useStore();
  const s = data.summary;
  const list = runs.some((r) => r.id === data.runId)
    ? runs
    : [{ id: data.runId, target: s.target, status, mode: s.llm?.mode ?? null, commit: s.commit }, ...runs];
  const st = STATUS[status] ?? { text: status.replace(/_/g, " "), cls: "" };
  const mode = llmMode(s.llm?.mode);
  return (
    <header className="top">
      <div className="brand">
        <Shield size={20} strokeWidth={2} aria-hidden />
        <span>Guardian</span>
      </div>
      <div className="top-run">
        <label className="switcher">
          <span className="sr">Choose a scan</span>
          <select value={data.runId} onChange={(e) => switchRun(e.target.value)} disabled={kind === "sample" || list.length < 2}>
            {list.map((r) => (
              <option key={r.id} value={r.id}>
                {r.target} · {r.id.replace(/^run_/, "")}
              </option>
            ))}
          </select>
          <ChevronDown size={16} aria-hidden className="sel-chev" />
        </label>
        <RunDetails />
      </div>
      <Tip text={mode.help} side="bottom">
        <span className="top-chip" tabIndex={0}>
          <span className="faint">AI</span>
          <span>
            {LLM_NAME(s.llm?.model)} <span className="faint">·</span> {mode.word}
          </span>
        </span>
      </Tip>
      <span className="grow" />
      <span className={`pill big ${st.cls}`}>
        <span className={`dot ${st.cls}`} aria-hidden />
        {st.text}
      </span>
      <Tip text={drawerOpen ? "Hide the activity log" : "Show everything the agents did, step by step"} side="bottom">
        <button
          type="button"
          className="btn"
          aria-expanded={drawerOpen}
          onClick={() => {
            setDrawerAgent(null);
            setDrawerOpen(!drawerOpen);
          }}
        >
          <Activity size={16} aria-hidden />
          Activity
          <span className={`live-dot ${live}`} aria-hidden />
          <span className="num faint">{events.length}</span>
        </button>
      </Tip>
      <ExportMenu />
      <Tip text={me.mode === "token" ? `Signed in as ${me.name} (${me.role})` : "Running without sign-in (local development)"} side="bottom">
        <span className="top-chip" tabIndex={0}>
          {me.mode === "token" ? (<>{me.name} <span className="pill">{me.role}</span></>) : <span>Local dev</span>}
        </span>
      </Tip>
      {me.mode === "token" && (
        <Tip text="Sign out" side="bottom">
          <button type="button" className="btn icon ghost" aria-label="Sign out" onClick={signOut}>
            <LogOut size={16} aria-hidden />
          </button>
        </Tip>
      )}
      <Tip text="Keyboard shortcuts (?)" side="bottom">
        <button type="button" className="btn icon ghost" aria-label="Keyboard shortcuts" onClick={() => setHelpOpen(true)}>
          <Keyboard size={16} aria-hidden />
        </button>
      </Tip>
    </header>
  );
}

function RunDetails() {
  const { data, kind, status } = useStore();
  const s = data.summary;
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const ref = useDismiss(open, close);
  const mode = llmMode(s.llm?.mode);
  return (
    <div className="menu" ref={ref}>
      <Tip text="Details about this scan" side="bottom">
        <button type="button" className="btn icon ghost" aria-label="Scan details" aria-expanded={open} onClick={() => setOpen(!open)}>
          <Info size={16} aria-hidden />
        </button>
      </Tip>
      {open && (
        <div className="menu-pop left" style={{ minWidth: 380 }} role="dialog" aria-label="Scan details">
          <p className="pop-head">This scan</p>
          <dl className="kv">
            <dt>Target</dt><dd>{s.target}</dd>
            <dt>Commit</dt><dd className="mono">{shortCommit(s.commit)}{s.commit ? <span className="faint"> {s.commit}</span> : null}</dd>
            <dt>Scan id</dt><dd className="mono">{data.runId}</dd>
            <dt>Started</dt><dd>{fmtDate(s.started_at)}</dd>
            {s.finished_at && (<><dt>Finished</dt><dd>{fmtDate(s.finished_at)}</dd></>)}
            <dt>Status</dt><dd>{statusText(status)}</dd>
            <dt>AI model</dt><dd>{LLM_NAME(s.llm?.model)} {s.llm?.model ? <span className="mono faint">({s.llm.model})</span> : null}</dd>
            <dt>AI mode</dt><dd>{mode.word}<br /><span className="muted">{mode.help}</span></dd>
            <dt>Data source</dt><dd>{kind === "api" ? "Live Guardian service" : kind === "static" ? "Static run folder" : "Built-in offline sample"}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}

function ExportMenu() {
  const { src, status } = useStore();
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const ref = useDismiss(open, close);
  const links = useReportLinks(src, status);
  const url = (k: "json" | "html") => (typeof links === "object" ? links[k] : null);
  const why = links === "pending" ? "checking" : links === "not_yet" ? "Available when the scan completes" : "Not generated for this scan";
  const item = (label: string, help: string, u: string | null, file: string) =>
    u ? (
      <a className="menu-item" href={u} download={file} target="_blank" rel="noreferrer" onClick={close}>
        {label}
        <small>{help}</small>
      </a>
    ) : (
      <span className="menu-item off" aria-disabled="true">
        {label}
        <small>{why}</small>
      </span>
    );
  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Download size={16} aria-hidden /> Export report <ChevronDown size={14} aria-hidden />
      </button>
      {open && (
        <div className="menu-pop" role="menu">
          {item("Report (HTML)", "A readable page you can share or print", url("html"), "report.html")}
          {item("Report (JSON)", "Every finding, score and decision, for other tools", url("json"), "report.json")}
        </div>
      )}
    </div>
  );
}
