import { CheckCircle2, CircleAlert, Loader2, Timer } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { type ActivityDoc, type ActivityStep, fetchActivity } from "../api/client";
import { useStore } from "../store";
import { useDismiss } from "./hooks";
import { Tip } from "./ui";

/** 75 -> "1m 15s", 8 -> "8s". */
function dur(s: number): string {
  const n = Math.max(0, Math.round(s));
  return n < 60 ? `${n}s` : `${Math.floor(n / 60)}m ${String(n % 60).padStart(2, "0")}s`;
}

const KIND: Record<string, string> = { tool: "Step", container: "Container", baseline: "Baseline" };

/** Poll /activity: every 2 s while something runs, every 6 s otherwise (a run can be resumed from elsewhere). */
function useActivity(): ActivityDoc | null {
  const { src } = useStore();
  const [doc, setDoc] = useState<ActivityDoc | null>(null);
  useEffect(() => {
    let dead = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setDoc(null);
    const tick = async () => {
      const d = await fetchActivity(src);
      if (dead) return;
      setDoc(d);
      if (d) timer = setTimeout(tick, d.running.length ? 2000 : 6000);
    };
    tick();
    return () => {
      dead = true;
      if (timer) clearTimeout(timer);
    };
  }, [src.kind, src.runId]); // eslint-disable-line react-hooks/exhaustive-deps
  return doc;
}

/** Re-render every second while open, so the elapsed timers move between polls. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

/** Steps in tree order (a container under the tool that started it) with their depth. */
function tree(steps: ActivityStep[]): { s: ActivityStep; depth: number }[] {
  const ids = new Set(steps.map((s) => s.id));
  const kids = new Map<string | null, ActivityStep[]>();
  for (const s of steps) {
    const p = s.parent && ids.has(s.parent) ? s.parent : null;
    kids.set(p, [...(kids.get(p) ?? []), s]);
  }
  const out: { s: ActivityStep; depth: number }[] = [];
  const walk = (p: string | null, depth: number) => {
    for (const s of kids.get(p) ?? []) {
      out.push({ s, depth });
      walk(s.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

export default function RunningNow() {
  const { kind } = useStore();
  const doc = useActivity();
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const ref = useDismiss(open, close);
  const running = doc?.running ?? [];
  const busy = running.length > 0;
  const now = useNow(open || busy);
  if (kind !== "api" || !doc) return null;

  // server and browser clocks may differ: elapsed = (server time + time since the poll) - started_at
  const skew = doc.server_time ? Date.parse(doc.server_time) - Date.now() : 0;
  const elapsed = (s: ActivityStep) => (now + skew - Date.parse(s.started_at)) / 1000;
  const containers = running.filter((s) => s.kind === "container").length;
  const label = busy ? (containers ? `${containers} container${containers === 1 ? "" : "s"} running` : "Working") : "Idle";
  const oldest = busy ? Math.max(...running.map(elapsed)) : 0;

  return (
    <div className="menu" ref={ref}>
      {(() => {
        const btn = (
          <button type="button" className={`btn run-now ${busy ? "busy" : ""}`} aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpen(!open)}>
            {busy ? <Loader2 size={16} className="spin" aria-hidden /> : <Timer size={16} aria-hidden />}
            {label}
            {busy && <span className="num faint">{dur(oldest)}</span>}
          </button>
        );
        // no hover tip while the panel is open: it would cover the list
        return open ? btn : (
          <Tip text={busy ? "See what Guardian is running right now" : "Nothing is running; see what finished last"} side="bottom">{btn}</Tip>
        );
      })()}
      {open && (
        <div className="menu-pop run-now-pop" role="dialog" aria-label="Running now">
          <p className="pop-head">Running now</p>
          {busy ? (
            <ul className="act-list">
              {tree(running).map(({ s, depth }) => (
                <li key={s.id} className={`act-row k-${s.kind}`} style={{ paddingLeft: `calc(var(--s3) + ${depth * 18}px)` }}>
                  <Loader2 size={14} className="spin act-ico" aria-hidden />
                  <span className="act-main">
                    <span className="act-label">{s.label}</span>
                    <small>{KIND[s.kind] ?? s.kind}{s.detail ? ` · ${s.detail}` : ""}</small>
                  </span>
                  <span className="num act-time">{dur(elapsed(s))}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="act-empty">
              {doc.stale
                ? "The process that was running these steps stopped (it was closed or crashed); they did not finish."
                : doc.status === "awaiting_human"
                  ? "Nothing is running. The scan is waiting for a decision."
                  : "Nothing is running."}
            </p>
          )}
          {doc.stale && doc.interrupted?.length ? (
            <ul className="act-list">
              {doc.interrupted.map((s) => (
                <li key={s.id} className="act-row">
                  <CircleAlert size={14} className="act-ico bad" aria-hidden />
                  <span className="act-main"><span className="act-label">{s.label}</span><small>interrupted</small></span>
                </li>
              ))}
            </ul>
          ) : null}
          {doc.recent.length > 0 && (
            <>
              <p className="pop-head">Just finished</p>
              <ul className="act-list">
                {doc.recent.slice(0, 8).map((s) => {
                  const ok = s.outcome === "ok";
                  return (
                    <li key={s.id} className="act-row">
                      {ok ? <CheckCircle2 size={14} className="act-ico ok" aria-hidden /> : <CircleAlert size={14} className="act-ico warn" aria-hidden />}
                      <span className="act-main">
                        <span className="act-label">{s.label}</span>
                        <small>{ok ? "done" : s.outcome}{s.ended_at ? ` · ${new Date(s.ended_at).toLocaleTimeString()}` : ""}</small>
                      </span>
                      <span className="num act-time faint">{dur(s.seconds ?? 0)}</span>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
