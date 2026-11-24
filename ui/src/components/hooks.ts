import { useEffect, useRef, useState } from "react";
import { firstAvailable, loadEvidence, reportCandidates } from "../api/client";
import type { Evidence } from "../api/types";
import { useStore } from "../store";

export type EvState = { status: "loading" } | { status: "missing" } | { status: "ok"; ev: Evidence };

export function useEvidence(id: string | null | undefined): EvState {
  const { src } = useStore();
  const [st, setSt] = useState<EvState>({ status: "loading" });
  useEffect(() => {
    let dead = false;
    if (!id) {
      setSt({ status: "missing" });
      return;
    }
    setSt({ status: "loading" });
    loadEvidence(src, id).then((ev) => {
      if (!dead) setSt(ev ? { status: "ok", ev } : { status: "missing" });
    });
    return () => {
      dead = true;
    };
  }, [src, id]);
  return st;
}

export function useEvidenceMany(ids: string[]): { loaded: boolean; items: Evidence[] } {
  const { src } = useStore();
  const key = ids.join("|");
  const [st, setSt] = useState<{ loaded: boolean; items: Evidence[] }>({ loaded: false, items: [] });
  useEffect(() => {
    let dead = false;
    setSt({ loaded: false, items: [] });
    Promise.all(ids.map((i) => loadEvidence(src, i))).then((r) => {
      if (!dead) setSt({ loaded: true, items: r.filter((x): x is Evidence => !!x) });
    });
    return () => {
      dead = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src, key]);
  return st;
}

export function useStoredState<T extends string = string>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      return (localStorage.getItem(key) as T | null) ?? initial;
    } catch {
      return initial;
    }
  });
  return [
    v,
    (n: T) => {
      setV(n);
      try {
        localStorage.setItem(key, n);
      } catch {
        /* storage unavailable */
      }
    },
  ];
}

export function useCountTween(target: number, ms = 240): number {
  const [v, setV] = useState(target);
  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setV(target);
      return;
    }
    const from = v;
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      setV(from + (target - from) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, ms]);
  return v;
}

/** React 18 types do not know `inert`; spread this on an element that must be unfocusable while hidden. */
export const inertProps = { inert: "" } as Record<string, string>;

/** Close a popover on outside click or Escape. */
export function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const off = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        close();
      }
    };
    document.addEventListener("mousedown", off);
    document.addEventListener("keydown", esc, true);
    return () => {
      document.removeEventListener("mousedown", off);
      document.removeEventListener("keydown", esc, true);
    };
  }, [open, close]);
  return ref;
}

export type ReportLinks = { json: string | null; html: string | null } | "pending" | "not_yet";

/**
 * Where the exported reports are. The API only has them once the run is done, so for a live run
 * nothing is requested (a probe would be a guaranteed 404).
 */
export function useReportLinks(src: { kind: string; runId: string }, status: string, enabled = true): ReportLinks {
  const [links, setLinks] = useState<ReportLinks>("pending");
  const mayHave = src.kind !== "api" || status === "done";
  useEffect(() => {
    let dead = false;
    if (!enabled) return;
    if (!mayHave) {
      setLinks("not_yet");
      return;
    }
    setLinks("pending");
    const s = src as Parameters<typeof reportCandidates>[0];
    Promise.all([firstAvailable(reportCandidates(s, "json")), firstAvailable(reportCandidates(s, "html"))]).then(
      ([json, html]) => !dead && setLinks({ json, html }),
    );
    return () => {
      dead = true;
    };
  }, [src.kind, src.runId, mayHave, enabled]); // eslint-disable-line react-hooks/exhaustive-deps
  return links;
}

export function typingTarget(t: EventTarget | null): boolean {
  return t instanceof HTMLElement && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
}
