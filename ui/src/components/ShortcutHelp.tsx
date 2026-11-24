import { X } from "lucide-react";
import { useEffect, useRef } from "react";
import { useStore } from "../store";

const GROUPS: { title: string; rows: [string[], string][] }[] = [
  {
    title: "Anywhere",
    rows: [
      [["1", "2", "3", "4", "5", "6"], "Switch view (Overview, Map, Findings, Remediation, Validation, Report)"],
      [["/"], "Search in the current view"],
      [["?"], "Show this help"],
      [["Esc"], "Close the panel on top"],
    ],
  },
  {
    title: "Findings list",
    rows: [
      [["j", "k"], "Move down / up (arrow keys work too)"],
      [["Enter"], "Open the selected finding"],
      [["→", "←"], "Expand / collapse a group of the same advisory"],
    ],
  },
  {
    title: "Finding details",
    rows: [
      [["↓", "↑"], "Next / previous finding"],
      [["Esc"], "Close"],
    ],
  },
  {
    title: "Dependency map",
    rows: [
      [["Scroll"], "Move around the map"],
      [["Ctrl", "Scroll"], "Zoom in and out (pinch works on a trackpad)"],
      [["+", "-"], "Zoom in / out"],
      [["0"], "Fit the whole map"],
      [["Double-click"], "Zoom to a package"],
    ],
  },
];

export default function ShortcutHelp() {
  const { helpOpen, setHelpOpen } = useStore();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!helpOpen) return;
    ref.current?.focus();
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setHelpOpen(false);
      }
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [helpOpen, setHelpOpen]);
  if (!helpOpen) return null;
  return (
    <div className="modal-scrim" onMouseDown={() => setHelpOpen(false)}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        tabIndex={-1}
        ref={ref}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="modal-head">
          <h2>Keyboard shortcuts</h2>
          <button type="button" className="btn ghost icon" aria-label="Close" onClick={() => setHelpOpen(false)}>
            <X size={16} aria-hidden />
          </button>
        </header>
        <div className="modal-body">
          {GROUPS.map((g) => (
            <section key={g.title}>
              <h3 className="mini-h">{g.title}</h3>
              <dl className="keys">
                {g.rows.map(([keys, what]) => (
                  <div key={what}>
                    <dt>{keys.map((k) => <kbd key={k}>{k}</kbd>)}</dt>
                    <dd>{what}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
