import { CheckCheck, FileText, FlaskConical, ListChecks, Network, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useStore, type View } from "../store";

const ITEMS: { id: View; label: string; Icon: LucideIcon }[] = [
  { id: "graph", label: "Dependency graph", Icon: Network },
  { id: "findings", label: "Findings", Icon: ListChecks },
  { id: "gate", label: "Approval gate", Icon: CheckCheck },
  { id: "validation", label: "Validation", Icon: FlaskConical },
  { id: "report", label: "Report", Icon: FileText },
];

export default function Rail({ collapsed, toggle }: { collapsed: boolean; toggle: () => void }) {
  const { view, setView, data, status } = useStore();
  const badge = (id: View) => {
    if (id === "findings") return String(data.findings.length);
    if (id === "gate" && data.summary.pending_plan) return "1";
    return null;
  };
  return (
    <nav className="rail" aria-label="Views">
      <ul>
        {ITEMS.map(({ id, label, Icon }) => {
          const b = badge(id);
          const gate = id === "gate" && status === "awaiting_human";
          return (
            <li key={id}>
              <button
                type="button"
                className={`rail-item${view === id ? " on" : ""}${gate ? " gate" : ""}`}
                aria-current={view === id ? "page" : undefined}
                title={collapsed ? label : undefined}
                onClick={() => setView(id)}
              >
                <Icon size={17} aria-hidden />
                <span className="rail-label">{label}</span>
                {b && <span className="rail-badge num">{b}</span>}
              </button>
            </li>
          );
        })}
      </ul>
      <button
        type="button"
        className="rail-item rail-toggle"
        onClick={toggle}
        aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
        title={collapsed ? "Expand navigation" : "Collapse navigation"}
      >
        {collapsed ? <PanelLeftOpen size={17} aria-hidden /> : <PanelLeftClose size={17} aria-hidden />}
        <span className="rail-label">Collapse</span>
      </button>
    </nav>
  );
}
