import {
  CheckCheck, FileText, FlaskConical, LayoutDashboard, ListChecks, Network, PanelLeftClose, PanelLeftOpen,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useStore, type View } from "../store";
import { Tip } from "./ui";

export const VIEW_INFO: Record<View, { label: string; title: string; Icon: LucideIcon; key: string }> = {
  overview: { label: "Overview", title: "Overview", Icon: LayoutDashboard, key: "1" },
  graph: { label: "Dependency map", title: "Dependency map", Icon: Network, key: "2" },
  findings: { label: "Findings", title: "Findings", Icon: ListChecks, key: "3" },
  gate: { label: "Approval", title: "Approval", Icon: CheckCheck, key: "4" },
  validation: { label: "Validation", title: "Validation", Icon: FlaskConical, key: "5" },
  report: { label: "Report", title: "Report", Icon: FileText, key: "6" },
};
const ORDER: View[] = ["overview", "graph", "findings", "gate", "validation", "report"];

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
        {ORDER.map((id) => {
          const { label, Icon, key } = VIEW_INFO[id];
          const b = badge(id);
          const gate = id === "gate" && status === "awaiting_human";
          const btn = (
            <button
              type="button"
              className={`rail-item${view === id ? " on" : ""}${gate ? " gate" : ""}`}
              aria-current={view === id ? "page" : undefined}
              aria-label={collapsed ? label : undefined}
              onClick={() => setView(id)}
            >
              <Icon size={18} aria-hidden />
              <span className="rail-label">{label}</span>
              {b && <span className="rail-badge num">{b}</span>}
              {!b && <kbd className="rail-key">{key}</kbd>}
            </button>
          );
          return (
            <li key={id}>
              {collapsed ? (
                <Tip text={`${label} (${key})`} side="right" block>
                  {btn}
                </Tip>
              ) : (
                btn
              )}
            </li>
          );
        })}
      </ul>
      <Tip text={collapsed ? "Expand the menu" : "Collapse the menu"} side="right" block>
        <button type="button" className="rail-item rail-toggle" onClick={toggle} aria-label={collapsed ? "Expand the menu" : "Collapse the menu"}>
          {collapsed ? <PanelLeftOpen size={18} aria-hidden /> : <PanelLeftClose size={18} aria-hidden />}
          <span className="rail-label">Collapse menu</span>
        </button>
      </Tip>
    </nav>
  );
}
