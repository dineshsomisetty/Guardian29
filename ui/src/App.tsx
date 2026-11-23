import { useEffect } from "react";
import { typingTarget, useStoredState } from "./components/hooks";
import Inspector from "./components/Inspector";
import Pipeline from "./components/Pipeline";
import EventDrawer from "./components/EventDrawer";
import Rail, { VIEW_INFO } from "./components/Rail";
import Header from "./components/Header";
import GraphView from "./components/GraphView";
import FindingsTable from "./components/FindingsTable";
import ApprovalGate from "./components/ApprovalGate";
import ValidationView from "./components/ValidationView";
import ReportView from "./components/ReportView";
import Overview from "./components/Overview";
import ShortcutHelp from "./components/ShortcutHelp";
import { Provider, VIEWS, useStore } from "./store";

export default function App() {
  return (
    <Provider>
      <Shell />
    </Provider>
  );
}

function Shell() {
  const { view, setView, data, setHelpOpen, helpOpen } = useStore();
  const [rail, setRail] = useStoredState<"open" | "closed">("guardian.rail", "open");

  useEffect(() => {
    document.title = `${VIEW_INFO[view].title} - ${data.summary.target} - Guardian`;
  }, [view, data.summary.target]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typingTarget(e.target) || helpOpen) return;
      if (e.key === "?") {
        e.preventDefault();
        setHelpOpen(true);
      } else if (e.key === "/") {
        const el = document.querySelector<HTMLInputElement>("[data-search]");
        if (el) {
          e.preventDefault();
          el.focus();
          el.select();
        }
      } else if (/^[1-6]$/.test(e.key)) {
        setView(VIEWS[Number(e.key) - 1]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setView, setHelpOpen, helpOpen]);

  return (
    <div className={`app${rail === "closed" ? " rail-c" : ""}`}>
      <Header />
      <Rail collapsed={rail === "closed"} toggle={() => setRail(rail === "closed" ? "open" : "closed")} />
      <main className="main">
        <Pipeline />
        <div className="stage" key={view}>
          {view === "overview" && <Overview />}
          {view === "graph" && <GraphView />}
          {view === "findings" && <FindingsTable />}
          {view === "gate" && <ApprovalGate />}
          {view === "validation" && <ValidationView />}
          {view === "report" && <ReportView />}
        </div>
        <EventDrawer />
      </main>
      <Inspector />
      <ShortcutHelp />
    </div>
  );
}
