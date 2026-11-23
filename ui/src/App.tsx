import { useStoredState } from "./components/hooks";
import Inspector from "./components/Inspector";
import Pipeline from "./components/Pipeline";
import EventDrawer from "./components/EventDrawer";
import Rail from "./components/Rail";
import Telemetry from "./components/Telemetry";
import GraphView from "./components/GraphView";
import FindingsTable from "./components/FindingsTable";
import ApprovalGate from "./components/ApprovalGate";
import ValidationView from "./components/ValidationView";
import ReportView from "./components/ReportView";
import { Provider, useStore } from "./store";

export default function App() {
  return (
    <Provider>
      <Shell />
    </Provider>
  );
}

function Shell() {
  const { view } = useStore();
  const [rail, setRail] = useStoredState<"open" | "closed">("guardian.rail", "open");
  return (
    <div className={`app${rail === "closed" ? " rail-c" : ""}`}>
      <Telemetry />
      <Rail collapsed={rail === "closed"} toggle={() => setRail(rail === "closed" ? "open" : "closed")} />
      <main className="main">
        <Pipeline />
        <div className="stage">
          {view === "graph" && <GraphView />}
          {view === "findings" && <FindingsTable />}
          {view === "gate" && <ApprovalGate />}
          {view === "validation" && <ValidationView />}
          {view === "report" && <ReportView />}
        </div>
        <EventDrawer />
      </main>
      <Inspector />
    </div>
  );
}
