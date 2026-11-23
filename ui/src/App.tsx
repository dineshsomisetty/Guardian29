import { useEffect, useState } from "react";
import { loadRun } from "./api/load";
import type { RunData } from "./api/types";
import { SelectionProvider, useSel } from "./state";
import Rail from "./components/Rail";
import CountStrip from "./components/CountStrip";
import GraphView from "./components/GraphView";
import FindingsList from "./components/FindingsList";
import ChangesPanel from "./components/ChangesPanel";
import CustodyLog from "./components/CustodyLog";
import ExhibitSheet from "./components/ExhibitSheet";

type Loaded = RunData & { source: "server" | "sample" };

export default function App() {
  const [run, setRun] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadRun().then(setRun).catch((e) => setError(String(e)));
  }, []);

  if (error) {
    return (
      <div className="boot">
        <p className="boot-title">No run to show</p>
        <p>Start the run server with <code>make serve-runs</code>, then run <code>python -m guardian run --repo targets/juice-shop</code>.</p>
        <p className="boot-err">{error}</p>
      </div>
    );
  }
  if (!run) return <div className="boot"><p className="boot-title">Opening case file…</p></div>;

  return (
    <SelectionProvider run={run}>
      <Shell source={run.source} />
    </SelectionProvider>
  );
}

function Shell({ source }: { source: "server" | "sample" }) {
  const { section } = useSel();
  return (
    <div className="shell">
      <Rail source={source} />
      <main className="work">
        <CountStrip />
        <div className="work-body">
          {section === "graph" && <GraphView />}
          {section === "exhibits" && <FindingsList />}
          {section === "changes" && <ChangesPanel />}
          {section === "custody" && <CustodyLog />}
        </div>
      </main>
      <ExhibitSheet />
    </div>
  );
}
