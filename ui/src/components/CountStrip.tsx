import { useSel } from "../state";

/** full copy on projector widths, abbreviated below 1360px where each cell is ~95px wide (CSS swaps them) */
function Alt({ full, short }: { full: string; short: string }) {
  return (
    <>
      <span className="s-full">{full}</span>
      <span className="s-short">{short}</span>
    </>
  );
}

export default function CountStrip() {
  const { run } = useSel();
  const { summary, changes } = run;
  const br = summary.findings.by_risk;
  const nonCve = Object.entries(summary.findings.by_category).filter(([k]) => k !== "cve").reduce((n, [, v]) => n + v, 0);

  const cve = summary.findings.by_category.cve ?? 0;
  const projects = summary.projects.join(" + ");
  // CVE findings reached through at least one intermediate package (root > direct > ... > vulnerable)
  const tracedPaths = run.findings.filter((f) => f.category === "cve" && (f.dependency_paths[0]?.length ?? 0) > 2).length;

  return (
    <section className="strip" aria-label="Run totals">
      <div className="cell">
        <span className="label">Components</span>
        <span className="v">{(summary.sbom.components ?? 0).toLocaleString()}</span>
        <span className="sub" title={projects}>{projects || "no projects"}</span>
      </div>
      <div className="cell">
        <span className="label">Direct deps</span>
        <span className="v">{summary.sbom.direct ?? "–"}</span>
        <span className="sub">{(summary.sbom.transitive ?? 0).toLocaleString()} transitive</span>
      </div>
      <div className="cell">
        <span className="label">Findings</span>
        <span className="v">{summary.findings.total}</span>
        <span className="sub">{cve} CVE · {nonCve} other</span>
      </div>
      <div className="cell">
        <span className="label">Critical · High</span>
        <span className="v"><span className="risk-critical">{br.critical}</span><small>·</small><span className="risk-high">{br.high}</span></span>
        <span className="sub">{br.medium} med · {br.low} low</span>
      </div>
      <div className="cell">
        <span className="label"><Alt full="Transitive CVEs" short="Transitive" /></span>
        <span className="v">{tracedPaths}</span>
        <span className="sub"><Alt full="paths traced" short="paths traced" /></span>
      </div>
      <div className="cell">
        <span className="label">Changed</span>
        <span className="v">{changes ? <>+{changes.added.length}<small>−{changes.removed.length}</small></> : "–"}</span>
        <span className="sub">{changes ? <Alt full="vs legacy manifest" short="vs legacy" /> : "no baseline"}</span>
      </div>
    </section>
  );
}
