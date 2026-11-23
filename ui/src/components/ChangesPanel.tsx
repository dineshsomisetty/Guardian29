import { ArrowRight, Minus, Plus } from "lucide-react";
import { useMemo, useState } from "react";
import { useSel } from "../state";
import "../styles/changes.css";
import { buildRows, type DiffRow, type RowKind } from "./changes/rows";
import Segmented from "./trace/Segmented";

type Tab = "all" | RowKind;

function legacyTag(path: string) {
  return /\.(bak|old|orig)$/i.test(path) ? "legacy" : "baseline";
}

export default function ChangesPanel() {
  const { run } = useSel();
  const c = run.changes;
  const rows = useMemo(() => (c ? buildRows(c) : []), [c]);
  const [tab, setTab] = useState<Tab>("all");

  if (!c) {
    return (
      <div className="ch">
        <div className="panelhead"><h2>What changed</h2><span className="meta">no baseline manifest</span></div>
        <div className="ch-empty">
          <p className="ch-empty-title">No baseline to compare</p>
          <p>This run found no earlier manifest (for example a <span className="value">package.json.bak</span>) to diff against the current one.</p>
        </div>
      </div>
    );
  }

  const n = (k: RowKind) => rows.filter((r) => r.kind === k).length;
  const counts = { major: n("major"), changed: n("changed"), removed: n("removed"), added: n("added") };
  const shown = tab === "all" ? rows : tab === "changed" ? rows.filter((r) => r.kind === "changed" || r.kind === "major") : rows.filter((r) => r.kind === tab);
  const baseTag = legacyTag(c.base);

  return (
    <div className="ch">
      <div className="panelhead">
        <h2>What changed</h2>
        <span className="meta">
          <span className="value">{c.base}</span> ({baseTag})<ArrowRight className="sum-arrow" size={13} strokeWidth={2} aria-label="to" /><span className="value">{c.head}</span> (current)
          {c.evidence_ids.length > 0 && <> · evidence <span className="value">{c.evidence_ids.join(", ")}</span></>}
        </span>
      </div>

      <section className="ch-sum" aria-label="Change totals">
        <Cell label="Added" v={`+${counts.added}`} />
        <Cell label="Removed" v={`−${counts.removed}`} />
        <Cell label="Version changed" v={`${counts.changed + counts.major}`} />
        <Cell label="Major jumps" v={`${counts.major}`} tone={counts.major ? "high" : undefined} />
        <Cell label="Integrity changed" v={`${c.integrity_changed.length}`} tone={c.integrity_changed.length ? "high" : undefined} />
      </section>

      <div className="ch-tools">
        <Segmented<Tab>
          label="Filter changes"
          value={tab}
          onChange={setTab}
          options={[
            { id: "all", label: "All", count: rows.length },
            { id: "major", label: "Major jumps", count: counts.major },
            { id: "changed", label: "Changed", count: counts.changed + counts.major },
            { id: "added", label: "Added", count: counts.added },
            { id: "removed", label: "Removed", count: counts.removed },
          ]}
        />
      </div>

      <div className="ch-scroll">
        <table className="ch-table">
          <colgroup><col /><col className="ch-gcol" /><col /></colgroup>
          <thead>
            <tr>
              <th scope="col"><span className="label">Before</span> <span className="ch-file value">{c.base}</span></th>
              <th scope="col"><span className="label">Change</span></th>
              <th scope="col"><span className="label">After</span> <span className="ch-file value">{c.head}</span></th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => <Row key={r.name} r={r} />)}
            {shown.length === 0 && (
              <tr><td colSpan={3} className="ch-none">No dependencies in this group.</td></tr>
            )}
          </tbody>
        </table>

        {(tab === "all" || c.integrity_changed.length > 0) && (
          <section className="ch-sec" aria-label="Integrity changes">
            <h3 className="ch-h3">Integrity changes <span className="value">{c.integrity_changed.length}</span></h3>
            {c.integrity_changed.length === 0 ? (
              <p className="ch-quiet">No lockfile integrity hash changed for a package present in both manifests.</p>
            ) : (
              <ul className="ch-integ">
                {c.integrity_changed.map((ic) => (
                  <li key={ic.purl}>
                    <div className="value ch-purl">{ic.purl}</div>
                    <dl>
                      <dt className="label">Before</dt><dd className="value">{ic.from}</dd>
                      <dt className="label">After</dt><dd className="value">{ic.to}</dd>
                    </dl>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {c.install_scripts_added.length > 0 && (
          <section className="ch-sec" aria-label="Install scripts added">
            <h3 className="ch-h3">Install scripts added <span className="value">{c.install_scripts_added.length}</span></h3>
            <ul className="ch-plain">
              {c.install_scripts_added.map((p) => <li key={p} className="value">{p}</li>)}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function Cell({ label, v, tone }: { label: string; v: string; tone?: "high" }) {
  return (
    <div className="ch-cell">
      <span className="label">{label}</span>
      <span className={`ch-v${tone ? ` risk-${tone}` : ""}`}>{v}</span>
    </div>
  );
}

function Side({ name, version, empty }: { name: string; version: string | null; empty: string | null }) {
  if (empty) return <span className="ch-void">{empty}</span>;
  return (
    <span className="ch-side">
      <span className="ch-name">{name}</span>
      <span className="value ch-ver">{version ?? "unversioned"}</span>
    </span>
  );
}

function Row({ r }: { r: DiffRow }) {
  return (
    <tr className={`ch-row k-${r.kind}`}>
      <td title={r.beforePurl}>
        <Side name={r.name} version={r.before} empty={r.kind === "added" ? "not in legacy" : null} />
      </td>
      <td className="ch-gutter">
        {r.kind === "major" && <span className="stamp high">Major</span>}
        {r.kind === "changed" && <ArrowRight size={15} strokeWidth={2} aria-label="changed to" />}
        {r.kind === "removed" && <Minus size={15} strokeWidth={2} aria-label="removed" />}
        {r.kind === "added" && <Plus size={15} strokeWidth={2} aria-label="added" />}
      </td>
      <td title={r.afterPurl}>
        <Side name={r.name} version={r.after} empty={r.kind === "removed" ? "removed" : null} />
      </td>
    </tr>
  );
}
