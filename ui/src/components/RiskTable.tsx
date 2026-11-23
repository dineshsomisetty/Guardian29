import type { RiskAssessment } from "../api/types";
import { FACTORS } from "../lib/format";
import { ClaimMark, EvChip } from "./ui";

export default function RiskTable({ risk }: { risk: RiskAssessment }) {
  const f = risk.factors;
  return (
    <div className="risktable">
      <table>
        <thead>
          <tr>
            <th>Factor</th>
            <th className="r">Value</th>
            <th className="r">Weight</th>
            <th className="r">Points</th>
            <th>Tier</th>
            <th>Basis</th>
          </tr>
        </thead>
        <tbody>
          {FACTORS.map(({ key, name, weight }) => {
            const v = f[key];
            return (
              <tr key={key}>
                <td>
                  <span className="mono fk">{key}</span> {name}
                </td>
                <td className="r num">{v.value.toFixed(2)}</td>
                <td className="r num">{weight.toFixed(2)}</td>
                <td className="r num">{(v.value * weight * 100).toFixed(1)}</td>
                <td>
                  {v.tier}
                  {v.unknown && <span className="muted"> (unknown)</span>}
                </td>
                <td className="basis">
                  <ClaimMark label={v.label} />
                  {v.evidence_ids.map((e) => (
                    <EvChip key={e} id={e} />
                  ))}
                </td>
              </tr>
            );
          })}
          {f.provenance_modifier !== 0 && (
            <tr>
              <td>Provenance modifier</td>
              <td className="r num">-</td>
              <td className="r num">-</td>
              <td className="r num">+{f.provenance_modifier.toFixed(1)}</td>
              <td />
              <td className="basis">
                {f.provenance_evidence_ids.map((e) => (
                  <EvChip key={e} id={e} />
                ))}
              </td>
            </tr>
          )}
        </tbody>
        <tfoot>
          <tr>
            <td colSpan={3}>
              Score, confidence {risk.confidence}
              {risk.override_applied ? `, override: ${risk.override_applied}` : ""}
            </td>
            <td className="r num total">{risk.score.toFixed(1)}</td>
            <td colSpan={2} className={`band sev-${risk.band}`}>
              {risk.band}
            </td>
          </tr>
        </tfoot>
      </table>
      {risk.summary && <p className="risk-summary">{risk.summary}</p>}
    </div>
  );
}

/** Stacked S/E/R/P/X contribution bar. */
export function ScoreBar({ risk }: { risk: RiskAssessment }) {
  const parts = FACTORS.map(({ key, name, weight }) => ({ key, name, pts: risk.factors[key].value * weight * 100 }));
  const prov = risk.factors.provenance_modifier;
  return (
    <div className="scorebar">
      <div className="scorebar-track" role="img" aria-label={`Risk score ${risk.score.toFixed(1)} of 100`}>
        {parts.map((p) => (
          <span key={p.key} className={`seg seg-${p.key}`} style={{ width: `${p.pts}%` }} title={`${p.name} ${p.pts.toFixed(1)} pts`} />
        ))}
        {prov > 0 && <span className="seg seg-prov" style={{ width: `${prov}%` }} title={`Provenance +${prov}`} />}
      </div>
      <ul className="scorebar-legend">
        {parts.map((p) => (
          <li key={p.key}>
            <i className={`sw seg-${p.key}`} aria-hidden />
            <span className="mono">{p.key}</span> {p.name} <span className="num">{p.pts.toFixed(1)}</span>
          </li>
        ))}
        {prov > 0 && (
          <li>
            <i className="sw seg-prov" aria-hidden />
            Provenance <span className="num">+{prov.toFixed(1)}</span>
          </li>
        )}
      </ul>
    </div>
  );
}
