import type { ReactNode } from "react";
import type { RiskAssessment } from "../api/types";
import { RISK_LABEL } from "../lib/format";
import { FACTOR_INFO, FACTOR_KEYS, evidenceKindTitle, tierLabel } from "../lib/labels";
import { useEvidenceMany } from "./hooks";
import { ClaimMark, Hint, Tip } from "./ui";

/** Neutral steps of one hue: colour never implies severity here. */
export const FACTOR_FILL: Record<string, string> = {
  S: "var(--n5)",
  E: "var(--n4)",
  R: "var(--n3)",
  P: "var(--n2)",
  X: "var(--n1)",
};

function BasedOn({ ids, onCite }: { ids: string[]; onCite: (id: string) => void }) {
  const ev = useEvidenceMany(ids);
  if (!ids.length) return <span className="faint">No source recorded</span>;
  if (!ev.loaded) return <span className="skel" style={{ width: 120, height: 20, display: "inline-block" }} aria-hidden />;
  return (
    <span className="basedon">
      {ev.items.map((e) => (
        <Tip key={e.evidence_id} text="Open this source below" side="top">
          <button type="button" className="srcchip" onClick={() => onCite(e.evidence_id)}>
            {evidenceKindTitle(e.kind)}
          </button>
        </Tip>
      ))}
    </span>
  );
}

/** Why it scored X: every factor with its value, weight, contribution and the evidence it came from. */
export function FactorTable({ risk, onCite }: { risk: RiskAssessment; onCite: (id: string) => void }) {
  const f = risk.factors;
  const prov = f.provenance_modifier;
  return (
    <div className="factors">
      <div className="fgrid fhead" role="row">
        <span>Factor</span>
        <span>Value</span>
        <span className="r">Weight</span>
        <span className="r">Adds</span>
      </div>
      {FACTOR_KEYS.map((key) => {
        const info = FACTOR_INFO[key];
        const v = f[key];
        const pts = v.value * info.weight * 100;
        return (
          <div className="frow" key={key}>
            <div className="fgrid" role="row">
              <span className="fname">
                {info.name}
                <Hint text={info.help} />
              </span>
              <span className="fval">
                <span className="fbar" aria-hidden><i style={{ width: `${Math.round(v.value * 100)}%`, background: FACTOR_FILL[key] }} /></span>
                <span className="num">{v.value.toFixed(2)}</span>
              </span>
              <span className="r num faint">{Math.round(info.weight * 100)}%</span>
              <span className="r num fpts">+{pts.toFixed(1)}</span>
            </div>
            <div className="fwhy">
              <span>{v.unknown ? "Not determined, so a cautious default was used" : tierLabel(v.tier)}</span>
              <ClaimMark label={v.label} help />
              <BasedOn ids={v.evidence_ids} onCite={onCite} />
            </div>
          </div>
        );
      })}
      {prov !== 0 && (
        <div className="frow">
          <div className="fgrid" role="row">
            <span className="fname">
              Supply-chain trust adjustment
              <Hint text="Extra points when a package's origin or signing could not be verified." />
            </span>
            <span />
            <span />
            <span className="r num fpts">+{prov.toFixed(1)}</span>
          </div>
          <div className="fwhy"><BasedOn ids={f.provenance_evidence_ids} onCite={onCite} /></div>
        </div>
      )}
      <div className="ftotal">
        <span>
          Total
          {risk.override_applied ? <span className="faint"> (rule applied: {risk.override_applied})</span> : null}
          <span className="faint"> · confidence {risk.confidence}</span>
        </span>
        <span className="num ftotal-n">{risk.score.toFixed(1)}<span className="faint"> / 100</span></span>
      </div>
    </div>
  );
}

/** Stacked contribution bar in neutral greys, with before -> expected after. */
export function ScoreBar({ risk, after, extra }: { risk: RiskAssessment; after?: number | null; extra?: ReactNode }) {
  const parts = FACTOR_KEYS.map((k) => ({ k, name: FACTOR_INFO[k].name, pts: risk.factors[k].value * FACTOR_INFO[k].weight * 100 }));
  const prov = risk.factors.provenance_modifier;
  return (
    <div className="scorebar">
      <div className="score-nums">
        <span className="score-big num">{risk.score.toFixed(0)}</span>
        <span className="muted">out of 100 ({RISK_LABEL[risk.band]})</span>
        {after != null && (
          <span className="score-after">
            Expected after the fix: <b className="num">{after.toFixed(0)}</b>
          </span>
        )}
      </div>
      <div className="scorebar-track" role="img" aria-label={`Risk score ${risk.score.toFixed(1)} out of 100`}>
        {parts.map((p) => (
          <span key={p.k} className="seg" title={`${p.name}: ${p.pts.toFixed(1)} points`} style={{ width: `${p.pts}%`, background: FACTOR_FILL[p.k] }} />
        ))}
        {prov > 0 && <span className="seg seg-prov" style={{ width: `${prov}%` }} />}
      </div>
      <ul className="scorebar-legend">
        {parts.map((p) => (
          <li key={p.k}>
            <i className="sw" style={{ background: FACTOR_FILL[p.k] }} aria-hidden />
            {p.name} <span className="num">{p.pts.toFixed(1)}</span>
          </li>
        ))}
        {prov > 0 && (
          <li>
            <i className="sw seg-prov" aria-hidden />
            Trust adjustment <span className="num">+{prov.toFixed(1)}</span>
          </li>
        )}
      </ul>
      {extra}
    </div>
  );
}
