import type { ReactNode } from "react";
import type { Finding, Risk, RiskAssessment } from "../api/types";
import { RISK_LABEL } from "../lib/format";
import { BAND_COPY, BAND_ORDER, BAND_RANGE, FACTOR_INFO, FACTOR_KEYS, evidenceKindTitle, factorFinding, weightsFor } from "../lib/labels";
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

/**
 * How the score adds up: each factor earns points up to its own maximum (its weight), and the points sum to the
 * 0-100 score. Track lengths are drawn to the maximum, so a 30-point factor is visibly three times a 10-point one.
 */
export function FactorTable({ risk, finding, onCite }: { risk: RiskAssessment; finding?: Finding; onCite: (id: string) => void }) {
  const f = risk.factors;
  const w = weightsFor(risk);
  const prov = f.provenance_modifier;
  const top = Math.max(...FACTOR_KEYS.map((k) => w[k]));
  return (
    <div className="factors">
      {FACTOR_KEYS.map((key) => {
        const info = FACTOR_INFO[key];
        const v = f[key];
        const max = w[key] * 100;
        if (max === 0) return null;
        const pts = v.value * max;
        return (
          <div className="frow" key={key}>
            <div className="fline">
              <span className="fname">
                {info.name}
                <Hint text={info.help} />
              </span>
              <span className="fpts num">
                <b>{pts.toFixed(1)}</b>
                <span className="faint"> of {max.toFixed(0)}</span>
              </span>
            </div>
            <Tip text={`${info.name}: ${v.value.toFixed(2)} of 1, weighted ${Math.round(w[key] * 100)}%`} side="top" block>
              <span className="fmeter" style={{ width: `${(w[key] / top) * 100}%` }} aria-hidden>
                <i style={{ width: `${Math.round(v.value * 100)}%` }} className={v.unknown ? "unknown" : ""} />
              </span>
            </Tip>
            <div className="fwhy">
              <span className="fwhy-text">{factorFinding(key, risk, finding)}</span>
              <ClaimMark label={v.label} help />
              <BasedOn ids={v.evidence_ids} onCite={onCite} />
            </div>
          </div>
        );
      })}
      {prov !== 0 && (
        <div className="frow">
          <div className="fline">
            <span className="fname">
              Supply-chain trust adjustment
              <Hint text="Extra points when a package's origin or signing could not be verified." />
            </span>
            <span className="fpts num"><b>+{prov.toFixed(1)}</b></span>
          </div>
          <div className="fwhy"><BasedOn ids={f.provenance_evidence_ids} onCite={onCite} /></div>
        </div>
      )}
      <div className="ftotal">
        <span>
          Total
          <span className="faint"> · {BAND_COPY[risk.band].name} is {BAND_RANGE[risk.band][0]} to {BAND_RANGE[risk.band][1]}</span>
          {risk.override_applied ? <span className="faint"> · safety rule applied: {risk.override_applied.replace(/_/g, " ")}</span> : null}
        </span>
        <span className="num ftotal-n">{risk.score.toFixed(1)}<span className="faint"> / 100</span></span>
      </div>
    </div>
  );
}

/** The 0-100 scale split into the four levels, with a marker at this score. */
export function BandScale({ score, band }: { score: number; band: Risk }) {
  return (
    <div className="bscale" role="img" aria-label={`Score ${score.toFixed(0)} of 100, in the ${RISK_LABEL[band]} range`}>
      <div className="bscale-track">
        {BAND_ORDER.map((b) => {
          const [lo, hi] = BAND_RANGE[b];
          return <span key={b} className={`bscale-seg s-${b}${b === band ? " on" : ""}`} style={{ flexGrow: hi - lo + 1 }} />;
        })}
        <span className="bscale-mark" style={{ left: `${Math.min(100, Math.max(0, score))}%` }} />
      </div>
      <div className="bscale-labels">
        {BAND_ORDER.map((b) => {
          const [lo, hi] = BAND_RANGE[b];
          return (
            <span key={b} className={b === band ? "on" : ""} style={{ flexGrow: hi - lo + 1 }}>
              {RISK_LABEL[b]} <span className="num faint">{lo}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

/** Stacked contribution bar in neutral greys, with before -> expected after. */
export function ScoreBar({ risk, after, extra }: { risk: RiskAssessment; after?: number | null; extra?: ReactNode }) {
  const w = weightsFor(risk);
  const parts = FACTOR_KEYS.filter((k) => w[k] > 0).map((k) => ({ k, name: FACTOR_INFO[k].name, pts: risk.factors[k].value * w[k] * 100 }));
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
