import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { agentMeta, buildScale, fmtDur, fmtOffset, type TEvent, type TraceModel } from "./model";
import Summary from "./Summary";

// The draw-in plays once per page load: the authored moment, not a tic on every visit.
let played = false;

const LW = 196;       // lane label column
const PAD_R = 20;
const AX_H = 26;      // axis row
const SV_H = 30;      // supervisor lane
const LANE_H = 44;    // worker lane
const BAR_H = 24;
const GR_H = 32;
const STAGGER = 380;  // ms between lanes
const GROW = 500;

interface Cluster<T> { x: number; items: T[] }
function cluster<T>(items: T[], xOf: (t: T) => number, gap: number): Cluster<T>[] {
  const out: Cluster<T>[] = [];
  for (const it of [...items].sort((a, b) => xOf(a) - xOf(b))) {
    const x = xOf(it);
    const last = out[out.length - 1];
    if (last && x - last.x < gap) last.items.push(it);
    else out.push({ x, items: [it] });
  }
  return out;
}

function textW(s: string, px = 6.6) { return s.length * px + 12; }

export default function RelayBand({ model }: { model: TraceModel }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(0);
  const [animate] = useState(() => !played);
  useEffect(() => { played = true; }, []);

  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    setW(el.clientWidth);
    const ro = new ResizeObserver(([e]) => setW(Math.round(e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const scale = useMemo(() => buildScale(model), [model]);
  const guards = model.events.filter((e) => e.type === "guardrail" || e.agent === "guardrail");
  const lanes = model.lanes;
  const trackW = Math.max(120, w - LW - PAD_R);
  const X = (t: number) => LW + scale.frac(t) * trackW;

  const laneTop = (i: number) => AX_H + SV_H + i * LANE_H;
  const barTop = (i: number) => laneTop(i) + (LANE_H - BAR_H) / 2;
  const grTop = laneTop(lanes.length);
  const H = grTop + (guards.length ? GR_H : 0) + 6;
  const arrowDelay = (lanes.length + 1) * STAGGER + GROW - 120;

  // axis ticks: real offsets at every span boundary, thinned so labels never collide
  const ticks: number[] = [];
  for (const t of scale.ticks) {
    const x = X(t);
    if (ticks.length && x - X(ticks[ticks.length - 1]) < 46) {
      if (t === model.total) ticks[ticks.length - 1] = t; // always print the end of the run
      continue;
    }
    ticks.push(t);
  }

  const decCl = cluster(model.decisions.filter((d) => d.agent === "supervisor"), (d) => X(d.t), 16);

  return (
    <div className="rb">
      <div className="rb-canvas" ref={wrap}>
        {w > 0 && (
          <svg
            className={`rb-svg${animate ? " rb-anim" : ""}`}
            width={w}
            height={H}
            viewBox={`0 0 ${w} ${H}`}
            role="img"
            aria-label={`Relay of ${lanes.length} agents over ${fmtDur(model.total)}: ${model.hands.length} hand-offs, ${model.decisions.length} decisions`}
          >
            {/* axis */}
            <line className="rb-axis" x1={LW} x2={LW + trackW} y1={AX_H - 6} y2={AX_H - 6} />
            {ticks.map((t) => (
              <g key={t}>
                <line className="rb-grid" x1={X(t)} x2={X(t)} y1={AX_H - 10} y2={H - 6} />
                <text className="rb-tick" x={X(t)} y={AX_H - 13} textAnchor={X(t) > LW + trackW - 30 ? "end" : X(t) < LW + 20 ? "start" : "middle"}>
                  {fmtOffset(t)}
                </text>
              </g>
            ))}

            {/* supervisor lane */}
            <LaneLabel y={AX_H} h={SV_H} agent="supervisor" dur={model.run ? model.run.end - model.run.start : model.total} />
            {model.run && (
              <g className="rb-grow" style={{ animationDelay: "0ms" }}>
                <line className="rb-svline" x1={X(model.run.start)} x2={X(model.run.end)} y1={AX_H + SV_H / 2} y2={AX_H + SV_H / 2} />
                <rect className="rb-svcap" x={X(model.run.start) - 2} y={AX_H + SV_H / 2 - 5} width={3} height={10} />
                <rect className="rb-svcap" x={X(model.run.end) - 2} y={AX_H + SV_H / 2 - 5} width={3} height={10} />
              </g>
            )}
            {decCl.map((c) => (
              <g key={c.items[0].i} className="rb-fade" style={{ animationDelay: `${arrowDelay}ms` }}>
                <rect className="rb-dec" x={c.x - 5} y={AX_H + SV_H / 2 - 5} width={10} height={10} transform={`rotate(45 ${c.x} ${AX_H + SV_H / 2})`} />
                <text className="rb-declbl" x={c.x + 9} y={AX_H + SV_H / 2 - 7}>{c.items.map((d) => `D${d.dno}`).join(" ")}</text>
              </g>
            ))}

            {/* worker lanes */}
            {lanes.map((a, i) => {
              const s = model.spans.get(a)!;
              const x0 = X(s.start), x1 = Math.max(X(s.end), x0 + 3);
              const m = agentMeta(a);
              const tools = model.tools.filter((t) => t.agent === a);
              const llm = model.events.filter((e) => e.agent === a && (e.type === "llm_call" || e.type === "llm_result"));
              const errs = model.events.filter((e) => e.agent === a && e.type === "error");
              const own = model.decisions.filter((d) => d.agent === a);
              const by = barTop(i);
              return (
                <g key={a}>
                  <line className="rb-lanesep" x1={0} x2={w} y1={laneTop(i)} y2={laneTop(i)} />
                  <LaneLabel y={laneTop(i)} h={LANE_H} agent={a} dur={s.end - s.start} />
                  <g className="rb-grow" style={{ animationDelay: `${(i + 1) * STAGGER}ms` }}>
                    <rect className={`rb-bar ${m.tone}`} x={x0} y={by} width={x1 - x0} height={BAR_H} />
                    {tools.map((t, k) => {
                      const tx0 = X(t.start), tx1 = Math.max(X(t.end), tx0 + 2);
                      const label = t.tool.replace(/^detector:/, "");
                      return (
                        <g key={k}>
                          <rect className="rb-tool" x={tx0} y={by + 3} width={tx1 - tx0} height={BAR_H - 6}>
                            <title>{`${t.tool} · ${fmtDur(t.end - t.start)}`}</title>
                          </rect>
                          {tx1 - tx0 > textW(label) && (
                            <text className="rb-toollbl" x={tx0 + 6} y={by + BAR_H / 2 + 4}>{label}</text>
                          )}
                        </g>
                      );
                    })}
                    {cluster(llm, (e) => X(e.t), 4).map((c) => (
                      <rect key={c.items[0].i} className="rb-llm" x={c.x - 1.5} y={by + 3} width={3} height={BAR_H - 6}>
                        <title>{`${c.items.length} LLM call${c.items.length > 1 ? "s" : ""}`}</title>
                      </rect>
                    ))}
                    {m.tone === "llm" && x1 - x0 > textW(`${llm.length} LLM calls`) + 6 && (
                      <text className="rb-llmlbl" x={x0 + 10} y={by + BAR_H / 2 + 4}>
                        {llm.length ? `${llm.length} LLM calls` : "rule-based"}
                      </text>
                    )}
                  </g>
                  <g className="rb-fade" style={{ animationDelay: `${arrowDelay}ms` }}>
                    {own.map((d) => (
                      <g key={d.i}>
                        <rect className="rb-dec own" x={X(d.t) - 4} y={by - 4} width={8} height={8} transform={`rotate(45 ${X(d.t)} ${by})`} />
                        <text className="rb-declbl" x={X(d.t) - 8} y={by - 4} textAnchor="end">{`D${d.dno}`}</text>
                      </g>
                    ))}
                    {cluster(errs, (e) => X(e.t), 14).map((c) => (
                      <ErrMark key={c.items[0].i} x={Math.min(c.x, x1 - 6)} y={by + BAR_H + 7} n={c.items.length} label="error" />
                    ))}
                  </g>
                </g>
              );
            })}

            {/* guardrail lane, only when the guardrail fired */}
            {guards.length > 0 && (
              <g>
                <line className="rb-lanesep" x1={0} x2={w} y1={grTop} y2={grTop} />
                <LaneLabel y={grTop} h={GR_H} agent="guardrail" />
                <g className="rb-fade" style={{ animationDelay: `${arrowDelay}ms` }}>
                  {cluster(guards, (e) => X(e.t), 18).map((c) => (
                    <ErrMark key={c.items[0].i} x={c.x} y={grTop + GR_H / 2} n={c.items.length} label="guardrail hit" guard />
                  ))}
                </g>
              </g>
            )}

            {/* hand-offs: source bar end -> next agent's bar start */}
            {model.hands.map((h, k) => {
              const si = lanes.indexOf(h.from), ti = lanes.indexOf(h.to);
              if (si < 0 || ti < 0) return null;
              const tgt = model.spans.get(h.to)!;
              const xs = Math.min(X(h.t), X(model.spans.get(h.from)!.end)) - 1;
              const xt = X(tgt.start) + 4;
              const down = ti > si;
              const ys = down ? barTop(si) + BAR_H : barTop(si);
              const yt = down ? barTop(ti) - 1 : barTop(ti) + BAR_H + 1;
              const ym = down ? laneTop(si + 1) : laneTop(si);
              const head = down ? `${xt - 4},${yt - 6} ${xt + 4},${yt - 6} ${xt},${yt}` : `${xt - 4},${yt + 6} ${xt + 4},${yt + 6} ${xt},${yt}`;
              const lbl = `${h.evidence} evidence`;
              const right = Math.max(xs, xt) + 10;
              const fitsRight = right + textW(lbl, 6.4) < w;
              return (
                <g key={k}>
                  <path
                    className="rb-hand"
                    pathLength={1}
                    d={`M${xs},${ys} V${ym} H${xt} V${down ? yt - 5 : yt + 5}`}
                    style={{ animationDelay: `${arrowDelay + k * 260}ms` }}
                  />
                  <g className="rb-fade" style={{ animationDelay: `${arrowDelay + k * 260 + 280}ms` }}>
                    <polygon className="rb-head" points={head} />
                    <rect className="rb-handbg" x={fitsRight ? right - 4 : Math.min(xs, xt) - 10 - textW(lbl, 6.4)} y={ym - 8} width={textW(lbl, 6.4) - 4} height={16} />
                    <text className="rb-handlbl" x={fitsRight ? right : Math.min(xs, xt) - 14} y={ym + 4} textAnchor={fitsRight ? "start" : "end"}>
                      {lbl}
                    </text>
                  </g>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {model.decisions.length > 0 && (
        <ol className="rb-routes" aria-label="Routing decisions">
          {model.decisions.map((d) => <RouteRow key={d.i} d={d} />)}
        </ol>
      )}
      {scale.compressed && (
        <p className="rb-note">Time axis is piecewise: short spans are widened so every agent stays readable. Offsets and durations are real.</p>
      )}
    </div>
  );
}

function LaneLabel({ y, h, agent, dur }: { y: number; h: number; agent: string; dur?: number }) {
  const m = agentMeta(agent);
  const cy = y + h / 2;
  return (
    <g className="rb-lab">
      <rect className={`rb-mono ${m.tone}`} x={16} y={cy - 12} width={30} height={24} />
      <text className={`rb-monotxt ${m.tone}`} x={31} y={cy + 4.5} textAnchor="middle">{m.mono}</text>
      <text className="rb-role" x={56} y={cy - 1}>{m.role}</text>
      <text className={`rb-kind ${m.tone}`} x={56} y={cy + 12}>
        {m.kind}{dur !== undefined ? ` · ${fmtDur(dur)}` : ""}
      </text>
    </g>
  );
}

function ErrMark({ x, y, n, label, guard }: { x: number; y: number; n: number; label: string; guard?: boolean }) {
  return (
    <g className={guard ? "rb-guard" : "rb-err"}>
      <title>{`${n} ${label}${n > 1 ? "s" : ""}`}</title>
      <rect x={x - 5} y={y - 5} width={10} height={10} />
      <path d={`M${x - 2.5},${y - 2.5} L${x + 2.5},${y + 2.5} M${x + 2.5},${y - 2.5} L${x - 2.5},${y + 2.5}`} />
      {n > 1 && <text x={x - 9} y={y + 4} textAnchor="end">{n}×</text>}
    </g>
  );
}

function RouteRow({ d }: { d: TEvent & { dno: number } }) {
  const m = agentMeta(d.agent);
  return (
    <li className={`rb-route${d.agent === "supervisor" ? " sv" : ""}`}>
      <span className="rb-dno">D{d.dno}</span>
      <span className="rb-rt value">{fmtOffset(d.t)}</span>
      <span className={`mono-chip ${m.tone}`} title={m.role}>{m.mono}</span>
      <span className="rb-rsum"><Summary text={d.summary} /></span>
    </li>
  );
}
