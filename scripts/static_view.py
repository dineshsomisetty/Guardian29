"""D5-09 static fallback viewer: one self-contained HTML page from a run folder (no server, no external assets).

    uv run python scripts/static_view.py                 # runs/LATEST
    uv run python scripts/static_view.py runs/<run_id>   # a specific run

Writes runs/<run_id>/static_view.html. Reads only the run's own output files (run_summary.json, findings.json,
graph.json, changes.json, trace.jsonl, evidence/*.json) - never runs/<id>/work/ or targets/.
Plain string templates + html.escape (Jinja2 is not a project dependency).
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from html import escape
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RISK_ORDER = ["critical", "high", "medium", "low", "info"]
KEY_EVENTS = {"agent_start", "tool_result", "handoff", "decision", "error", "agent_end", "approval"}

CSS = """
:root{--navy:#14233F;--ink:#1b2333;--muted:#5d6678;--line:#d9dde4;--bg:#f2f4f7;--sheet:#fff;
--critical:#a1121f;--high:#c2410c;--medium:#a16207;--low:#3f6212;--info:#475569}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,
"Helvetica Neue",Arial,sans-serif}
code,.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,"SFMono-Regular",Menlo,monospace;font-size:12.5px}
header{background:var(--navy);color:#fff;padding:20px 28px 18px}
header h1{margin:0 0 2px;font-size:20px;font-weight:600;letter-spacing:.2px}
header .sub{color:#c3cbd9;font-size:12.5px}
.stats{display:flex;flex-wrap:wrap;gap:0;margin-top:16px;border:1px solid #2f4266}
.stat{padding:10px 18px;border-right:1px solid #2f4266;min-width:110px}
.stat:last-child{border-right:0}
.stat b{display:block;font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.stat span{color:#c3cbd9;font-size:11.5px;text-transform:uppercase;letter-spacing:.6px}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}
nav{margin:0 0 16px;font-size:13px}
nav a{color:var(--navy);margin-right:14px;text-decoration:none;border-bottom:1px solid var(--line)}
section{background:var(--sheet);border:1px solid var(--line);margin:0 0 18px;padding:18px 22px}
h2{margin:0 0 12px;font-size:15px;font-weight:600;color:var(--navy);text-transform:uppercase;letter-spacing:.7px}
h3{margin:18px 0 8px;font-size:14px;font-weight:600}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
.risk{display:inline-block;padding:1px 7px;border:1px solid currentColor;font-size:11px;font-weight:600;
text-transform:uppercase;letter-spacing:.5px}
.risk.critical{color:var(--critical)}.risk.high{color:var(--high)}.risk.medium{color:var(--medium)}
.risk.low{color:var(--low)}.risk.info,.risk.none{color:var(--info)}
.muted{color:var(--muted)}
.finding{border-top:1px solid var(--line);padding:10px 0}
.finding:first-of-type{border-top:0}
.finding .t{font-weight:600}
.path{margin:3px 0 0;color:var(--ink)}
.label{font-size:10.5px;font-weight:700;letter-spacing:.6px;padding:1px 5px;border:1px solid var(--line);
color:var(--muted)}
.label.verified{color:#14532d;border-color:#14532d}.label.inferred{color:#6b21a8;border-color:#6b21a8}
details summary{cursor:pointer;color:var(--navy);margin:6px 0}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px}
ul.plain{margin:0;padding-left:18px}
.ev-agent{font-weight:600;white-space:nowrap}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
@media print{body{background:#fff}section{border:0;border-bottom:1px solid var(--line)}}
"""


def e(v) -> str:
    return escape("" if v is None else str(v))


def risk_badge(r) -> str:
    r = (r or "none").lower()
    return f'<span class="risk {e(r)}">{e(r)}</span>'


def short_purl(p: str) -> str:
    if not p.startswith("pkg:"):
        return p
    return p.split("/", 1)[-1].replace("%40", "@")


def path_text(path: list[str]) -> str:
    return " &rarr; ".join(f"<code>{e(short_purl(x))}</code>" for x in path)


def resolve_run_dir(arg: str | None) -> Path:
    if arg:
        p = Path(arg)
        return p if p.is_absolute() else (Path.cwd() / p).resolve()
    latest = REPO / "runs" / "LATEST"
    if not latest.is_file():
        sys.exit("no runs/LATEST - pass a run folder: python scripts/static_view.py runs/<run_id>")
    return REPO / "runs" / latest.read_text(encoding="utf-8").strip()


def load(run_dir: Path) -> dict:
    def j(name, default):
        p = run_dir / name
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else default

    trace_p = run_dir / "trace.jsonl"
    trace = []
    if trace_p.is_file():
        trace = [json.loads(x) for x in trace_p.read_text(encoding="utf-8").splitlines() if x.strip()]
    evidence = {}
    ev_dir = run_dir / "evidence"
    if ev_dir.is_dir():
        for p in ev_dir.glob("*.json"):
            ev = json.loads(p.read_text(encoding="utf-8"))
            evidence[ev.get("evidence_id", p.stem)] = ev
    return {"summary": j("run_summary.json", {}), "findings": j("findings.json", []),
            "graph": j("graph.json", {"nodes": [], "edges": [], "roots": []}), "changes": j("changes.json", None),
            "trace": trace, "evidence": evidence}


def sort_key(f: dict):
    r = (f.get("initial_risk") or "info").lower()
    return (RISK_ORDER.index(r) if r in RISK_ORDER else 9, -(f.get("cvss") or 0), f.get("title") or "")


# ---- sections -------------------------------------------------------------------------------------------------

def header(d: dict) -> str:
    s = d["summary"]
    sb = s.get("sbom", {})
    by_risk = s.get("findings", {}).get("by_risk", {})
    llm = s.get("llm", {})
    stats = [("components", sb.get("components")), ("direct", sb.get("direct")), ("transitive", sb.get("transitive")),
             ("findings", s.get("findings", {}).get("total"))]
    stats += [(r, by_risk.get(r, 0)) for r in RISK_ORDER[:4]]
    cells = "".join(f'<div class="stat"><b>{e(v)}</b><span>{e(k)}</span></div>' for k, v in stats)
    commit = (s.get("commit") or "")[:12]
    return f"""<header><h1>Guardian &middot; {e(s.get('target'))}</h1>
<div class="sub">run <span class="mono">{e(s.get('run_id'))}</span> &middot; commit <span class="mono">{e(commit)}</span>
&middot; status {e(s.get('status'))} &middot; projects {e(', '.join(s.get('projects', [])))}
&middot; LLM {e(llm.get('model'))} ({e(llm.get('mode'))}) &middot; started {e(s.get('started_at'))}</div>
<div class="stats">{cells}</div></header>"""


def trace_section(d: dict) -> str:
    rows, seen = [], Counter()
    for ev in d["trace"]:
        if ev.get("type") not in KEY_EVENTS:
            continue
        key = (ev.get("agent"), ev.get("type"), ev.get("summary"))
        seen[key] += 1
        if seen[key] > 1:
            continue
        rows.append(ev)
    body = []
    for ev in rows:
        n = seen[(ev.get("agent"), ev.get("type"), ev.get("summary"))]
        times = f' <span class="muted">&times;{n}</span>' if n > 1 else ""
        ts = (ev.get("ts") or "")[11:19]
        body.append(f"<tr><td class='mono muted'>{e(ts)}</td><td class='ev-agent'>{e(ev.get('agent'))}</td>"
                    f"<td class='mono'>{e(ev.get('type'))}</td><td>{e(ev.get('summary'))}{times}</td></tr>")
    counts = Counter(ev.get("agent") for ev in d["trace"])
    agents = ", ".join(f"{e(a)} ({n})" for a, n in counts.items())
    return f"""<section id="trace"><h2>Agent trace</h2>
<p class="muted">{len(d['trace'])} events &middot; {agents}. Showing hand-offs, routing decisions, tool results
and errors (tool_call / llm_call omitted; repeats collapsed).</p>
<table><tr><th>time</th><th>agent</th><th>event</th><th>summary</th></tr>{''.join(body)}</table></section>"""


def finding_block(f: dict, evidence: dict) -> str:
    bits = []
    if f.get("vuln_id"):
        al = ", ".join(f.get("aliases") or [])
        bits.append(f"<code>{e(f['vuln_id'])}</code>" + (f" <span class='muted'>({e(al)})</span>" if al else ""))
    if f.get("severity") or f.get("cvss"):
        bits.append(f"severity {e(f.get('severity'))}" + (f" &middot; CVSS {e(f.get('cvss'))}" if f.get("cvss") else ""))
    if f.get("fixed_versions"):
        bits.append("fix " + ", ".join(f"<code>{e(v)}</code>" for v in f["fixed_versions"]))
    if f.get("file_path"):
        loc = f["file_path"] + (f":{f['line']}" if f.get("line") else "")
        bits.append(f"<code>{e(loc)}</code>")
    bits.append(f"risk source: {e(f.get('initial_risk_source') or 'n/a')}")
    paths = "".join(f"<div class='path'>{path_text(p)}</div>" for p in (f.get("dependency_paths") or [])[:5])
    ev_ids = f.get("evidence_ids") or []
    ev_txt = ", ".join(f"<code>{e(i)}</code>" + ("" if i in evidence else " <b>(missing)</b>") for i in ev_ids)
    expl = ""
    if f.get("explanation"):
        expl = f"<div><span class='label inferred'>AI INFERRED</span> {e(f['explanation'])}</div>"
    claims = ""
    if f.get("claims"):
        items = "".join(f"<li><span class='label {'verified' if (c.get('label') or '').upper() == 'VERIFIED' else 'inferred'}'>"
                        f"{e((c.get('label') or '').upper())}</span> {e(c.get('text') or c.get('statement'))}</li>"
                        for c in f["claims"])
        claims = f"<ul class='plain'>{items}</ul>"
    return f"""<div class="finding">{risk_badge(f.get('initial_risk'))} <span class="t">{e(f.get('title'))}</span>
<span class="muted mono">{e(f.get('category'))}</span>
<div class="muted">{' &middot; '.join(bits)}</div>{paths}{expl}{claims}
<div class="muted">evidence: <span class="label verified">VERIFIED</span> {ev_txt or '<b>none</b>'}</div></div>"""


def direct_section(d: dict) -> str:
    nodes = [n for n in d["graph"].get("nodes", []) if n.get("kind") == "package" and n.get("direct")]
    by_purl = defaultdict(list)
    for f in d["findings"]:
        for p in f.get("dependency_paths") or []:
            direct = next((x for x in p if x.startswith("pkg:")), None)
            if direct:
                by_purl[direct].append(f)
    risky = [n for n in nodes if n["id"] in by_purl]

    def worst(fs):
        return min(sort_key(f) for f in fs)

    risky.sort(key=lambda n: (worst(by_purl[n["id"]]), n.get("label", "")))
    rows = []
    for n in risky:
        fs = sorted({f["finding_id"]: f for f in by_purl[n["id"]]}.values(), key=sort_key)
        top = sort_key(fs[0])[0]
        cats = Counter(f.get("category") for f in fs)
        rows.append(f"<tr><td>{risk_badge(RISK_ORDER[top] if top < len(RISK_ORDER) else None)}</td>"
                    f"<td><code>{e(n.get('label'))}@{e(n.get('version'))}</code></td><td>{e(n.get('project'))}</td>"
                    f"<td>{e(n.get('scope'))}</td><td>{len(fs)} ({e(', '.join(f'{k} {v}' for k, v in cats.items()))})</td>"
                    f"<td class='mono muted'>{e((n.get('integrity') or '')[:22])}&hellip;</td></tr>")
    clean = sorted((n for n in nodes if n["id"] not in by_purl), key=lambda n: (n.get("project", ""), n.get("label", "")))
    clean_list = ", ".join(f"<code>{e(n.get('label'))}@{e(n.get('version'))}</code>" for n in clean)
    return f"""<section id="direct"><h2>Direct dependencies with findings</h2>
<p class="muted">{len(nodes)} direct dependencies across {e(', '.join(d['graph'].get('roots', [])))};
{len(risky)} reach at least one finding (directly or through a transitive dependency).</p>
<table><tr><th>worst</th><th>package</th><th>project</th><th>scope</th><th>findings on its paths</th><th>integrity</th></tr>
{''.join(rows)}</table>
<details><summary>{len(clean)} direct dependencies without findings</summary><p>{clean_list}</p></details></section>"""


def findings_section(d: dict) -> str:
    pkg = sorted((f for f in d["findings"] if f.get("dependency_paths") or (f.get("component_purl") or "").startswith("pkg:")),
                 key=sort_key)
    groups = defaultdict(list)
    for f in pkg:
        groups[(f.get("initial_risk") or "info").lower()].append(f)
    out = []
    for r in RISK_ORDER:
        if groups.get(r):
            blocks = "".join(finding_block(f, d["evidence"]) for f in groups[r])
            out.append(f"<h3>{risk_badge(r)} {len(groups[r])}</h3>{blocks}")
    return f"""<section id="findings"><h2>Package findings by risk</h2>
<p class="muted">{len(pkg)} findings on packages. Paths are shown as text: project &rarr; direct dependency &rarr;
&hellip; &rarr; vulnerable package.</p>{''.join(out)}</section>"""


def paths_section(d: dict) -> str:
    lines = []
    seen = set()
    for f in sorted(d["findings"], key=sort_key):
        for p in f.get("dependency_paths") or []:
            if len(p) < 3:
                continue
            key = tuple(p)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"<tr><td>{risk_badge(f.get('initial_risk'))}</td><td>{path_text(p)}</td></tr>")
    return f"""<section id="paths"><h2>Transitive dependency paths</h2>
<p class="muted">{len(lines)} distinct paths where a vulnerable package is reached through a direct parent.</p>
<table><tr><th>risk</th><th>path</th></tr>{''.join(lines)}</table></section>"""


def nonpkg_section(d: dict) -> str:
    fs = sorted((f for f in d["findings"]
                 if not f.get("dependency_paths") and not (f.get("component_purl") or "").startswith("pkg:")), key=sort_key)
    rows = []
    for f in fs:
        loc = (f.get("file_path") or "") + (f":{f['line']}" if f.get("line") else "")
        excerpts = [d["evidence"].get(i, {}).get("excerpt") for i in f.get("evidence_ids") or []]
        exc = next((x for x in excerpts if x), "")
        rows.append(f"<tr><td>{risk_badge(f.get('initial_risk'))}</td><td class='mono'>{e(f.get('category'))}</td>"
                    f"<td><code>{e(loc)}</code></td><td>{e(f.get('title'))}"
                    f"{f'<div class=mono muted>{e(exc[:200])}</div>' if exc else ''}</td>"
                    f"<td class='mono muted'>{e(', '.join(f.get('evidence_ids') or []))}</td></tr>")
    return f"""<section id="nonpkg"><h2>Non-package findings</h2>
<p class="muted">CI, container image, lockfile and manifest findings ({len(fs)}). In the graph these are
pseudo-nodes (<code>ci:</code>, <code>image:</code>, <code>config:</code>).</p>
<table><tr><th>risk</th><th>category</th><th>where</th><th>finding / excerpt</th><th>evidence</th></tr>{''.join(rows)}</table>
</section>"""


def changes_section(d: dict) -> str:
    c = d["changes"]
    if not c:
        return '<section id="changes"><h2>What changed</h2><p class="muted">No changes.json in this run.</p></section>'
    flagged = {(f.get("file_path") or ""): f for f in d["findings"] if f.get("category") == "typosquat"}
    base_flag = flagged.get(c.get("base"))

    def lst(items):
        return "".join(f"<li><code>{e(short_purl(x))}</code></li>" for x in items) or "<li class='muted'>none</li>"

    changed = "".join(
        f"<tr><td><code>{e(x.get('name'))}</code></td><td>{e(x.get('from_range') or x.get('from'))}</td>"
        f"<td>{e(x.get('to_range') or x.get('to'))}</td><td>{'major' if x.get('major_jump') else ''}</td></tr>"
        for x in c.get("changed", []))
    note = ""
    if base_flag:
        note = (f"<p>{risk_badge(base_flag.get('initial_risk'))} {e(base_flag.get('title'))} "
                f"<span class='muted'>(the legacy manifest carried it; it was removed in the current one)</span></p>")
    extra = []
    for k in ("integrity_changed", "install_scripts_added"):
        if c.get(k):
            extra.append(f"<h3>{e(k)}</h3><ul class='plain'>" +
                         "".join(f"<li><code>{e(json.dumps(x))}</code></li>" for x in c[k]) + "</ul>")
    return f"""<section id="changes"><h2>What changed</h2>
<p>Base <code>{e(c.get('base'))}</code> &rarr; head <code>{e(c.get('head'))}</code>:
{len(c.get('added', []))} added, {len(c.get('removed', []))} removed, {len(c.get('changed', []))} version changes,
{len(c.get('integrity_changed', []))} integrity changes, {len(c.get('install_scripts_added', []))} install scripts added.
<span class="muted">evidence {e(', '.join(c.get('evidence_ids', [])))}</span></p>{note}
<div class="cols"><div><h3>Removed</h3><ul class="plain">{lst(c.get('removed', []))}</ul></div>
<div><h3>Added</h3><ul class="plain">{lst(c.get('added', []))}</ul></div>
<div><h3>Version changes</h3><table><tr><th>name</th><th>from</th><th>to</th><th></th></tr>{changed}</table></div></div>
{''.join(extra)}</section>"""


def render(d: dict) -> str:
    s = d["summary"]
    nav = "".join(f'<a href="#{i}">{t}</a>' for i, t in [("trace", "Agent trace"), ("direct", "Direct deps"),
                  ("findings", "Findings"), ("paths", "Paths"), ("nonpkg", "Non-package"), ("changes", "What changed")])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Guardian run {e(s.get('run_id'))}</title>
<style>{CSS}</style></head><body>{header(d)}<main><nav>{nav}</nav>
{trace_section(d)}{direct_section(d)}{findings_section(d)}{paths_section(d)}{nonpkg_section(d)}{changes_section(d)}
<footer>Guardian static fallback view (D5-09) &middot; generated from run files only &middot;
VERIFIED = tool evidence, AI INFERRED = LLM explanation checked by grounding</footer></main></body></html>"""


def main(argv: list[str]) -> int:
    run_dir = resolve_run_dir(argv[1] if len(argv) > 1 else None)
    if not (run_dir / "run_summary.json").is_file():
        print(f"not a finished run folder: {run_dir}", file=sys.stderr)
        return 2
    out = run_dir / "static_view.html"
    out.write_text(render(load(run_dir)), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
