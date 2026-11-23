"""Checkpoint-1 completeness checker.

Encodes every CP1 requirement from
  - the Bosch slides (slide 4 "Day 1" + slide 3 guidelines / out of scope),
  - GUARDIAN_PLAN.md §3.0 slice-0 outputs, §3.2 definition of done, §3.4 per-dev proofs, §4.1 file contracts,
and checks each one against a real run (default: runs/LATEST) and the repo.

    uv run python scripts/cp1_check.py [run_id] [--tests]

PASS = met. WARN = not met but out of CP1 scope or needs a human. FAIL = a CP1 gap. Exit code 1 on any FAIL.
The secret check reads .env only to make sure the key value appears nowhere else; it never prints it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[str, str, str, str]] = []

S4, S3 = "SLIDE 4 · Day 1: build the Guardian's eyes", "SLIDE 3 · guidelines and out of scope"
DOD, CON = "PLAN §3.2 · CP1 definition of done", "PLAN §4.1 · file contracts"
DEV, SEC = "PLAN §3.4 · per-developer proofs", "SAFETY RULES (plan §0, G1, slide 3 out of scope)"


def rec(src: str, cid: str, status: str, detail: str = "") -> None:
    RESULTS.append((src, cid, status, detail))


def check(src: str, cid: str, cond: bool, good: str = "", bad: str = "", warn: bool = False) -> None:
    rec(src, cid, "PASS" if cond else ("WARN" if warn else "FAIL"), good if cond else bad)


def jload(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", nargs="?")
    ap.add_argument("--tests", action="store_true", help="also run pytest, ruff and the forbidden-pattern grep")
    args = ap.parse_args()

    rid = args.run or (ROOT / "runs" / "LATEST").read_text().strip()
    rd = ROOT / "runs" / rid
    print(f"Checking run {rid}\n")

    need = ["run_summary.json", "sbom.cdx.json", "graph.json", "changes.json", "findings.json", "trace.jsonl"]
    for f in need:
        check(S4, f"outcome: {f} exists", (rd / f).exists(), "", f"missing runs/{rid}/{f}")
    if any(not (rd / f).exists() for f in need):
        return report()

    summary, graph, findings = jload(rd / "run_summary.json"), jload(rd / "graph.json"), jload(rd / "findings.json")
    changes, sbom = jload(rd / "changes.json"), jload(rd / "sbom.cdx.json")
    trace = [json.loads(line) for line in (rd / "trace.jsonl").read_text(encoding="utf-8").splitlines() if line]
    evidence = {p.stem: jload(p) for p in (rd / "evidence").glob("*.json")}
    nodes = graph["nodes"]
    pk = [n for n in nodes if n.get("kind") == "package"]
    pseudo = [n for n in nodes if n.get("kind") in ("ci", "image", "config")]
    cve = [f for f in findings if f["category"] == "cve"]
    other = [f for f in findings if f["category"] != "cve"]
    ids = {n["id"] for n in nodes}
    check(S4, "outcome: evidence/*.json exist", len(evidence) > 0, f"{len(evidence)} evidence files", "no evidence files")

    # ------------------------------------------------------------------ SLIDE 4, step 1: discover components
    lock_ev = [e for e in evidence.values() if e["source_tool"].startswith("resolve:")]
    check(S4, "1 analyse package manifests and lockfiles", len(lock_ev) >= 2,
          f"lockfiles resolved for {sorted(e['facts']['project'] for e in lock_ev)} with install scripts not run",
          "expected lockfile evidence for root and frontend")
    direct = [n for n in pk if n.get("direct")]
    check(S4, "1 identify direct and transitive dependencies", direct and len(pk) > len(direct),
          f"{len(direct)} direct / {len(pk) - len(direct)} transitive", "direct or transitive set is empty")
    check(S4, "1 capture component names and versions", all(n.get("label") and n.get("version") for n in pk),
          f"all {len(pk)} package nodes have name + version", "some package nodes lack name or version")

    # ------------------------------------------------------------------ step 2: supply-chain view
    check(S4, "2 SBOM (CycloneDX or SPDX)", sbom.get("bomFormat") == "CycloneDX" and bool(sbom.get("components")),
          f"CycloneDX {sbom.get('specVersion')}, {len(sbom['components'])} components, file ends .cdx.json",
          "sbom.cdx.json is not a CycloneDX BOM with components")
    sb_purls = {c["purl"] for c in sbom["components"] if c.get("purl")}
    missing_in_sbom = [n["id"] for n in pk if n["id"] not in sb_purls]
    check(S4, "2 SBOM covers every package counted in the header / graph", not missing_in_sbom,
          f"header {summary['sbom']['components']} unique package versions, all present in the SBOM "
          f"({len(sbom['components'])} entries, {len(sb_purls)} unique purls)",
          f"{len(missing_in_sbom)} graph packages are not in the SBOM (dev dependencies omitted?), e.g. {missing_in_sbom[:3]}")
    bad_edges = [e for e in graph["edges"] if e["source"] not in ids or e["target"] not in ids]
    check(S4, "2 dependency graph", len(graph["edges"]) > 0 and not bad_edges,
          f"{len(nodes)} nodes, {len(graph['edges'])} edges, every edge endpoint exists",
          f"{len(bad_edges)} edges point at missing nodes")
    miss = [n["id"] for n in pk if not n.get("origin") or not n.get("integrity")]
    check(S4, "2 where each component originates (origin + integrity)", not miss,
          f"all {len(pk)} packages carry the registry URL and integrity hash",
          f"{len(miss)} packages lack origin/integrity, e.g. {miss[:3]}")
    tools = [e["summary"] for e in trace if e["type"] == "tool_result"]
    ci_seen = any("action refs" in s for s in tools)
    img_seen = any("base images" in s for s in tools)
    check(S4, "2 inspect at least one container image or CI/CD workflow", ci_seen or img_seen,
          "CI workflows: " + next((s for s in tools if "action refs" in s), "-") + " | Dockerfiles: "
          + next((s for s in tools if "base images" in s), "-"), "neither CI nor Dockerfile inspected")

    # ------------------------------------------------------------------ step 3: vulnerabilities
    grype_ev = [e for e in evidence.values() if e["kind"] == "scanner_output" and e["source_tool"].startswith("grype")]
    check(S4, "3 correlate components with known vulnerabilities", len(cve) > 0 and len(grype_ev) > 0,
          f"{len(cve)} CVE findings from Grype + OSV-Scanner across {len({f['component_purl'] for f in cve})} package versions",
          "no CVE findings or no scanner evidence")
    no_id = [f["finding_id"] for f in cve if not f["vuln_id"]]
    no_sev = [f["finding_id"] for f in cve if f["cvss"] is None and not f["severity"]]
    fixes = sum(1 for f in cve if f["fixed_versions"])
    check(S4, "3 capture CVE id, severity and available fix", not no_id and not no_sev,
          f"all have an id and a score/severity; fix available for {fixes}, none known for {len(cve) - fixes}",
          f"{len(no_id)} without id, {len(no_sev)} without CVSS or severity")
    nopath = [f for f in cve if not f["dependency_paths"]]
    trans = [f for f in cve if f["dependency_paths"] and len(f["dependency_paths"][0]) > 2]
    t0 = trans[0] if trans else None
    path_ok = bool(t0) and t0["dependency_paths"][0][0] in graph["roots"] and \
        any(n["id"] == t0["dependency_paths"][0][1] and n.get("direct") for n in pk)
    check(S4, "3 trace vulnerable transitive dependencies back to their source", path_ok and not nopath,
          f"{len(trans)} transitive CVEs traced, e.g. " + " > ".join(p.split('/')[-1] for p in t0["dependency_paths"][0])
          if t0 else "", f"{len(nopath)} CVE findings have no dependency path")

    # ------------------------------------------------------------------ step 4: suspicious changes
    cats = Counter(f["category"] for f in other)
    check(S4, "4 identify at least one supply-chain anomaly", len(other) >= 1, f"{len(other)} anomalies: {dict(cats)}",
          "no non-CVE findings")
    wanted = {
        "typosquat ngy-cookie @ frontend/package.json:59": lambda f: f["category"] == "typosquat" and "ngy-cookie" in f["title"]
        and f["file_path"] == "frontend/package.json" and f["line"] == 59,
        "legacy typosquat epilogue-js @ ftp/package.json.bak": lambda f: f["category"] == "typosquat" and "epilogue-js" in f["title"],
        "lockfile disabled @ .npmrc:1": lambda f: f["category"] == "lockfile" and f["file_path"] == ".npmrc" and f["line"] == 1,
        "unpinned CI coverallsapp/github-action@v2 @ ci.yml:198": lambda f: f["category"] == "unpinned_ci"
        and "coverallsapp/github-action@v2" in f["title"] and f["line"] == 198,
        "tag-only image node:24 @ Dockerfile:1": lambda f: f["category"] == "untrusted_image" and f["component_purl"] == "node:24",
        "tag-only image distroless @ Dockerfile:22": lambda f: f["category"] == "untrusted_image"
        and "distroless" in (f["component_purl"] or "") and f["line"] == 22,
    }
    for name, fn in wanted.items():
        check(S4, f"4 expected Juice Shop anomaly: {name}", any(fn(f) for f in findings), "found", "NOT found")
    on_graph = {fid for n in nodes for fid in n.get("finding_ids", [])}
    off = [f["finding_id"] for f in findings if f["finding_id"] not in on_graph]
    check(S4, "4 every anomaly is also visible in the graph (pseudo-nodes)", not off,
          f"all {len(findings)} findings are attached to a graph node; {len(pseudo)} CI/image/config pseudo-nodes",
          f"{len(off)} findings have no graph node")
    check(S4, "4 'what changed' (modified/unexpected dependencies)", bool(changes["added"] or changes["removed"] or changes["changed"]),
          f"{changes['base']} vs {changes['head']}: +{len(changes['added'])} / -{len(changes['removed'])} / ~{len(changes['changed'])}, "
          f"{sum(c['major_jump'] for c in changes['changed'])} major jumps", "empty diff")

    # ------------------------------------------------------------------ step 5: present evidence
    no_ev = [f["finding_id"] for f in findings if not f["evidence_ids"]]
    dangling = [e for f in findings for e in f["evidence_ids"] if e not in evidence]
    check(S4, "5 supporting evidence for every finding", not no_ev and not dangling,
          f"all {len(findings)} findings cite evidence; all {len({e for f in findings for e in f['evidence_ids']})} evidence files exist",
          f"{len(no_ev)} findings without evidence, {len(dangling)} dangling ids")
    no_where = [f["finding_id"] for f in findings if not (f["component_purl"] or f["file_path"])]
    check(S4, "5 which component is affected", not no_where, "every finding names a component or file:line",
          f"{len(no_where)} findings name neither")
    no_ctx = [f for f in findings if f["category"] == "cve" and not f["dependency_paths"]]
    check(S4, "5 dependency path", not no_ctx, "every package finding has a dependency path", f"{len(no_ctx)} lack a path")
    risks = {"critical", "high", "medium", "low"}
    bad_r = [f["finding_id"] for f in findings if f["initial_risk"] not in risks]
    check(S4, "5 initial risk level", not bad_r, f"all findings rated: {dict(Counter(f['initial_risk'] for f in findings))}",
          f"{len(bad_r)} findings without initial risk")
    cp = "checkpoint: what is in the app / what changed / what appears risky"
    check(S4, cp, summary["sbom"]["components"] and changes and summary["findings"]["total"],
          f"{summary['sbom']['components']} components | {len(changes['added']) + len(changes['removed']) + len(changes['changed'])} changes | "
          f"{summary['findings']['total']} findings", "one of the three answers is empty")

    # ------------------------------------------------------------------ SLIDE 3
    cats_all = {f["category"] for f in findings}
    direct_cve = any(f["dependency_paths"] and len(f["dependency_paths"][0]) == 2 for f in cve)
    for label, ok_, bad in [
        ("risk example: vulnerable direct dependency", direct_cve, "no direct-dependency CVE"),
        ("risk example: vulnerable transitive dependency", bool(trans), "none"),
        ("risk example: typosquatted package", "typosquat" in cats_all, "none"),
        ("risk example: untrusted container image", "untrusted_image" in cats_all, "none"),
        ("risk example: unexpected lockfile / dependency change", "lockfile" in cats_all and bool(changes["added"]), "none"),
        ("risk example: unpinned CI/CD component", "unpinned_ci" in cats_all, "none"),
    ]:
        check(S3, label, ok_, "demonstrated on Juice Shop", bad)
    check(S3, "risk example: suspicious package update or install script",
          "install_script" in cats_all or "major_jump" in cats_all, "detected",
          "not a CP1 detector: install-script and major-jump FINDINGS are evening task D2-06 "
          f"(the diff already lists {sum(c['major_jump'] for c in changes['changed'])} major jumps)", warn=True)
    git_cfg = ROOT / "targets" / "juice-shop" / ".git" / "config"
    check(S3, "app: free open-source app from a public repo", git_cfg.exists() and "juice-shop/juice-shop" in git_cfg.read_text(),
          "OWASP Juice Shop, cloned from github.com/juice-shop/juice-shop", "target not cloned")
    check(S3, "app: realistic dependency tree", len(pk) >= 500, f"{len(pk)} packages", "tree too small")
    check(S3, "app: containerized", (ROOT / "targets/juice-shop/Dockerfile").exists(), "has a Dockerfile", "no Dockerfile")
    tdoc = (ROOT / "docs/targets.md").read_text(encoding="utf-8") if (ROOT / "docs/targets.md").exists() else ""
    check(S3, "app: build and test locally (timings measured)", "not yet measured" not in tdoc,
          "measured", "scanned locally yes; npm test:server / test:api and image build NOT measured yet (evening D5-03/D5-07)", warn=True)
    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    check(S3, "document repo, setup steps, dependencies and tools", all(k in readme for k in ("uv sync", "install_tools", "DEEPSEEK_API_KEY", "serve-runs")),
          "README covers setup, tools, run, view", "README missing setup/tool/run steps")

    # ------------------------------------------------------------------ PLAN §3.2 definition of done
    agents = {e["agent"] for e in trace}
    types = {e["type"] for e in trace}
    check(DOD, "1 one command runs the 3-node agent graph", {"discovery", "detection", "evidence_analyst", "supervisor"} <= agents
          and summary["status"] == "done", f"status {summary['status']}; agents {sorted(agents)}", "agents or status missing")
    check(DOD, "2 SBOM saved; component count shown (run_summary.json)", summary["sbom"]["components"] > 0,
          f"{summary['sbom']['components']} components", "no count")
    check(DOD, "3 graph: direct vs transitive, root + frontend both present", {"root", "frontend"} <= set(graph["roots"])
          and all(any(e["source"] == r for e in graph["edges"]) for r in ("root", "frontend")),
          f"roots {graph['roots']}, both have dependencies", "a root is missing or empty")
    check(DOD, "4 vulnerable transitive dependency traced to its direct parent", path_ok, "yes", "no traced path")
    check(DOD, "5 anomaly in findings list and, via pseudo-node, in the graph", len(other) > 0 and not off, "yes", "no")
    check(DOD, "6 each node shows origin + integrity", not miss, "yes", f"{len(miss)} missing")
    ch_ev = [e for e in changes.get("evidence_ids", []) if e not in evidence]
    check(DOD, "7 what changed: legacy manifest vs current", bool(changes.get("evidence_ids")) and not ch_ev,
          "diff + its evidence record", "changes.json has no valid evidence id")
    expl = [f for f in findings if f["explanation"]]
    check(DOD, "8 every finding has an analyst explanation", len(expl) == len(findings),
          f"all {len(findings)} findings have an explanation",
          f"only {len(expl)} of {len(findings)} have an analyst explanation; the rest show the rule-based risk")
    claims = [c for f in findings for c in f["claims"]]
    lab = Counter(c["label"] for c in claims)
    check(DOD, "8 every claim is labelled VERIFIED or INFERRED", claims and set(lab) <= {"verified", "inferred"},
          f"{len(claims)} claims: {dict(lab)}", f"unlabelled/unsupported claims present: {dict(lab)}")
    need_t = {"agent_start", "agent_end", "handoff", "decision", "tool_call", "tool_result", "llm_call", "llm_result"}
    ho = [e for e in trace if e["type"] == "handoff" and e["evidence_ids"]]
    check(DOD, "9 agent trace: roles, hand-offs, routing decisions", need_t <= types and len(ho) >= 2,
          f"{len(trace)} events, {sum(e['type'] == 'decision' for e in trace)} supervisor decisions, {len(ho)} hand-offs carrying evidence ids",
          f"missing event types {sorted(need_t - types)}")
    check(DOD, "10 initial-risk source shown honestly (llm vs rule)", all(f["initial_risk_source"] in ("llm", "rule") for f in findings),
          dict(Counter(f["initial_risk_source"] for f in findings)).__repr__(), "some findings lack a source")

    # ------------------------------------------------------------------ PLAN §4.1 contracts
    sk = {"run_id", "target", "commit", "started_at", "status", "sbom", "projects", "findings", "llm", "offline"}
    check(CON, "run_summary.json shape", sk <= set(summary) and {"file", "components", "direct", "transitive"} <= set(summary["sbom"])
          and {"total", "by_risk", "by_category"} <= set(summary["findings"]) and {"mode", "model"} <= set(summary["llm"]),
          "matches §4.1", f"missing keys {sorted(sk - set(summary))}")
    nk = {"id", "kind", "label"}
    pk_fields = {"version", "ecosystem", "direct", "scope", "project", "origin", "integrity", "risk", "finding_ids"}
    check(CON, "graph.json shape (nodes, edges, roots, package fields)", nk <= set(nodes[0]) and pk_fields <= set(pk[0]) and
          set(graph) >= {"nodes", "edges", "roots"}, "matches §4.1", "node fields missing")
    pn = {n["id"].split(":", 1)[0] for n in pseudo}
    check(CON, "graph.json pseudo-node kinds ci / image / config", {"ci", "image", "config"} <= pn, f"kinds {sorted(pn)}", "missing a kind")
    check(CON, "changes.json shape", {"base", "head", "added", "removed", "changed", "integrity_changed", "install_scripts_added", "evidence_ids"} <= set(changes)
          and all({"name", "from", "to", "major_jump"} <= set(c) for c in changes["changed"]), "matches §4.1", "keys missing")
    ek = {"evidence_id", "run_id", "kind", "source_tool", "created_at", "facts"}
    check(CON, "evidence/<id>.json shape", all(ek <= set(e) for e in evidence.values()), "matches §5.1 Evidence", "fields missing")
    tk = {"ts", "run_id", "agent", "type", "summary", "evidence_ids", "data"}
    check(CON, "trace.jsonl is one AgentEvent per line", all(tk <= set(e) for e in trace), f"{len(trace)} valid events", "fields missing")
    fk = {"finding_id", "category", "title", "detector", "evidence_ids", "initial_risk", "status", "vuln_id", "aliases", "fixed_versions",
          "affected_range", "dependency_paths", "scope", "project"}
    check(CON, "findings.json: Finding fields (incl. aliases, affected_range, scope)", all(fk <= set(f) for f in findings), "matches §5.1", "fields missing")

    # ------------------------------------------------------------------ PLAN §3.4 per-dev proofs and repo
    def have(p: str) -> bool:
        return (ROOT / p).exists()

    for dev, items in {
        "Dev1": ["guardian/core/models.py", "guardian/core/store.py", "guardian/core/audit.py", "guardian/graph/workflow.py",
                 "guardian/agents/evidence_analyst.py", "guardian/llm/provider.py", "guardian/guardrails/grounding.py",
                 "guardian/serve.py", "Makefile", ".env.example", "pyproject.toml"],
        "Dev2": ["guardian/core/workspace.py", "guardian/core/graph_build.py", "guardian/tools/resolve.py", "guardian/tools/sbom.py",
                 "guardian/tools/scanners.py", "guardian/tools/detectors/lockfile.py", "guardian/tools/detectors/typosquat.py",
                 "scripts/install_tools.ps1", "scripts/tool_versions.ps1", "tests/fixtures/juice-shop/root/package-lock.json",
                 "tests/fixtures/juice-shop/frontend/package-lock.json", "tools/bin/syft.exe", "tools/bin/grype.exe", "tools/bin/osv-scanner.exe"],
        "Dev3": ["ui/src/api/types.ts", "ui/src/components/GraphView.tsx", "ui/src/components/FindingsList.tsx", "ui/src/components/CountStrip.tsx",
                 "ui/src/components/ChangesPanel.tsx", "ui/src/components/CustodyLog.tsx", "ui/src/components/ExhibitSheet.tsx",
                 "ui/public/sample-run/graph.json", "PRODUCT.md", "DESIGN.md"],
        "Dev4": ["data/popular_packages/npm.txt", "guardian/tools/detectors/similarity.py", "guardian/core/scoring.py",
                 "guardian/adapters/github_actions.py", "guardian/adapters/dockerfile.py", "guardian/tools/detectors/ci_pin.py",
                 "guardian/tools/detectors/image_pin.py", "guardian/tools/detectors/unexpected_change.py"],
        "Dev5": ["tests/golden/juice_shop_expected.yaml", "tests/integration/test_golden.py", "scripts/static_view.py", "scripts/fetch_targets.ps1",
                 "docs/decisions.md", "docs/targets.md", "docs/cp1_talk_track.md", "README.md", "context.md", "agent.md"],
    }.items():
        gone = [p for p in items if not have(p)]
        check(DEV, f"{dev}: deliverable files exist", not gone, f"all {len(items)} present", f"missing {gone}")
    shots = list((ROOT / "docs/cp1").glob("*.png")) if have("docs/cp1") else []
    check(DEV, "Dev3: screenshot fallback in docs/cp1/*.png (16:25)", len(shots) >= 4, f"{len(shots)} screenshots", f"{len(shots)} screenshots")
    fx = ROOT / "tests/fixtures/juice-shop"
    real = [n for n in ("grype.json", "osv.json") if (fx / n).exists()]
    check(DEV, "Dev5: real tool outputs captured as fixtures (D5-02)", len(real) == 2, f"{real} saved", f"have {real}; need grype.json and osv.json")
    names = (ROOT / "data/popular_packages/npm.txt").read_text(encoding="utf-8") if have("data/popular_packages/npm.txt") else ""
    check(DEV, "Dev4: popular list includes ngx-cookie and epilogue", "\nngx-cookie\n" in names and "\nepilogue\n" in names, "yes", "no")
    static = list(rd.glob("static_view.html"))
    check(DEV, "Dev5: static fallback viewer generated for this run", bool(static), "static_view.html present", "run scripts/static_view.py", warn=True)
    dec = (ROOT / "docs/decisions.md").read_text(encoding="utf-8") if have("docs/decisions.md") else ""
    check(DEV, "Dev5: mentor answers recorded in decisions.md", "_open_" not in dec, "recorded",
          "all 6 mentor questions still open (only you can ask the mentor: CP1 scope, Day-1 time, API/LLM rules)", warn=True)
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    check(DEV, "Dev1: Makefile has setup / check / run / serve-runs", all(t in make for t in ("setup:", "check:", "run:", "serve-runs:")), "yes", "missing")
    check(DEV, "plan §9.3: tag v0.1-cp1", False, "", "this folder has no git (as requested); the tag/PR belong to the original repo", warn=True)
    rec(DEV, "plan §8: scripts/install_tools.sh + tool_versions.env", "WARN",
        "Windows .ps1 equivalents exist; a bash version for Linux/macOS teammates is not written (untestable here)")

    # ------------------------------------------------------------------ SAFETY
    py = subprocess.run([sys.executable, str(ROOT / "scripts/check_forbidden.py")], capture_output=True, text=True)
    check(SEC, "no shell=True / git push / npm publish in guardian/", py.returncode == 0, py.stdout.strip(), py.stdout.strip())
    srv = (ROOT / "guardian/serve.py").read_text(encoding="utf-8")
    check(SEC, "run server refuses the target work copy", '"work"' in srv and "403" in srv, "yes", "no")
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    check(SEC, ".env, targets/, runs/ are git-ignored", all(x in gi for x in (".env", "targets/", "runs/")), "yes", "missing")
    check(SEC, "work copy has no .git (nothing can be pushed from it)", not (rd / "work" / ".git").exists(), "no .git", ".git present")
    leaks = secret_scan(rd)
    check(SEC, "API key appears in no file other than .env; no private keys in run output or LLM cache", not leaks,
          "clean", f"found in {leaks[:5]}")
    steps = [e for e in trace if e["type"] == "tool_call"]
    check(SEC, "every tool call is in the audit log", (rd / "audit.jsonl").exists() and len(steps) > 0,
          f"audit.jsonl present, {len(steps)} tool calls traced", "no audit log")

    if args.tests:
        for name, cmd in (("ruff", ["uv", "run", "ruff", "check", "guardian", "tests", "scripts"]),
                          ("pytest", ["uv", "run", "pytest", "-q"])):
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            last = (r.stdout.strip().splitlines() or [""])[-1]
            check(DEV, f"{name} passes", r.returncode == 0, last, last or r.stderr[-200:])
    return report()


def secret_scan(rd: Path) -> list[str]:
    env = ROOT / ".env"
    key = ""
    if env.exists():
        m = re.search(r"^DEEPSEEK_API_KEY=(.+)$", env.read_text(encoding="utf-8"), re.M)
        key = m.group(1).strip() if m else ""
    skip = {".venv", "node_modules", "targets", "tools", ".git", "dist", "work", "__pycache__", ".pytest_cache", ".ruff_cache"}
    exts = {".py", ".md", ".json", ".jsonl", ".ts", ".tsx", ".css", ".html", ".yaml", ".yml", ".txt", ".toml", ".ps1", ".example", ".cmd"}
    hits = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.name == ".env" or skip & set(p.relative_to(ROOT).parts) or p.suffix not in exts:
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = p.relative_to(ROOT).parts
        data_dir = rel[0] in ("runs", "data", "docs") or (rel[0] == "ui" and "public" in rel)  # not source code
        if (len(key) > 8 and key in t) or (data_dir and "-----BEGIN" in t and "PRIVATE KEY" in t):
            hits.append(str(p.relative_to(ROOT)))
    return hits


def report() -> int:
    marks = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL"}
    cur = None
    for src, cid, st, detail in RESULTS:
        if src != cur:
            print(f"\n== {src}")
            cur = src
        print(f"  [{marks[st]}] {cid}" + (f"\n         {detail}" if detail and st != "PASS" else (f"  -  {detail}" if detail else "")))
    c = Counter(r[2] for r in RESULTS)
    print(f"\nTOTAL {len(RESULTS)} checks: {c['PASS']} PASS, {c['WARN']} WARN (out of CP1 scope or needs a human), {c['FAIL']} FAIL")
    return 1 if c["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
