"""`python -m guardian ...` entry points. Owner: Dev1.

  run         run the pipeline on a repo (pauses at the human gate when a plan needs a decision)
  plans       show the plan waiting for a decision: diff, rationale with labels, the hash to approve
  decide      approve / reject / accept_risk the pending plan and resume the run
  serve-runs  static file server for the UI (§4.2)
  api         FastAPI + SSE (§4.4)
  watch       re-check a finished run against fresh OSV/EPSS/KEV (continuous monitoring, D1-11)
  run --repos A B ...  batch: several targets sequentially with a shared intel cache (D1-12)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from guardian.core.config import load_settings


def _cmd_run(args: argparse.Namespace) -> int:
    if bool(args.repo) == bool(args.repos):
        print("give exactly one of --repo <dir> or --repos <dir> [<dir> ...]", file=sys.stderr)
        return 2
    settings = load_settings(llm_mode=args.llm_mode, max_llm_findings=args.max_llm_findings, max_plans=args.max_plans)
    if args.repos:
        if args.run_id:
            print("--run-id applies to a single --repo run", file=sys.stderr)
            return 2
        return _cmd_batch(args, settings)
    from guardian.graph.workflow import run

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"repo not found: {repo}", file=sys.stderr)
        return 2
    run_dir = run(repo, run_id=args.run_id, settings=settings, compare_ref=args.compare_ref)
    return _report(run_dir)


def _batch_row(target: str, run_dir: Path | None, error: str | None) -> dict:
    row = {"target": target, "run_id": run_dir.name if run_dir else None, "components": None,
           "findings": {"total": 0, "by_risk": {}}, "top_risk": None, "status": "failed" if error else "unknown"}
    if error:
        row["error"] = error[:300]
    if run_dir is None:
        return row
    try:
        summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
        row["status"] = summary.get("status", row["status"])
        row["components"] = (summary.get("sbom") or {}).get("components")
        row["findings"] = {"total": summary["findings"]["total"], "by_risk": summary["findings"]["by_risk"]}
        risks = json.loads((run_dir / "risk.json").read_text(encoding="utf-8")) if (run_dir / "risk.json").exists() else []
        if risks:
            titles = {f["finding_id"]: f["title"] for f in json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))}
            top = risks[0]
            row["top_risk"] = {"finding_id": top["finding_id"], "score": top["score"], "band": top["band"],
                               "title": titles.get(top["finding_id"], "")}
    except (OSError, ValueError, KeyError):
        pass
    return row


def _print_batch(rows: list[dict]) -> None:
    head = f"{'target':<18}{'components':>10}  {'C/H/M/L':<14}{'top risk':<46}status"
    print(chr(10) + head + chr(10) + "-" * len(head))
    for r in rows:
        br = r["findings"]["by_risk"]
        sev = "/".join(str(br.get(k, 0)) for k in ("critical", "high", "medium", "low"))
        t = r["top_risk"]
        top = f"{t['score']:.0f} {t['band']}: {t['title']}"[:44] if t else "-"
        print(f"{r['target'][:17]:<18}{r['components'] if r['components'] is not None else '-':>10}  "
              f"{sev:<14}{top:<46}{r['status']}")


def _cmd_batch(args: argparse.Namespace, settings) -> int:
    """D1-12: run each target sequentially. The intel cache (data/cache/intel/threat, or GUARDIAN_INTEL_CACHE) is
    shared by every run, so registry/EPSS/KEV/OSV responses are fetched once."""
    import os
    from datetime import datetime

    from guardian.graph.workflow import run
    from guardian.tools.threat_intel import DEFAULT_CACHE

    os.environ.setdefault("GUARDIAN_INTEL_CACHE", str(DEFAULT_CACHE))
    rows = []
    for raw in args.repos:
        repo = Path(raw)
        if not repo.is_dir():
            print(f"repo not found: {repo}", file=sys.stderr)
            rows.append(_batch_row(repo.name, None, "repo not found"))
            continue
        run_dir, error = None, None
        try:
            run_dir = run(repo, settings=settings, compare_ref=args.compare_ref)
        except Exception as exc:  # noqa: BLE001  one failing target must not stop the batch
            error = f"{type(exc).__name__}: {exc}"
            print(f"{repo.name} failed: {error}", file=sys.stderr)
            run_dir = None
        rows.append(_batch_row(repo.name, run_dir, error))
    _print_batch(rows)
    out = settings.runs_dir / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"created_at": datetime.now().astimezone().isoformat(),
                               "intel_cache": os.environ["GUARDIAN_INTEL_CACHE"], "runs": rows}, indent=2),
                   encoding="utf-8")
    print(f"{chr(10)}Batch summary: {out}")
    return 1 if any(r["status"] == "failed" for r in rows) else 0


def _cmd_watch(args: argparse.Namespace) -> int:
    from guardian.watch import WatchError, parse_interval, watch_loop

    run_dir = _run_dir(args)
    try:
        interval = parse_interval(args.interval)
        return watch_loop(run_dir.name, interval, once=args.once, max_age_s=parse_interval(args.max_age),
                          max_components=args.max_components)
    except (ValueError, WatchError) as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 2


def _report(run_dir: Path) -> int:
    summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
    print(f"\nRun output: {run_dir}  (status: {summary['status']})")
    pending = summary.get("pending_plan")
    if pending:
        print(f"Waiting for a human decision on plan {pending['plan_id']}:\n"
              f"  python -m guardian plans --run {summary['run_id']}")
    return 0


def _run_dir(args: argparse.Namespace) -> Path:
    settings = load_settings()
    run_id = args.run
    if run_id == "latest":
        run_id = (settings.runs_dir / "LATEST").read_text(encoding="utf-8").strip()
    return settings.runs_dir / run_id


def _cmd_plans(args: argparse.Namespace) -> int:
    from guardian.core.plans import get_pending, list_plans

    run_dir = _run_dir(args)
    pending = get_pending(run_dir)
    if pending is None:
        plans = list_plans(run_dir)
        print(f"No plan is waiting for a decision in {run_dir.name} ({len(plans)} plans in total).")
        return 0
    from guardian.core.store import JsonStore

    store = JsonStore(run_dir)
    finding = store.get_finding(pending.finding_id)
    diff = next((e.excerpt for e in (store.get_evidence(i) for i in pending.evidence_ids)
                 if e and e.kind == "patch_diff"), None)
    print(f"Finding : {finding.title}  [{finding.initial_risk.value if finding.initial_risk else '?'}]")
    print(f"Plan    : {pending.plan_id}  attempt {pending.attempt}  action={pending.action}"
          + (f"  target={pending.target_version}" if pending.target_version else ""))
    print("Why     :")
    for c in pending.rationale:
        print(f"  [{c.label.value.upper():<8}] {c.text}")
    print(f"Expected: {pending.expected_risk_reduction}")
    print(f"Rollback: {pending.rollback}")
    print("Diff    :\n" + (diff or "(no diff)"))
    print(f"\nplan_hash {pending.plan_hash}\n"
          f"  python -m guardian decide --run {run_dir.name} --plan {pending.plan_id} "
          f"--plan-hash {pending.plan_hash[:12]} --decision approve|reject|accept_risk [--comment ...]")
    return 0


def _cmd_decide(args: argparse.Namespace) -> int:
    from guardian.core.models import Approval
    from guardian.core.plans import get_pending
    from guardian.graph.workflow import DecisionRejected, resume

    run_dir = _run_dir(args)
    pending = get_pending(run_dir)
    if pending is None:
        print(f"{run_dir.name} is not waiting for a decision", file=sys.stderr)
        return 2
    # The human types (a prefix of) the hash they were shown, so the approval binds to that exact plan (G5.1).
    if len(args.plan_hash) < 12 or not pending.plan_hash.startswith(args.plan_hash):
        print("--plan-hash must be at least the first 12 characters of the hash shown by `guardian plans`",
              file=sys.stderr)
        return 2
    approval = Approval(plan_id=args.plan, plan_hash=pending.plan_hash, decision=args.decision,
                        comment=args.comment, decided_by=args.by)
    try:
        run_dir = resume(run_dir.name, approval)
    except DecisionRejected as exc:
        print(f"decision refused: {exc}", file=sys.stderr)
        return 2
    return _report(run_dir)


def _cmd_serve(args: argparse.Namespace) -> int:
    from guardian.serve import serve_runs

    serve_runs(load_settings().runs_dir, port=args.port)
    return 0


def _cmd_api(args: argparse.Namespace) -> int:
    from guardian.api.app import serve_api

    serve_api(host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardian", description="Software supply chain guardian")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the agent pipeline on a target repo")
    r.add_argument("--repo")
    r.add_argument("--repos", nargs="+", metavar="DIR", help="batch: run each target sequentially (D1-12)")
    r.add_argument("--run-id")
    r.add_argument("--compare-ref", help="git ref of the target to diff manifests/lockfiles against (D2-06)")
    r.add_argument("--llm-mode", choices=["live", "record", "replay"])
    r.add_argument("--max-llm-findings", type=int)
    r.add_argument("--max-plans", type=int, help="findings taken into the remediation loop (0 = none)")
    r.set_defaults(func=_cmd_run)

    w = sub.add_parser("watch", help="re-check a finished run against fresh advisories and rescore (D1-11)")
    w.add_argument("--run", default="latest")
    w.add_argument("--interval", default="1h", help="time between checks, e.g. 30s, 15m, 1h (default 1h)")
    w.add_argument("--once", action="store_true", help="check once and exit")
    w.add_argument("--max-age", default="15m", help="intel cache max-age in watch mode (default 15m)")
    w.add_argument("--max-components", type=int, default=400, help="components looked up in OSV per check")
    w.set_defaults(func=_cmd_watch)

    pl = sub.add_parser("plans", help="show the plan waiting for a human decision")
    pl.add_argument("--run", default="latest")
    pl.set_defaults(func=_cmd_plans)

    d = sub.add_parser("decide", help="approve / reject / accept the risk of the pending plan, then resume")
    d.add_argument("--run", default="latest")
    d.add_argument("--plan", required=True)
    d.add_argument("--plan-hash", required=True, help="the hash shown by `guardian plans` (>= 12 chars)")
    d.add_argument("--decision", required=True, choices=["approve", "reject", "accept_risk"])
    d.add_argument("--comment", help="required for reject and accept_risk (G5.2)")
    d.add_argument("--by", default="local-user", help="who decides (recorded in approvals.jsonl)")
    d.set_defaults(func=_cmd_decide)

    s = sub.add_parser("serve-runs", help="serve runs/ over HTTP with CORS for the UI (§4.2)")
    s.add_argument("--port", type=int, default=8001)
    s.set_defaults(func=_cmd_serve)

    a = sub.add_parser("api", help="FastAPI routes + SSE trace + decision endpoint on localhost (§4.4)")
    a.add_argument("--port", type=int, default=8000)
    a.add_argument("--host", default="127.0.0.1",
                   help="bind address; anything but loopback requires GUARDIAN_API_TOKENS (name:token:role,...)")
    a.set_defaults(func=_cmd_api)

    args = p.parse_args(argv)
    return args.func(args)
