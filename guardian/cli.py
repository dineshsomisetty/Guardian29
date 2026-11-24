"""`python -m guardian ...` entry points. Owner: Dev1.

The command-line front end of Guardian. `main(argv)` builds an argparse tree, picks the subcommand's `_cmd_*`
function and returns its exit code (0 ok, 1 a batch target failed, 2 bad usage or a refused decision);
guardian/__main__.py passes that to sys.exit. Runs live under runs/<run_id>/ (settings.runs_dir); every command
that takes --run accepts a run id or "latest" (the runs/LATEST pointer). Heavy imports (the LangGraph workflow)
are done inside each command so `--help` stays fast.

Subcommands, each with a usage example:

  run         run the pipeline on a repo (pauses at the human gate when a plan needs a decision)
              python -m guardian run --repo targets/juice-shop [--compare-ref main] [--llm-mode replay]
  run --repos A B ...  batch: several targets sequentially with a shared intel cache (D1-12)
              python -m guardian run --repos targets/a targets/b   (prints a table, writes runs/batch_*.json)
  plans       show the plan (sequential) or the batch of recommendations (batch) waiting for decisions
              python -m guardian plans --run latest
  decide      approve / reject / accept_risk the pending plan and resume the run
              python -m guardian decide --run latest --plan pl_... --plan-hash <12+ chars> --decision approve
  validate-held validate the approved fixes held in one-at-a-time mode now, the rest keep waiting
  decide-batch  decide every fix of the pending batch (--approve-all or --file decisions.json) and resume
              python -m guardian decide-batch --run latest --batch bt_... --approve-all
  serve-runs  static file server for the UI (§4.2)
              python -m guardian serve-runs --port 8001
  api         FastAPI + SSE (§4.4)
              python -m guardian api --host 127.0.0.1 --port 8000
  watch       re-check a finished run against fresh OSV/EPSS/KEV (continuous monitoring, D1-11)
              python -m guardian watch --run latest --interval 1h [--once]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from guardian.core.config import load_settings


def _cmd_run(args: argparse.Namespace) -> int:
    """`run`: one --repo through the workflow, or several --repos as a batch. Exactly one of the two is required.

    Prints where the output went and whether a human decision is awaited (see `_report`). Returns 2 on bad args.
    """
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
    """One summary row (target, counts, top-risk finding, status) for the batch table and batch_*.json.

    Reads run_summary.json / risk.json / findings.json of the finished run; every read is best-effort, so a
    crashed or partial run still yields a row (status "failed"/"unknown") instead of aborting the batch.
    """
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
    """Print the batch rows as a fixed-width table (C/H/M/L = critical/high/medium/low finding counts)."""
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
    """`watch`: continuous monitoring of a finished run (see guardian/watch.py); returns 2 on a bad interval/run."""
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
    """Tell the user where the run output is and, if the run paused at the human gate, what to type next."""
    summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
    print(f"\nRun output: {run_dir}  (status: {summary['status']})")
    batch = summary.get("pending_batch")
    if batch:
        print(f"Waiting for decisions on {batch['count']} fix(es) (batch {batch['batch_id']}, round {batch['round']}):\n"
              f"  python -m guardian plans --run {summary['run_id']}")
    pending = summary.get("pending_plan")
    if pending:
        print(f"Waiting for a human decision on plan {pending['plan_id']}:\n"
              f"  python -m guardian plans --run {summary['run_id']}")
    return 0


def _run_dir(args: argparse.Namespace) -> Path:
    """Resolve --run (a run id or "latest") to its folder under settings.runs_dir. Does not check it exists."""
    settings = load_settings()
    run_id = args.run
    if run_id == "latest":
        run_id = (settings.runs_dir / "LATEST").read_text(encoding="utf-8").strip()
    return settings.runs_dir / run_id


def _cmd_plans(args: argparse.Namespace) -> int:
    """`plans`: show what is waiting for a human (a pending batch, else the single pending plan) and the exact
    command to answer it. The printed plan_hash is what `decide` must be given (G5.1)."""
    from guardian.core.plans import get_pending, get_pending_batch, list_plans

    run_dir = _run_dir(args)
    batch = get_pending_batch(run_dir)
    if batch is not None:
        return _print_batch_plans(run_dir, batch)
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


def _print_batch_plans(run_dir: Path, batch: dict) -> int:
    """Print every recommendation of a pending batch (fix plans and "no alternative" notes) with decision hints."""
    from guardian.core.plans import load_plan
    from guardian.core.recs import load_recs
    from guardian.core.store import JsonStore

    store = JsonStore(run_dir)
    recs = load_recs(run_dir)["items"]
    print(f"Batch {batch['batch_id']}  round {batch['round']}  {len(batch['items'])} fix(es) need a decision "
          f"(validation starts when ALL are decided)\n")
    for r in recs:
        f = store.get_finding(r.primary_finding_id)
        band = f.initial_risk.value if f and f.initial_risk else "?"
        title = f.title if f else r.primary_finding_id
        extra = f" (+{len(r.finding_ids) - 1} more on the same package)" if len(r.finding_ids) > 1 else ""
        if r.kind == "no_alternative" or r.plan_id is None:
            print(f"[{band:<8}] {title[:80]}{extra}\n    {r.reason or 'No alternatives'}  [{r.outcome}]")
            continue
        plan = load_plan(run_dir, r.plan_id)
        print(f"[{band:<8}] {title[:80]}{extra}\n    plan {r.plan_id}  attempt {plan.attempt}  action={plan.action}"
              + (f"  target={plan.target_version}" if plan.target_version else "") + f"  [{r.outcome}]")
        if r.previous:
            print(f"    previous plan {r.previous.plan_id} {r.previous.outcome}: {r.previous.detail}")
        for c in plan.rationale[:3]:
            print(f"      [{c.label.value.upper():<8}] {c.text}")
        for alt in r.alternatives:
            print(f"      alternative: {alt.summary}")
        print(f"    plan_hash {plan.plan_hash}")
    print(f"\n  python -m guardian decide-batch --run {run_dir.name} --batch {batch['batch_id']} "
          f"--approve-all [--by NAME]\n  python -m guardian decide-batch --run {run_dir.name} "
          f"--batch {batch['batch_id']} --file decisions.json\n"
          '  decisions.json: [{"plan_id": ..., "plan_hash": ..., "decision": "approve|reject|accept_risk", '
          '"comment": ..., "reason_type": "too_big|breaks_app|different_approach|other (reject only)"}, ...]')
    return 0


def _cmd_decide_batch(args: argparse.Namespace) -> int:
    """`decide-batch`: build Approvals for the pending batch (all approved, or from a JSON file) and resume it.

    --only / --partial decide just some fixes and leave the rest pending. The workflow re-checks the batch
    (guardrails/approval.py), so a refusal comes back as DecisionRejected and exit code 2.
    """
    from guardian.core.models import Approval
    from guardian.core.plans import get_pending_batch
    from guardian.graph.workflow import DecisionRejected, resume_batch

    run_dir = _run_dir(args)
    batch = get_pending_batch(run_dir)
    if batch is None:
        print(f"{run_dir.name} has no batch waiting for decisions", file=sys.stderr)
        return 2
    if bool(args.approve_all) == bool(args.file):
        print("give exactly one of --approve-all or --file decisions.json", file=sys.stderr)
        return 2
    only = list(args.only or [])  # plan ids the user named; empty = the whole batch
    partial = bool(only) or args.partial  # one at a time: the fixes not named stay pending
    pending_ids = {i["plan_id"] for i in batch["items"]}
    if unknown := [p for p in only if p not in pending_ids]:
        print(f"not in the pending batch: {', '.join(unknown)}", file=sys.stderr)
        return 2
    if args.approve_all:
        rows = [{"plan_id": i["plan_id"], "plan_hash": i["plan_hash"], "decision": "approve", "comment": args.comment}
                for i in batch["items"] if not only or i["plan_id"] in only]
    else:
        try:
            rows = json.loads(Path(args.file).read_text(encoding="utf-8"))
            if not isinstance(rows, list):
                raise ValueError("expected a JSON list")
        except (OSError, ValueError) as exc:
            print(f"cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
        if only:
            rows = [r for r in rows if isinstance(r, dict) and r.get("plan_id") in only]
    try:
        approvals = [Approval(plan_id=r["plan_id"], plan_hash=r["plan_hash"], decision=r["decision"],
                              comment=r.get("comment") or args.comment, reason_type=r.get("reason_type"),
                              decided_by=args.by) for r in rows]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        print(f"bad decision entry: {exc!r}", file=sys.stderr)
        return 2
    try:
        run_dir = resume_batch(run_dir.name, args.batch, approvals, partial=partial)
    except DecisionRejected as exc:
        print(f"decisions refused: {exc}", file=sys.stderr)
        return 2
    return _report(run_dir)


def _cmd_validate_held(args: argparse.Namespace) -> int:
    """`validate-held`: validate the approved fixes that are held (one-at-a-time mode) now, while the other fixes of
    the pending batch keep waiting for decisions. --only limits it to some plans; refusals exit with code 2."""
    from guardian.core.plans import get_pending_batch
    from guardian.graph.workflow import DecisionRejected, resume_validate_now

    run_dir = _run_dir(args)
    batch = get_pending_batch(run_dir)
    if batch is None:
        print(f"{run_dir.name} has no batch waiting for decisions", file=sys.stderr)
        return 2
    try:
        run_dir = resume_validate_now(run_dir.name, batch["batch_id"], list(args.only or []) or None,
                                      requested_by=args.by)
    except DecisionRejected as exc:
        print(f"validate-held refused: {exc}", file=sys.stderr)
        return 2
    return _report(run_dir)


def _cmd_decide(args: argparse.Namespace) -> int:
    """`decide`: record the human decision on the single pending plan and resume the run.

    The typed --plan-hash prefix must match the pending plan (G5.1); the workflow enforces that reject and
    accept_risk carry a comment (G5.2). Exit 2 when nothing is pending or the decision is refused.
    """
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
                        comment=args.comment, reason_type=args.reason_type, decided_by=args.by)
    try:
        run_dir = resume(run_dir.name, approval)
    except DecisionRejected as exc:
        print(f"decision refused: {exc}", file=sys.stderr)
        return 2
    return _report(run_dir)


def _cmd_serve(args: argparse.Namespace) -> int:
    """`serve-runs`: blocking static file server for runs/ (guardian/serve.py)."""
    from guardian.serve import serve_runs

    serve_runs(load_settings().runs_dir, port=args.port)
    return 0


def _cmd_api(args: argparse.Namespace) -> int:
    """`api`: blocking FastAPI server (guardian/api/app.py); non-loopback hosts need GUARDIAN_API_TOKENS."""
    from guardian.api.app import serve_api

    serve_api(host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse `argv` (default sys.argv[1:]) and run the chosen subcommand; returns its process exit code."""
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
    d.add_argument("--reason-type", choices=["too_big", "breaks_app", "different_approach", "other"],
                   help="for reject: why, which steers the next suggestion")
    d.add_argument("--by", default="local-user", help="who decides (recorded in approvals.jsonl)")
    d.set_defaults(func=_cmd_decide)

    db = sub.add_parser("decide-batch", help="decide every fix of the pending batch, then resume (batch mode)")
    db.add_argument("--run", default="latest")
    db.add_argument("--batch", required=True, help="the batch id shown by `guardian plans`")
    db.add_argument("--approve-all", action="store_true", help="approve every fix in the batch")
    db.add_argument("--file", help="JSON list of {plan_id, plan_hash, decision, comment} for every fix")
    db.add_argument("--only", nargs="+", metavar="PLAN_ID",
                    help="one at a time: decide just these plans (implies --partial); the rest stay pending")
    db.add_argument("--partial", action="store_true", help="--file may decide only some fixes; the rest stay pending")
    db.add_argument("--comment", help="comment for --approve-all, or the default for entries without one")
    db.add_argument("--by", default="local-user", help="who decides (recorded in approvals.jsonl)")
    db.set_defaults(func=_cmd_decide_batch)

    vh = sub.add_parser("validate-held", help="validate the held approved fixes now; the rest keep waiting (batch mode)")
    vh.add_argument("--run", default="latest")
    vh.add_argument("--only", nargs="+", metavar="PLAN_ID", help="just these approved plans (default: all held)")
    vh.add_argument("--by", default="local-user", help="who asks (recorded in the audit trail)")
    vh.set_defaults(func=_cmd_validate_held)

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
