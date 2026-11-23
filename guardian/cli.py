"""`python -m guardian ...` entry points. Owner: Dev1."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from guardian.core.config import load_settings


def _cmd_run(args: argparse.Namespace) -> int:
    from guardian.graph.workflow import run

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"repo not found: {repo}", file=sys.stderr)
        return 2
    settings = load_settings(llm_mode=args.llm_mode, max_llm_findings=args.max_llm_findings)
    run_dir = run(repo, run_id=args.run_id, settings=settings)
    print(f"\nRun output: {run_dir}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from guardian.serve import serve_runs

    serve_runs(load_settings().runs_dir, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardian", description="Software supply chain guardian")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the agent pipeline on a target repo")
    r.add_argument("--repo", required=True)
    r.add_argument("--run-id")
    r.add_argument("--llm-mode", choices=["live", "record", "replay"])
    r.add_argument("--max-llm-findings", type=int)
    r.set_defaults(func=_cmd_run)

    s = sub.add_parser("serve-runs", help="serve runs/ over HTTP with CORS for the UI (§4.2)")
    s.add_argument("--port", type=int, default=8001)
    s.set_defaults(func=_cmd_serve)

    args = p.parse_args(argv)
    return args.func(args)
