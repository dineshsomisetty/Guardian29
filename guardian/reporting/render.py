"""Write report.json (machine) and report.html (human, Jinja2, autoescape on, no external assets).

Called by the workflow at the end (or pause) of a run, and available to the CLI/API for finished runs.
Input: a run directory. Output: runs/<id>/report.json (the `Report` model as indented JSON, the contract other
tools read) and runs/<id>/report.html (the same data rendered with templates/report.html.j2, one self-contained
file that opens offline). Both are rewritten on every call, so a report written while a run waits at the human
gate is replaced by the final one after the decision.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from guardian.reporting.build import build_report
from guardian.reporting.schema import Report

TEMPLATES = Path(__file__).parent / "templates"


def render_html(report: Report) -> str:
    """Render the report to an HTML string. Autoescape is on, so evidence text (which may contain markup from
    the scanned repo) cannot inject HTML or script into the report."""
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(r=report.model_dump(mode="json"))


def write_reports(run_dir: Path, **kw) -> tuple[Path, Path]:
    """Build the report for `run_dir` and write report.json and report.html there; returns both paths.

    Extra keyword arguments (summary, inventory, target, commit) are forwarded to `build_report`.
    """
    run_dir = Path(run_dir)
    report = build_report(run_dir, **kw)
    j, h = run_dir / "report.json", run_dir / "report.html"
    j.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    h.write_text(render_html(report), encoding="utf-8")
    return j, h
