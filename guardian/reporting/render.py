"""Write report.json (machine) and report.html (human, Jinja2, autoescape on, no external assets)."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from guardian.reporting.build import build_report
from guardian.reporting.schema import Report

TEMPLATES = Path(__file__).parent / "templates"


def render_html(report: Report) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(r=report.model_dump(mode="json"))


def write_reports(run_dir: Path, **kw) -> tuple[Path, Path]:
    run_dir = Path(run_dir)
    report = build_report(run_dir, **kw)
    j, h = run_dir / "report.json", run_dir / "report.html"
    j.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    h.write_text(render_html(report), encoding="utf-8")
    return j, h
