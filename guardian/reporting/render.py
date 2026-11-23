"""Write report.json (machine) and report.html (human) for a run (D4-06)."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from guardian.reporting.build import build_report
from guardian.reporting.schema import Report

TEMPLATES = Path(__file__).parent / "templates"


def render_html(report: Report) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(r=report.model_dump())


def write_reports(run_dir: Path | str, target: str | None = None) -> tuple[Path, Path]:
    run = Path(run_dir)
    report = build_report(run, target=target)
    j, h = run / "report.json", run / "report.html"
    j.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    h.write_text(render_html(report), encoding="utf-8")
    return j, h
