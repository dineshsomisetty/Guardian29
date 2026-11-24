# Document the contract for the surrounding module or callable.
"""Write report.json (machine) and report.html (human, Jinja2, autoescape on, no external assets).

Called by the workflow at the end (or pause) of a run, and available to the CLI/API for finished runs.
Input: a run directory. Output: runs/<id>/report.json (the `Report` model as indented JSON, the contract other
tools read) and runs/<id>/report.html (the same data rendered with templates/report.html.j2, one self-contained
file that opens offline). Both are rewritten on every call, so a report written while a run waits at the human
gate is replaced by the final one after the decision.
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import Path from pathlib.
from pathlib import Path

# Import Environment, FileSystemLoader, select_autoescape from jinja2.
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Import build_report from guardian.reporting.build.
from guardian.reporting.build import build_report
# Import Report from guardian.reporting.schema.
from guardian.reporting.schema import Report

# Store Path(__file__).parent / 'templates' in TEMPLATES.
TEMPLATES = Path(__file__).parent / "templates"


# Define render_html for report serialization.
# Inputs include report.
def render_html(report: Report) -> str:
    # Document the contract for the surrounding module or callable.
    """Render the report to an HTML string. Autoescape is on, so evidence text (which may contain markup from
    the scanned repo) cannot inject HTML or script into the report."""
    # Store the result of Environment in env.
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    # Return the result of env.get_template('report.html.j2').render to the caller.
    return env.get_template("report.html.j2").render(r=report.model_dump(mode="json"))


# Serialize the report for programmatic and browser use.
# Inputs include run_dir.
def write_reports(run_dir: Path, **kw) -> tuple[Path, Path]:
    # Document the contract for the surrounding module or callable.
    """Build the report for `run_dir` and write report.json and report.html there; returns both paths.

    Extra keyword arguments (summary, inventory, target, commit) are forwarded to `build_report`.
    """
    # Store the result of Path in run_dir.
    run_dir = Path(run_dir)
    # Store the result of build_report in report.
    report = build_report(run_dir, **kw)
    # Store (run_dir / 'report.json', run_dir / 'report.html') in (j, h).
    j, h = run_dir / "report.json", run_dir / "report.html"
    # Call j.write_text at this point.
    j.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    # Call h.write_text at this point.
    h.write_text(render_html(report), encoding="utf-8")
    # Return (j, h) to the caller.
    return j, h
