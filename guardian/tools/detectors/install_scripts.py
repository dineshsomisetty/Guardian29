"""Detector `dependency_install_scripts` (D2-06, Dev2): DEPENDENCIES that run code at install time.

Source: `hasInstallScript` in the resolved lockfiles (no network, nothing executed). The project's own
`postinstall` is deliberately not flagged (decision C7: it is the app's build step, not a supply-chain risk).
"""
from __future__ import annotations

from pathlib import Path

from guardian.adapters.npm import find_projects, lock_entries, npm_purl
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolOutput

DETECTOR = "detector:install_scripts"


def detect(ctx) -> ToolOutput:
    base = Path(ctx.work_dir or ctx.repo)
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for proj in find_projects(base):
        lock = proj.dir / "package-lock.json"
        if not lock.is_file():
            continue
        seen: set[str] = set()
        for key, ent in lock_entries(lock).items():
            if not ent.get("hasInstallScript") or not ent.get("version"):
                continue
            purl = npm_purl(ent["_name"], ent["version"])
            if purl in seen:
                continue
            seen.add(purl)
            dev = bool(ent.get("dev") or ent.get("devOptional"))
            optional = bool(ent.get("optional"))
            file_path = proj.relpath("package-lock.json")
            ev = Evidence(
                run_id=ctx.run_id, kind="file_excerpt", source_tool=DETECTOR, file_path=file_path,
                line=ent["_line"], excerpt=f'"{key}": {{ "version": "{ent["version"]}", "hasInstallScript": true }}',
                facts={"purl": purl, "lock_key": key, "hasInstallScript": True, "dev": dev, "optional": optional,
                       "resolved": ent.get("resolved"), "integrity": ent.get("integrity"), "project": proj.name})
            evidence.append(ev)
            findings.append(Finding(
                run_id=ctx.run_id, category=FindingCategory.INSTALL_SCRIPT, detector=DETECTOR,
                title=f"Dependency {ent['_name']}@{ent['version']} runs an install script"
                      + (" (dev)" if dev else "") + (" (optional)" if optional else ""),
                component_purl=purl, scope=Scope.DEV if dev else Scope.PROD, project=proj.name,
                file_path=file_path, line=ent["_line"], evidence_ids=[ev.evidence_id]))
    prod = sum(1 for f in findings if f.scope is Scope.PROD)
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(findings)} dependencies with install scripts ({prod} prod)")
