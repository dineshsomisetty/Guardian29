"""D2-06 dependency install scripts: packages in the resolved tree that run code at `npm install`. Owner: Dev2.

Called by: the detection agent (tool `detector:install_scripts`); the investigator tool registry_metadata
(tools/investigate.py) reuses CACHE, REGISTRY, HOOKS and the throttle defined here.
Why: preinstall/install/postinstall hooks execute arbitrary code on every developer machine and CI runner that
installs the dependency, which is the classic npm supply-chain attack path.
Source of truth is the resolved lockfile (`hasInstallScript: true`, written by npm from registry metadata);
the project's own scripts are not flagged (C7: that is the app's build, not a supply-chain risk). For each
hit the script text is read from the registry version document (`scripts.preinstall/install/postinstall`) so
the analyst and a human can see *what* would run. Nothing is ever executed (installs use --ignore-scripts).
Output: Finding category `install_script` per distinct package (scope dev when the lockfile marks it dev, else
prod). Evidence kind `registry_metadata`, facts {package, version, purl, has_install_script, lockfile_key, project,
dev, hooks (names, or None when unknown), scripts_source}; excerpt = the hook commands.
Network/cache: registry version documents are cached as data/cache/intel/npm/<name>@<version>.json (only the three
hook scripts are stored) and throttled; with offline mode only the cache is read and hooks stay unknown (the
finding is still raised, because the lockfile flag alone proves a script exists). Calls use G3.5 check_url.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from guardian.adapters.npm import find_projects, purl
from guardian.core.config import REPO_ROOT
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.guardrails.network import check_url
from guardian.tools.registry import ToolContext, ToolOutput

# On-disk cache of {hook: command} per name@version (scoped names use "__" in place of "/").
CACHE = REPO_ROOT / "data" / "cache" / "intel" / "npm"
REGISTRY = "https://registry.npmjs.org"
# npm lifecycle scripts that run automatically on install (others, like "test", do not).
HOOKS = ("preinstall", "install", "postinstall")
_THROTTLE_S = 0.2  # pause after each registry call (public service, shared network)


def _registry_scripts(name: str, version: str, offline: bool, ctx: ToolContext | None = None) -> dict | None:
    """The install-hook scripts {hook: command} of name@version, from cache or the registry.
    Returns None when unknown (offline cache miss, HTTP error, non-200). {} means the version has no hooks.
    Side effect: writes the cache after a successful fetch."""
    path = CACHE / f"{name.replace('/', '__')}@{version}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if offline:
        return None
    url = check_url(f"{REGISTRY}/{quote(name, safe='@')}/{quote(version)}", ctx=ctx, agent="detection")  # G3.5
    try:
        r = httpx.get(url, timeout=10,
                      headers={"Accept": "application/json"})
        time.sleep(_THROTTLE_S)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    scripts = {k: v for k, v in (r.json().get("scripts") or {}).items() if k in HOOKS}
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scripts, indent=1), encoding="utf-8")
    return scripts


def _hits(lock_path: Path) -> list[tuple[str, str, bool, str]]:
    """[(name, version, dev, lockfile key)] for dependency entries with hasInstallScript.
    Workspace links and the root project entry are skipped."""
    packages = json.loads(lock_path.read_text(encoding="utf-8")).get("packages") or {}
    out = []
    for key, e in packages.items():
        if not key or not e.get("hasInstallScript") or "version" not in e or e.get("link"):
            continue  # key "" is the project itself (C7)
        # alias installs (npm:other@1) carry their real name in `name`; otherwise derive it from the lockfile path
        out.append((e.get("name") or key.rsplit("node_modules/", 1)[-1], e["version"], bool(e.get("dev")), key))
    return out


def detect(ctx: ToolContext) -> ToolOutput:
    """Findings for every dependency in every npm project's lockfile that declares an install script."""
    work = ctx.work_dir or ctx.repo
    seen: dict[str, Finding] = {}  # purl -> finding already raised (the same package can appear in several projects)
    findings, evidence = [], []
    for proj in find_projects(work):
        if not proj.lockfile.exists():
            continue
        rel = proj.lockfile.relative_to(work).as_posix()
        for name, version, dev, key in _hits(proj.lockfile):
            p = purl(name, version)
            if p in seen:  # same package in root and frontend: one finding, both projects in the evidence
                continue
            scripts = _registry_scripts(name, version, ctx.settings.offline, ctx)
            facts = {"package": name, "version": version, "purl": p, "has_install_script": True,
                     "lockfile_key": key, "project": proj.name, "dev": dev,
                     "hooks": sorted(scripts) if scripts else None,
                     "scripts_source": "registry.npmjs.org" if scripts is not None else "unavailable (offline/cache miss)"}
            excerpt = "\n".join(f"{k}: {v}" for k, v in (scripts or {}).items()) or None
            ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool="detector:install_scripts",
                          facts=facts, file_path=rel, excerpt=excerpt)
            evidence.append(ev)
            hooks = f" ({', '.join(sorted(scripts))})" if scripts else ""
            f = Finding(run_id=ctx.run_id, category=FindingCategory.INSTALL_SCRIPT,
                        title=f"Dependency {name}@{version} runs an install script{hooks}",
                        detector="detector:install_scripts", component_purl=p,
                        scope=Scope.DEV if dev else Scope.PROD, project=proj.name, file_path=rel,
                        evidence_ids=[ev.evidence_id])
            seen[p] = f
            findings.append(f)
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(findings)} dependencies with install scripts (not executed: --ignore-scripts)")
