"""D2-05 typosquat detector: direct dependency names close to popular packages (Dev4 similarity). Owner: Dev2.

Called by: the detection agent (tool `detector:typosquat`).
Why: attackers publish packages whose names differ from a popular one by a typo or an affix and wait for someone
to install them by mistake.
Inputs: every npm project's package.json (dependencies and devDependencies) plus legacy/backup manifests
(`ftp/package.json.bak`) that ship with the target, compared with detectors/similarity.check_name.
Registry check: a lookalike that the registry shows to be long established is cleared (see `established`):
>= 5 years old with >= 30 stable releases. The registry call is cached, throttled and G3.5-checked; offline with a
cache miss there is no registry data, so the name match stays a finding (we never clear on missing data).
Output: Finding category `typosquat` per suspect (scope dev for devDependencies else prod; no component_purl for
the legacy manifest). Evidence kind `detector_result`, facts {name, range, section, similar_to, distance, reason,
legacy_manifest}. One extra detector_result Evidence {cleared_as_established, rule} records every lookalike that
was cleared, so the decision not to flag is auditable.
"""

from __future__ import annotations

from pathlib import Path

from guardian.adapters.npm import find_projects, manifest_deps, purl
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.detectors.similarity import check_name
from guardian.tools.registry import ToolContext, ToolOutput

# Backup manifests shipped inside targets (old dependency lists attackers/benchmarks leave behind); also scanned.
LEGACY_MANIFESTS = ["ftp/package.json.bak"]
# A real lookalike is usually young or barely released; a package that is both old and heavily released is a
# legitimate project that happens to have a similar name (e.g. query-string vs querystring).
ESTABLISHED_YEARS = 5
ESTABLISHED_RELEASES = 30  # stable (non pre-release) versions published


def established(meta: dict | None) -> dict | None:
    """Registry facts showing a long-established package (e.g. `query-string`, 13 years and 93 releases, looks
    like `querystring`): a name match alone is not a typosquat then. Typosquats are young or barely released
    (`ngy-cookie`: 2 releases). No registry data -> None, and the name match stays a finding."""
    if not meta:
        return None
    from datetime import UTC, datetime

    created = (meta.get("time") or {}).get("created")
    try:
        years = (datetime.now(UTC) - datetime.fromisoformat(str(created).replace("Z", "+00:00"))).days / 365.25
    except ValueError:
        return None
    releases = sum(1 for v in meta.get("version_list") or [] if "-" not in v)
    if years >= ESTABLISHED_YEARS and releases >= ESTABLISHED_RELEASES:
        return {"age_years": round(years, 1), "stable_releases": releases}
    return None


def _scan(ctx: ToolContext, manifest: Path, rel: str, project: str, legacy: bool,
          cleared: list[dict]) -> tuple[list, list]:
    """Check every dependency of one manifest; returns (findings, evidence).
    `rel` is the repo-relative path shown in findings; `legacy` marks a backup manifest (no installed purl);
    `cleared` is appended to with lookalikes dismissed as established packages."""
    findings, evidence = [], []
    intel = None  # created lazily: most manifests have no suspect, so most runs never need the registry
    for name, rng, section, line in manifest_deps(manifest):
        hit = check_name(name)
        if not hit:
            continue
        if intel is None:
            from guardian.tools.threat_intel import IntelClient

            intel = IntelClient(ctx=ctx, agent="detection")  # cached, offline-safe, G3.5
        est = established(intel.registry_metadata(purl(name, "0")))
        if est:
            cleared.append({"name": name, "similar_to": hit.popular, **est, "file": rel})
            continue
        version = rng.lstrip("^~=<> ")  # best-effort purl version: the range with its operators stripped
        installed = None  # exact installed purl from the dependency graph, preferred when known
        if ctx.graph is not None and not legacy:
            installed = next((n for n, d in ctx.graph.g.nodes(data=True)
                              if d.get("label") == name and project in d.get("projects", [])), None)
        ev =Evidence(run_id=ctx.run_id, kind="detector_result", source_tool="detector:typosquat",
                      facts={"name": name, "range": rng, "section": section, "similar_to": hit.popular,
                             "distance": hit.distance, "reason": hit.reason, "legacy_manifest": legacy},
                      file_path=rel, line=line, excerpt=f'"{name}": "{rng}"')
        evidence.append(ev)
        where = "legacy backup manifest" if legacy else section
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.TYPOSQUAT,
            title=f"Possible typosquat '{name}' (looks like '{hit.popular}') in {where}",
            detector="detector:typosquat", component_purl=None if legacy else (installed or purl(name, version)),
            scope=Scope.DEV if section == "devDependencies" else Scope.PROD, project=project,
            file_path=rel, line=line, evidence_ids=[ev.evidence_id]))
    return findings, evidence


def detect(ctx: ToolContext) -> ToolOutput:
    """Scan all npm projects and the legacy manifests; report suspects and the lookalikes cleared as established."""
    work = ctx.work_dir or ctx.repo
    findings, evidence, cleared = [], [], []
    for proj in find_projects(work):
        f, e = _scan(ctx, proj.manifest, proj.manifest.relative_to(work).as_posix(), proj.name, legacy=False,
                     cleared=cleared)
        findings += f
        evidence += e
    for rel in LEGACY_MANIFESTS:
        path = work / rel
        if path.exists():
            f, e = _scan(ctx, path, rel, "root", legacy=True, cleared=cleared)
            findings += f
            evidence += e
    if cleared:  # the decision not to flag is recorded too, with its registry facts
        evidence.append(Evidence(run_id=ctx.run_id, kind="detector_result", source_tool="detector:typosquat",
                                 facts={"cleared_as_established": cleared,
                                        "rule": f">= {ESTABLISHED_YEARS} years and >= {ESTABLISHED_RELEASES} stable releases"}))
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(findings)} typosquat suspects" + (f", {len(cleared)} lookalikes cleared as "
                                                                        f"established packages" if cleared else ""))
