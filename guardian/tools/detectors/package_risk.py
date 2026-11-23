"""D4-10 advanced package risk detectors (registry metadata, offline-safe). Owner: Dev1 (ported from dev04).

One tool, four rules, each capped (guardian.yaml thresholds.package_risk_max_findings, default 15):
maintainer change, unusual release activity, dependency confusion, provenance gap.
Only DIRECT PROD dependencies are looked up (thresholds.package_risk_max_packages, default 80); internal-scope
names are checked in every dependency section. Registry calls go through IntelClient (G3.5, cache, throttle);
with GUARDIAN_OFFLINE=1 only the cache is read and a miss simply yields no finding.
"""
from __future__ import annotations

from guardian.adapters import npm
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools import package_risk as pr
from guardian.tools.policy import load_config
from guardian.tools.registry import ToolContext, ToolOutput
from guardian.tools.threat_intel import IntelClient

DETECTOR = "detector:package_risk"


def _installed(ctx: ToolContext) -> dict[str, str]:
    g = getattr(ctx.graph, "g", None)
    if g is None:
        return {}
    return {d["label"]: n for n, d in g.nodes(data=True) if d.get("kind") == "package" and d.get("label")}


def detect(ctx: ToolContext) -> ToolOutput:
    cfg = ctx.artifacts.get("guardian_config") or load_config()
    thr = cfg.get("thresholds", {})
    cap = int(thr.get("package_risk_max_findings", 15))
    max_pkgs = int(thr.get("package_risk_max_packages", 80))
    internal = list(cfg.get("internal_scopes") or [])
    root = ctx.work_dir or ctx.repo
    intel = IntelClient(ctx=ctx, agent="detection")
    installed = _installed(ctx)

    direct: dict[str, tuple[str, str, int, str]] = {}  # name -> (range, manifest rel, line, project)
    internal_names: dict[str, tuple[str, str, int, str]] = {}
    for proj in npm.find_projects(root):
        rel = proj.manifest.relative_to(root).as_posix()
        try:
            deps = npm.manifest_deps(proj.manifest)
        except (ValueError, OSError):
            continue
        for name, rng, section, line in deps:
            if pr.matches_internal(name, internal):
                internal_names.setdefault(name, (rng, rel, line, proj.name))
            if section == "dependencies":
                direct.setdefault(name, (rng, rel, line, proj.name))

    def purl_of(name: str, rng: str) -> str:
        return installed.get(name) or npm.purl(name, rng.lstrip("^~=<> ") or "0")

    names = sorted(direct)[:max_pkgs]
    by_purl = {purl_of(n, direct[n][0]): n for n in names}
    metas: dict[str, dict] = {}  # purl -> trimmed packument
    for purl, name in by_purl.items():
        meta = intel.registry_metadata(npm.purl(name, "0"))
        if meta:
            metas[purl] = meta

    findings: list[Finding] = []
    evidence: list[Evidence] = []

    def emit(category: FindingCategory, name: str, purl: str, title: str, facts: dict, where) -> None:
        rng, rel, line, project = where
        ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool=DETECTOR,
                      facts={"name": name, "purl": purl, **facts}, file_path=rel, line=line,
                      excerpt=f'"{name}": "{rng}"')
        evidence.append(ev)
        findings.append(Finding(run_id=ctx.run_id, category=category, title=title, detector=DETECTOR,
                                component_purl=purl, scope=Scope.PROD, project=project, file_path=rel, line=line,
                                evidence_ids=[ev.evidence_id]))

    counts = {"maintainer_change": 0, "release_activity": 0, "dependency_confusion": 0, "provenance_gap": 0}
    for purl, meta in metas.items():
        name = by_purl[purl]
        where = direct[name]
        mf = pr.maintainer_facts(meta)
        if mf and counts["maintainer_change"] < cap:
            counts["maintainer_change"] += 1
            emit(FindingCategory.MAINTAINER_CHANGE, name, purl,
                 f"{name}: maintainer set changed in latest release ({meta.get('latest')})",
                 {"rule": "maintainer_change", **mf}, where)
        acts = pr.release_activity(meta, thr)
        if acts and counts["release_activity"] < cap:
            counts["release_activity"] += 1
            emit(FindingCategory.MAINTAINER_CHANGE, name, purl,
                 f"{name}: unusual release activity ({', '.join(a['rule'] for a in acts)})",
                 {"rule": "release_activity", "signals": acts}, where)
    for purl, gap in pr.provenance_gaps(metas).items():
        if counts["provenance_gap"] >= cap:
            break
        counts["provenance_gap"] += 1
        name = by_purl[purl]
        emit(FindingCategory.PROVENANCE_GAP, name, purl,
             f"{name}: provenance gap ({', '.join(gap['reasons'])})", {"rule": "provenance_gap", **gap}, direct[name])
    for name in sorted(internal_names)[:cap * 2]:
        if counts["dependency_confusion"] >= cap:
            break
        facts = pr.confusion_facts(intel.registry_metadata(npm.purl(name, "0")))
        if facts is None:
            continue
        counts["dependency_confusion"] += 1
        emit(FindingCategory.DEPENDENCY_CONFUSION, name, purl_of(name, internal_names[name][0]),
             f"{name} is an internal name that also exists on the public registry",
             {"rule": "dependency_confusion", **facts, "internal_scopes": internal}, internal_names[name])
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(metas)}/{len(names)} direct prod packages with registry metadata; "
                              f"findings {counts}")
