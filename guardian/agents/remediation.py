"""Remediation agent (Day-1 form): build one concrete, evidence-backed plan per attempt. Owner: Dev1.

Deterministic on purpose for Day 1: candidates come from the finding's evidence (similar-name evidence for a
typosquat, the workflow line for an action, the resolved lockfile for a missing lockfile) and every target
(replacement name, commit SHA, lockfile) is itself evidence (G4.5). The LLM choice between candidates and the
CVE upgrade path are D1-07 (Day 2). A retry never repeats an earlier plan for the same finding: after a reject
or a failed validation the next candidate is used, and when none is left the finding is escalated (G5.4).

CVE findings get upgrade candidates (D1-07): `safe_version_lookup` (OSV + scanner fixed versions + registry latest)
and `compat_hint` evidence. A direct dependency is moved to a fixed version (lowest first, then later ones on
retry); a transitive one is fixed by upgrading its direct parent. `target_version` must appear in the
safe_version_lookup evidence the plan cites (G4.5, enforced in `build_plan`). When no untried candidate is left
the finding is escalated. `expected_risk_reduction` comes from `scoring.simulate_after`, never from an LLM.

Heuristic findings (typosquat, malicious indicator) only get replace / remove / block / escalate (G5.3).
Base images tagged without a digest (UNTRUSTED_IMAGE, D2-07b) get `pin` (digest from `resolve_image_digest`
evidence) and, only when the finding's evidence lists a newer tag (`newer_tags`), `update_base_image`; the digest,
the new tag and a blocked package name are checked against evidence in `build_plan` (G4.5).
A CVE with no upgrade candidate whose package is never imported (risk factor R = not_imported) gets a no-op
`mitigate` plan: it changes nothing, does not claim a fix, and once approved the finding is recorded as ACCEPTED
(validator verdict "mitigated"); the report lists it as remaining, accepted risk.
The plan, its dry-run diff and its hash are fixed *before* the human gate (C6), so the approval binds to the
exact change that will be applied.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from guardian.core.models import (
    Claim,
    ClaimLabel,
    CompatHint,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    PatchOp,
    RemediationPlan,
    new_id,
)
from guardian.core.plans import list_plans, load_risks, save_plan, set_pending
from guardian.core.scoring import simulate_after
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import plan_hash
from guardian.guardrails.grounding import value_matches
from guardian.tools.registry import call_tool
from guardian.tools.threat_intel import parse_purl, version_key

AGENT = "remediation"
MAX_ATTEMPTS = 3  # G5.4
HEURISTIC_ACTIONS = {"replace", "remove", "block", "escalate"}  # G5.3
HEURISTIC = {FindingCategory.TYPOSQUAT, FindingCategory.MALICIOUS_INDICATOR, FindingCategory.DEPENDENCY_CONFUSION}


@dataclass
class Candidate:
    action: str
    ops: list[PatchOp]
    target: str | None
    claims: list[tuple[str, str | None, str | None]]  # (text, field, value) citing the finding's evidence
    detector: str
    evidence_ids: list[str] = field(default_factory=list)
    sha_lookup: tuple[str, str] | None = None  # (action, ref) resolved just before the plan is fixed
    image: dict | None = None  # {file, image, tag, new_tag?}: digest resolved just before the plan is fixed
    compat: CompatHint | None = None


def ops_key(ops: list[PatchOp]) -> str:
    return json.dumps([o.model_dump(mode="json") for o in ops], sort_keys=True)


def _facts(rc: RunContext, f: Finding) -> tuple[dict, Evidence | None]:
    for eid in f.evidence_ids:
        ev = rc.store.get_evidence(eid)
        if ev is not None:
            return ev.facts, ev
    return {}, None


def _manifest_declares(rc: RunContext, rel: str, name: str) -> bool:
    try:
        text = (rc.tool_ctx.repo / rel).read_text(encoding="utf-8")
    except OSError:
        return False
    return re.search(rf'"{re.escape(name)}"\s*:\s*"', text) is not None


def _lookup(rc: RunContext, purl: str, vuln_ids: list[str], fixed: list[str], *, child: str | None = None,
            child_fixed: str | None = None) -> Evidence | None:
    ctx = rc.tool_ctx
    args = {"purl": purl, "vuln_ids": vuln_ids[:50], "scanner_fixed": fixed[:50]}
    if child and child_fixed:
        args |= {"child": child, "child_fixed": child_fixed}
    out = call_tool(AGENT, "safe_version_lookup", None, ctx, rc.store, rc.audit, args=args)
    return out.evidence[0] if out and out.evidence else None


def _compat(rc: RunContext, purl: str, cur: str, to: str) -> Evidence | None:
    out = call_tool(AGENT, "compat_hint", None, rc.tool_ctx, rc.store, rc.audit,
                    args={"purl": purl, "from_version": cur, "to_version": to})
    return out.evidence[0] if out and out.evidence else None


def _upgrade(rc: RunContext, f: Finding, purl: str, pkg_file: str, why: list, lookup: Evidence, target: str,
             *, via: str | None = None, op: str = "set_dependency_version", spec: str = "^") -> Candidate | None:
    name, cur, _ = parse_purl(purl)
    compat = _compat(rc, purl, cur or "0.0.0", target)
    claims = list(why)
    claims.append((f"{target} is a candidate version from safe_version_lookup", "candidates", target))
    ev_ids = [lookup.evidence_id]
    hint = None
    if compat is not None:
        ev_ids.append(compat.evidence_id)
        fx = compat.facts
        hint = CompatHint(from_version=fx["from_version"], to_version=fx["to_version"], semver_delta=fx["semver_delta"],
                          engines_ok=fx.get("engines_ok"), peer_dep_changes=fx.get("peer_dep_changes", []),
                          deprecated_target=fx.get("deprecated_target"), level=fx["level"])
        claims.append((f"{name} {cur} -> {target} is a {fx['semver_delta']} version change "
                       f"(compatibility risk {fx['level']})", "semver_delta", fx["semver_delta"]))
    if via:
        claims.append((f"the vulnerable package is transitive; upgrading its direct parent {via} is not proven "
                       f"to pull a fixed version until the sandbox rebuild and rescan", None, None))
    version = f"{spec}{target}" if spec != "==" else target
    return Candidate("upgrade", [PatchOp(op=op, file_path=pkg_file, args={"name": name, "version": version})],
                     target, claims, "scanner re-scan", evidence_ids=ev_ids, compat=hint)


def cve_candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    """Upgrade candidates, safest first. Direct dependency: each fixed version; transitive: the direct parent."""
    purl = f.component_purl
    if purl and purl.startswith("pkg:pypi/"):
        return pip_candidates(rc, f)
    if not purl or not purl.startswith("pkg:npm/"):
        return []
    name, cur, _ = parse_purl(purl)
    pkg_file = "package.json" if f.project in (None, "root") else f"{f.project}/package.json"
    ids = [i for i in [f.vuln_id, *f.aliases] if i]
    out: list[Candidate] = []
    direct = any(len(p) == 2 for p in f.dependency_paths) or not f.dependency_paths
    if direct and _manifest_declares(rc, pkg_file, name):
        lk = _lookup(rc, purl, ids, f.fixed_versions)
        if lk is not None:
            # checkable against the scanner evidence (vuln_id), so grounding can mark it a verified fact
            why = [(f"{f.vuln_id} affects {name} {cur}; affected range {lk.facts.get('affected_range') or f.affected_range}",
                    "vuln_id", f.vuln_id)]
            for v in lk.facts.get("candidates", []):
                c = _upgrade(rc, f, purl, pkg_file, why, lk, v)
                if c:
                    out.append(c)
        return out
    for path in f.dependency_paths:
        if len(path) < 3 or not path[1].startswith("pkg:npm/"):
            continue
        parent = path[1]
        pname, pcur, _ = parse_purl(parent)
        if not _manifest_declares(rc, pkg_file, pname):
            continue
        child_fixed = min(f.fixed_versions, key=version_key) if f.fixed_versions else None
        lk = _lookup(rc, parent, [], [], child=name if child_fixed else None, child_fixed=child_fixed)
        if lk is None:
            continue
        why = [(f"{f.vuln_id} affects {name} {cur}, which is pulled in by {pname} {pcur}", "vuln_id", f.vuln_id)]
        ranges = lk.facts.get("child_ranges") or {}
        # safest first: the smallest parent upgrade whose dependency range provably excludes the vulnerable
        # child; then the parent's registry latest. A failed attempt moves on to the next (G5.4: max 3).
        order = [*lk.facts.get("pulls_fixed_child", []), *lk.facts.get("candidates", [])[-1:]]
        for v in dict.fromkeys(order):
            extra = []
            if v in ranges:
                extra.append((f"{pname} {v} depends on {name} {ranges[v]}, whose lowest allowed version is at or "
                              f"above the fixed {child_fixed}", "child_ranges", ranges[v]))
            c = _upgrade(rc, f, parent, pkg_file, why + extra, lk, v, via=None if v in ranges else pname)
            if c and ops_key(c.ops) not in {ops_key(o.ops) for o in out}:
                out.append(c)
    return out


def _requirement_pins(rc: RunContext, rel: str, name: str) -> str | None:
    """The exact `==` pin of `name` in requirements file `rel`, or None if it is not pinned there."""
    from guardian.adapters.pypi import requirement_pins

    try:
        pins = requirement_pins(confined_path(rc, rel))
    except (OSError, ValueError):
        return None
    norm = re.sub(r"[-_.]+", "-", name).lower()
    return next((v for n, v, _s, _l in pins if re.sub(r"[-_.]+", "-", n).lower() == norm and v), None)


def confined_path(rc: RunContext, rel: str):
    from guardian.tools.patching import confined

    return confined(rc.tool_ctx.repo, rel)


def pip_candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    """pip: every package in requirements*.txt is pinned directly, so the fix is a new `==` pin in the file the
    scanner located, at a version from safe_version_lookup evidence (G4.5), lowest fixing version first."""
    name, cur, _ = parse_purl(f.component_purl)
    rel = (f.file_path or "").replace("\\", "/")
    if not rel.endswith(".txt") or _requirement_pins(rc, rel, name) is None:
        return []
    ids = [i for i in [f.vuln_id, *f.aliases] if i]
    lk = _lookup(rc, f.component_purl, ids, f.fixed_versions)
    if lk is None:
        return []
    why = [(f"{f.vuln_id} affects {name} {cur}, pinned in {rel}", "vuln_id", f.vuln_id)]
    out = []
    for v in lk.facts.get("candidates", []):
        c = _upgrade(rc, f, f.component_purl, rel, why, lk, v, op="set_requirement_version", spec="==")
        if c:
            out.append(c)
    return out


def _pname(f: Finding) -> str | None:
    try:
        return parse_purl(f.component_purl)[0] if f.component_purl else None
    except ValueError:  # e.g. an image reference, not a purl
        return None


def mitigation_candidate(rc: RunContext, f: Finding) -> Candidate | None:
    """No upgrade exists and the package is never imported in production paths: a no-op, explicitly-not-a-fix
    plan a human can accept. Needs the reachability evidence the risk analyst cited for factor R."""
    risk = load_risks(rc.tool_ctx.run_dir).get(f.finding_id)
    if risk is None or risk.factors.R.tier != "not_imported" or not risk.factors.R.evidence_ids:
        return None
    name = parse_purl(f.component_purl)[0] if f.component_purl else "the package"
    return Candidate("mitigate", [], None,
                     [(f"{name} is not imported in production paths (reachability tier not_imported)", "tier",
                       "not_imported"),
                      ("no fixed version could be taken from safe_version_lookup evidence, so nothing is upgraded",
                       None, None),
                      ("the vulnerable package stays installed: this accepts the risk, it does not fix it", None,
                       None)],
                     "scanner re-scan", evidence_ids=list(risk.factors.R.evidence_ids))


def _image_candidates(f: Finding, facts: dict) -> list[Candidate]:
    image, raw_tag = facts.get("image"), str(facts.get("tag") or "latest")
    if not image or not f.file_path:
        return []
    tag = "latest" if raw_tag.startswith("latest") else raw_tag
    why = [(f"{image}:{tag} is referenced by tag only in {f.file_path}", "tag", raw_tag),
           ("a tag can be re-pointed by whoever controls the registry repository, a digest cannot", None, None)]
    out = [Candidate("pin", [], None, why, "detector:image_pin",
                     image={"file": f.file_path, "image": image, "tag": tag})]
    newer = facts.get("newer_tags") or ([facts["newer_tag"]] if facts.get("newer_tag") else [])
    for nt in [str(t) for t in newer][:2]:  # only tags a tool put into the evidence (G4.5)
        out.append(Candidate("update_base_image", [], nt,
                             [*why, (f"{image}:{nt} is a newer tag listed in the finding's evidence", "newer_tags", nt)],
                             "detector:image_pin", image={"file": f.file_path, "image": image, "tag": tag,
                                                          "new_tag": nt}))
    return out


SOURCE_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def importing_files(repo, manifest_rel: str, name: str, limit: int = 500) -> list[str]:
    """Source files of the manifest's project that import `name` (tests included: they must still compile)."""
    from pathlib import Path

    from guardian.tools.patching import _module_spec

    root = Path(repo)
    project = (root / manifest_rel).parent
    pat = re.compile(_module_spec(name), re.M)
    out = []
    for p in sorted(project.rglob("*")):
        rel = p.relative_to(root)
        if p.suffix not in SOURCE_EXT or not p.is_file() or "node_modules" in rel.parts or "dist" in rel.parts:
            continue
        try:
            if pat.search(p.read_text(encoding="utf-8", errors="replace")):
                out.append(rel.as_posix())
        except OSError:
            continue
        if len(out) >= limit:
            break
    return out


def candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    facts, _ = _facts(rc, f)
    out: list[Candidate] = []
    if f.category is FindingCategory.CVE:
        out = cve_candidates(rc, f)
        if not out and (m := mitigation_candidate(rc, f)):
            out.append(m)
        return out
    if f.category is FindingCategory.UNTRUSTED_IMAGE:
        return _image_candidates(f, facts)
    pname = facts.get("name") or (_pname(f))
    if f.category in (FindingCategory.TYPOSQUAT, FindingCategory.MALICIOUS_INDICATOR) and pname and f.file_path:
        name, popular = pname, facts.get("similar_to")
        why = (f"'{name}' differs from the popular package '{popular}' by {facts.get('distance')} edit(s)",
               "similar_to", popular) if f.category is FindingCategory.TYPOSQUAT else (
            f"'{name}' was flagged by {f.detector}: {f.title[:100]}", None, None)
        renames: list[str] = []
        if popular and not facts.get("legacy_manifest"):
            renames = importing_files(rc.tool_ctx.repo, f.file_path, name)
        from guardian.tools.patching import MAX_PLAN_OPS

        if popular and not facts.get("legacy_manifest") and len(renames) < MAX_PLAN_OPS:
            # never a partial rename: more importing files than one plan may hold -> no replace candidate
            out.append(Candidate("replace", [PatchOp(op="replace_dependency", file_path=f.file_path,
                                                     args={"name": name, "new_name": popular}),
                                             *(PatchOp(op="rename_import", file_path=r,
                                                       args={"name": name, "new_name": popular}) for r in renames)],
                                 popular, [why, (f"declared in {f.file_path} as {facts.get('range')}", "range",
                                                 facts.get("range")),
                                           (f"version range {facts.get('range')} is kept; API compatibility of "
                                            f"'{popular}' is not verified until the sandbox build (Day 2)", None,
                                            None)],
                                 "detector:typosquat"))
        out.append(Candidate("remove", [PatchOp(op="remove_dependency", file_path=f.file_path, args={"name": name})],
                             None, [why, ("removing it drops the suspicious package from the manifest; code that "
                                          "imports it would break", None, None)], "detector:typosquat"))
        out.append(Candidate("block", [PatchOp(op="block_package", file_path=f.file_path, args={"name": name})],
                             None, [why, ("the name is removed from the manifest and added to "
                                          ".guardian/denylist.txt so it is not reinstalled", None, None)],
                             "detector:typosquat"))
    elif f.category is FindingCategory.LOCKFILE:
        projects = sorted({"root", *facts.get("projects_without_lockfile", [])} if facts.get("projects_without_lockfile")
                          else {"root"})
        out.append(Candidate("pin", [PatchOp(op="generate_lockfile", file_path=".npmrc", args={"projects": projects})],
                             None, [("lockfile generation is disabled in .npmrc", "package_lock_disabled", "True"),
                                    ("lockfiles come from discovery's npm install --package-lock-only "
                                     "--ignore-scripts, so no install script ran to produce them", None, None)],
                             "detector:lockfile"))
    elif f.category is FindingCategory.UNPINNED_CI and facts.get("action") and facts.get("ref"):
        out.append(Candidate("pin", [], None,
                             [(f"{facts['action']} is referenced by the mutable ref {facts['ref']}", "ref", facts["ref"]),
                              ("a commit SHA cannot be moved by the action's owner, a tag can", None, None)],
                             "detector:ci_pin", sha_lookup=(facts["action"], facts["ref"])))
    if f.category in HEURISTIC:
        out = [c for c in out if c.action in HEURISTIC_ACTIONS]
    return out


def _claims(rc: RunContext, f: Finding, cand: Candidate, extra: list[str]) -> list[Claim]:
    cited = [e for e in (rc.store.get_evidence(i) for i in [*f.evidence_ids, *extra]) if e]
    out = []
    for text, fld, value in cand.claims:
        label = ClaimLabel.VERIFIED if value is not None and value_matches(cited, fld, str(value)) else ClaimLabel.INFERRED
        out.append(Claim(text=text, field=fld, value=None if value is None else str(value),
                         evidence_ids=[e.evidence_id for e in cited], label=label))
    return out


def ungrounded_target(rc: RunContext, f: Finding, ops: list[PatchOp], evidence_ids: list[str]) -> str | None:
    """G4.5 for image and block ops: why a digest, tag or package name is not backed by tool evidence, else None."""
    cited = [e for e in (rc.store.get_evidence(i) for i in dict.fromkeys([*f.evidence_ids, *evidence_ids])) if e]
    own = [e for e in (rc.store.get_evidence(i) for i in f.evidence_ids) if e]
    for o in ops:
        a = o.args
        if o.op in ("pin_image_digest", "update_base_image"):
            want_tag = a.get("new_tag") or a.get("tag")
            if not any(e.kind == "registry_metadata" and e.source_tool != "git ls-remote"
                       and e.facts.get("digest") == a.get("digest") and e.facts.get("image") == a.get("image")
                       and e.facts.get("tag") == want_tag for e in cited):
                return f"digest {a.get('digest')} for {a.get('image')}:{want_tag} is not in resolve_image_digest evidence"
            if o.op == "update_base_image":
                newer = {str(t) for e in own for t in [*(e.facts.get("newer_tags") or []), e.facts.get("newer_tag")] if t}
                if a.get("new_tag") not in newer:
                    return f"new tag {a.get('new_tag')} is not listed in the finding's evidence"
        elif o.op == "block_package":
            names = {e.facts.get("name") for e in own} | {_pname(f)}
            if a.get("name") not in names:
                return f"package {a.get('name')} to block is not the one in the finding's evidence"
    return None


def _files_phrase(files: list[str]) -> str:
    """'a and b', or 'frontend/package.json and 35 source files' for a long list (the diff lists them all)."""
    if len(files) <= 3:
        return ", ".join(files)
    manifests = [f for f in files if f.endswith(("package.json", "requirements.txt", "Dockerfile", ".yml", ".yaml"))]
    rest = len(files) - len(manifests)
    return (", ".join(manifests) + (" and " if manifests else "")) + f"{rest} source files (listed in the diff)"


def build_plan(rc: RunContext, f: Finding, cand: Candidate, attempt: int) -> RemediationPlan | None:
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    extra: list[str] = list(cand.evidence_ids)
    if cand.action == "upgrade":  # G4.5: the target version must come from safe_version_lookup evidence
        allowed = {v for i in cand.evidence_ids if (e := store.get_evidence(i)) and e.kind == "osv"
                   for v in e.facts.get("candidates", [])}
        if cand.target not in allowed:
            audit.emit("guardrail", "guardrail", f"G4.5 blocked upgrade target {cand.target}: not in "
                       f"safe_version_lookup evidence", finding_id=f.finding_id, data={"rule": "G4.5"})
            return None
    ops = list(cand.ops)
    target = cand.target
    if cand.sha_lookup:
        action, ref = cand.sha_lookup
        out = call_tool(AGENT, "resolve_action_sha", None, ctx, store, audit, args={"action": action, "ref": ref})
        if out is None:
            return None
        sha = out.artifacts["action_sha"]
        target = sha
        extra.append(out.evidence[0].evidence_id)
        ops = [PatchOp(op="pin_action_sha", file_path=f.file_path, args={"action": action, "ref": ref, "sha": sha})]
        cand.claims.append((f"{action}@{ref} currently resolves to commit {sha}", "sha", sha))
    if cand.image:
        img = cand.image
        new_tag = img.get("new_tag")
        out = call_tool(AGENT, "resolve_image_digest", None, ctx, store, audit,
                        args={"image": img["image"], "tag": new_tag or img["tag"]})
        if out is None:
            return None
        digest = out.artifacts["image_digest"]
        extra.append(out.evidence[0].evidence_id)
        a = {"image": img["image"], "tag": img["tag"], "digest": digest}
        if new_tag:
            ops = [PatchOp(op="update_base_image", file_path=img["file"], args={**a, "new_tag": new_tag})]
            target = f"{new_tag}@{digest}"
        else:
            ops = [PatchOp(op="pin_image_digest", file_path=img["file"], args=a)]
            target = digest
        cand.claims.append((f"{img['image']}:{new_tag or img['tag']} currently resolves to {digest}", "digest", digest))
    why = ungrounded_target(rc, f, ops, extra)
    if why:
        audit.emit("guardrail", "guardrail", f"G4.5 blocked {cand.action}: {why}",
                   finding_id=f.finding_id, data={"rule": "G4.5"})
        return None
    plan_id = new_id("pl")
    if ops:
        preview = call_tool(AGENT, "plan_preview", None, ctx, store, audit,
                            args={"plan_id": plan_id, "ops": [o.model_dump(mode="json") for o in ops]})
        if preview is None:
            return None
        extra.append(preview.evidence[0].evidence_id)
    files = sorted({o.file_path for o in ops})
    before = load_risks(rc.tool_ctx.run_dir).get(f.finding_id)
    after_score, after_band = simulate_after(before, cand.action)
    reduction = (f"score {before.score} ({before.band.value}) -> {after_score} ({after_band.value}) once the "
                 f"patched copy re-scans clean (simulate_after, section 7)" if before else
                 f"{f.initial_risk.value if f.initial_risk else 'unknown'} -> resolved if {cand.detector} no longer "
                 f"reports it on the patched copy")
    plan = RemediationPlan(
        plan_id=plan_id, plan_hash="", finding_id=f.finding_id, attempt=attempt, action=cand.action, ops=ops,
        target_version=target, rationale=_claims(rc, f, cand, extra),
        expected_risk_reduction=reduction, compatibility_impact=cand.compat,
        rollback=(f"Nothing is applied to the target: the patch lands in a fresh copy under runs/<run>/attempts/. "
                  f"Discard that folder to roll back; after adoption, revert the diff of {_files_phrase(files)}."
                  if files else "Nothing is changed by this plan. Re-open the finding to withdraw the acceptance."),
        evidence_ids=[*f.evidence_ids, *extra],
    )
    plan.plan_hash = plan_hash(plan)
    return plan


def remediation_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    store, audit = rc.store, rc.audit
    queue = list(state.get("plan_queue") or [])
    current, attempt = state.get("current"), state.get("attempt") or 0
    if current is None:
        if not queue:
            return {"route": "next", "plan_id": None}
        current, attempt = queue.pop(0), 0
    f = store.get_finding(current)
    attempt += 1
    audit.emit(AGENT, "agent_start", f"Planning attempt {attempt} for: {f.title[:90]}", finding_id=f.finding_id,
               evidence_ids=f.evidence_ids,
               data={"last_validation": state.get("last_validation")} if state.get("last_validation") else {})

    mine = [p for p in list_plans(rc.tool_ctx.run_dir) if p.finding_id == f.finding_id]
    tried = {ops_key(p.ops) for p in mine}
    tried_noop = {p.action for p in mine if not p.ops}  # a rejected mitigation is not offered again
    plan = None
    if attempt <= MAX_ATTEMPTS:
        for cand in candidates(rc, f):
            if cand.ops and ops_key(cand.ops) in tried:
                continue
            if not cand.ops and cand.action in tried_noop:
                continue
            plan = build_plan(rc, f, cand, attempt)
            if plan is not None and ops_key(plan.ops) in tried:  # resolved to an op we already tried
                plan = None
                continue
            if plan is not None:
                break
    if plan is None:
        f.status = FindingStatus.ESCALATED
        store.update_finding(f)
        why = "attempt limit reached (G5.4)" if attempt > MAX_ATTEMPTS else "no untried safe plan left"
        audit.emit("supervisor", "decision", f"Escalated for security review: {f.title[:80]} ({why})",
                   finding_id=f.finding_id)
        return {"plan_queue": queue, "current": None, "attempt": 0, "plan_id": None, "route": "next",
                "last_validation": None}

    save_plan(rc.tool_ctx.run_dir, plan)
    set_pending(rc.tool_ctx.run_dir, plan)
    f.status = FindingStatus.AWAITING_HUMAN
    store.update_finding(f)
    verified = sum(1 for c in plan.rationale if c.label is ClaimLabel.VERIFIED)
    audit.emit(AGENT, "agent_end", f"Plan {plan.plan_id}: {plan.action} ({len(plan.ops)} ops, {verified} verified / "
                                   f"{len(plan.rationale) - verified} inferred claims)",
               finding_id=f.finding_id, evidence_ids=plan.evidence_ids,
               data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "action": plan.action,
                     "target": plan.target_version})
    audit.emit("human_gate", "gate_wait", f"Waiting for a human decision on plan {plan.plan_id} "
                                         f"(guardian decide --run {state['run_id']} --plan {plan.plan_id} ...)",
               finding_id=f.finding_id, data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    return {"plan_queue": queue, "current": current, "attempt": attempt, "plan_id": plan.plan_id,
            "decision": None, "route": "gate"}
