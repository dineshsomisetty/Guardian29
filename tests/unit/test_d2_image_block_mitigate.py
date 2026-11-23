"""D2-07b/D2-08/D2-10: image + block patch ops, digest lookup, remediation candidates (pin / update_base_image /
block / mitigate), integration-test phase, built-artifact rescan, validator mitigation. No Docker, no network."""

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from guardian.agents import remediation as rem
from guardian.agents import risk_analyst as ra
from guardian.agents.validator import validator_node
from guardian.core.models import (
    Approval,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    PatchOp,
    RiskAssessment,
    Scope,
)
from guardian.core.plans import list_plans, list_validations, load_plan, save_risks
from guardian.core.scoring import compute, factor, simulate_after
from guardian.guardrails.network import NetworkBlocked
from guardian.reporting.build import build_report
from guardian.tools import patching, sandbox
from guardian.tools.patching import ImageArgs, PatchError, apply_ops, resolve_image_digest
from guardian.tools.registry import ToolContext
from tests.unit.test_risk_remediation import PURL, RUN, cve, rc  # noqa: F401
from tests.unit.test_sandbox import FakeDocker, ctx_for, use, work  # noqa: F401

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64


def op(kind, file_path, **args):
    return PatchOp(op=kind, file_path=file_path, args=args)


def apply_one(root: Path, text: str, name: str, o: PatchOp) -> str:
    (root / name).write_text(text, encoding="utf-8", newline="")
    apply_ops(root, [o], None, write=True)
    return (root / name).read_bytes().decode("utf-8")


# ---------------------------------------------------------------- patch ops


def test_pin_image_digest_touches_only_matching_from_lines(tmp_path):
    before = ("FROM node:24 AS installer\nRUN x\nFROM --platform=linux/amd64 node:24\n"
              f"FROM node:24@{D2}\nFROM installer\nFROM node:240\nFROM alpine\n")
    after = apply_one(tmp_path, before, "Dockerfile", op("pin_image_digest", "Dockerfile", image="node", tag="24",
                                                         digest=D1))
    b, a = before.splitlines(), after.splitlines()
    assert [i for i in range(len(b)) if a[i] != b[i]] == [0, 2]
    assert a[0] == f"FROM node:24@{D1} AS installer" and a[2] == f"FROM --platform=linux/amd64 node:24@{D1}"
    # an implicit tag is :latest
    out = apply_one(tmp_path, "FROM alpine\n", "Dockerfile", op("pin_image_digest", "Dockerfile", image="alpine",
                                                               tag="latest", digest=D1))
    assert out == f"FROM alpine:latest@{D1}\n"


def test_pin_image_digest_compose_and_errors(tmp_path):
    text = "services:\n  web:\n    image: \"node:24\" # base\n  db:\n    image: postgres:16\n"
    out = apply_one(tmp_path, text, "docker-compose.yml",
                    op("pin_image_digest", "docker-compose.yml", image="node", tag="24", digest=D1))
    assert f'image: "node:24@{D1}" # base' in out and "image: postgres:16\n" in out
    with pytest.raises(PatchError, match="not found"):
        apply_ops(tmp_path, [op("pin_image_digest", "docker-compose.yml", image="redis", tag="7", digest=D1)], None, True)
    for bad in ("sha256:abc", f"{D1};rm -rf /", "latest"):
        with pytest.raises(PatchError, match="digest"):
            apply_ops(tmp_path, [op("pin_image_digest", "docker-compose.yml", image="node", tag="24", digest=bad)],
                      None, True)


def test_update_base_image_bumps_tag_and_pins_new_digest(tmp_path):
    out = apply_one(tmp_path, "FROM node:20-slim\nCMD x\n", "Dockerfile",
                    op("update_base_image", "Dockerfile", image="node", tag="20-slim", new_tag="22-slim", digest=D2))
    assert out == f"FROM node:22-slim@{D2}\nCMD x\n"
    with pytest.raises(PatchError, match="new_tag"):
        apply_ops(tmp_path, [op("update_base_image", "Dockerfile", image="node", tag="22-slim", new_tag="22-slim",
                                digest=D2)], None, True)


def test_block_package_removes_dependency_and_writes_denylist(tmp_path):
    pkg = '{\n  "dependencies": {\n    "express": "^4",\n    "ngy-cookie": "^6.0.0"\n  }\n}\n'
    (tmp_path / "package.json").write_text(pkg)
    res = apply_ops(tmp_path, [op("block_package", "package.json", name="ngy-cookie")], None, write=True)
    assert "ngy-cookie" not in (tmp_path / "package.json").read_text()
    json.loads((tmp_path / "package.json").read_text())
    deny = (tmp_path / ".guardian" / "denylist.txt").read_text()
    assert deny.splitlines()[-1] == "ngy-cookie" and deny.startswith("#")
    assert res[0]["files"] == ["package.json", ".guardian/denylist.txt"]
    assert "--- a/.guardian/denylist.txt" in res[0]["diff"] and "-    \"ngy-cookie\"" in res[0]["diff"]
    # a second block on the same list appends once and keeps earlier names
    (tmp_path / "requirements.txt").write_text("django==4.2\nreqeusts==2.0\n# c\n")
    apply_ops(tmp_path, [op("block_package", "requirements.txt", name="reqeusts")], None, write=True)
    assert (tmp_path / "requirements.txt").read_text() == "django==4.2\n# c\n"
    assert (tmp_path / ".guardian" / "denylist.txt").read_text().splitlines()[-2:] == ["ngy-cookie", "reqeusts"]


def test_block_package_preview_writes_nothing_and_is_confined(tmp_path):
    (tmp_path / "package.json").write_text('{\n  "dependencies": {\n    "evil": "1"\n  }\n}\n')
    apply_ops(tmp_path, [op("block_package", "package.json", name="evil")], None, write=False)
    assert not (tmp_path / ".guardian").exists() and "evil" in (tmp_path / "package.json").read_text()
    with pytest.raises(PatchError, match="outside"):
        apply_ops(tmp_path, [op("block_package", "../package.json", name="evil")], None, write=True)
    with pytest.raises(PatchError, match="supports"):
        apply_ops(tmp_path, [op("block_package", "Gemfile", name="evil")], None, write=True)


# ---------------------------------------------------------------- resolve_image_digest


class FakeInspect:
    def __init__(self, digests=None, buildx_ok=True):
        self.calls: list[list[str]] = []
        self.digests, self.buildx_ok = digests or {}, buildx_ok

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        ref = argv[-1]
        d = self.digests.get(ref, D1)
        if argv[:3] == ["docker", "buildx", "imagetools"]:
            return subprocess.CompletedProcess(argv, 0 if self.buildx_ok else 1,
                                               json.dumps({"mediaType": "x", "digest": d, "size": 1}), "")
        return subprocess.CompletedProcess(argv, 0, json.dumps([{"Ref": ref, "Descriptor": {"digest": d}}]), "")


@pytest.fixture
def inspect_fake():
    fake = FakeInspect()
    patching.set_inspect_runner(fake)
    yield fake
    patching.set_inspect_runner(None)


def digest_ctx(rc, offline=False):  # noqa: F811
    rc.tool_ctx.settings = replace(rc.tool_ctx.settings, offline=offline)
    return rc.tool_ctx


def test_resolve_image_digest_argv_cache_and_evidence(rc, inspect_fake):  # noqa: F811
    ctx = digest_ctx(rc)
    out = resolve_image_digest(ctx, ImageArgs(image="node", tag="24"))
    assert out.artifacts["image_digest"] == D1
    ev = out.evidence[0]
    assert ev.kind == "registry_metadata" and ev.facts["digest"] == D1 and ev.facts["registry"] == "registry-1.docker.io"
    assert inspect_fake.calls == [["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}",
                                   "node:24"]]
    again = resolve_image_digest(ctx, ImageArgs(image="node", tag="24"))
    assert again.evidence[0].facts["source"] == "cache" and len(inspect_fake.calls) == 1
    # offline: cache answers, a miss is an error and never reaches Docker
    off = digest_ctx(rc, offline=True)
    assert resolve_image_digest(off, ImageArgs(image="node", tag="24")).artifacts["image_digest"] == D1
    with pytest.raises(PatchError, match="OFFLINE"):
        resolve_image_digest(off, ImageArgs(image="node", tag="25"))
    assert len(inspect_fake.calls) == 1


def test_resolve_image_digest_falls_back_to_manifest_inspect(rc, inspect_fake):  # noqa: F811
    inspect_fake.buildx_ok = False
    out = resolve_image_digest(digest_ctx(rc), ImageArgs(image="ghcr.io/acme/app", tag="v1"))
    assert out.artifacts["image_digest"] == D1 and out.evidence[0].facts["registry"] == "ghcr.io"
    assert inspect_fake.calls[-1][:3] == ["docker", "manifest", "inspect"]


def test_resolve_image_digest_host_allowlist_and_arg_validation(rc, inspect_fake):  # noqa: F811
    with pytest.raises(NetworkBlocked):
        resolve_image_digest(digest_ctx(rc), ImageArgs(image="evil.example.com/a/b", tag="1"))
    assert inspect_fake.calls == []
    assert patching.registry_host("gcr.io/proj/x") == "gcr.io" and patching.registry_host("acme/app") == "registry-1.docker.io"
    for image in ("--help", "a@sha256:abc", "../x", "a b", "a;b"):
        with pytest.raises(ValueError):
            ImageArgs(image=image, tag="1")
    with pytest.raises(ValueError):
        ImageArgs(image="node", tag="-v")


# ---------------------------------------------------------------- remediation candidates


def image_finding(rc, tag="20", newer=None):  # noqa: F811
    facts = {"image": "node", "tag": tag, "digest": None, "stage": None, "exposed_ports": ["3000"]}
    if newer:
        facts["newer_tags"] = newer
    ev = Evidence(run_id=RUN, kind="file_excerpt", source_tool="detector:image_pin", facts=facts,
                  file_path="Dockerfile", line=1, excerpt=f"FROM node:{tag}")
    rc.store.add_evidence(ev)
    f = Finding(run_id=RUN, category=FindingCategory.UNTRUSTED_IMAGE, title=f"Base image node:{tag} referenced by tag only",
                detector="detector:image_pin", component_purl=f"node:{tag}", scope=Scope.PROD, project="image",
                file_path="Dockerfile", line=1, evidence_ids=[ev.evidence_id], initial_risk="medium")
    rc.store.add_finding(f)
    return f


def test_untrusted_image_is_plannable_one_per_category():
    def img(i):
        return Finding(run_id="r", category=FindingCategory.UNTRUSTED_IMAGE, title=f"i{i}", detector="d",
                       evidence_ids=["ev_1"], initial_risk="medium")

    chosen = ra.select([img(1), img(2)], 3)
    assert [f.category for f in chosen] == [FindingCategory.UNTRUSTED_IMAGE] and len(chosen) == 1


def test_image_pin_plan_digest_comes_from_evidence_and_diff_is_previewed(rc, inspect_fake):  # noqa: F811
    digest_ctx(rc)
    f = image_finding(rc)
    st = {"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0}
    out = rem.remediation_node(st)
    plan = list_plans(rc.tool_ctx.run_dir)[0]
    assert out["route"] == "gate" and plan.action == "pin" and plan.target_version == D1
    assert plan.ops[0].op == "pin_image_digest" and plan.ops[0].args == {"image": "node", "tag": "20", "digest": D1}
    kinds = {e.kind for e in (rc.store.get_evidence(i) for i in plan.evidence_ids)}
    assert {"registry_metadata", "patch_diff"} <= kinds
    diff = next(e for e in (rc.store.get_evidence(i) for i in plan.evidence_ids) if e.kind == "patch_diff")
    assert f"+FROM node:20@{D1}" in diff.excerpt
    assert any(c.field == "digest" and c.label.value == "verified" for c in plan.rationale)
    # no newer tag in evidence: the second attempt escalates instead of inventing one
    out2 = rem.remediation_node({**st, "current": f.finding_id, "attempt": 1})
    assert out2["route"] == "next" and rc.store.get_finding(f.finding_id).status is FindingStatus.ESCALATED


def test_update_base_image_only_with_newer_tag_from_evidence(rc, inspect_fake):  # noqa: F811
    digest_ctx(rc)
    inspect_fake.digests = {"node:20": D1, "node:22": D2}
    f = image_finding(rc, newer=["22"])
    assert [c.action for c in rem.candidates(rc, f)] == ["pin", "update_base_image"]
    st = {"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0}
    first = rem.remediation_node(st)
    rem.remediation_node({**st, "current": first["current"], "attempt": 1, "last_validation": {"verdict": "failed_build"}})
    p1, p2 = list_plans(rc.tool_ctx.run_dir)
    assert p2.action == "update_base_image" and p2.ops[0].args["new_tag"] == "22" and p2.ops[0].args["digest"] == D2
    assert p2.target_version == f"22@{D2}" and p1.ops != p2.ops


def test_g45_blocks_digest_tag_and_name_not_in_evidence(rc, inspect_fake):  # noqa: F811
    digest_ctx(rc)
    f = image_finding(rc, newer=["22"])
    good = rem.candidates(rc, f)[1]
    good.image["new_tag"] = "99"  # a tag nobody listed
    assert rem.build_plan(rc, f, good, 1) is None
    bad_digest = [op("pin_image_digest", "Dockerfile", image="node", tag="20", digest=D2)]
    assert "resolve_image_digest evidence" in rem.ungrounded_target(rc, f, bad_digest, [])
    assert "not the one in the finding" in rem.ungrounded_target(rc, f, [op("block_package", "package.json",
                                                                              name="left-pad")], [])
    assert "G4.5" in (rc.tool_ctx.run_dir / "trace.jsonl").read_text()


def typosquat(rc):  # noqa: F811
    (rc.tool_ctx.repo / "package.json").write_text('{\n  "dependencies": {\n    "ngy-cookie": "^6.0.0",\n'
                                                   '    "jsonwebtoken": "0.4.0"\n  }\n}\n')
    ev = Evidence(run_id=RUN, kind="detector_result", source_tool="detector:typosquat",
                  facts={"name": "ngy-cookie", "similar_to": "ng-cookie", "distance": 1, "range": "^6.0.0"},
                  file_path="package.json")
    rc.store.add_evidence(ev)
    f = Finding(run_id=RUN, category=FindingCategory.TYPOSQUAT, title="Possible typosquat ngy-cookie",
                detector="detector:typosquat", component_purl="pkg:npm/ngy-cookie@6.0.0", scope=Scope.PROD,
                project="root", file_path="package.json", evidence_ids=[ev.evidence_id], initial_risk="high")
    rc.store.add_finding(f)
    return f


def test_typosquat_gets_block_candidate_and_only_g53_actions(rc):  # noqa: F811
    f = typosquat(rc)
    cands = rem.candidates(rc, f)
    assert [c.action for c in cands] == ["replace", "remove", "block"]
    assert {c.action for c in cands} <= rem.HEURISTIC_ACTIONS
    plan = rem.build_plan(rc, f, cands[2], 3)
    assert plan.ops[0].op == "block_package" and plan.ops[0].args == {"name": "ngy-cookie"}
    diff = next(e for e in (rc.store.get_evidence(i) for i in plan.evidence_ids) if e.kind == "patch_diff")
    assert ".guardian/denylist.txt" in diff.facts["files"] and "+ngy-cookie" in diff.excerpt


def not_imported_cve(rc):  # noqa: F811
    child = "pkg:npm/jws@1.0.0"
    f = cve(rc, paths=[["root", PURL, child]])  # transitive, no parent upgrade can be proven offline
    f.component_purl = child
    rc.store.update_finding(f)
    reach = Evidence(run_id=RUN, kind="reachability", source_tool="reachability_import",
                     facts={"package": "jws", "ecosystem": "npm", "tier": "not_imported", "hits": []})
    rc.store.add_evidence(reach)
    ids = [reach.evidence_id]
    fac = {k: factor(0.5, "unknown", ids) for k in "SEPX"}
    from guardian.core.models import RiskFactors

    factors = RiskFactors(**fac, R=factor(0.1, "not_imported", ids))
    c = compute(factors)
    save_risks(rc.tool_ctx.run_dir, [RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band,
                                                    confidence=c.confidence, factors=factors, summary="s")])
    return f, reach


def test_mitigate_plan_for_unreachable_cve_without_upgrade(rc):  # noqa: F811
    f, reach = not_imported_cve(rc)
    cands = rem.candidates(rc, f)
    assert [c.action for c in cands] == ["mitigate"]
    st = {"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0}
    out = rem.remediation_node(st)
    plan = list_plans(rc.tool_ctx.run_dir)[0]
    assert out["route"] == "gate" and plan.action == "mitigate" and plan.ops == []
    assert reach.evidence_id in plan.evidence_ids
    tier = next(c for c in plan.rationale if c.field == "tier")
    assert tier.label.value == "verified" and "NOT" not in plan.expected_risk_reduction.upper().split("->")[0]
    risk = RiskAssessment.model_validate(json.loads((rc.tool_ctx.run_dir / "risk.json").read_text())[0])
    assert f"-> {simulate_after(risk, 'mitigate')[0]}" in plan.expected_risk_reduction
    assert any("does not fix" in c.text for c in plan.rationale)
    # a rejected mitigation is not offered a second time: escalate
    out2 = rem.remediation_node({**st, "current": f.finding_id, "attempt": 1})
    assert out2["route"] == "next" and rc.store.get_finding(f.finding_id).status is FindingStatus.ESCALATED


def test_mitigate_without_unreachable_evidence_offers_nothing(rc):  # noqa: F811
    f = cve(rc, paths=[["root", PURL, "pkg:npm/jws@1.0.0"]])
    f.component_purl = "pkg:npm/jws@1.0.0"
    assert rem.candidates(rc, f) == []  # no risk.json: no reachability evidence, no mitigation


def test_validator_records_mitigation_as_accepted_not_verified(rc):  # noqa: F811
    f, _ = not_imported_cve(rc)
    rem.remediation_node({"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0})
    plan = list_plans(rc.tool_ctx.run_dir)[0]
    appr = Approval(plan_id=plan.plan_id, plan_hash=plan.plan_hash, decision="approve", decided_by="alice")
    (rc.tool_ctx.run_dir / "approvals.jsonl").write_text(appr.model_dump_json() + "\n")
    out = validator_node({"run_id": RUN, "plan_id": plan.plan_id, "decision": appr.model_dump(mode="json")})
    assert out["route"] == "next"
    v = list_validations(rc.tool_ctx.run_dir)[0]
    assert v.verdict == "mitigated" and v.target_finding_resolved is False and v.build_ok is None
    assert v.final_confidence.value == "low" and v.risk_after <= v.risk_before
    assert rc.store.get_finding(f.finding_id).status is FindingStatus.ACCEPTED
    assert not (rc.tool_ctx.run_dir / "attempts").exists()  # nothing was applied
    rep = build_report(rc.tool_ctx.run_dir, summary={})
    rem_row = next(r for r in rep.remaining_risk if r.finding_id == f.finding_id)
    assert rem_row.status == "accepted" and "NOT fixed" in rem_row.note
    assert load_plan(rc.tool_ctx.run_dir, plan.plan_id).ops == []


# ---------------------------------------------------------------- sandbox: integration tests (D2-08)


class ApiDocker(FakeDocker):
    def __init__(self, api_exit=0, **kw):
        super().__init__(**kw)
        self.api_exit = api_exit

    def __call__(self, argv, timeout):
        if argv[1] == "run" and ("test:api" in argv[-1] or "manage.py test" in argv[-1]):
            self.calls.append(argv)
            out = "Tests: 1 failed, 3 passed, 4 total" if self.api_exit else "Tests: 4 passed, 4 total"
            if "manage.py" in argv[-1]:
                out = "Ran 4 tests in 0.1s\n\nFAILED (failures=1)" if self.api_exit else "Ran 4 tests in 0.1s\n\nOK"
            return subprocess.CompletedProcess(argv, self.api_exit, out, "")
        return super().__call__(argv, timeout)


def test_npm_integration_phase_runs_after_unit_tests_without_network(work, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sandbox, "_scripts", lambda w: {"build:server": "x", "test:server": "y", "test:api": "z"})
    fake = use(monkeypatch, ApiDocker())
    res = sandbox.sandbox_validate(ctx_for(work, tmp_path)).artifacts["sandbox_result"]
    assert res.verdict is None and res.integration_tests == {"passed": 4, "failed": 0, "total": 4}
    assert res.unit_tests["passed"] == 3
    runs = [a for a in fake.calls if a[1] == "run"]
    assert [a[-1].rsplit("npm run ", 1)[1] for a in runs] == ["build:server", "test:server", "test:api"]
    assert all(a[a.index("--network") + 1] == "none" for a in runs)


def test_npm_integration_failure_is_failed_tests(work, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sandbox, "_scripts", lambda w: {"test:server": "y", "test:api": "z"})
    use(monkeypatch, ApiDocker(api_exit=1))
    out = sandbox.sandbox_validate(ctx_for(work, tmp_path))
    res = out.artifacts["sandbox_result"]
    assert res.verdict == "failed_tests" and res.integration_tests["failed"] == 1 and res.tests_ran
    tr = next(e for e in out.evidence if e.kind == "test_result")
    assert tr.facts["integration_tests"]["failed"] == 1


def test_django_integration_phase(tmp_path, monkeypatch):
    w = tmp_path / "run" / "attempts" / ("at_" + "C" * 26) / "work"
    (w / "tests").mkdir(parents=True)
    (w / "requirements.txt").write_text("django==4.2\n")
    (w / "manage.py").write_text("import django\n")
    fake = use(monkeypatch, ApiDocker())
    res = sandbox.sandbox_validate(ctx_for(w, tmp_path)).artifacts["sandbox_result"]
    assert res.integration_tests == {"passed": 4, "failed": 0, "total": 4}
    assert "manage.py test" in [a[-1] for a in fake.calls if a[1] == "run"][-1]
    assert sandbox.parse_counts("Ran 5 tests in 1s\n\nFAILED (failures=1, errors=1)") == {"passed": 3, "failed": 2,
                                                                                         "total": 5}


# ---------------------------------------------------------------- sandbox: built-artifact rescan (G6.7)


def image_runner(fake, seen, build_rc=0, grype_ids=("CVE-9",)):
    def run(argv, timeout):
        seen.append(argv)
        cp = subprocess.CompletedProcess
        if argv[0] == "syft":
            Path(argv[argv.index("-o") + 1].split("=", 1)[1]).write_text(json.dumps({"components": [{"name": "a"}]}))
            return cp(argv, 0, "", "")
        if argv[0] == "grype":
            m = [{"vulnerability": {"id": v}, "artifact": {"name": "lodash"}} for v in grype_ids]
            return cp(argv, 0, json.dumps({"matches": m}), "")
        if argv[1] == "build" and argv[-2].startswith("guardian-built"):
            seen.append(["dockerignore", (Path(argv[-1]) / ".dockerignore").read_text()])
            return cp(argv, build_rc, "built token=abcdef123456", "")
        return fake(argv, timeout)

    return run


def test_image_build_off_by_default_and_disclosed(work, tmp_path, monkeypatch):  # noqa: F811
    (work / "Dockerfile").write_text("FROM node:24\n")
    monkeypatch.delenv("GUARDIAN_IMAGE_BUILD", raising=False)
    fake = use(monkeypatch, FakeDocker())
    res = sandbox.sandbox_validate(ctx_for(work, tmp_path)).artifacts["sandbox_result"]
    assert res.artifact_image is None and not any("guardian-built" in " ".join(a) for a in fake.calls)
    assert "GUARDIAN_IMAGE_BUILD is off" in sandbox.known_limitations(res, work)[0]


def test_image_build_rescan_limits_ignore_and_cleanup(work, tmp_path, monkeypatch):  # noqa: F811
    (work / "Dockerfile").write_text("FROM node:24\n")
    (work / ".dockerignore").write_text("custom\n")
    monkeypatch.setenv("GUARDIAN_IMAGE_BUILD", "1")
    seen: list = []
    use(monkeypatch, image_runner(FakeDocker(), seen))
    ctx = ctx_for(work, tmp_path)
    ctx.run_dir.mkdir(exist_ok=True)
    out = sandbox.sandbox_validate(ctx)
    res = out.artifacts["sandbox_result"]
    assert res.artifact_image and res.artifact_image.startswith("guardian-built:")
    assert res.image_vulns == {("CVE-9", "lodash")}
    build = next(a for a in seen if a[0] != "dockerignore" and a[1] == "build" and res.artifact_image in a)
    assert build[build.index("--memory") + 1] == "4g" and "--cpu-quota" in build
    assert "--secret" not in build and "--build-arg" not in build and build[-1] == str(work)
    ignore = next(a[1] for a in seen if a[0] == "dockerignore")
    for pat in (".env*", "*.pem", "*.key", "encryptionkeys/", "custom"):
        assert pat in ignore.splitlines()
    assert (work / ".dockerignore").read_text() == "custom\n"  # the original is restored
    assert any(a[1:3] == ["rmi", "-f"] and a[3] == res.artifact_image for a in seen if a[0] != "dockerignore")
    assert any(e.kind == "scanner_output" and e.facts["image"] == res.artifact_image for e in out.evidence)
    assert "[REDACTED]" in next(e for e in out.evidence if e.kind == "build_log").excerpt
    assert "network access" in sandbox.known_limitations(res, work)[0]


def test_image_build_failure_is_disclosed_not_fatal(work, tmp_path, monkeypatch):  # noqa: F811
    (work / "Dockerfile").write_text("FROM node:24\n")
    monkeypatch.setenv("GUARDIAN_IMAGE_BUILD", "1")
    seen: list = []
    use(monkeypatch, image_runner(FakeDocker(), seen, build_rc=1))
    ctx = ctx_for(work, tmp_path)
    res = sandbox.sandbox_validate(ctx).artifacts["sandbox_result"]
    assert res.verdict is None and res.artifact_image is None and not (work / ".dockerignore").exists()
    assert any("docker build failed" in n for n in res.notes)
    assert any(a[1:3] == ["rmi", "-f"] for a in seen if a[0] != "dockerignore")


def test_registry_tools_are_registered_with_g3_guards():
    from guardian.tools.registry import allowed_tools, tool_specs

    assert "resolve_image_digest" in allowed_tools("remediation") and "resolve_image_digest" not in allowed_tools("validator")
    spec = tool_specs()["local_fix_branch"]
    assert spec.writes and spec.agents == frozenset({"validator"})


def test_tool_context_type_is_used():  # keeps the import honest for type checkers
    assert ToolContext
