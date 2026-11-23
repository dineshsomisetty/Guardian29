"""The SBOM must include devDependencies (Syft omits them by default), or the graph and the SBOM disagree and
Grype never scans build tooling."""

import json

from guardian.core.config import load_settings
from guardian.tools import sbom
from guardian.tools.registry import ToolContext


def test_syft_is_told_to_include_dev_dependencies(tmp_path, monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen["env"] = kw.get("env")
        out = next(a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json="))
        open(out, "w", encoding="utf-8").write(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [
            {"purl": "pkg:npm/a@1"}, {"purl": "pkg:npm/a@1"}, {"purl": "pkg:npm/b@2"}]}))

    monkeypatch.setattr(sbom, "run", fake_run)
    monkeypatch.setattr(sbom, "find", lambda name: name)
    monkeypatch.setattr(sbom, "version", lambda name: "0")
    ctx = ToolContext(run_id="r", run_dir=tmp_path, repo=tmp_path, settings=load_settings(), work_dir=tmp_path)
    out = sbom.generate_sbom(ctx)
    assert seen["env"]["SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES"] == "true"
    facts = out.evidence[0].facts
    assert facts["includes_dev_dependencies"] is True and facts["components"] == 3 and facts["unique_purls"] == 2
