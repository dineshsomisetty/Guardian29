from types import SimpleNamespace

from guardian.tools.cosign import from_images, image_signatures, verify_image

DF = """ARG BASE=node:24
FROM node:24 AS installer
RUN echo hi
FROM installer AS second
FROM $BASE
FROM gcr.io/distroless/nodejs24-debian13@sha256:ba59
"""


def fake(outcomes):
    def run(cmd):
        image = cmd[2]
        rc, err = outcomes[image]
        assert ("--certificate-identity" in cmd) == image.startswith("gcr.io/distroless/")  # strict only if known
        return SimpleNamespace(returncode=rc, stdout="[]" if rc == 0 else "", stderr=err)
    return run


def test_from_images_skips_stages_and_args(tmp_path):
    (tmp_path / "Dockerfile").write_text(DF)
    assert from_images(tmp_path / "Dockerfile") == [("node:24", 2),
                                                     ("gcr.io/distroless/nodejs24-debian13@sha256:ba59", 6)]


def test_verify_statuses():
    run = fake({"gcr.io/distroless/x": (0, ""), "node:24": (1, "Error: no signatures found"),
                "gcr.io/distroless/bad": (1, "Error: none of the expected identities matched")})
    assert verify_image("gcr.io/distroless/x", run)["status"] == "verified"
    assert verify_image("node:24", run)["status"] == "unsigned"
    bad = verify_image("gcr.io/distroless/bad", run)
    assert bad["status"] == "failed" and not bad["signature_verified"]


def test_tool_emits_evidence_and_provenance_gap(tmp_path):
    (tmp_path / "Dockerfile").write_text(DF)
    run = fake({"node:24": (1, "Error: no signatures found"),
                "gcr.io/distroless/nodejs24-debian13@sha256:ba59": (0, "")})
    out = image_signatures(SimpleNamespace(run_id="r", repo=tmp_path, work_dir=tmp_path), runner=run)
    assert [e.facts["status"] for e in out.evidence] == ["unsigned", "verified"]
    (fd,) = out.findings
    assert fd.category.value == "provenance_gap" and fd.line == 2 and fd.component_purl == "image:node:24"
    assert fd.provenance.signature_verified is False
