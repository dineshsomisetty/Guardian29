"""GitLab CI as a supply-chain source: job/service images and remote includes (same rules as GitHub/Docker)."""

from types import SimpleNamespace

from guardian.adapters import gitlab_ci
from guardian.core.models import PatchOp
from guardian.tools.detectors import ci_pin, image_pin
from guardian.tools.patching import apply_ops

PIPE = """
build:
  services:
    - docker:19.03.1-dind
  image: docker:19.03.1
scan:
  image:
    name: "stackhawk/hawkscan:beta"
    entrypoint: [""]
pinned:
  image: python:3.12@sha256:%s
deploy:
  image: $CI_REGISTRY_IMAGE
include:
  - project: 'acme/ci-templates'
    ref: main
  - project: 'acme/pinned'
    ref: %s
  - remote: 'https://example.com/ci.yml'
  - template: Security/SAST.gitlab-ci.yml
  - local: other.gitlab-ci.yml
""" % ("a" * 64, "b" * 40)


def _repo(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(PIPE, encoding="utf-8")
    return tmp_path


def test_parse_images_services_and_includes(tmp_path):
    images, includes = gitlab_ci.parse(_repo(tmp_path))
    got = {(i.role, i.image, i.tag, bool(i.digest), i.line) for i in images}
    assert got == {("service", "docker", "19.03.1-dind", False, 4), ("image", "docker", "19.03.1", False, 5),
                   ("image", "stackhawk/hawkscan", "beta", False, 8), ("image", "python", "3.12", True, 11)}
    assert {(i.source, i.ref, i.pinned) for i in includes} == {
        ("acme/ci-templates", "main", False), ("acme/pinned", "b" * 40, True), ("https://example.com/ci.yml", None, False)}


def test_detectors_flag_tag_only_ci_images_and_unpinned_includes(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    root = _repo(tmp_path)
    ctx = SimpleNamespace(run_id="r", work_dir=root, repo=root, settings=None)
    imgs = image_pin.detect(ctx).findings
    assert sorted(f.title for f in imgs) == [
        "GitLab CI job image docker:19.03.1 referenced by tag only (no digest)",
        "GitLab CI job image stackhawk/hawkscan:beta referenced by tag only (no digest)",
        "GitLab CI service container docker:19.03.1-dind referenced by tag only (no digest)"]
    cis = ci_pin.detect(ctx).findings
    assert sorted(f.title for f in cis) == [
        "GitLab CI include acme/ci-templates@main not pinned to a commit SHA",
        "GitLab CI include https://example.com/ci.yml (remote URL) not pinned to a commit SHA"]


def test_pin_digest_in_a_gitlab_pipeline_rewrites_only_the_exact_image(tmp_path):
    root = _repo(tmp_path)
    d = "sha256:" + "c" * 64
    for image, tag in (("docker", "19.03.1"), ("docker", "19.03.1-dind"), ("stackhawk/hawkscan", "beta")):
        apply_ops(root, [PatchOp(op="pin_image_digest", file_path=".gitlab-ci.yml",
                                 args={"image": image, "tag": tag, "digest": d})], None, write=True)
    text = (root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert f"  image: docker:19.03.1@{d}\n" in text
    assert f"    - docker:19.03.1-dind@{d}\n" in text
    assert f'    name: "stackhawk/hawkscan:beta@{d}"' in text
