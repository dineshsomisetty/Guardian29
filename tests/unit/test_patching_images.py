import json

import pytest

from guardian.tools import patching
from guardian.tools.patching import PatchError, apply_op, split_image

DOCKERFILE = """FROM node:24 AS installer
COPY . /juice-shop
RUN npm i --omit=dev
FROM gcr.io/distroless/nodejs24-debian13
COPY --from=installer /juice-shop .
"""
D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
PKG = '{\n  "name": "app",\n  "dependencies": {\n    "express": "^4.0.0",\n    "ngy-cookie": "^6.0.0"\n  }\n}\n'


@pytest.fixture
def work(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    (tmp_path / "package.json").write_text(PKG)
    return tmp_path


def test_split_image():
    assert split_image("node:24") == ("registry-1.docker.io", "library/node", "24")
    assert split_image("gcr.io/distroless/nodejs24-debian13") == ("gcr.io", "distroless/nodejs24-debian13", "latest")
    assert split_image("bkimminich/juice-shop:v20.4.0") == ("registry-1.docker.io", "bkimminich/juice-shop", "v20.4.0")


def test_pin_image_digest_keeps_stage_name(work):
    r = patching.pin_image_digest(work, "Dockerfile", {"image": "node:24"}, resolver=lambda i: D1)
    text = (work / "Dockerfile").read_text()
    assert f"FROM node:24@{D1} AS installer" in text
    assert "FROM gcr.io/distroless/nodejs24-debian13\n" in text  # other stage untouched
    assert r.facts["digest"] == D1 and "-FROM node:24 AS installer" in r.diff


def test_pin_untagged_image_as_latest(work):
    patching.pin_image_digest(work, "Dockerfile", {"image": "gcr.io/distroless/nodejs24-debian13"},
                              resolver=lambda i: D2)
    assert f"FROM gcr.io/distroless/nodejs24-debian13:latest@{D2}" in (work / "Dockerfile").read_text()


def test_repin_replaces_existing_digest(work):
    patching.pin_image_digest(work, "Dockerfile", {"image": "node:24"}, resolver=lambda i: D1)
    patching.pin_image_digest(work, "Dockerfile", {"image": "node:24"}, resolver=lambda i: D2)
    text = (work / "Dockerfile").read_text()
    assert f"node:24@{D2} AS installer" in text and D1 not in text


def test_update_base_image_bumps_tag_and_pins(work):
    seen = []
    r = patching.update_base_image(work, "Dockerfile", {"image": "node:24", "to_tag": "24.11.1"},
                                   resolver=lambda i: seen.append(i) or D1)
    assert seen == ["node:24.11.1"]  # digest looked up for the NEW tag
    assert f"FROM node:24.11.1@{D1} AS installer" in (work / "Dockerfile").read_text()
    assert r.facts["to"] == "node:24.11.1"


def test_image_ops_reject_bad_input(work):
    with pytest.raises(PatchError):
        patching.pin_image_digest(work, "Dockerfile", {"image": "node:24", "digest": "sha256:xyz"})
    with pytest.raises(PatchError):
        patching.pin_image_digest(work, "Dockerfile", {"image": "python:3", "digest": D1})  # not in file
    with pytest.raises(PatchError):
        patching.update_base_image(work, "Dockerfile", {"image": "node:24", "to_tag": "24; rm -rf /", "digest": D1})
    with pytest.raises(PatchError):
        patching.lookup_image_digest("evil.example.com/x:1")  # registry not allowlisted


def test_block_package_denylists_in_work_copy_and_removes(work):
    r = apply_op(work, {"op": "block_package", "file_path": "package.json",
                        "args": {"name": "ngy-cookie", "reason": "typosquat of ngx-cookie"}})
    pol = (work / "guardian.yaml").read_text()
    assert "denylist:" in pol and "- name: ngy-cookie" in pol and "typosquat of ngx-cookie" in pol
    assert "ngy-cookie" not in json.loads((work / "package.json").read_text())["dependencies"]
    assert r.files == ["guardian.yaml", "package.json"] and r.facts["dependency_action"] == "remove_dependency"


def test_block_package_appends_to_existing_denylist_and_can_replace(work):
    (work / "guardian.yaml").write_text("version: 1\n# keep me\ndenylist:\n  - name: left-pad\n    reason: x\n"
                                        "thresholds:\n  a: 1\n")
    apply_op(work, {"op": "block_package", "file_path": "package.json",
                    "args": {"name": "ngy-cookie", "reason": "typo", "new_name": "ngx-cookie", "version": "^6.0.1"}})
    pol = (work / "guardian.yaml").read_text()
    assert "# keep me" in pol and "- name: left-pad" in pol and "- name: ngy-cookie" in pol
    assert pol.index("ngy-cookie") < pol.index("thresholds:")
    assert json.loads((work / "package.json").read_text())["dependencies"]["ngx-cookie"] == "^6.0.1"
