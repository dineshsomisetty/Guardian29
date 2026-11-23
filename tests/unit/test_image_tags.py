"""update_base_image evidence: newest explicit releases on the same line, cached and offline-safe."""

import httpx

from guardian.tools import image_tags as it


def test_pick_newer_keeps_line_and_variant_and_prefers_full_releases():
    tags = ["24", "24.22", "24.22.3", "24.22.2", "24.9.0", "26.1.0", "24.22.3-alpine", "24-alpine", "latest"]
    assert it.pick_newer("24", tags) == ["24.22.3", "24.22.2"]
    assert it.pick_newer("24-alpine", tags) == ["24.22.3-alpine"]
    assert it.pick_newer("3.9-alpine", ["3.9.25-alpine", "3.9.24-alpine", "3.13.1-alpine"]) == [
        "3.9.25-alpine", "3.9.24-alpine"]
    assert it.pick_newer("latest", tags) == [] and it.pick_newer("v19", ["v19.1.0"]) == []
    # a full release only moves to strictly newer patches on its own minor line, same variant
    slim = ["20.19.2-bookworm-slim", "20.19.6-bookworm-slim", "20.20.0-bookworm-slim", "20.19.6-bookworm"]
    assert it.pick_newer("20.19.2-bookworm-slim", slim) == ["20.19.6-bookworm-slim"]
    assert it.pick_newer("20.19.6-bookworm-slim", slim) == []


def test_hub_repo_only_for_docker_hub():
    assert it.hub_repo("node") == "library/node"
    assert it.hub_repo("bkimminich/juice-shop") == "bkimminich/juice-shop"
    assert it.hub_repo("docker.io/library/node") == "library/node"
    assert it.hub_repo("gcr.io/distroless/nodejs24-debian13") is None
    assert it.hub_repo("ghcr.io/org/app") is None


def test_lookup_is_cached_and_offline_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path))
    calls = []

    def handler(request):
        calls.append(str(request.url))
        assert request.url.host == "hub.docker.com"
        return httpx.Response(200, json={"results": [{"name": "24.22.3"}, {"name": "24.22.2"}, {"name": "24.21.0"}]})

    assert it.newer_tags("node", "24", offline=True) == ([], "unavailable (offline, cache miss)")
    assert calls == []
    got = it.newer_tags("node", "24", offline=False, transport=httpx.MockTransport(handler))
    assert got == (["24.22.3", "24.22.2"], "hub.docker.com") and len(calls) == 1
    assert it.newer_tags("node", "24", offline=True) == (["24.22.3", "24.22.2"], "cache")  # offline: cache only
    assert len(calls) == 1
    assert it.newer_tags("gcr.io/distroless/nodejs24-debian13", "latest", offline=False)[0] == []
