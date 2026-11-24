"""G3.5 network allowlist: only the §14 hosts (+ the configured LLM host) may be contacted."""

import json
from dataclasses import replace

import pytest

from guardian.core.audit import AuditLog
from guardian.guardrails.network import ALLOWED_HOSTS, NetworkBlocked, check_url
from guardian.llm.provider import LLMError, OpenAICompatBackend
from guardian.tools import investigate
from guardian.tools.detectors import install_scripts
from guardian.tools.registry import ToolContext


def _events(run_dir):
    return [json.loads(x) for x in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def ctx(tmp_path, settings):
    return ToolContext(run_id="run_n", run_dir=tmp_path / "run", repo=tmp_path, settings=settings)


def test_plan_hosts_are_allowed(settings):
    assert ALLOWED_HOSTS == {"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "api.osv.dev",
                             "api.first.org", "www.cisa.gov", "api.deps.dev", "github.com", "api.github.com"}
    for host in ALLOWED_HOSTS:
        assert check_url(f"https://{host}/x", settings=settings).startswith("https://")


def test_unknown_host_raises_and_emits_guardrail_event(tmp_path):
    audit = AuditLog(tmp_path, "run_n", echo=False)
    for url in ("https://evil.example.com/x", "https://registry.npmjs.org.evil.io/x",
                "https://user:pw@registry.npmjs.org/x", "http://registry.npmjs.org/x", "file:///etc/passwd"):
        with pytest.raises(NetworkBlocked):
            check_url(url, audit=audit)
    events = [e for e in _events(tmp_path) if e["type"] == "guardrail"]
    assert len(events) == 5 and all(e["data"]["rule"] == "G3.5" for e in events)


def test_configured_llm_host_is_allowed(settings):
    s = replace(settings, llm_base_url="https://llm.internal.test/v1")
    assert check_url("https://llm.internal.test/v1/chat/completions", settings=s)
    with pytest.raises(NetworkBlocked):
        check_url("https://llm.internal.test/v1/chat/completions", settings=settings)


def test_ctx_event_lands_in_run_trace(ctx):
    with pytest.raises(NetworkBlocked):
        check_url("https://evil.example.com/", ctx=ctx, agent="investigator")
    (event,) = [e for e in _events(ctx.run_dir) if e["type"] == "guardrail"]
    assert event["data"]["rule"] == "G3.5" and event["data"]["agent"] == "investigator"


def test_outbound_callers_go_through_check(ctx, monkeypatch, tmp_path):
    """registry lookups and the LLM backend call check_url before any request is made."""
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        raise AssertionError("network")

    monkeypatch.setattr("httpx.get", fake_get)
    monkeypatch.setattr(install_scripts, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(install_scripts, "REGISTRY", "https://evil.example.com")
    with pytest.raises(NetworkBlocked):
        install_scripts._registry_scripts("left-pad", "1.0.0", False, ctx)
    with pytest.raises(NetworkBlocked):
        investigate.registry_metadata(ctx, investigate.RegistryMetadataArgs(name="left-pad"))
    assert seen == []
    backend = OpenAICompatBackend("m", "http://llm.local:8000/v1", key_env="NOPE", allowed_host="other.test")
    monkeypatch.setattr("httpx.post", lambda *a, **k: pytest.fail("network"))
    with pytest.raises(LLMError, match="G3.5"):
        backend.complete_json("s", "u", {})
