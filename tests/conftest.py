from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian.core.config import load_settings
from guardian.llm.provider import LLMProvider, LLMResponse


class FakeBackend:
    """Scripted LLM. `responder(system, user, schema) -> str` or a list of strings returned in order."""

    model = "fake-llm"

    def __init__(self, responder):
        self.responder = responder
        self.calls: list[str] = []

    def complete_json(self, system, user, schema):
        self.calls.append(user)
        if callable(self.responder):
            text = self.responder(system, user, schema)
        else:
            text = self.responder.pop(0)
        return LLMResponse(text=text if isinstance(text, str) else json.dumps(text), model=self.model)


@pytest.fixture
def settings(tmp_path: Path):
    return load_settings(runs_dir=tmp_path / "runs", llm_mode="live", llm_cache_dir=tmp_path / "llmcache",
                         max_llm_findings=40, max_plans=0)  # CP1 tests: no remediation loop


@pytest.fixture
def fake_llm_factory(settings):
    def make(responder, mode="live"):
        backend = FakeBackend(responder)
        return LLMProvider(mode, settings.llm_cache_dir, backend.model, backend=backend), backend

    return make


@pytest.fixture(autouse=True)
def _sandbox_off(monkeypatch):
    """Tests never need Docker/Syft for the validator unless they opt in (D2-08)."""
    monkeypatch.setenv("GUARDIAN_SANDBOX", "off")


@pytest.fixture(autouse=True)
def _intel_offline(monkeypatch, tmp_path):
    """Risk/remediation intel lookups (EPSS, KEV, OSV, registry) never touch the network or the shared cache."""
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel_cache"))
    monkeypatch.setattr("guardian.tools.threat_intel.is_offline", lambda: True)
