"""Live LLM smoke test (D1-02 15:50 proof). Skipped unless ANTHROPIC_API_KEY is set.

Runs the CP1 pipeline with fake tools and the REAL evidence analyst model, then checks that the
structured output parsed, grounding labelled every claim, and no claim cites unknown evidence.
"""

import json
import os

import pytest

from guardian.core.config import load_settings
from guardian.graph import workflow
from guardian.llm.provider import LLMProvider
from tests.integration import fake_tools
from guardian.tools import registry

pytestmark = pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY not set")


def test_live_evidence_analyst(tmp_path, monkeypatch):
    import guardian.agents.detection as det
    import guardian.agents.discovery as dis

    for mod in (registry, dis, det):
        monkeypatch.setattr(mod, "BINDINGS", fake_tools.BINDINGS)
    settings = load_settings(runs_dir=tmp_path / "runs", llm_mode="live")
    llm = LLMProvider.from_settings(settings)
    run_dir = workflow.run(tmp_path, run_id="run_live", settings=settings, llm=llm, echo=True)

    findings = json.loads((run_dir / "findings.json").read_text())
    assert findings and all(f["initial_risk"] for f in findings)
    llm_f = [f for f in findings if f["initial_risk_source"] == "llm"]
    assert llm_f, "LLM produced no assessment (check trace.jsonl for errors / guardrail events)"
    evidence_ids = {p.stem for p in (run_dir / "evidence").glob("*.json")}
    for f in llm_f:
        assert f["explanation"] or f["claims"]
        for c in f["claims"]:
            assert c["label"] in {"verified", "inferred"}
            assert set(c["evidence_ids"]) <= evidence_ids
