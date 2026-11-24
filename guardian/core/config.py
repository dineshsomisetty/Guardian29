"""Runtime settings from the environment (and .env). Owner: Dev1.

`load_settings()` is the single place where GUARDIAN_* / LLM_* environment variables become a frozen `Settings`
object, which the CLI, the API and the graph then pass around. Precedence: explicit keyword overrides (CLI
flags) > process environment > `.env` in the repo root > the defaults below.

Secrets are only read here and never logged or copied into events (G1.3): the API key itself is not even part
of `Settings` (the LLM backend reads it from the environment when it is created), and `describe()` is the
only view that is written to the trace.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Repo root (two levels above guardian/core/); relative runs/ and the LLM cache are resolved against it.
REPO_ROOT = Path(__file__).resolve().parents[2]

# provider -> defaults. deepseek and openai_compat share the OpenAI-compatible backend.
PROVIDER_DEFAULTS = {
    "deepseek": {"model": "deepseek-chat", "base_url": "https://api.deepseek.com", "key_env": "DEEPSEEK_API_KEY"},
    "anthropic": {"model": "claude-opus-5-5", "key_env": "ANTHROPIC_API_KEY"},
    "openai_compat": {"key_env": "LLM_API_KEY"},
}


@dataclass(frozen=True)
class Settings:
    """Immutable run configuration. Fields without comments are described by their name; see load_settings
    for the environment variable behind each one."""

    runs_dir: Path
    llm_provider: str  # anthropic | openai_compat
    llm_model: str
    llm_mode: str  # live | record | replay (see llm/provider.py: replay = recorded answers only, no network)
    llm_base_url: str | None
    llm_cache_dir: Path  # recorded LLM responses (record writes, replay reads)
    max_llm_findings: int  # cap on findings sent to the evidence analyst LLM; the rest keep their rule risk
    offline: bool  # GUARDIAN_OFFLINE=1: no network at all, external lookups are served from caches only (G7.3)
    max_llm_tokens: int = 600_000  # G3.6 run budget (input + output tokens)
    max_plans: int = 3  # D1-05: findings taken into the remediation loop per run (sequential mode; 0 = none)
    remediation_mode: str = "batch"  # batch: every finding gets a recommendation, one decision round, combined
    #                                  validation | sequential: one plan at a time (the original loop)
    # Demo mode: one critical finding, a short simulated sandbox run before the human gate, and no Docker
    # sandbox after approval (the validator still applies the plan and re-runs the detectors for real)
    demo_validator: bool = False
    demo_sandbox_seconds: float = 6.0

    @property
    def batch_remediation(self) -> bool:
        """Batch mode is on (max_plans == 0 still means no remediation at all)."""
        # demo mode runs the one-plan loop (remediation -> sandbox_preview -> human gate), never batch
        return self.remediation_mode == "batch" and self.max_plans != 0 and not self.demo_validator

    def describe(self) -> dict:
        """Safe-to-log view (no keys): the dict written into the `agent_start` event and run summary."""
        return {
            "provider": self.llm_provider,
            "model": self.llm_model,
            "mode": self.llm_mode,
            "base_url": self.llm_base_url,
            "max_llm_findings": self.max_llm_findings,
            "offline": self.offline,
            "max_llm_tokens": self.max_llm_tokens,
            "max_plans": self.max_plans,
            "remediation_mode": self.remediation_mode,
            "demo_validator": self.demo_validator,
        }


def load_settings(**overrides) -> Settings:
    """Build `Settings` from the environment. `overrides` (None values ignored) win over everything, which is
    how CLI flags and tests set a field. Raises ValueError for an unknown LLM mode or remediation mode, so a
    typo fails at start-up instead of silently running live or sequential."""
    load_dotenv(REPO_ROOT / ".env", override=False)  # override=False: a real environment variable beats .env
    env = os.environ
    runs = Path(env.get("GUARDIAN_RUNS_DIR", "runs"))
    if not runs.is_absolute():  # a relative GUARDIAN_RUNS_DIR is anchored at the repo, not the current directory
        runs = REPO_ROOT / runs
    provider = env.get("GUARDIAN_LLM_PROVIDER", "deepseek")  # unknown provider -> no defaults, LLM_BASE_URL needed
    defaults = PROVIDER_DEFAULTS.get(provider, {})
    values = dict(
        runs_dir=runs,
        llm_provider=provider,
        llm_model=env.get("GUARDIAN_MODEL") or defaults.get("model", "deepseek-chat"),
        llm_mode=env.get("GUARDIAN_LLM_MODE", "live"),
        llm_base_url=env.get("LLM_BASE_URL") or defaults.get("base_url"),
        llm_cache_dir=REPO_ROOT / "data" / "cache" / "llm",
        max_llm_findings=int(env.get("GUARDIAN_MAX_LLM_FINDINGS", "200")),
        offline=env.get("GUARDIAN_OFFLINE", "0") == "1",
        max_llm_tokens=int(env.get("GUARDIAN_MAX_LLM_TOKENS", "600000")),
        max_plans=int(env.get("GUARDIAN_MAX_PLANS", "3")),
        remediation_mode=env.get("GUARDIAN_REMEDIATION_MODE", "batch").strip().lower(),
        demo_validator=env.get("GUARDIAN_DEMO_VALIDATOR", "0") == "1",
        demo_sandbox_seconds=float(env.get("GUARDIAN_DEMO_SANDBOX_SECONDS", "6")),
    )
    values.update({k: v for k, v in overrides.items() if v is not None})
    if values["llm_mode"] not in {"live", "record", "replay"}:
        raise ValueError(f"GUARDIAN_LLM_MODE must be live|record|replay, got {values['llm_mode']!r}")
    if values["remediation_mode"] not in {"batch", "sequential"}:
        raise ValueError(f"GUARDIAN_REMEDIATION_MODE must be batch|sequential, got {values['remediation_mode']!r}")
    return Settings(**values)
