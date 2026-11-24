"""Runtime settings from the environment (and .env). Owner: Dev1.

Secrets are only read here and never logged or copied into events (G1.3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]

# provider -> defaults. deepseek and openai_compat share the OpenAI-compatible backend.
PROVIDER_DEFAULTS = {
    "deepseek": {"model": "deepseek-chat", "base_url": "https://api.deepseek.com", "key_env": "DEEPSEEK_API_KEY"},
    "anthropic": {"model": "claude-opus-5-5", "key_env": "ANTHROPIC_API_KEY"},
    "openai_compat": {"key_env": "LLM_API_KEY"},
}


@dataclass(frozen=True)
class Settings:
    runs_dir: Path
    llm_provider: str  # anthropic | openai_compat
    llm_model: str
    llm_mode: str  # live | record | replay
    llm_base_url: str | None
    llm_cache_dir: Path
    max_llm_findings: int
    offline: bool
    max_llm_tokens: int = 600_000  # G3.6 run budget (input + output tokens)
    max_plans: int = 3  # D1-05: findings taken into the remediation loop per run
    # Demo mode: one critical finding, a short simulated sandbox run before the human gate, and no Docker
    # sandbox after approval (the validator still applies the plan and re-runs the detectors for real)
    demo_validator: bool = False
    demo_sandbox_seconds: float = 6.0

    def describe(self) -> dict:
        """Safe-to-log view (no keys)."""
        return {
            "provider": self.llm_provider,
            "model": self.llm_model,
            "mode": self.llm_mode,
            "base_url": self.llm_base_url,
            "max_llm_findings": self.max_llm_findings,
            "offline": self.offline,
            "max_llm_tokens": self.max_llm_tokens,
            "max_plans": self.max_plans,
            "demo_validator": self.demo_validator,
        }


def load_settings(**overrides) -> Settings:
    load_dotenv(REPO_ROOT / ".env", override=False)
    env = os.environ
    runs = Path(env.get("GUARDIAN_RUNS_DIR", "runs"))
    if not runs.is_absolute():
        runs = REPO_ROOT / runs
    provider = env.get("GUARDIAN_LLM_PROVIDER", "deepseek")
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
        demo_validator=env.get("GUARDIAN_DEMO_VALIDATOR", "0") == "1",
        demo_sandbox_seconds=float(env.get("GUARDIAN_DEMO_SANDBOX_SECONDS", "6")),
    )
    values.update({k: v for k, v in overrides.items() if v is not None})
    if values["llm_mode"] not in {"live", "record", "replay"}:
        raise ValueError(f"GUARDIAN_LLM_MODE must be live|record|replay, got {values['llm_mode']!r}")
    return Settings(**values)
