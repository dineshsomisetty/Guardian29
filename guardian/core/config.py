"""Runtime settings from the environment (and .env). Owner: Dev1.

Secrets are only read here and never logged or copied into events (G1.3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]


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

    def describe(self) -> dict:
        """Safe-to-log view (no keys)."""
        return {
            "provider": self.llm_provider,
            "model": self.llm_model,
            "mode": self.llm_mode,
            "base_url": self.llm_base_url,
            "max_llm_findings": self.max_llm_findings,
            "offline": self.offline,
        }


def load_settings(**overrides) -> Settings:
    load_dotenv(REPO_ROOT / ".env", override=False)
    env = os.environ
    runs = Path(env.get("GUARDIAN_RUNS_DIR", "runs"))
    if not runs.is_absolute():
        runs = REPO_ROOT / runs
    values = dict(
        runs_dir=runs,
        llm_provider=env.get("GUARDIAN_LLM_PROVIDER", "anthropic"),
        llm_model=env.get("GUARDIAN_MODEL", "claude-opus-5-5"),
        llm_mode=env.get("GUARDIAN_LLM_MODE", "live"),
        llm_base_url=env.get("LLM_BASE_URL") or None,
        llm_cache_dir=REPO_ROOT / "data" / "cache" / "llm",
        max_llm_findings=int(env.get("GUARDIAN_MAX_LLM_FINDINGS", "40")),
        offline=env.get("GUARDIAN_OFFLINE", "0") == "1",
    )
    values.update({k: v for k, v in overrides.items() if v is not None})
    if values["llm_mode"] not in {"live", "record", "replay"}:
        raise ValueError(f"GUARDIAN_LLM_MODE must be live|record|replay, got {values['llm_mode']!r}")
    return Settings(**values)
