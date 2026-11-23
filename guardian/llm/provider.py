"""LLM provider with live / record / replay modes (§5.3, C27). Owner: Dev1.

- anthropic (default): official Anthropic SDK, structured JSON output, server-side refusal fallback.
- openai_compat: any OpenAI-compatible endpoint via LLM_BASE_URL (e.g. a local model). Same code path above.
- record: live call + store response under data/cache/llm/<hash>.json
- replay: serve from cache only; fail closed if missing (no network).

Keys come only from the environment and are never logged (G1.3).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from guardian.core.config import Settings


class LLMError(Exception):
    pass


class LLMRefusal(LLMError):
    pass


class ReplayMiss(LLMError):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    cached: bool = False
    usage: dict[str, int] | None = None


class Backend(Protocol):
    model: str

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse: ...


# ---------------------------------------------------------------- backends


class AnthropicBackend:
    def __init__(self, model: str, effort: str = "low", max_tokens: int = 16000):
        import anthropic  # local import: replay mode never needs the SDK or a key

        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise LLMError("ANTHROPIC_API_KEY not set (live/record mode needs it; use replay for offline)")
        self._client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        resp = self._client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if resp.stop_reason == "refusal":
            raise LLMRefusal(f"model declined (category={getattr(resp.stop_details, 'category', None)})")
        if resp.stop_reason == "max_tokens":
            raise LLMError("output truncated at max_tokens")
        text = next((b.text for b in resp.content if b.type == "text"), None)
        if text is None:
            raise LLMError("no text block in response")
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        return LLMResponse(text=text, model=resp.model, usage=usage)


class OpenAICompatBackend:
    def __init__(self, model: str, base_url: str, timeout: float = 120.0):
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._key = os.environ.get("LLM_API_KEY", "")
        self._timeout = timeout

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "output", "schema": schema}},
        }
        r = httpx.post(self._url, json=body, headers=headers, timeout=self._timeout)
        if r.status_code >= 400:
            raise LLMError(f"endpoint returned HTTP {r.status_code}")
        data = r.json()
        return LLMResponse(text=data["choices"][0]["message"]["content"], model=data.get("model", self.model))


# ---------------------------------------------------------------- mode wrapper


class LLMProvider:
    """Wraps a backend with record/replay caching. `backend` may be injected (tests: fake LLM)."""

    def __init__(self, mode: str, cache_dir: Path, model: str, backend: Backend | None = None,
                 backend_factory=None):
        self.mode = mode
        self.cache_dir = cache_dir
        self.model = model
        self._backend = backend
        self._factory = backend_factory

    @classmethod
    def from_settings(cls, s: Settings) -> LLMProvider:
        def factory() -> Backend:
            if s.llm_provider == "openai_compat":
                if not s.llm_base_url:
                    raise LLMError("GUARDIAN_LLM_PROVIDER=openai_compat needs LLM_BASE_URL")
                return OpenAICompatBackend(s.llm_model, s.llm_base_url)
            return AnthropicBackend(s.llm_model)

        return cls(s.llm_mode, s.llm_cache_dir, s.llm_model, backend_factory=factory)

    def _backend_or_create(self) -> Backend:
        if self._backend is None:
            if self._factory is None:
                raise LLMError("no LLM backend configured")
            self._backend = self._factory()
        return self._backend

    def cache_key(self, agent: str, system: str, user: str, schema: dict[str, Any]) -> str:
        blob = json.dumps([agent, self.model, system, user, schema], sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def complete_json(self, agent: str, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        key = self.cache_key(agent, system, user, schema)
        path = self.cache_dir / f"{key}.json"
        if self.mode == "replay":
            if not path.exists():
                raise ReplayMiss(f"no recorded LLM response for {agent} (key {key[:12]})")
            data = json.loads(path.read_text(encoding="utf-8"))
            return LLMResponse(text=data["text"], model=data["model"], cached=True)
        resp = self._backend_or_create().complete_json(system, user, schema)
        if self.mode == "record":
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"agent": agent, "text": resp.text, "model": resp.model}), encoding="utf-8")
        return resp
