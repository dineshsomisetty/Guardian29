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

from guardian.core.config import PROVIDER_DEFAULTS, Settings


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
    """OpenAI-compatible chat completions (DeepSeek, local models).

    json_mode="json_object": DeepSeek's JSON output mode — the schema is given in the system prompt and the
    reply is validated by our own Pydantic parser (G4.1). json_mode="json_schema": endpoints with strict schemas.
    """

    def __init__(self, model: str, base_url: str, key_env: str = "LLM_API_KEY", json_mode: str = "json_schema",
                 timeout: float = 180.0, max_tokens: int = 8000):
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._key = os.environ.get(key_env, "")
        self._key_env = key_env
        self._json_mode = json_mode
        self._timeout = timeout
        self._max_tokens = max_tokens

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> LLMResponse:
        if not self._key and "api." in self._url:
            raise LLMError(f"{self._key_env} not set (live/record mode needs it; use replay for offline)")
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        if self._json_mode == "json_object":
            system = (system + "\n\nRespond with a single JSON object (json) that matches this JSON schema "
                      "exactly, no prose:\n" + json.dumps(schema))
            fmt: dict[str, Any] = {"type": "json_object"}
        else:
            fmt = {"type": "json_schema", "json_schema": {"name": "output", "schema": schema}}
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": fmt,
            "max_tokens": self._max_tokens,
            "temperature": 0,
        }
        try:
            r = httpx.post(self._url, json=body, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            raise LLMError(f"endpoint unreachable: {type(exc).__name__}") from exc
        if r.status_code >= 400:
            raise LLMError(f"endpoint returned HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        choice = data["choices"][0]
        if choice.get("finish_reason") == "length":
            raise LLMError("output truncated at max_tokens")
        usage = data.get("usage") or {}
        return LLMResponse(text=choice["message"]["content"] or "", model=data.get("model", self.model),
                           usage={"input_tokens": usage.get("prompt_tokens", 0),
                                  "output_tokens": usage.get("completion_tokens", 0)})


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
            if s.llm_provider == "anthropic":
                return AnthropicBackend(s.llm_model)
            if not s.llm_base_url:
                raise LLMError(f"GUARDIAN_LLM_PROVIDER={s.llm_provider} needs LLM_BASE_URL")
            key_env = PROVIDER_DEFAULTS.get(s.llm_provider, {}).get("key_env", "LLM_API_KEY")
            mode = "json_object" if s.llm_provider == "deepseek" else "json_schema"
            return OpenAICompatBackend(s.llm_model, s.llm_base_url, key_env=key_env, json_mode=mode)

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
