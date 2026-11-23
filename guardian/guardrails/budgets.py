"""G3.6 budgets: per-agent tool calls + wall-clock, per-run LLM tokens. Owner: Dev1.

A budget is checked *before* the call. An exhausted budget blocks the call (guardrail event); the pipeline
then degrades the same way as for an unavailable tool, it never crashes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentLimit:
    tool_calls: int
    seconds: float


# Generous for Juice Shop (discovery 4 tools, detection 8, remediation 1 lookup + dry run per attempt),
# tight enough that a looping agent is stopped. The investigator's ReAct limit (8) is plan §6.1 D1-08.
DEFAULT_LIMITS: dict[str, AgentLimit] = {
    "discovery": AgentLimit(tool_calls=12, seconds=1800),
    "detection": AgentLimit(tool_calls=20, seconds=1800),
    "investigator": AgentLimit(tool_calls=8, seconds=300),
    "risk_analyst": AgentLimit(tool_calls=20, seconds=900),
    "remediation": AgentLimit(tool_calls=60, seconds=900),
    "validator": AgentLimit(tool_calls=40, seconds=1800),
}
FALLBACK_LIMIT = AgentLimit(tool_calls=10, seconds=300)


@dataclass
class Budget:
    max_llm_tokens: int = 600_000
    limits: dict[str, AgentLimit] = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    tool_calls: dict[str, int] = field(default_factory=dict)
    started: dict[str, float] = field(default_factory=dict)
    llm_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def charge_tool(self, agent: str) -> str | None:
        """Count one tool call for `agent`. Returns the reason if the budget is exhausted (call blocked)."""
        limit = self.limits.get(agent, FALLBACK_LIMIT)
        with self._lock:
            now = time.monotonic()
            start = self.started.setdefault(agent, now)
            used = self.tool_calls.get(agent, 0)
            if used >= limit.tool_calls:
                return f"{agent} used {used}/{limit.tool_calls} tool calls"
            if now - start > limit.seconds:
                return f"{agent} exceeded {limit.seconds:.0f}s wall-clock"
            self.tool_calls[agent] = used + 1
        return None

    def tokens_left(self) -> int:
        return max(0, self.max_llm_tokens - self.llm_tokens)

    def charge_tokens(self, n: int) -> None:
        with self._lock:
            self.llm_tokens += max(0, n)

    def snapshot(self) -> dict:
        return {"tool_calls": dict(self.tool_calls), "llm_tokens": self.llm_tokens,
                "max_llm_tokens": self.max_llm_tokens}
