"""G3.6 budgets: per-agent tool calls + wall-clock, per-run LLM tokens. Owner: Dev1.

A budget is checked *before* the call. An exhausted budget blocks the call (guardrail event); the pipeline
then degrades the same way as for an unavailable tool, it never crashes.

Two kinds of budget share one object, `Budget`, created per run (ToolContext.budget):
- per agent: a number of tool calls and a wall-clock window counted from the agent's first call. This stops a
  looping agent (e.g. an LLM that keeps asking for more lookups) without limiting a well-behaved one.
- per run: LLM tokens (input + output). Callers charge the usage reported by the provider after each call and
  ask `tokens_left()` before the next one; at 0 they stop calling the LLM and use deterministic fallbacks.
Limits are per process: a run resumed after the human gate gets a fresh `Budget`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentLimit:
    """Tool-call count and wall-clock seconds one agent may use (the clock starts at its first tool call)."""

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
    # per validation (reset by window()): sandbox install + baseline + build + unit + API tests can each take
    # up to GUARDIAN_SANDBOX_TIMEOUT; a real Juice Shop validation took over 30 minutes
    "validator": AgentLimit(tool_calls=40, seconds=3 * 3600),
}
# Used for an agent name that has no entry in `limits` (e.g. a new agent or a test), so nothing is unlimited.
FALLBACK_LIMIT = AgentLimit(tool_calls=10, seconds=300)


@dataclass
class Budget:
    """Mutable counters for one run. Thread-safe: charging happens under a lock because tools run in parallel.
    `started` holds each agent's first-call time (monotonic clock, immune to system clock changes)."""

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

    def window(self, agent: str) -> None:
        """Start a fresh budget window for `agent` (the validator: one window per validation attempt, so a
        long attempt cannot starve the next one in the same process)."""
        with self._lock:
            self.started.pop(agent, None)
            self.tool_calls.pop(agent, None)

    def tokens_left(self) -> int:
        """LLM tokens still available in this run (never negative). Checked before every LLM call (G3.6)."""
        return max(0, self.max_llm_tokens - self.llm_tokens)

    def charge_tokens(self, n: int) -> None:
        """Add `n` tokens (input + output of one LLM call) to the run total; a negative `n` is ignored."""
        with self._lock:
            self.llm_tokens += max(0, n)

    def snapshot(self) -> dict:
        """Plain-dict view of what was used, written into run_summary.json under "budget"."""
        return {"tool_calls": dict(self.tool_calls), "llm_tokens": self.llm_tokens,
                "max_llm_tokens": self.max_llm_tokens}
