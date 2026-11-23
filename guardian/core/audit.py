"""Append-only audit log + agent trace (G7.1, G7.2, §2.4). Owner: Dev1.

- audit.jsonl : every tool call, LLM call, guardrail hit, approval (machine record)
- trace.jsonl : AgentEvent per line (what the UI trace list shows)
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any

from guardian.core.models import AgentEvent, utcnow
from guardian.guardrails.redact import redact_obj

_ROLE_COLOURS = {
    "supervisor": "\033[95m",
    "discovery": "\033[94m",
    "detection": "\033[96m",
    "evidence_analyst": "\033[92m",
    "guardrail": "\033[91m",
}


class AuditLog:
    def __init__(self, run_dir: Path, run_id: str, echo: bool = True):
        self.run_id = run_id
        self.trace_path = run_dir / "trace.jsonl"
        self.audit_path = run_dir / "audit.jsonl"
        self.echo = echo
        self._lock = threading.Lock()
        run_dir.mkdir(parents=True, exist_ok=True)

    def _append(self, path: Path, line: str) -> None:
        with self._lock, path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def emit(self, agent: str, type: str, summary: str, **kw: Any) -> AgentEvent:
        if "data" in kw:
            kw["data"] = redact_obj(kw["data"])
        event = AgentEvent(run_id=self.run_id, agent=agent, type=type, summary=summary, **kw)
        self._append(self.trace_path, event.model_dump_json())
        if type in {"tool_call", "tool_result", "llm_call", "llm_result", "guardrail", "error"}:
            self.record(type, {"agent": agent, "summary": summary, **event.data})
        if self.echo:
            colour = _ROLE_COLOURS.get(agent, "")
            reset = "\033[0m" if colour else ""
            print(f"{colour}[{agent:>16}] {type:<11}{reset} {summary}", file=sys.stderr)
        return event

    def record(self, action: str, payload: dict[str, Any]) -> None:
        entry = {"ts": utcnow().isoformat(), "run_id": self.run_id, "action": action, **redact_obj(payload)}
        self._append(self.audit_path, json.dumps(entry, default=str))
