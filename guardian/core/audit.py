"""Append-only audit log + agent trace (G7.1, G7.2, §2.4). Owner: Dev1.

Every agent and guardrail reports through one `AuditLog` per run, so there is a single place where "what
happened" is written. Two files are produced under runs/<run_id>/:

- audit.jsonl : machine record of every tool call, LLM call, guardrail hit and approval (G7.1). Each line is
                {ts, run_id, action, ...payload}; secrets are redacted before they are written (G1.2).
- trace.jsonl : one `AgentEvent` per line, exactly what the UI trace list shows (§2.4). It is a superset of
                the audit file: every event is traced, only the "important" types are also audited.

Both files are append-only and written under a lock, because agents run on threads (parallel tool calls) and
interleaved writes would corrupt a JSONL line. Guardrail blocks always arrive as `type="guardrail"` events (G7.2).
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any

from guardian.core.models import AgentEvent, utcnow
from guardian.guardrails.redact import redact_obj

# ANSI colours for the stderr echo, one per agent role (unknown agents print uncoloured).
_ROLE_COLOURS = {
    "supervisor": "\033[95m",
    "discovery": "\033[94m",
    "detection": "\033[96m",
    "evidence_analyst": "\033[92m",
    "guardrail": "\033[91m",
}


class AuditLog:
    """Writer for one run's trace.jsonl and audit.jsonl; cheap to construct, so guardrails may build their own."""

    def __init__(self, run_dir: Path, run_id: str, echo: bool = True):
        # run_dir is created here (parents too), so an AuditLog can be the first thing a run touches.
        self.run_id = run_id
        self.trace_path = run_dir / "trace.jsonl"
        self.audit_path = run_dir / "audit.jsonl"
        self.echo = echo
        self._lock = threading.Lock()
        run_dir.mkdir(parents=True, exist_ok=True)

    def _append(self, path: Path, line: str) -> None:
        """Append one line under the lock (threads share the files; a torn line would break the JSONL)."""
        with self._lock, path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def emit(self, agent: str, type: str, summary: str, **kw: Any) -> AgentEvent:
        """Record one `AgentEvent` and return it.

        `agent` / `type` / `summary` are the trace columns; `kw` carries the optional AgentEvent fields
        (finding_id, evidence_ids, data). Side effects: always appends to trace.jsonl; for the event types that
        matter for accountability (tool/LLM calls, guardrail hits, errors) also appends to audit.jsonl; and with
        `echo` prints a one-line coloured copy to stderr for the CLI user. `data` is redacted first (G1.2).
        """
        if "data" in kw:
            kw["data"] = redact_obj(kw["data"])
        event = AgentEvent(run_id=self.run_id, agent=agent, type=type, summary=summary, **kw)
        self._append(self.trace_path, event.model_dump_json())
        # Only these types are audit-worthy; handoffs/decisions/gate events live in the trace only.
        if type in {"tool_call", "tool_result", "llm_call", "llm_result", "guardrail", "error"}:
            self.record(type, {"agent": agent, "summary": summary, **event.data})
        if self.echo:
            colour = _ROLE_COLOURS.get(agent, "")
            reset = "\033[0m" if colour else ""
            print(f"{colour}[{agent:>16}] {type:<11}{reset} {summary}", file=sys.stderr)
        return event

    def record(self, action: str, payload: dict[str, Any]) -> None:
        """Append a timestamped, redacted entry to audit.jsonl only (no trace line), e.g. for an approval."""
        entry = {"ts": utcnow().isoformat(), "run_id": self.run_id, "action": action, **redact_obj(payload)}
        self._append(self.audit_path, json.dumps(entry, default=str))
