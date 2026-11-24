"""Evidence store, JSON-file backend (§2.1, C10). Owner: Dev1.

Layout under runs/<run_id>/:
  evidence/<evidence_id>.json   one Evidence, written once, never overwritten (append-only)
  findings.json                 list[Finding]; findings are never deleted, only status/analysis updated

Day 2 swaps this for SQLite behind the same interface.

The store is the run's memory: tools add `Evidence` (the only thing grounding checks LLM claims against, G4),
agents add and update `Finding`s that cite that evidence. Two invariants are enforced here and not left to
callers: evidence is immutable once written, and a finding can only cite evidence that exists (a Finding
without evidence is a bug in the pipeline, not a state to repair later). All mutations take a lock because
detectors and the investigator run on worker threads.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from guardian.core.models import Evidence, Finding


class StoreError(Exception):
    """An append-only or referential rule was broken (duplicate evidence id, finding citing unknown evidence)."""

    pass


class JsonStore:
    """In-memory index of one run's evidence and findings, persisted to JSON files as they change.

    Constructing it on an existing run directory reloads everything, which is how a run resumed at the human
    gate (possibly in a new process) sees the evidence and findings of its first half."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.evidence_dir = run_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.findings_path = run_dir / "findings.json"
        self._evidence: dict[str, Evidence] = {}
        self._findings: dict[str, Finding] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Read evidence/*.json and findings.json from disk into memory (no-op on a fresh run directory)."""
        for path in self.evidence_dir.glob("*.json"):
            ev = Evidence.model_validate_json(path.read_text(encoding="utf-8"))
            self._evidence[ev.evidence_id] = ev
        if self.findings_path.exists():
            for raw in json.loads(self.findings_path.read_text(encoding="utf-8")):
                fd = Finding.model_validate(raw)
                self._findings[fd.finding_id] = fd

    # ------------------------------------------------------------ evidence
    def add_evidence(self, ev: Evidence) -> Evidence:
        """Write evidence/<id>.json once. A second write with the same id raises StoreError (append-only)."""
        with self._lock:
            if ev.evidence_id in self._evidence:
                raise StoreError(f"evidence {ev.evidence_id} already exists (append-only)")
            path = self.evidence_dir / f"{ev.evidence_id}.json"
            path.write_text(ev.model_dump_json(indent=2), encoding="utf-8")
            self._evidence[ev.evidence_id] = ev
        return ev

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        return self._evidence.get(evidence_id)

    def has_evidence(self, evidence_id: str) -> bool:
        return evidence_id in self._evidence

    def list_evidence(self) -> list[Evidence]:
        return list(self._evidence.values())

    # ------------------------------------------------------------ findings
    def add_finding(self, fd: Finding) -> Finding:
        """Register a new finding and rewrite findings.json. Every cited evidence id must already be stored."""
        with self._lock:
            if fd.finding_id in self._findings:
                raise StoreError(f"finding {fd.finding_id} already exists")
            missing = [e for e in fd.evidence_ids if e not in self._evidence]
            if missing:
                raise StoreError(f"finding {fd.finding_id} cites unknown evidence {missing}")
            self._findings[fd.finding_id] = fd
            self._flush()
        return fd

    def update_finding(self, fd: Finding) -> Finding:
        """Replace a stored finding (status, explanation, claims ...). Findings are never deleted."""
        with self._lock:
            if fd.finding_id not in self._findings:
                raise StoreError(f"unknown finding {fd.finding_id}")
            self._findings[fd.finding_id] = fd
            self._flush()
        return fd

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def list_findings(self) -> list[Finding]:
        return list(self._findings.values())

    def _flush(self) -> None:
        """Rewrite findings.json atomically (temp file + replace) so a crash never leaves a half-written list.
        Callers hold the lock."""
        data = [f.model_dump(mode="json") for f in self._findings.values()]
        tmp = self.findings_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.findings_path)
