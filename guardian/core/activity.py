"""Live "what is running right now" for a run: runs/<id>/activity.json.

The trace (trace.jsonl) records what started and what finished, but a sandbox validation can sit between
"sandbox_validate" and its result for minutes with several containers working at once (build, unit tests, each
integration shard, the unpatched baseline). This module keeps, per run, the steps that are in flight right now and
the last few that finished, and writes them to activity.json so the API / UI can show them with live timers.

    with activity.scope(run_dir):              # bind the run (call_tool does this for every tool)
        with activity.step("Unit tests", kind="container", detail="..."):
            ...

The binding is a ContextVar, so threads started by a tool must carry the context (`activity.bound(fn)` /
`contextvars.copy_context().run`). Outside a scope, `step` is a no-op: tools stay usable on their own.

File shape: {"updated_at", "heartbeat_s", "running": [{id, label, kind, detail, started_at}],
"recent": [{..., ended_at, seconds, outcome}]}. While something runs, a daemon heartbeat rewrites the file every
HEARTBEAT_S seconds; a reader treats `running` as stale when updated_at is much older than that (the process died).
Writing is best effort: an I/O error never fails the step it describes.
"""

from __future__ import annotations

import contextvars
import itertools
import json
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FILE = "activity.json"
HEARTBEAT_S = 5.0
RECENT = 12  # finished steps kept for the "just finished" list

_run: contextvars.ContextVar[Path | None] = contextvars.ContextVar("guardian_activity_run", default=None)
_parent: contextvars.ContextVar[str | None] = contextvars.ContextVar("guardian_activity_parent", default=None)
_lock = threading.RLock()
_ids = itertools.count(1)
# run_dir -> {"running": {id: entry}, "recent": [entry, ...]}
_state: dict[Path, dict[str, Any]] = {}
_beat: threading.Thread | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write(run_dir: Path) -> None:
    """Atomically rewrite activity.json for `run_dir` (call with _lock held)."""
    st = _state.get(run_dir)
    if st is None:
        return
    doc = {"updated_at": _now(), "heartbeat_s": HEARTBEAT_S,
           "running": sorted(st["running"].values(), key=lambda e: e["started_at"]), "recent": st["recent"]}
    try:
        tmp = run_dir / f".{FILE}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        tmp.replace(run_dir / FILE)
    except OSError:
        pass


def _heartbeat() -> None:
    """Keep updated_at fresh while anything runs, so readers can tell a live step from a dead process."""
    import time

    while True:
        time.sleep(HEARTBEAT_S)
        with _lock:
            for run_dir, st in list(_state.items()):
                if st["running"]:
                    _write(run_dir)


def _ensure_heartbeat() -> None:
    global _beat
    if _beat is None or not _beat.is_alive():
        _beat = threading.Thread(target=_heartbeat, name="guardian-activity-heartbeat", daemon=True)
        _beat.start()


@contextmanager
def scope(run_dir: Path | None) -> Iterator[None]:
    """Bind `run_dir` for the steps started inside (no-op when None)."""
    if run_dir is None:
        yield
        return
    tok = _run.set(Path(run_dir))
    try:
        yield
    finally:
        _run.reset(tok)


def current_run() -> Path | None:
    return _run.get()


@contextmanager
def step(label: str, kind: str = "step", detail: str | None = None) -> Iterator[dict[str, Any] | None]:
    """Mark `label` as running for the duration of the block. The yielded dict's "outcome" may be set by the
    caller ("ok", "failed", "timeout", ...); an exception sets "error" and is re-raised."""
    run_dir = _run.get()
    if run_dir is None:
        yield None
        return
    sid = f"s{next(_ids)}"
    entry: dict[str, Any] = {"id": sid, "label": label, "kind": kind, "detail": detail, "started_at": _now(),
                             "parent": _parent.get()}
    with _lock:
        st = _state.setdefault(run_dir, {"running": {}, "recent": []})
        st["running"][sid] = entry
        _write(run_dir)
        _ensure_heartbeat()
    tok = _parent.set(sid)
    result: dict[str, Any] = {"outcome": "ok"}
    t0 = datetime.now(UTC)
    try:
        yield result
    except BaseException:
        result["outcome"] = "error"
        raise
    finally:
        _parent.reset(tok)
        done = {**entry, "ended_at": _now(), "seconds": round((datetime.now(UTC) - t0).total_seconds(), 1),
                "outcome": result.get("outcome") or "ok"}
        with _lock:
            st = _state.setdefault(run_dir, {"running": {}, "recent": []})
            st["running"].pop(sid, None)
            st["recent"] = [done, *st["recent"]][:RECENT]
            _write(run_dir)


def bound(fn: Callable[..., Any]) -> Callable[..., Any]:
    """`fn` wrapped to run in a copy of the caller's context (for ThreadPoolExecutor.submit / Thread targets),
    so steps started on the worker thread are attributed to the same run and parent step."""
    ctx = contextvars.copy_context()
    return lambda *a, **kw: ctx.run(fn, *a, **kw)


def read(run_dir: Path, stale_after: float | None = None) -> dict[str, Any]:
    """activity.json of a run, with "stale": True (and `running` moved aside) when the heartbeat stopped, i.e. the
    process that wrote it is gone. A missing file reads as nothing running."""
    f = Path(run_dir) / FILE
    empty = {"updated_at": None, "running": [], "recent": [], "stale": False}
    if not f.is_file():
        return empty
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    doc.setdefault("running", [])
    doc.setdefault("recent", [])
    limit = stale_after if stale_after is not None else 6 * float(doc.get("heartbeat_s") or HEARTBEAT_S)
    try:
        age = (datetime.now(UTC) - datetime.fromisoformat(doc["updated_at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        age = float("inf")
    doc["stale"] = bool(doc["running"]) and age > limit
    if doc["stale"]:
        doc["interrupted"], doc["running"] = doc["running"], []
    return doc
