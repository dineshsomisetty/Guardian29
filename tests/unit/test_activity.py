"""Live activity (runs/<id>/activity.json): what is running now, nested steps, worker threads, stale writers."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from guardian.core import activity
from guardian.tools.sandbox import phase_label


def _doc(run_dir):
    return json.loads((run_dir / activity.FILE).read_text(encoding="utf-8"))


def test_step_outside_a_scope_is_a_noop(tmp_path):
    with activity.step("x") as act:
        assert act is None
    assert not (tmp_path / activity.FILE).exists()


def test_running_then_recent_with_parent_and_outcome(tmp_path):
    with activity.scope(tmp_path):
        with activity.step("validator: sandbox_validate", kind="tool") as outer:
            with activity.step("Unit tests", kind="container") as inner:
                doc = _doc(tmp_path)
                labels = [e["label"] for e in doc["running"]]
                assert labels == ["validator: sandbox_validate", "Unit tests"]
                assert doc["running"][1]["parent"] == doc["running"][0]["id"]
                inner["outcome"] = "exit 1"
            assert [e["label"] for e in _doc(tmp_path)["running"]] == ["validator: sandbox_validate"]
            assert outer is not None
    doc = _doc(tmp_path)
    assert doc["running"] == []
    assert [(e["label"], e["outcome"]) for e in doc["recent"][:2]] == [
        ("validator: sandbox_validate", "ok"), ("Unit tests", "exit 1")]


def test_error_marks_the_step_and_reraises(tmp_path):
    with activity.scope(tmp_path), pytest.raises(RuntimeError):
        with activity.step("boom"):
            raise RuntimeError("x")
    assert _doc(tmp_path)["recent"][0]["outcome"] == "error"


def test_worker_threads_report_under_the_same_run(tmp_path):
    seen = threading.Barrier(3)

    def shard(i):
        with activity.step(f"Integration tests (shard {i})", kind="container"):
            seen.wait(timeout=5)  # all three are running at the same moment
            if i == 1:
                return [e["label"] for e in _doc(tmp_path)["running"]]
        return None

    with activity.scope(tmp_path), activity.step("validator: sandbox_validate"):
        with ThreadPoolExecutor(3) as pool:
            out = [f.result() for f in [pool.submit(activity.bound(shard), i) for i in (1, 2, 3)]]
    running = out[0]
    assert "validator: sandbox_validate" in running and sum("shard" in r for r in running) == 3
    assert _doc(tmp_path)["running"] == []


def test_read_marks_a_dead_writer_stale(tmp_path):
    old = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    (tmp_path / activity.FILE).write_text(json.dumps(
        {"updated_at": old, "heartbeat_s": 5, "running": [{"id": "s1", "label": "Unit tests"}], "recent": []}))
    doc = activity.read(tmp_path)
    assert doc["stale"] is True and doc["running"] == [] and doc["interrupted"][0]["label"] == "Unit tests"
    assert activity.read(tmp_path / "missing")["running"] == []


@pytest.mark.parametrize("name,container,text", [
    ("integration-2", "guardian-at_x-integration-2", "Integration tests (shard 2)"),
    ("test", "guardian-at_baselineabc-test", "Baseline (unpatched): Unit tests"),
    ("build", None, "Build"),
])
def test_phase_labels(name, container, text):
    assert phase_label(name, container) == text


def test_old_excerpt_is_split_back_into_phases():
    from guardian.reporting.narrative import _split_excerpt

    text = "$ docker run [build] exit=0\nbuilt ok\n$ docker run [test] exit=1\nnot ok 1 - x\n# fail 1"
    assert _split_excerpt(text) == {"build": "built ok", "test": "not ok 1 - x\n# fail 1"}
    assert _split_excerpt("no heads here") == {}


def test_phase_facts_keep_command_counts_and_a_full_log(tmp_path):
    from pathlib import Path

    from guardian.core.config import load_settings
    from guardian.tools.registry import ToolContext
    from guardian.tools.sandbox import Phase, _phase_facts

    ctx = ToolContext(run_id="r", run_dir=tmp_path, repo=Path("."), settings=load_settings())
    out = "ok 1 - a\nnot ok 2 - b fails\n# tests 2\n# pass 1\n# fail 1\n"
    ph = Phase("integration-2", ["docker", "run", "img", "sh", "-c", "npm run test:api"], 1, out, 12.34)
    f = _phase_facts(ctx, "at_1", ph)
    assert f["label"] == "Integration tests (shard 2)" and f["command"] == "npm run test:api"
    assert f["tests"] == {"passed": 1, "failed": 1, "total": 2} and f["seconds"] == 12.3
    assert (tmp_path / f["log"]).read_text(encoding="utf-8") == out and "# fail 1" in f["output_tail"]
