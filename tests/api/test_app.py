from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from guardian.api import app as api_module
from guardian.api.app import app


class RunApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.runs_dir = Path(self.temp_dir.name)
        app.state.runs_dir = self.runs_dir
        app.state.run_starter = None
        app.state.gate_resumer = None
        self.client = TestClient(app)
        self.run_dir = self.runs_dir / "run_test_01"
        (self.run_dir / "evidence").mkdir(parents=True)
        (self.run_dir / "plans").mkdir()
        (self.run_dir / "validation").mkdir()
        self._write("run_summary.json", {"run_id": "run_test_01", "status": "done"})
        self._write("graph.json", {"nodes": [], "edges": [], "roots": []})
        self._write("changes.json", {"added": [], "removed": [], "changed": []})
        self._write("findings.json", [{"finding_id": "fd_test_01", "evidence_ids": ["ev_test_01"]}])
        self._write("evidence/ev_test_01.json", {"evidence_id": "ev_test_01", "facts": {"cvss": 9.8}})
        self._write("trace.jsonl", {"agent": "discovery", "type": "agent_start"})
        self._write(
            "plans/plan_test_01.json",
            {"plan_id": "plan_test_01", "plan_hash": "hash-good"},
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()
        app.state.runs_dir = (Path(__file__).resolve().parents[2] / "runs").resolve()
        app.state.run_starter = None
        app.state.gate_resumer = None

    def _write(self, relative_path: str, value: object) -> None:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative_path.endswith(".jsonl"):
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")

    def test_reads_run_artifacts_and_latest(self) -> None:
        self.assertEqual(self.client.get("/runs").json()[0]["run_id"], "run_test_01")
        self.assertEqual(self.client.get("/runs/latest").json()["run_id"], "run_test_01")
        self.assertEqual(self.client.get("/runs/run_test_01/graph").json()["roots"], [])
        self.assertEqual(
            self.client.get("/runs/run_test_01/findings/fd_test_01").json()["finding_id"],
            "fd_test_01",
        )
        self.assertEqual(
            self.client.get("/runs/run_test_01/evidence/ev_test_01").json()["facts"]["cvss"],
            9.8,
        )

    def test_events_stream_jsonl_records(self) -> None:
        response = self.client.get("/runs/run_test_01/events")
        self.assertEqual(response.status_code, 200)
        self.assertIn('"agent": "discovery"', response.text)

    def test_missing_artifact_is_not_returned_as_success(self) -> None:
        response = self.client.get("/runs/run_test_01/report.json")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            self.client.get("/runs/run_test_01/report").json(),
            {"json_available": False, "html_available": False},
        )

    def test_run_id_cannot_escape_runs_root(self) -> None:
        response = self.client.get("/runs/..%2F..%2Foutside/summary")
        self.assertEqual(response.status_code, 404)

    def test_decision_rejects_stale_plan_hash(self) -> None:
        response = self.client.post(
            "/runs/run_test_01/plans/plan_test_01/decision",
            json={"decision": "approve", "plan_hash": "stale"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertFalse((self.run_dir / "approvals.jsonl").exists())

    def test_reject_requires_comment(self) -> None:
        response = self.client.post(
            "/runs/run_test_01/plans/plan_test_01/decision",
            json={"decision": "reject", "plan_hash": "hash-good"},
        )
        self.assertEqual(response.status_code, 422)

    def test_decision_is_recorded_but_gate_status_is_explicit(self) -> None:
        response = self.client.post(
            "/runs/run_test_01/plans/plan_test_01/decision",
            json={"decision": "approve", "plan_hash": "hash-good"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertFalse(response.json()["gate_resumed"])
        approval = json.loads((self.run_dir / "approvals.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(approval["plan_hash"], "hash-good")

    def test_run_creation_reports_missing_pipeline_integration(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "targets" / "example"
            target.mkdir(parents=True)
            with patch.object(api_module, "ROOT_DIR", Path(root)):
                response = self.client.post("/runs", json={"repo": "targets/example"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("orchestration is not connected", response.json()["detail"])

    def test_run_creation_uses_registered_starter(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "targets" / "example"
            target.mkdir(parents=True)
            with patch.object(api_module, "ROOT_DIR", Path(root)):
                app.state.run_starter = lambda _: "run_new_01"
                response = self.client.post("/runs", json={"repo": "targets/example"})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"run_id": "run_new_01"})
