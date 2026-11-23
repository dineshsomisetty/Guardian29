from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

ROOT_DIR = Path(__file__).resolve().parents[2]
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class CreateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(min_length=1, max_length=512)
    compare_ref: str | None = None
    llm_mode: Literal["live", "record", "replay"] | None = None


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject", "accept_risk"]
    plan_hash: str = Field(min_length=1, max_length=128)
    comment: str | None = Field(default=None, max_length=2000)


RunStarter = Callable[[CreateRunRequest], str | Awaitable[str]]
GateResumer = Callable[[str, str, DecisionRequest], None | Awaitable[None]]

app = FastAPI(title="Guardian API", version="0.1.0")
app.state.runs_dir = Path(
    os.environ.get("GUARDIAN_RUNS_DIR", ROOT_DIR / "runs")
).resolve()
app.state.run_starter = None
app.state.gate_resumer = None


def register_run_starter(starter: RunStarter) -> None:
    app.state.run_starter = starter


def register_gate_resumer(resumer: GateResumer) -> None:
    app.state.gate_resumer = resumer


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


def _runs_root(request: Request) -> Path:
    return Path(request.app.state.runs_dir).resolve()


def _run_dir(request: Request, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    root = _runs_root(request)
    candidate = (root / run_id).resolve()
    if candidate.parent != root or not candidate.is_dir():
        raise HTTPException(status_code=404, detail="Run not found")
    return candidate


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Requested run artifact not found") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON artifact: {path.name}") from exc


def _artifact(run_dir: Path, *parts: str) -> Path:
    candidate = run_dir.joinpath(*parts).resolve()
    if run_dir not in candidate.parents:
        raise HTTPException(status_code=404, detail="Requested run artifact not found")
    return candidate


def _identifier(value: str, kind: str) -> str:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise HTTPException(status_code=404, detail=f"{kind} not found")
    return value


def _summary_path(run_dir: Path) -> Path:
    return _artifact(run_dir, "run_summary.json")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/runs")
def list_runs(request: Request) -> list[Any]:
    root = _runs_root(request)
    if not root.is_dir():
        return []
    candidates = [
        item
        for item in root.iterdir()
        if item.is_dir()
        and item.resolve().parent == root
        and (item / "run_summary.json").is_file()
    ]
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return [_read_json(_summary_path(item)) for item in candidates]


@app.get("/runs/latest")
def latest_run(request: Request) -> Any:
    root = _runs_root(request)
    if not root.is_dir():
        raise HTTPException(status_code=404, detail="No completed runs found")
    candidates = [
        item
        for item in root.iterdir()
        if item.is_dir()
        and item.resolve().parent == root
        and (item / "run_summary.json").is_file()
    ]
    if not candidates:
        raise HTTPException(status_code=404, detail="No runs with summaries found")
    latest = max(candidates, key=lambda item: item.stat().st_mtime)
    return _read_json(_summary_path(latest))


@app.post("/runs", status_code=202)
async def create_run(body: CreateRunRequest, request: Request) -> dict[str, str]:
    targets_root = (ROOT_DIR / "targets").resolve()
    requested_repo = Path(body.repo)
    if requested_repo.is_absolute():
        raise HTTPException(status_code=400, detail="repo must be a path under targets/")
    repo_path = (ROOT_DIR / requested_repo).resolve()
    if targets_root not in repo_path.parents or not repo_path.is_dir():
        raise HTTPException(status_code=400, detail="repo must name an existing directory under targets/")

    starter: RunStarter | None = request.app.state.run_starter
    if starter is None:
        raise HTTPException(
            status_code=503,
            detail="Run orchestration is not connected yet; the Guardian pipeline must register a run starter.",
        )
    run_id = starter(body)
    if inspect.isawaitable(run_id):
        run_id = await run_id
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        raise HTTPException(status_code=500, detail="Run starter returned an invalid run_id")
    return {"run_id": run_id}


@app.get("/runs/{run_id}")
def get_run(request: Request, run_id: str) -> Any:
    return _read_json(_summary_path(_run_dir(request, run_id)))


@app.get("/runs/{run_id}/summary")
def get_summary(request: Request, run_id: str) -> Any:
    return _read_json(_summary_path(_run_dir(request, run_id)))


@app.get("/runs/{run_id}/graph")
def get_graph(request: Request, run_id: str) -> Any:
    return _read_json(_artifact(_run_dir(request, run_id), "graph.json"))


@app.get("/runs/{run_id}/changes")
def get_changes(request: Request, run_id: str) -> Any:
    return _read_json(_artifact(_run_dir(request, run_id), "changes.json"))


@app.get("/runs/{run_id}/findings")
def get_findings(request: Request, run_id: str) -> Any:
    return _read_json(_artifact(_run_dir(request, run_id), "findings.json"))


@app.get("/runs/{run_id}/findings/{finding_id}")
def get_finding(request: Request, run_id: str, finding_id: str) -> Any:
    _identifier(finding_id, "Finding")
    findings = _read_json(_artifact(_run_dir(request, run_id), "findings.json"))
    if not isinstance(findings, list):
        raise HTTPException(status_code=500, detail="findings.json must contain a list")
    for finding in findings:
        if isinstance(finding, dict) and finding.get("finding_id") == finding_id:
            return finding
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/runs/{run_id}/evidence/{evidence_id}")
def get_evidence(request: Request, run_id: str, evidence_id: str) -> Any:
    _identifier(evidence_id, "Evidence")
    return _read_json(_artifact(_run_dir(request, run_id), "evidence", f"{evidence_id}.json"))


@app.get("/runs/{run_id}/events")
async def stream_events(request: Request, run_id: str) -> StreamingResponse:
    run_dir = _run_dir(request, run_id)
    trace_path = _artifact(run_dir, "trace.jsonl")
    if not trace_path.is_file():
        raise HTTPException(status_code=404, detail="Trace not found")

    async def event_stream():
        offset = 0
        event_id = 0
        while True:
            if await request.is_disconnected():
                break
            try:
                with trace_path.open("r", encoding="utf-8") as trace:
                    trace.seek(offset)
                    while True:
                        line_offset = trace.tell()
                        line = trace.readline()
                        if not line or not line.endswith("\n"):
                            trace.seek(line_offset)
                            break
                        offset = trace.tell()
                        payload = line.strip()
                        if payload:
                            event_id += 1
                            yield f"id: {event_id}\ndata: {payload}\n\n"
            except FileNotFoundError:
                break

            summary_path = _summary_path(run_dir)
            if summary_path.is_file():
                summary = _read_json(summary_path)
                if isinstance(summary, dict) and summary.get("status") in {"done", "failed"}:
                    break
            yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/runs/{run_id}/plans")
def list_plans(request: Request, run_id: str) -> list[Any]:
    plans_dir = _artifact(_run_dir(request, run_id), "plans")
    if not plans_dir.is_dir():
        return []
    return [
        _read_json(_artifact(plans_dir.parent, "plans", path.name))
        for path in sorted(plans_dir.glob("*.json"))
    ]


@app.get("/runs/{run_id}/plans/{plan_id}")
def get_plan(request: Request, run_id: str, plan_id: str) -> Any:
    _identifier(plan_id, "Plan")
    return _read_json(_artifact(_run_dir(request, run_id), "plans", f"{plan_id}.json"))


@app.post("/runs/{run_id}/plans/{plan_id}/decision", status_code=202)
async def decide_plan(
    request: Request,
    run_id: str,
    plan_id: str,
    body: DecisionRequest,
) -> dict[str, Any]:
    _identifier(plan_id, "Plan")
    run_dir = _run_dir(request, run_id)
    plan = _read_json(_artifact(run_dir, "plans", f"{plan_id}.json"))
    if not isinstance(plan, dict) or plan.get("plan_id") != plan_id:
        raise HTTPException(status_code=500, detail="Plan artifact does not match its filename")
    if plan.get("plan_hash") != body.plan_hash:
        raise HTTPException(status_code=409, detail="plan_hash does not match the current plan")
    if body.decision in {"reject", "accept_risk"} and not (body.comment or "").strip():
        raise HTTPException(status_code=422, detail="A comment is required for reject and accept_risk")

    approval = {
        "plan_id": plan_id,
        "plan_hash": body.plan_hash,
        "decision": body.decision,
        "comment": body.comment,
        "decided_by": "api",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    approvals_path = _artifact(run_dir, "approvals.jsonl")
    with approvals_path.open("a", encoding="utf-8", newline="\n") as approvals:
        approvals.write(json.dumps(approval, separators=(",", ":")) + "\n")

    resumer: GateResumer | None = request.app.state.gate_resumer
    if resumer is None:
        return {
            "recorded": True,
            "gate_resumed": False,
            "detail": "Decision recorded; the LangGraph gate resumer is not connected.",
        }
    result = resumer(run_id, plan_id, body)
    if inspect.isawaitable(result):
        await result
    return {"recorded": True, "gate_resumed": True}


@app.get("/runs/{run_id}/validation")
def get_validation(request: Request, run_id: str) -> list[Any]:
    validation_dir = _artifact(_run_dir(request, run_id), "validation")
    if not validation_dir.is_dir():
        return []
    return [
        _read_json(_artifact(validation_dir.parent, "validation", path.name))
        for path in sorted(validation_dir.glob("*.json"))
    ]


@app.get("/runs/{run_id}/report")
def get_report_availability(request: Request, run_id: str) -> dict[str, bool]:
    run_dir = _run_dir(request, run_id)
    return {
        "json_available": _artifact(run_dir, "report.json").is_file(),
        "html_available": _artifact(run_dir, "report.html").is_file(),
    }


@app.get("/runs/{run_id}/report.json")
def get_report_json(request: Request, run_id: str) -> Any:
    return _read_json(_artifact(_run_dir(request, run_id), "report.json"))


@app.get("/runs/{run_id}/report.html")
def get_report_html(request: Request, run_id: str) -> Response:
    path = _artifact(_run_dir(request, run_id), "report.html")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Requested run artifact not found")
    return FileResponse(path, media_type="text/html")
