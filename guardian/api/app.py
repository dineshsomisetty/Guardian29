"""Guardian HTTP API (D3-03 + D3-09): read-only views of runs/<id>/ plus start-run and the human-gate decision.

Security (see guardian/api/auth.py):
* authentication: bearer tokens from GUARDIAN_API_TOKENS (name:token:role); with none configured the API is a
  local dev tool and `serve_api` refuses to bind anything but loopback;
* authorization: viewer reads, operator starts runs, approver decides at the human gate; `decided_by` is the
  authenticated name, never a request field;
* runs can only target directories under the allowed target roots (GUARDIAN_TARGET_ROOTS, default targets/);
* at most GUARDIAN_MAX_ACTIVE_RUNS background runs at once (429 beyond), one per run id (409);
* CORS only from the UI origins (GUARDIAN_UI_ORIGINS, default the Vite dev server).
Work copies (runs/<id>/work, attempts/*/work) are never served: every route maps to a fixed file name or a
strictly validated id, so no user path reaches the disk.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi import Path as PathParam
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from guardian.api.auth import Principal, TokenStore, check_bind, principal_for
from guardian.core.config import REPO_ROOT, load_settings
from guardian.core.models import Approval

RUN_RE = r"^(latest|run_[A-Za-z0-9_]+)$"
FID_RE = r"^fd_[0-9A-Z]{26}$"
EID_RE = r"^ev_[0-9A-Z]{26}$"
PID_RE = r"^pl_[0-9A-Z]{26}$"
AID_RE = r"^at_[0-9A-Z]{26}$"

RunId = Annotated[str, PathParam(pattern=RUN_RE)]
Fid = Annotated[str, PathParam(pattern=FID_RE)]
Eid = Annotated[str, PathParam(pattern=EID_RE)]
Pid = Annotated[str, PathParam(pattern=PID_RE)]
Aid = Annotated[str, PathParam(pattern=AID_RE)]

SSE_POLL_S = 0.25
SSE_KEEPALIVE_S = 15.0
SSE_GATE_IDLE_S = 3.0  # end the stream this long after the last line while waiting at the human gate


class DecisionBody(BaseModel):
    decision: Literal["approve", "reject", "accept_risk"]
    comment: str | None = Field(default=None, max_length=2000)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{12,64}$")
    decided_by: str = Field(default="human", max_length=64)  # local dev mode only; token mode uses the caller


class StartRunBody(BaseModel):
    repo: str
    compare_ref: str | None = None
    llm_mode: Literal["live", "record", "replay"] | None = None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HTTPException(404, f"{path.name} not found") from None
    except ValueError:
        raise HTTPException(500, f"{path.name} is not valid JSON") from None


def _list_json(directory: Path) -> list[Any]:
    if not directory.is_dir():
        return []
    return [_read_json(p) for p in sorted(directory.glob("*.json"))]


def _mark_failed(runs_dir: Path, run_id: str, exc: BaseException) -> None:
    """A crashed background thread must not leave the run looking 'running' forever."""
    try:
        d = runs_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        summary = d / "run_summary.json"
        if not summary.exists():
            summary.write_text(json.dumps({"run_id": run_id, "status": "failed", "error": str(exc)}),
                               encoding="utf-8")
    except OSError:
        pass


def _target_roots() -> list[Path]:
    raw = os.environ.get("GUARDIAN_TARGET_ROOTS")
    roots = [Path(p) for p in raw.split(os.pathsep) if p.strip()] if raw else [REPO_ROOT / "targets"]
    return [r.resolve() for r in roots]


def create_app(runs_dir: Path | None = None, *, tokens: TokenStore | None = None,
               target_roots: list[Path] | None = None, max_active: int | None = None) -> FastAPI:
    runs = Path(runs_dir) if runs_dir is not None else load_settings().runs_dir
    store = tokens if tokens is not None else TokenStore.from_env()
    roots = [Path(r).resolve() for r in target_roots] if target_roots is not None else _target_roots()
    limit = max_active if max_active is not None else int(os.environ.get("GUARDIAN_MAX_ACTIVE_RUNS", "2"))

    def viewer(request: Request) -> Principal:
        # the browser's EventSource cannot send headers: only the SSE route takes ?access_token=
        return principal_for(request, store, "viewer", allow_query=request.url.path.endswith("/events"))

    app = FastAPI(title="Guardian API", docs_url=None, redoc_url=None, dependencies=[Depends(viewer)])
    origins = os.environ.get("GUARDIAN_UI_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in origins.split(",") if o.strip()],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "Last-Event-ID"],
    )
    active: set[str] = set()  # run ids with a background thread in flight
    lock = threading.Lock()

    def run_dir(run_id: str) -> Path:
        if run_id == "latest":
            latest = runs / "LATEST"
            run_id = latest.read_text(encoding="utf-8").strip() if latest.is_file() else ""
            if not re.fullmatch(r"run_[A-Za-z0-9_]+", run_id):
                raise HTTPException(404, "no runs yet")
        d = runs / run_id
        if not d.is_dir():
            raise HTTPException(404, f"run {run_id} not found")
        return d

    def status_of(d: Path) -> tuple[str, Any]:
        f = d / "run_summary.json"
        if not f.is_file():
            return "running", None
        summary = _read_json(f)
        return str(summary.get("status", "running")), summary

    def spawn(run_id: str, fn, /, *args, **kwargs) -> None:
        def target() -> None:
            try:
                fn(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 - thread boundary
                _mark_failed(runs, run_id, exc)
            finally:
                with lock:
                    active.discard(run_id)

        with lock:
            if run_id in active:
                raise HTTPException(409, f"run {run_id} is already busy")
            if len(active) >= limit:
                raise HTTPException(429, f"{len(active)} runs already in progress (GUARDIAN_MAX_ACTIVE_RUNS={limit})",
                                    headers={"Retry-After": "30"})
            active.add(run_id)
        threading.Thread(target=target, name=f"guardian-{run_id}", daemon=True).start()

    # ---- starting runs -------------------------------------------------
    # ---- who am I ------------------------------------------------------
    @app.get("/auth/me")
    def me(request: Request) -> dict:
        p = principal_for(request, store, "viewer")
        return {"name": p.name, "role": p.role, "mode": "token" if store.enabled else "local-dev",
                "can_start_runs": p.can("operator"), "can_decide": p.can("approver")}

    @app.post("/runs", status_code=202)
    def start_run(body: StartRunBody, request: Request) -> dict:
        principal_for(request, store, "operator")
        repo = Path(body.repo)
        if not repo.is_dir():
            raise HTTPException(400, f"repo is not an existing directory: {body.repo}")
        resolved = repo.resolve()
        if not any(resolved == r or r in resolved.parents for r in roots):
            raise HTTPException(403, "repo is outside the allowed target roots (GUARDIAN_TARGET_ROOTS)")
        from guardian.graph import workflow  # lazy: may not exist yet while others build it

        run_id = workflow.new_run_id()
        settings = load_settings(runs_dir=runs, llm_mode=body.llm_mode)
        spawn(run_id, workflow.run, repo.resolve(), run_id=run_id, settings=settings,
              echo=False, compare_ref=body.compare_ref)
        return {"run_id": run_id}

    # ---- run views -----------------------------------------------------
    @app.get("/runs")
    def list_runs() -> list[str]:
        if not runs.is_dir():
            return []
        return sorted((p.name for p in runs.iterdir()
                       if p.is_dir() and re.fullmatch(r"run_[A-Za-z0-9_]+", p.name)), reverse=True)

    @app.get("/runs/{run_id}")
    def get_run(run_id: RunId) -> dict:
        d = run_dir(run_id)
        status, summary = status_of(d)
        return {"run_id": d.name, "status": status, "summary": summary}

    def fixed(name: str, file: str) -> None:
        def handler(run_id: RunId) -> Any:
            return _read_json(run_dir(run_id) / file)

        handler.__name__ = f"get_{name.replace('.', '_')}"
        app.get(f"/runs/{{run_id}}/{name}")(handler)

    fixed("summary", "run_summary.json")
    fixed("graph", "graph.json")
    fixed("changes", "changes.json")
    fixed("findings", "findings.json")
    fixed("report.json", "report.json")

    @app.get("/runs/{run_id}/risk")
    def get_risk(run_id: RunId) -> Any:
        f = run_dir(run_id) / "risk.json"
        return _read_json(f) if f.is_file() else []

    @app.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
    def get_report_html(run_id: RunId) -> HTMLResponse:
        f = run_dir(run_id) / "report.html"
        if not f.is_file():
            raise HTTPException(404, "report.html not found")
        return HTMLResponse(f.read_text(encoding="utf-8"))

    @app.get("/runs/{run_id}/findings/{fid}")
    def get_finding(run_id: RunId, fid: Fid) -> Any:
        for f in _read_json(run_dir(run_id) / "findings.json"):
            if f.get("finding_id") == fid:
                return f
        raise HTTPException(404, f"finding {fid} not found")

    @app.get("/runs/{run_id}/evidence/{eid}")
    def get_evidence(run_id: RunId, eid: Eid) -> Any:
        return _read_json(run_dir(run_id) / "evidence" / f"{eid}.json")

    @app.get("/runs/{run_id}/plans")
    def list_plans(run_id: RunId) -> list:
        return _list_json(run_dir(run_id) / "plans")

    @app.get("/runs/{run_id}/plans/{plan_id}")
    def get_plan(run_id: RunId, plan_id: Pid) -> Any:
        return _read_json(run_dir(run_id) / "plans" / f"{plan_id}.json")

    @app.get("/runs/{run_id}/attempts/{attempt_id}/pr.md")
    def get_pr_markdown(run_id: RunId, attempt_id: Aid) -> Response:
        f = run_dir(run_id) / "attempts" / attempt_id / "PR.md"  # fixed file name, id validated by regex
        if not f.is_file():
            raise HTTPException(404, "PR.md not found")
        return Response(f.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/runs/{run_id}/validation")
    def list_validation(run_id: RunId) -> list:
        return _list_json(run_dir(run_id) / "validation")

    @app.get("/runs/{run_id}/approvals")
    def list_approvals(run_id: RunId) -> list:
        f = run_dir(run_id) / "approvals.jsonl"
        if not f.is_file():
            return []
        return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]

    # ---- human gate ----------------------------------------------------
    @app.post("/runs/{run_id}/plans/{plan_id}/decision", status_code=202)
    def decide(run_id: RunId, plan_id: Pid, body: DecisionBody, request: Request) -> dict:
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        pending_file = d / "pending_plan.json"
        if not pending_file.is_file():
            raise HTTPException(409, "no plan is pending a decision")
        pending = _read_json(pending_file)
        if plan_id != pending.get("plan_id") or body.plan_hash != pending.get("plan_hash"):
            raise HTTPException(400, "plan_id/plan_hash do not match the pending plan (G5.1)")
        if body.decision in ("reject", "accept_risk") and not (body.comment and body.comment.strip()):
            raise HTTPException(400, f"{body.decision} requires a comment (G5.2)")
        decided_by = who.name if who.authenticated else (body.decided_by.strip() or "human")
        approval = Approval(plan_id=plan_id, plan_hash=body.plan_hash, decision=body.decision,
                            comment=body.comment, decided_by=decided_by)
        from guardian.graph import workflow

        spawn(d.name, workflow.resume, d.name, approval, settings=load_settings(runs_dir=runs), echo=False)
        return {"run_id": d.name, "plan_id": plan_id, "decision": body.decision, "decided_by": decided_by}

    # ---- live trace (SSE) ------------------------------------------------
    @app.get("/runs/{run_id}/events")
    async def events(run_id: RunId, request: Request) -> StreamingResponse:
        d = run_dir(run_id)
        trace = d / "trace.jsonl"
        try:
            sent = max(int(request.headers.get("last-event-id", "-1")) + 1, 0)
        except ValueError:
            sent = 0

        pos = {"bytes": 0, "lines": 0}

        def read_new(offset: int) -> list[str]:
            """Complete lines after line `offset`. Keeps a byte cursor so a long trace is read once, not on
            every poll; a partial last line stays unread until its newline arrives."""
            if not trace.is_file():
                return []
            with trace.open("rb") as fh:
                if pos["lines"] > offset:  # client asked to rewind (Last-Event-ID): start over
                    pos["bytes"] = pos["lines"] = 0
                fh.seek(pos["bytes"])
                chunk = fh.read()
            end = chunk.rfind(b"\n")
            if end < 0:
                return []
            lines = chunk[:end].decode("utf-8", errors="replace").split("\n")
            pos["bytes"] += end + 1
            first = pos["lines"]
            pos["lines"] += len(lines)
            return lines[max(0, offset - first):]

        async def stream():
            nonlocal sent
            idle = since_keepalive = 0.0
            while True:
                if await request.is_disconnected():
                    return
                new = await asyncio.to_thread(read_new, sent)
                complete = []
                for ln in new:  # a half-written last line is retried on the next poll
                    try:
                        json.loads(ln)
                    except ValueError:
                        break
                    complete.append(ln)
                for ln in complete:
                    yield f"id: {sent}\ndata: {ln}\n\n"
                    sent += 1
                if complete:
                    idle = since_keepalive = 0.0
                    continue
                status, _ = await asyncio.to_thread(status_of, d)
                if status in ("done", "failed"):
                    return
                if status == "awaiting_human" and idle >= SSE_GATE_IDLE_S:
                    return
                await asyncio.sleep(SSE_POLL_S)
                idle += SSE_POLL_S
                since_keepalive += SSE_POLL_S
                if since_keepalive >= SSE_KEEPALIVE_S:
                    since_keepalive = 0.0
                    yield ": keep-alive\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    return app


def serve_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    store = TokenStore.from_env()
    check_bind(host, store)
    uvicorn.run(create_app(tokens=store), host=host, port=port, log_level="info")
