"""Guardian HTTP API (D3-03 + D3-09): read-only views of runs/<id>/ plus start-run and the human-gate decision.

Who calls it: the React UI (ui/), CI bots and `guardian serve` (guardian/serve.py -> `serve_api`). It reads the
artefacts a run leaves under runs/<run_id>/ and, for two POST routes, starts or resumes the LangGraph workflow in
a background thread. Nothing here analyses code itself.

Route table (every route needs at least role "viewer"; `{run}` is a run id or the alias "latest"):

  method path                                   returns                                        role
  GET    /auth/me                               caller name, role, mode, can_start/can_decide  viewer
  POST   /runs                                  202 {run_id}; starts a run on body.repo        operator
  GET    /runs                                  run ids, newest first                          viewer
  GET    /runs/{run}                            {run_id, status, summary}                      viewer
  GET    /runs/{run}/summary|graph|changes|     the matching fixed JSON file of the run        viewer
         findings|report.json|recommendations
  GET    /runs/{run}/risk                       risk.json (the prioritised ranking), [] if none viewer
  GET    /runs/{run}/report.html                the rendered HTML report                       viewer
  GET    /runs/{run}/findings/{fid}             one finding                                    viewer
  GET    /runs/{run}/evidence/{eid}             one evidence record                            viewer
  GET    /runs/{run}/plans[/{plan_id}]          remediation plans (all, or one)                viewer
  GET    /runs/{run}/attempts/{aid}/pr.md       PR.md of a remediation attempt (markdown)      viewer
  GET    /runs/{run}/validation                 validation results                             viewer
  GET    /runs/{run}/trace                      whole agent trace (AgentEvent list)            viewer
  GET    /runs/{run}/watch                      continuous-monitoring checks (guardian watch)  viewer
  GET    /runs/{run}/approvals                  approvals.jsonl, the human decisions           viewer
  GET    /runs/{run}/events                     live trace as Server-Sent Events               viewer
  POST   /runs/{run}/plans/{plan}/decision      202; one decision for the pending plan         approver
  POST   /runs/{run}/batches/{batch}/decisions  202; decisions for the pending fix batch       approver

Human-gate guardrails enforced by the two POST decision routes (before any background work starts):
* G5.1 hash binding: the decision must carry the plan_id and plan_hash of what is pending, so an approval
  can never be applied to a plan that changed after the human looked at it (400 otherwise);
* G5.2 comment required: "reject" and "accept_risk" need a non-empty comment (batch: a reject needs a reason_type);
* decided_by is the authenticated token name, never trusted from the request body in token mode.
A decision is only *recorded* here: the route builds an `Approval` and hands it to `workflow.resume` /
`workflow.resume_batch` on a background thread (`spawn`), then returns 202 at once. The UI follows progress via
/events or by polling /runs/{run}; the run status goes awaiting_human -> running -> done/failed.

CORS: only the origins in GUARDIAN_UI_ORIGINS (comma separated; default the Vite dev server on :5173), GET/POST.

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
from datetime import UTC, datetime
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
from guardian.core.plans import read_approvals

# Path-parameter patterns. Every id that reaches the file system is matched against one of these first, so a
# request can never smuggle "../" or an absolute path into a runs/ lookup (path traversal defence).
RUN_RE = r"^(latest|run_[A-Za-z0-9_]+)$"
FID_RE = r"^fd_[0-9A-Z]{26}$"
EID_RE = r"^ev_[0-9A-Z]{26}$"
PID_RE = r"^pl_[0-9A-Z]{26}$"
AID_RE = r"^at_[0-9A-Z]{26}$"
BID_RE = r"^bt_[0-9A-Z]{26}$"

# Typed aliases so FastAPI validates (and 422s) a malformed id before the handler runs.
RunId = Annotated[str, PathParam(pattern=RUN_RE)]
Fid = Annotated[str, PathParam(pattern=FID_RE)]
Eid = Annotated[str, PathParam(pattern=EID_RE)]
Pid = Annotated[str, PathParam(pattern=PID_RE)]
Aid = Annotated[str, PathParam(pattern=AID_RE)]
Bid = Annotated[str, PathParam(pattern=BID_RE)]

SSE_POLL_S = 0.25  # how often the event stream re-reads trace.jsonl
SSE_KEEPALIVE_S = 15.0  # comment line sent when idle so proxies do not close the connection
SSE_GATE_IDLE_S = 3.0  # end the stream this long after the last line while waiting at the human gate


class DecisionBody(BaseModel):
    """Body of POST .../plans/{plan_id}/decision: the human's verdict on the single pending plan."""

    decision: Literal["approve", "reject", "accept_risk"]
    comment: str | None = Field(default=None, max_length=2000)
    reason_type: Literal["too_big", "too_new", "breaks_app", "different_approach", "other"] | None = None  # for reject
    plan_hash: str = Field(pattern=r"^[0-9a-f]{12,64}$")
    decided_by: str = Field(default="human", max_length=64)  # local dev mode only; token mode uses the caller


class BatchItemBody(BaseModel):
    """One fix's verdict inside a batch decision; plan_hash binds it to the exact plan the human reviewed (G5.1)."""

    plan_id: str = Field(pattern=PID_RE)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{12,64}$")
    decision: Literal["approve", "reject", "accept_risk"]
    comment: str | None = Field(default=None, max_length=2000)
    reason_type: Literal["too_big", "too_new", "breaks_app", "different_approach", "other"] | None = None  # for reject


class BatchDecisionBody(BaseModel):
    """Body of POST .../batches/{batch_id}/decisions: verdicts for the pending batch of fixes."""

    partial: bool = False  # one at a time: decide some of the pending fixes now, the rest stay pending
    decisions: list[BatchItemBody] = Field(max_length=1000)
    decided_by: str = Field(default="human", max_length=64)  # local dev mode only; token mode uses the caller


class ValidateNowBody(BaseModel):
    """Body of POST .../batches/{batch_id}/validate: which held approved fixes to validate now (default: all)."""

    plan_ids: list[str] | None = Field(default=None, max_length=1000)


class StartRunBody(BaseModel):
    """Body of POST /runs. `repo` must be a directory under an allowed target root; llm_mode overrides settings."""

    repo: str
    compare_ref: str | None = None
    llm_mode: Literal["live", "record", "replay"] | None = None


def _read_json(path: Path) -> Any:
    """Parse a JSON artefact. A missing file is the client's 404; a corrupt one is our 500 (never a stack trace)."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HTTPException(404, f"{path.name} not found") from None
    except ValueError:
        raise HTTPException(500, f"{path.name} is not valid JSON") from None


def _list_json(directory: Path) -> list[Any]:
    """All *.json files of a directory parsed, in file-name order; a missing directory means an empty list."""
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
    """Directories a run may target: GUARDIAN_TARGET_ROOTS (os.pathsep separated) or <repo>/targets, resolved."""
    raw = os.environ.get("GUARDIAN_TARGET_ROOTS")
    roots = [Path(p) for p in raw.split(os.pathsep) if p.strip()] if raw else [REPO_ROOT / "targets"]
    return [r.resolve() for r in roots]


def create_app(runs_dir: Path | None = None, *, tokens: TokenStore | None = None,
               target_roots: list[Path] | None = None, max_active: int | None = None) -> FastAPI:
    """Build the FastAPI app (also the test entry point).

    runs_dir: where run folders live (default from settings). tokens: a TokenStore (default: from
    GUARDIAN_API_TOKENS; empty store = local dev mode). target_roots: allowed repo roots for POST /runs.
    max_active: cap on concurrent background runs (default GUARDIAN_MAX_ACTIVE_RUNS, 2). All handlers close over
    these values, so several apps with different config can coexist in one process.
    """
    runs = Path(runs_dir) if runs_dir is not None else load_settings().runs_dir
    store = tokens if tokens is not None else TokenStore.from_env()
    roots = [Path(r).resolve() for r in target_roots] if target_roots is not None else _target_roots()
    limit = max_active if max_active is not None else int(os.environ.get("GUARDIAN_MAX_ACTIVE_RUNS", "2"))

    def viewer(request: Request) -> Principal:
        """App-wide dependency: every route needs at least the viewer role (a no-op in local dev mode)."""
        # the browser's EventSource cannot send headers: only the SSE route takes ?access_token=
        return principal_for(request, store, "viewer", allow_query=request.url.path.endswith("/events"))

    # docs_url/redoc_url off: no interactive docs page on a service that can start runs.
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
        """Map a validated run id (or "latest", via the runs/LATEST pointer file) to its folder, else 404."""
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
        """(status, summary) of a run. No run_summary.json yet means the run is still going: "running"."""
        f = d / "run_summary.json"
        if not f.is_file():
            return "running", None
        summary = _read_json(f)
        return str(summary.get("status", "running")), summary

    def spawn(run_id: str, fn, /, *args, **kwargs) -> None:
        """Run `fn(*args, **kwargs)` on a daemon thread, tracked in `active` so the caps below hold.

        Raises 409 if this run id already has a thread in flight, 429 if the global limit is reached. If fn
        raises, the run is marked failed on disk (`_mark_failed`) so the UI never waits forever. The caller
        returns 202 immediately; callers learn the outcome from the run status / event stream.
        """
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
        """Who the caller is and what the UI may offer them (start-run / decide buttons)."""
        p = principal_for(request, store, "viewer")
        return {"name": p.name, "role": p.role, "mode": "token" if store.enabled else "local-dev",
                "can_start_runs": p.can("operator"), "can_decide": p.can("approver")}

    @app.post("/runs", status_code=202)
    def start_run(body: StartRunBody, request: Request) -> dict:
        """Start a background run on a local repo directory; 400 not a directory, 403 outside the target roots."""
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
        """Run ids, newest first (ids sort by time); only folders whose name looks like a run id are listed."""
        if not runs.is_dir():
            return []
        return sorted((p.name for p in runs.iterdir()
                       if p.is_dir() and re.fullmatch(r"run_[A-Za-z0-9_]+", p.name)), reverse=True)

    @app.get("/runs/{run_id}")
    def get_run(run_id: RunId) -> dict:
        """Status of one run: running, awaiting_human, done or failed, plus its summary when finished."""
        d = run_dir(run_id)
        status, summary = status_of(d)
        return {"run_id": d.name, "status": status, "summary": summary}

    def fixed(name: str, file: str) -> None:
        """Register GET /runs/{run_id}/<name> serving one fixed file of the run folder (file name is a constant)."""
        def handler(run_id: RunId) -> Any:
            return _read_json(run_dir(run_id) / file)

        handler.__name__ = f"get_{name.replace('.', '_')}"
        app.get(f"/runs/{{run_id}}/{name}")(handler)

    fixed("summary", "run_summary.json")
    fixed("graph", "graph.json")
    fixed("changes", "changes.json")
    fixed("findings", "findings.json")
    fixed("report.json", "report.json")
    fixed("recommendations", "recommendations.json")  # batch remediation: every finding's fix or "no alternatives"

    @app.get("/runs/{run_id}/risk")
    def get_risk(run_id: RunId) -> Any:
        """The risk ranking; an empty list (not 404) before the risk step has run."""
        f = run_dir(run_id) / "risk.json"
        return _read_json(f) if f.is_file() else []

    @app.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
    def get_report_html(run_id: RunId) -> HTMLResponse:
        """The self-contained HTML report written by guardian.reporting at the end of a run."""
        f = run_dir(run_id) / "report.html"
        if not f.is_file():
            raise HTTPException(404, "report.html not found")
        return HTMLResponse(f.read_text(encoding="utf-8"))

    @app.get("/runs/{run_id}/findings/{fid}")
    def get_finding(run_id: RunId, fid: Fid) -> Any:
        """One finding looked up by id inside findings.json."""
        for f in _read_json(run_dir(run_id) / "findings.json"):
            if f.get("finding_id") == fid:
                return f
        raise HTTPException(404, f"finding {fid} not found")

    @app.get("/runs/{run_id}/evidence/{eid}")
    def get_evidence(run_id: RunId, eid: Eid) -> Any:
        """One evidence record (evidence/<eid>.json); the id regex is the only thing that picks the file."""
        return _read_json(run_dir(run_id) / "evidence" / f"{eid}.json")

    @app.get("/runs/{run_id}/plans")
    def list_plans(run_id: RunId) -> list:
        """Every remediation plan of the run (plans/*.json)."""
        return _list_json(run_dir(run_id) / "plans")

    @app.get("/runs/{run_id}/plans/{plan_id}")
    def get_plan(run_id: RunId, plan_id: Pid) -> Any:
        """One remediation plan by id."""
        return _read_json(run_dir(run_id) / "plans" / f"{plan_id}.json")

    @app.get("/runs/{run_id}/attempts/{attempt_id}/pr.md")
    def get_pr_markdown(run_id: RunId, attempt_id: Aid) -> Response:
        """The pull-request text drafted for one remediation attempt, as text/markdown."""
        f = run_dir(run_id) / "attempts" / attempt_id / "PR.md"  # fixed file name, id validated by regex
        if not f.is_file():
            raise HTTPException(404, "PR.md not found")
        return Response(f.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/runs/{run_id}/validation")
    def list_validation(run_id: RunId) -> list:
        """Validator results (validation/*.json): did each attempted fix build/test/rescan clean."""
        return _list_json(run_dir(run_id) / "validation")

    @app.get("/runs/{run_id}/activity")
    def get_activity(run_id: RunId) -> Any:
        """What is running right now (tools, sandbox containers, the baseline) with start times, plus the steps that
        just finished (activity.json). `stale` is true when the writer stopped heartbeating (the process is gone);
        its steps are then listed under `interrupted`, never as running."""
        from guardian.core import activity

        d = run_dir(run_id)
        out = activity.read(d)
        out["status"] = status_of(d)[0]
        out["server_time"] = datetime.now(UTC).isoformat(timespec="seconds")
        return out

    @app.get("/runs/{run_id}/trace")
    def get_trace(run_id: RunId) -> list:
        """The whole agent trace (AgentEvent per item); live updates come from /events (SSE)."""
        f = run_dir(run_id) / "trace.jsonl"
        if not f.is_file():
            return []
        out = []
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                break  # a half-written last line
        return out

    @app.get("/runs/{run_id}/watch")
    def list_watch(run_id: RunId) -> list:
        """Continuous-monitoring checks (guardian watch), oldest first."""
        return _list_json(run_dir(run_id) / "watch")

    @app.get("/runs/{run_id}/approvals")
    def list_approvals(run_id: RunId) -> list:
        """The audit trail of human decisions (approvals.jsonl), oldest first; a decision the user withdrew stays in
        the list, marked `"withdrawn": true`."""
        return read_approvals(run_dir(run_id), include_withdrawn=True)

    # ---- human gate ----------------------------------------------------
    @app.post("/runs/{run_id}/plans/{plan_id}/decision", status_code=202)
    def decide(run_id: RunId, plan_id: Pid, body: DecisionBody, request: Request) -> dict:
        """Record the human's decision on the single pending plan and resume the run in the background.

        409 if nothing is pending; 400 on a plan_id/plan_hash mismatch (G5.1) or a reject/accept_risk without a
        comment (G5.2). Returns 202 with who decided; the run continues asynchronously.
        """
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        pending_file = d / "pending_plan.json"
        if not pending_file.is_file():
            raise HTTPException(409, "no plan is pending a decision")
        pending = _read_json(pending_file)  # written by the workflow when it stopped at the human gate
        if plan_id != pending.get("plan_id") or body.plan_hash != pending.get("plan_hash"):
            raise HTTPException(400, "plan_id/plan_hash do not match the pending plan (G5.1)")
        if body.decision in ("reject", "accept_risk") and not (body.comment and body.comment.strip()):
            raise HTTPException(400, f"{body.decision} requires a comment (G5.2)")
        decided_by = who.name if who.authenticated else (body.decided_by.strip() or "human")
        if body.reason_type and body.decision != "reject":
            raise HTTPException(400, "reason_type is only for a reject")
        approval = Approval(plan_id=plan_id, plan_hash=body.plan_hash, decision=body.decision,
                            comment=body.comment, reason_type=body.reason_type, decided_by=decided_by)
        from guardian.graph import workflow

        spawn(d.name, workflow.resume, d.name, approval, settings=load_settings(runs_dir=runs), echo=False)
        return {"run_id": d.name, "plan_id": plan_id, "decision": body.decision, "decided_by": decided_by}

    @app.post("/runs/{run_id}/batches/{batch_id}/decisions", status_code=202)
    def decide_batch(run_id: RunId, batch_id: Bid, body: BatchDecisionBody, request: Request) -> dict:
        """One decision for EVERY fix of the pending batch (anything less or more is refused as a whole), or with
        `partial` one or more decisions now while the rest stay pending."""
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        pending_file = d / "pending_batch.json"
        if not pending_file.is_file():
            raise HTTPException(409, "no batch is pending a decision")
        decided_by = who.name if who.authenticated else (body.decided_by.strip() or "human")
        for i in body.decisions:  # a reject says why, so the next suggestion can follow it
            if i.decision == "reject" and not i.reason_type:
                raise HTTPException(400, f"reject of {i.plan_id} needs a reason_type: too_big, too_new, breaks_app, "
                                         f"different_approach or other")
            if i.reason_type and i.decision != "reject":
                raise HTTPException(400, f"reason_type on {i.plan_id} is only for a reject")
        approvals = [Approval(plan_id=i.plan_id, plan_hash=i.plan_hash, decision=i.decision, comment=i.comment,
                              reason_type=i.reason_type, decided_by=decided_by) for i in body.decisions]
        from guardian.guardrails.approval import check_batch

        reason = check_batch(_read_json(pending_file), batch_id, approvals, partial=body.partial)
        if reason:
            raise HTTPException(400, reason)
        from guardian.graph import workflow

        spawn(d.name, workflow.resume_batch, d.name, batch_id, approvals, settings=load_settings(runs_dir=runs),
              echo=False, partial=body.partial)
        return {"run_id": d.name, "batch_id": batch_id, "decisions": len(approvals), "decided_by": decided_by}

    @app.post("/runs/{run_id}/batches/{batch_id}/validate", status_code=202)
    def validate_held(run_id: RunId, batch_id: Bid, request: Request, body: ValidateNowBody | None = None) -> dict:
        """Validate the held approved fixes now (all, or `plan_ids`) while the other fixes keep waiting for decisions.

        409 if no batch is pending, the batch id is stale or no approved fix is held; 400 if a plan is not an
        approved held fix with a matching recorded approval (G5.1). The run continues in the background."""
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        from guardian.agents.batch import check_validate_now

        pending_file = d / "pending_batch.json"
        pending = _read_json(pending_file) if pending_file.is_file() else None
        checked = check_validate_now(d, pending, batch_id, body.plan_ids if body else None)
        if isinstance(checked, tuple):
            raise HTTPException(checked[0], checked[1])
        requested_by = who.name if who.authenticated else "human"
        from guardian.graph import workflow

        spawn(d.name, workflow.resume_validate_now, d.name, batch_id, checked, requested_by,
              settings=load_settings(runs_dir=runs), echo=False)
        return {"run_id": d.name, "batch_id": batch_id, "plan_ids": checked, "requested_by": requested_by}

    # ---- live trace (SSE) ------------------------------------------------
    @app.get("/runs/{run_id}/events")
    async def events(run_id: RunId, request: Request) -> StreamingResponse:
        """Server-Sent Events: replay trace.jsonl from the start (or after Last-Event-ID), then follow it live.

        Each event's id is the 0-based line number, so a reconnecting EventSource resumes without duplicates.
        The stream ends when the run is done/failed, or shortly after it reaches the human gate and goes quiet.
        """
        d = run_dir(run_id)
        trace = d / "trace.jsonl"
        try:
            sent = max(int(request.headers.get("last-event-id", "-1")) + 1, 0)
        except ValueError:
            sent = 0

        pos = {"bytes": 0, "lines": 0}  # read cursor: bytes consumed and complete lines delivered so far

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
    """Run the API under uvicorn (blocking). Exits if host is non-loopback and no tokens are configured."""
    import uvicorn

    store = TokenStore.from_env()
    check_bind(host, store)
    uvicorn.run(create_app(tokens=store), host=host, port=port, log_level="info")
