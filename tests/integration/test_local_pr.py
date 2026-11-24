"""D2-10: a verified fix leaves a local branch + PR.md in the attempt copy; nothing is pushed; API serves PR.md."""

import json
import subprocess

from fastapi.testclient import TestClient

from guardian.api import app as api_app
from guardian.api.auth import TokenStore
from guardian.core.plans import list_validations
from guardian.graph import workflow
from tests.integration.test_human_gate import _decide, _settings, target  # noqa: F401


def git(cwd, *a):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def test_verified_fix_gets_local_branch_and_pr_md(target, settings, fake_llm_factory):  # noqa: F811
    s = _settings(settings, plans=1)
    llm, _ = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_pr", settings=s, llm=llm, echo=False)
    _decide(s, "run_pr", "approve")
    v = list_validations(run_dir)[0]
    assert v.verdict == "verified"
    at = run_dir / "attempts" / v.attempt_id
    md = (at / "PR.md").read_text(encoding="utf-8")
    for needle in ("## Proposed fix", "## Rationale", "VERIFIED", "## Validation", "## Rollback", "## Approval",
                   "plan_hash", "not pushed"):
        assert needle in md
    work = at / "work"
    branch = git(work, "rev-parse", "--abbrev-ref", "HEAD")
    assert branch.startswith("guardian/fix-")
    assert git(work, "remote") == "" and git(work, "log", "--format=%an <%ae>", "-1") == "Guardian <guardian@localhost>"
    assert git(work, "diff", "--name-only", "HEAD~1", "HEAD") == "package.json"
    assert not (target / ".git").exists()
    ev = [json.loads(x) for x in (run_dir / "trace.jsonl").read_text().splitlines()]
    end = next(e for e in ev if e["agent"] == "validator" and e["type"] == "agent_end")
    assert end["data"]["pr_markdown"] == f"attempts/{v.attempt_id}/PR.md"
    rep = json.loads((run_dir / "report.json").read_text()) if (run_dir / "report.json").exists() else None
    if rep:
        assert any(a["pr_markdown"] for a in rep["actions"])
    client = TestClient(api_app.create_app(s.runs_dir, tokens=TokenStore(None), target_roots=[s.runs_dir.parent]))
    r = client.get(f"/runs/run_pr/attempts/{v.attempt_id}/pr.md")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown") and "Guardian fix" in r.text
    assert client.get("/runs/run_pr/attempts/at_bad/pr.md").status_code == 422
    assert client.get(f"/runs/run_pr/attempts/at_{'A' * 26}/pr.md").status_code == 404
