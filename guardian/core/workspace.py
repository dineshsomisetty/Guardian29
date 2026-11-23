"""D2-02 work copy: copy the target into runs/<id>/work/ without .git (no remote, nothing to push). Owner: Dev2."""

from __future__ import annotations

import shutil

from guardian.core.models import Evidence
from guardian.tools.registry import ToolContext, ToolOutput

IGNORE = shutil.ignore_patterns(".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".angular")


def prepare_workspace(ctx: ToolContext) -> ToolOutput:
    work = ctx.run_dir / "work"
    shutil.copytree(ctx.repo, work, ignore=IGNORE)
    files = sum(1 for p in work.rglob("*") if p.is_file())
    ev = Evidence(run_id=ctx.run_id, kind="detector_result", source_tool="workspace",
                  facts={"source": str(ctx.repo), "work_copy": "work/", "files": files, "git_stripped": True})
    return ToolOutput(evidence=[ev], artifacts={"work_dir": work},
                      summary=f"work copy with {files} files (no .git, no node_modules)")
