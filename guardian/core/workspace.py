"""D2-02 work copy: copy the target into runs/<id>/work/ without .git (no remote, nothing to push). Owner: Dev2.

Discovery calls `prepare_workspace` first. Every later tool (SBOM, detectors, patching, the sandbox) works on
this copy, never on the user's repository, so the original is never modified. Stripping `.git` means the copy
has no remote and no history to push (G5.5) and keeps the copy small; bulky or generated directories
(node_modules, build output, virtualenvs) are skipped because Guardian reads lockfiles, not installed packages.
"""

from __future__ import annotations

import shutil

from guardian.core.models import Evidence
from guardian.tools.registry import ToolContext, ToolOutput

# Directory names never copied into the work copy (matched at any depth by copytree).
IGNORE = shutil.ignore_patterns(".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".angular")


def prepare_workspace(ctx: ToolContext) -> ToolOutput:
    """Copy `ctx.repo` to `<run_dir>/work` and return a `detector_result` Evidence recording the file count.

    Side effect: creates the work directory (raises if it already exists, i.e. a run id is never reused). The
    returned artifact `work_dir` is picked up by discovery and put on the ToolContext for the rest of the run."""
    work = ctx.run_dir / "work"
    shutil.copytree(ctx.repo, work, ignore=IGNORE)
    files = sum(1 for p in work.rglob("*") if p.is_file())
    ev = Evidence(run_id=ctx.run_id, kind="detector_result", source_tool="workspace",
                  facts={"source": str(ctx.repo), "work_copy": "work/", "files": files, "git_stripped": True})
    return ToolOutput(evidence=[ev], artifacts={"work_dir": work},
                      summary=f"work copy with {files} files (no .git, no node_modules)")
