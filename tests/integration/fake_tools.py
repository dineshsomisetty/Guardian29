"""Stand-ins for Dev2/Dev4 tools, following the ToolContext -> ToolOutput contract."""

from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


class FakeGraph:
    def __init__(self):
        self.nodes = {
            "pkg:npm/express-jwt@0.1.3": {"direct": True},
            "pkg:npm/jsonwebtoken@0.4.0": {"direct": False},
        }

    def stats(self):
        return {"components": 2, "direct": 1, "transitive": 1, "projects": ["root"]}

    def paths_to(self, purl, max_paths=5):
        if purl == "pkg:npm/jsonwebtoken@0.4.0":
            return [["root", "pkg:npm/express-jwt@0.1.3", purl]]
        return []

    def to_json(self):
        return {
            "nodes": [{"id": k, "kind": "package", "label": k.split("/")[-1], **v} for k, v in self.nodes.items()],
            "edges": [{"source": "root", "target": "pkg:npm/express-jwt@0.1.3"},
                      {"source": "pkg:npm/express-jwt@0.1.3", "target": "pkg:npm/jsonwebtoken@0.4.0"}],
            "roots": ["root"],
        }


def workspace(ctx: ToolContext) -> ToolOutput:
    return ToolOutput(artifacts={"work_dir": ctx.repo})


def sbom(ctx: ToolContext) -> ToolOutput:
    path = ctx.run_dir / "sbom.cdx.json"
    path.write_text('{"bomFormat": "CycloneDX", "components": []}')
    ev = Evidence(run_id=ctx.run_id, kind="sbom", source_tool="syft@fake", facts={"components": 2},
                  artifact_path=str(path))
    return ToolOutput(evidence=[ev], artifacts={"sbom_path": path})


def graph(ctx: ToolContext) -> ToolOutput:
    ev = Evidence(run_id=ctx.run_id, kind="graph", source_tool="graph_build", facts={"nodes": 2})
    return ToolOutput(evidence=[ev], artifacts={"graph": FakeGraph()})


def _cve(ctx, tool, vuln_id, aliases):
    ev = Evidence(run_id=ctx.run_id, kind="scanner_output", source_tool=tool,
                  facts={"vuln_id": vuln_id, "aliases": aliases, "fixed_versions": ["9.0.0"], "cvss": 8.1,
                         "purl": "pkg:npm/jsonwebtoken@0.4.0"})
    fd = Finding(run_id=ctx.run_id, category=FindingCategory.CVE, title=f"{vuln_id} in jsonwebtoken",
                 detector=tool, component_purl="pkg:npm/jsonwebtoken@0.4.0", scope=Scope.PROD, project="root",
                 vuln_id=vuln_id, aliases=aliases, cvss=8.1, severity="High", fixed_versions=["9.0.0"],
                 affected_range="<9.0.0", evidence_ids=[ev.evidence_id])
    return ToolOutput(findings=[fd], evidence=[ev])


def grype(ctx):
    return _cve(ctx, "grype@fake", "GHSA-c7qv-q95q-8v27", ["CVE-2022-23539"])


def osv(ctx):
    return _cve(ctx, "osv-scanner@fake", "CVE-2022-23539", ["GHSA-c7qv-q95q-8v27"])


def lockfile(ctx):
    ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:lockfile",
                  facts={"setting": "package-lock=false"}, file_path=".npmrc", line=1, excerpt="package-lock=false")
    fd = Finding(run_id=ctx.run_id, category=FindingCategory.LOCKFILE, title="Lockfile disabled in .npmrc",
                 detector="detector:lockfile", file_path=".npmrc", line=1, project="root", evidence_ids=[ev.evidence_id])
    return ToolOutput(findings=[fd], evidence=[ev])


def changes(ctx):
    ev = Evidence(run_id=ctx.run_id, kind="changes", source_tool="detector:mini_diff", facts={"added": 1})
    return ToolOutput(evidence=[ev], artifacts={"changes": {"base": "ftp/package.json.bak", "head": "package.json",
                                                            "added": ["pkg:npm/foo@1.0.0"], "removed": [],
                                                            "changed": [], "evidence_ids": [ev.evidence_id]}})


def boom(ctx):
    raise RuntimeError("scanner crashed")


BINDINGS = {
    "discovery": [("workspace", f"{__name__}:workspace"), ("sbom", f"{__name__}:sbom"),
                  ("graph_build", f"{__name__}:graph"), ("missing", "guardian.tools.not_there:run")],
    "detection": [("grype", f"{__name__}:grype"), ("osv", f"{__name__}:osv"),
                  ("detector:lockfile", f"{__name__}:lockfile"), ("crash", f"{__name__}:boom"),
                  ("changes", f"{__name__}:changes")],
}
