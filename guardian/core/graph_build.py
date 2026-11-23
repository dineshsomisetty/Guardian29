"""D2-03 dependency graph. Owner: Dev2.

Edges come from each project's package-lock.json `packages` map using Node's resolution rule (look in
<pkg>/node_modules/<dep>, then walk up). We use the lockfile rather than the CycloneDX `dependencies` array
because Syft's npm edges can be partial and the lockfile also gives scope (dev flag), origin (`resolved`)
and integrity — the source is recorded in the graph evidence. Node ids are purls, matching Syft/Grype.
"""

from __future__ import annotations

import json
from itertools import islice
from pathlib import Path

import networkx as nx

from guardian.adapters import pypi
from guardian.adapters.npm import find_projects, purl
from guardian.core.models import Evidence
from guardian.tools.registry import ToolContext, ToolOutput


def _pkg_name(key: str, entry: dict) -> str:
    return entry.get("name") or key.rsplit("node_modules/", 1)[-1]


def _resolve(packages: dict, from_key: str, dep: str) -> str | None:
    base = from_key
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx > 0 else ""


class DependencyGraph:
    def __init__(self):
        self.g = nx.DiGraph()
        self.roots: list[str] = []

    # --------------------------------------------------------------- build
    def add_project(self, name: str, lock: dict) -> None:
        packages = lock.get("packages", {})
        root_entry = packages.get("", {})
        self.roots.append(name)
        self.g.add_node(name, id=name, kind="project", label=name, project=name)
        direct = {**root_entry.get("dependencies", {}), **root_entry.get("optionalDependencies", {})}
        direct_dev = root_entry.get("devDependencies", {})

        key_to_id: dict[str, str] = {}
        for key, entry in packages.items():
            if not key or entry.get("link") or "version" not in entry:
                continue
            pname = _pkg_name(key, entry)
            nid = purl(pname, entry["version"])
            key_to_id[key] = nid
            is_direct = key == f"node_modules/{pname}" and (pname in direct or pname in direct_dev)
            scope = "dev" if entry.get("dev") else "prod"
            if nid in self.g:
                n = self.g.nodes[nid]
                n["direct"] = n["direct"] or is_direct
                if scope == "prod":
                    n["scope"] = "prod"
                if name not in n["projects"]:
                    n["projects"].append(name)
            else:
                self.g.add_node(nid, id=nid, kind="package", label=pname, version=entry["version"], ecosystem="npm",
                                direct=is_direct, scope=scope, project=name, projects=[name],
                                origin=entry.get("resolved"), integrity=entry.get("integrity"),
                                deprecated=bool(entry.get("deprecated")), has_install_script=bool(entry.get("hasInstallScript")))

        for dep in list(direct) + list(direct_dev):
            k = _resolve(packages, "", dep)
            if k in key_to_id:
                self.g.add_edge(name, key_to_id[k])
        for key, src in key_to_id.items():
            entry = packages[key]
            for dep in {**entry.get("dependencies", {}), **entry.get("optionalDependencies", {})}:
                k = _resolve(packages, key, dep)
                if k in key_to_id and key_to_id[k] != src:
                    self.g.add_edge(src, key_to_id[k])

    def add_flat_components(self, name: str, components: list[dict], ecosystem: str) -> int:
        """Fallback for ecosystems without a lockfile graph (pip): one package node per SBOM component, a root
        edge to each (requirements pins are direct, production scope)."""
        if name not in self.g:
            self.roots.append(name)
            self.g.add_node(name, id=name, kind="project", label=name, project=name)
        n = 0
        for c in components:
            p = c.get("purl") or ""
            if not p.startswith(f"pkg:{ecosystem}/") or p in self.g:
                continue
            self.g.add_node(p, id=p, kind="package", label=c.get("name") or p.split("/")[-1].split("@")[0],
                            version=c.get("version"), ecosystem=ecosystem, direct=True, scope="prod", project=name,
                            projects=[name], origin=None, integrity=None, deprecated=False, has_install_script=False)
            self.g.add_edge(name, p)
            n += 1
        return n

    # --------------------------------------------------------------- queries
    def packages(self) -> list[str]:
        return [n for n, d in self.g.nodes(data=True) if d.get("kind") == "package"]

    def stats(self) -> dict:
        pk = self.packages()
        direct = sum(1 for n in pk if self.g.nodes[n]["direct"])
        return {"components": len(pk), "direct": direct, "transitive": len(pk) - direct, "projects": self.roots,
                "edges": self.g.number_of_edges()}

    def paths_to(self, target: str, max_paths: int = 5) -> list[list[str]]:
        if target not in self.g:
            return []
        out: list[list[str]] = []
        for root in self.roots:
            try:
                out.extend(islice(nx.all_shortest_paths(self.g, root, target), max_paths - len(out)))
            except nx.NetworkXNoPath:
                continue
            if len(out) >= max_paths:
                break
        return out

    def to_json(self) -> dict:
        nodes = []
        for _, d in self.g.nodes(data=True):
            n = dict(d)
            n.setdefault("risk", None)
            n.setdefault("finding_ids", [])
            nodes.append(n)
        edges = [{"source": u, "target": v} for u, v in self.g.edges()]
        return {"nodes": nodes, "edges": edges, "roots": list(self.roots)}


def build_graph(ctx: ToolContext) -> ToolOutput:
    work: Path = ctx.work_dir or ctx.repo
    graph = DependencyGraph()
    used = []
    for proj in find_projects(work):
        if proj.lockfile.exists():
            graph.add_project(proj.name, json.loads(proj.lockfile.read_text(encoding="utf-8")))
            used.append(proj.lockfile.relative_to(work).as_posix())
    edge_source = "package-lock.json packages map (node resolution)"
    if ctx.sbom_path is not None and Path(ctx.sbom_path).exists():
        comps = json.loads(Path(ctx.sbom_path).read_text(encoding="utf-8")).get("components", [])
        # ecosystems without a lockfile graph here (pip, maven, gem, golang, ...): one node per SBOM component
        # with a root edge. GitHub Actions purls are CI steps, shown as ci: pseudo-nodes, not packages.
        ecos = sorted({(c.get("purl") or "")[4:].split("/", 1)[0] for c in comps
                       if (c.get("purl") or "").startswith("pkg:")} - {"npm", "github", "githubactions", "docker", "oci"})
        for eco in ecos:
            if eco == "pypi" and not pypi.find_projects(work):
                continue
            label = {"pypi": "pip"}.get(eco, eco)
            added = graph.add_flat_components("root" if "root" not in graph.roots else label, comps, eco)
            if added:
                used.append(f"sbom.cdx.json ({eco} components)")
                edge_source += f"; {label}: SBOM components with root edges"
    stats = graph.stats()
    ev = Evidence(run_id=ctx.run_id, kind="graph", source_tool="graph_build:npm-lockfile",
                  facts={**stats, "edge_source": edge_source,
                         "lockfiles": used})
    return ToolOutput(evidence=[ev], artifacts={"graph": graph},
                      summary=f"{stats['components']} packages, {stats['edges']} edges, roots {stats['projects']}")
