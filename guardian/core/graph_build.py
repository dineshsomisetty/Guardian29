"""Dependency graph (D2-03, Dev2).

CycloneDX SBOM (Syft) -> networkx DiGraph -> `graph.json` (plan §4.1).
Facts only: direct/scope/origin/integrity come from the lockfile and manifest, never from an LLM.
If the SBOM has no usable `dependencies` for a project, edges are rebuilt from the lockfile `packages` map
(source recorded in `graph.graph["edge_source"]`).
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import networkx as nx

DEFAULT_PROJECTS = {"root": ".", "frontend": "frontend"}
_RISK_ORDER = ["low", "medium", "high", "critical"]


def _purl(ref_or_purl: str) -> str:
    """Strip Syft's `?package-id=...` qualifier so ids look like `pkg:npm/express@4.21.2`."""
    return ref_or_purl.split("?", 1)[0]


def _load_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _project_of(component: dict, projects: dict[str, str]) -> str | None:
    """Which npm project a component belongs to, from the lockfile path Syft recorded."""
    for prop in component.get("properties", []):
        if prop["name"].startswith("syft:location:") and prop["name"].endswith(":path"):
            val = prop["value"].lstrip("/")
            if not val.endswith("package-lock.json"):
                continue
            for name, rel in sorted(projects.items(), key=lambda kv: -len(kv[1])):
                prefix = "" if rel in (".", "") else rel.strip("/") + "/"
                if val == prefix + "package-lock.json":
                    return name
    return None


def _read_lock(work: Path, rel: str) -> dict:
    p = Path(work) / ("" if rel in (".", "") else rel) / "package-lock.json"
    return _load_json(p) if p.is_file() else {}


def _lock_entries(lock: dict) -> dict[tuple[str, str], dict]:
    """(name, version) -> lockfile `packages` entry (first wins; same pair has same integrity)."""
    out: dict[tuple[str, str], dict] = {}
    for key, ent in lock.get("packages", {}).items():
        if not key or "node_modules/" not in key:
            continue
        name = ent.get("name") or key.rsplit("node_modules/", 1)[1]
        ver = ent.get("version")
        if ver and (name, ver) not in out:
            out[(name, ver)] = ent
    return out


def _lock_edges(lock: dict) -> list[tuple[str, str, str, str]]:
    """Resolve dependency edges from the lockfile using Node's lookup rule (nearest node_modules up the tree)."""
    pk = lock.get("packages", {})

    def resolve(frm: str, dep: str) -> str | None:
        base = frm
        while True:
            cand = (base + "/" if base else "") + "node_modules/" + dep
            if cand in pk:
                return cand
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx != -1 else ""

    edges = []
    for key, ent in pk.items():
        if key and "node_modules/" not in key:
            continue  # workspace links etc.
        deps = {**ent.get("dependencies", {}), **ent.get("optionalDependencies", {}),
                **ent.get("peerDependencies", {})}  # npm installs peers; they are real edges
        if key == "":
            deps = {**deps, **ent.get("devDependencies", {})}
        for d in deps:
            tgt = resolve(key, d)
            if tgt and pk[tgt].get("version"):
                src_name = ent.get("name") or (key.rsplit("node_modules/", 1)[1] if key else "")
                edges.append((src_name, ent.get("version", ""), pk[tgt].get("name") or d, pk[tgt]["version"]))
    return edges


def build_dependency_graph(work: Path, sbom_path: Path, projects: dict[str, str] | None = None) -> nx.DiGraph:
    projects = projects or DEFAULT_PROJECTS
    work = Path(work)
    sbom = _load_json(sbom_path)
    G = nx.DiGraph(roots=[], edge_source={}, sbom=Path(sbom_path).name)

    locks = {p: _read_lock(work, rel) for p, rel in projects.items()}
    entries = {p: _lock_entries(lk) for p, lk in locks.items()}

    # ---- nodes from the SBOM (npm packages only) ----
    ref_to_id: dict[str, str] = {}
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        if c.get("type") != "library" or not purl.startswith("pkg:npm/"):
            continue
        project = _project_of(c, projects)
        if project is None:
            continue
        own = locks.get(project, {}).get("packages", {}).get("", {})
        if c["name"] == own.get("name") and c.get("version") == own.get("version"):
            continue  # the application itself, not a dependency
        nid = _purl(purl)
        ref_to_id[c["bom-ref"]] = nid
        ent = entries.get(project, {}).get((c["name"], c.get("version", "")), {})
        if nid in G:
            if project not in G.nodes[nid]["projects"]:
                G.nodes[nid]["projects"].append(project)
            continue
        G.add_node(
            nid, id=nid, kind="package", label=c["name"], version=c.get("version"), ecosystem="npm",
            direct=False, scope="prod" if not (ent.get("dev") or ent.get("devOptional")) else "dev",
            project=project, projects=[project],
            origin=ent.get("resolved"), integrity=ent.get("integrity"),
            deprecated=bool(ent.get("deprecated")), has_install_script=bool(ent.get("hasInstallScript")),
            risk=None, finding_ids=[],
        )

    # ---- roots + direct deps (manifest/lockfile root entry) ----
    for project in projects:
        lk = locks[project]
        if not lk:
            continue
        G.graph["roots"].append(project)
        G.add_node(project, id=project, kind="project", label=project, risk=None, finding_ids=[])
        root_ent = lk.get("packages", {}).get("", {})
        names = {**root_ent.get("dependencies", {}), **root_ent.get("devDependencies", {}),
                 **root_ent.get("optionalDependencies", {})}
        prod = set(root_ent.get("dependencies", {})) | set(root_ent.get("optionalDependencies", {}))
        for name in names:
            top = lk["packages"].get(f"node_modules/{name}")
            if not top or not top.get("version"):
                continue
            nid = f"pkg:npm/{_enc(name)}@{top['version']}"
            if nid in G:
                G.nodes[nid]["direct"] = True
                G.nodes[nid]["scope"] = "prod" if name in prod else "dev"
                G.add_edge(project, nid)

    # ---- edges: SBOM dependencies, else lockfile fallback per project ----
    sbom_edges = 0
    per_project_edges: dict[str, int] = {p: 0 for p in projects}
    for dep in sbom.get("dependencies", []):
        src = ref_to_id.get(dep["ref"])
        for t in dep.get("dependsOn", []):
            tgt = ref_to_id.get(t)
            if src and tgt and src != tgt:
                G.add_edge(src, tgt)
                sbom_edges += 1
                per_project_edges[G.nodes[src]["project"]] += 1
    # Syft drops many optional/platform edges, so ALWAYS union the lockfile edges (more complete).
    for project, lk in locks.items():
        if not lk:
            continue
        added = 0
        for sn, sv, tn, tv in _lock_edges(lk):
            s = f"pkg:npm/{_enc(sn)}@{sv}" if sn else project
            t = f"pkg:npm/{_enc(tn)}@{tv}"
            if s in G and t in G and s != t and not G.has_edge(s, t):
                G.add_edge(s, t)
                added += 1
        G.graph["edge_source"][project] = (
            "sbom+package-lock.json" if per_project_edges[project] else "package-lock.json")
        G.graph.setdefault("lock_edges_added", {})[project] = added
    return G


def _enc(name: str) -> str:
    """purl-encode an npm scope: @scope/name -> %40scope/name (matches Syft purls)."""
    return name.replace("@", "%40", 1) if name.startswith("@") else name


def paths_to(G: nx.DiGraph, target: str, max_paths: int = 5) -> list[list[str]]:
    """Shortest-first paths from any project root to `target` (purl ids). Empty if unreachable."""
    if target not in G:
        return []
    out: list[list[str]] = []
    for root in G.graph.get("roots", []):
        if root not in G or not nx.has_path(G, root, target):
            continue
        for p in nx.shortest_simple_paths(G, root, target):
            out.append(p)
            if len(out) >= max_paths:
                break
        if len(out) >= max_paths:
            break
    out.sort(key=len)
    return out[:max_paths]


# ---------------------------------------------------------------- findings -> graph
def _g(f: Any, name: str, default=None):
    return f.get(name, default) if isinstance(f, dict) else getattr(f, name, default)


def _val(x):  # Enum or str
    return getattr(x, "value", x)


def add_findings(G: nx.DiGraph, findings: Iterable[Any]) -> None:
    """Annotate package nodes with risk/finding_ids and add `ci`/`image`/`config` pseudo-nodes for non-package
    findings. Accepts Finding objects or dicts (fields: finding_id, category, component_purl, file_path, title,
    initial_risk). Image findings use id `image:<component_purl or title>`."""
    for f in findings:
        fid, cat, risk = _g(f, "finding_id"), _val(_g(f, "category")), _val(_g(f, "initial_risk"))
        purl = _g(f, "component_purl")
        if purl and purl.startswith("pkg:"):
            nid = _purl(purl)
            if nid in G:
                _attach(G, nid, fid, risk)
            continue
        if cat == "cve":
            continue  # CVE on a component that is not in the graph: nothing to attach to
        fp, title = _g(f, "file_path"), _g(f, "title", "")
        kind = {"unpinned_ci": "ci", "untrusted_image": "image"}.get(cat, "config")
        if kind == "image" and purl:
            nid = f"image:{purl}"  # same id scheme as guardian.graph.workflow.pseudo_node_id
        else:
            nid = f"{kind}:{fp or title}"
        label = nid.split(":", 1)[1].split("/")[-1]
        if nid not in G:
            G.add_node(nid, id=nid, kind=kind, label=label, risk=None, finding_ids=[])
            for root in G.graph.get("roots", [])[:1]:
                G.add_edge(root, nid, type="uses")
        _attach(G, nid, fid, risk)


def _attach(G: nx.DiGraph, nid: str, fid: str | None, risk: str | None) -> None:
    n = G.nodes[nid]
    if fid and fid not in n["finding_ids"]:
        n["finding_ids"].append(fid)
    if risk and (n["risk"] is None or _RISK_ORDER.index(risk) > _RISK_ORDER.index(n["risk"])):
        n["risk"] = risk


# ---------------------------------------------------------------- export
def to_json(G: nx.DiGraph) -> dict:
    nodes = []
    for _, d in G.nodes(data=True):
        nd = {k: v for k, v in d.items() if k != "projects"}
        nodes.append(nd)
    edges = []
    for s, t, d in G.edges(data=True):
        e = {"source": s, "target": t}
        if d.get("type"):
            e["type"] = d["type"]
        edges.append(e)
    return {"nodes": nodes, "edges": edges, "roots": list(G.graph.get("roots", []))}


def export_graph(G: nx.DiGraph, out_file: Path) -> dict:
    """Write graph.json. Returns summary facts (for Evidence(kind='graph') and run_summary.json)."""
    data = to_json(G)
    Path(out_file).write_text(json.dumps(data, indent=1), encoding="utf-8")
    pk = [n for n in data["nodes"] if n["kind"] == "package"]
    return {"nodes": len(data["nodes"]), "edges": len(data["edges"]), "packages": len(pk),
            "direct": sum(1 for n in pk if n["direct"]), "transitive": sum(1 for n in pk if not n["direct"]),
            "roots": data["roots"], "edge_source": dict(G.graph["edge_source"])}


IMAGE_ROOT = "image"


def merge_image_sbom(G: nx.DiGraph, image_sbom: Path, image_ref: str | None = None) -> dict:
    """D2-11: add container components from an image SBOM under root `image`.

    * OS packages (deb/apk/rpm) and npm packages not already in the app graph -> new nodes, project "image",
      edge image -> node (they are what the image ships).
    * npm packages that ARE in the app graph (same purl) -> marked `in_image: true`; no extra edge, so the UI
      graph does not get hundreds of duplicate children under the image root.
    Returns counts for Evidence/run_summary.
    """
    sbom = _load_json(image_sbom)
    if IMAGE_ROOT not in G:
        G.add_node(IMAGE_ROOT, id=IMAGE_ROOT, kind="project", label=image_ref or "image", risk=None, finding_ids=[])
        G.graph["roots"].append(IMAGE_ROOT)
    G.graph["edge_source"][IMAGE_ROOT] = "image-sbom"
    added = shared = os_pkgs = 0
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        if c.get("type") != "library" or not purl.startswith("pkg:"):
            continue
        nid = _purl(purl)
        eco = purl[4:].split("/", 1)[0]
        if nid in G:
            G.nodes[nid]["in_image"] = True
            if IMAGE_ROOT not in G.nodes[nid].setdefault("projects", []):
                G.nodes[nid]["projects"].append(IMAGE_ROOT)
            shared += 1
            continue
        G.add_node(nid, id=nid, kind="package", label=c.get("name"), version=c.get("version"), ecosystem=eco,
                   direct=True, scope="prod", project=IMAGE_ROOT, projects=[IMAGE_ROOT], origin=None,
                   integrity=None, deprecated=False, has_install_script=False, in_image=True,
                   risk=None, finding_ids=[])
        G.add_edge(IMAGE_ROOT, nid)
        added += 1
        os_pkgs += eco in ("deb", "apk", "rpm")
    return {"image_ref": image_ref, "added": added, "shared_with_app": shared, "os_packages": os_pkgs}


class DependencyGraph:
    """Object handed to the pipeline as `ctx.graph` (contract: to_json, paths_to, stats, add_pseudo_nodes, nodes)."""

    def __init__(self, G: nx.DiGraph, sbom_components: int | None = None):
        self.G = G
        self.sbom_components = sbom_components

    @property
    def nodes(self):
        return self.G.nodes

    def paths_to(self, purl: str, max_paths: int = 5) -> list[list[str]]:
        return paths_to(self.G, _purl(purl), max_paths)

    def node_for_name(self, name: str) -> dict | None:
        """First package node with this npm name (used by detectors that start from a manifest entry)."""
        for _, d in self.G.nodes(data=True):
            if d.get("kind") == "package" and d.get("label") == name:
                return d
        return None

    def add_pseudo_nodes(self, findings: Iterable[Any]) -> None:
        add_findings(self.G, findings)

    def to_json(self) -> dict:
        return to_json(self.G)

    def merge_image(self, image_sbom: Path, image_ref: str | None = None) -> dict:
        return merge_image_sbom(self.G, image_sbom, image_ref)

    def stats(self) -> dict:
        """App counts (root + frontend) drive the header strip; image counts are reported separately."""
        all_pk = [d for _, d in self.G.nodes(data=True) if d.get("kind") == "package"]
        pk = [d for d in all_pk if d.get("project") != IMAGE_ROOT]
        return {"components": len(pk), "direct": sum(1 for d in pk if d["direct"]),
                "transitive": sum(1 for d in pk if not d["direct"]), "projects": list(self.G.graph["roots"]),
                "edge_source": dict(self.G.graph["edge_source"]),
                "image_packages": sum(1 for d in all_pk if d.get("in_image"))}


def build_pypi_graph(work: Path, sbom_path: Path, requirements: str = "requirements.txt",
                     fetch=None) -> nx.DiGraph:
    """D2-09: pip project. Nodes = pinned requirements found by Syft in `requirements` (other requirement files,
    e.g. PyGoat's separate labs, are out of scope); edges = PyPI `requires_dist` between pinned packages;
    direct = not required by any other pinned package (requirements files are flat). Integrity is None unless
    the file uses --hash (reported by the lockfile detector)."""
    from guardian.adapters.pypi import normalize, parse_requirements, release_metadata, runtime_dependencies

    fetch = fetch or release_metadata
    work = Path(work)
    sbom = _load_json(sbom_path)
    reqs = {r.name: r for r in parse_requirements(work / requirements)} if (work / requirements).is_file() else {}
    G = nx.DiGraph(roots=["root"], edge_source={"root": "pypi requires_dist"}, sbom=Path(sbom_path).name,
                   ecosystem="pypi", unpinned_requirements=[])
    G.add_node("root", id="root", kind="project", label="root", risk=None, finding_ids=[])
    by_name: dict[str, str] = {}
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        if c.get("type") != "library" or not purl.startswith("pkg:pypi/"):
            continue
        locs = [p["value"] for p in c.get("properties", []) if p["name"].startswith("syft:location:")
                and p["name"].endswith(":path")]
        if not any(loc.lstrip("/") == requirements for loc in locs):
            continue
        nid, name = _purl(purl), normalize(c["name"])
        if nid in G:
            continue
        r = reqs.get(name)
        G.add_node(nid, id=nid, kind="package", label=name, version=c.get("version"), ecosystem="pypi",
                   direct=True, scope="prod", project="root", projects=["root"],
                   origin=f"https://pypi.org/project/{name}/{c.get('version')}/", integrity=None,
                   deprecated=False, has_install_script=False, risk=None, finding_ids=[],
                   declared_line=r.line if r else None)
        by_name[name] = nid
    missing: set[str] = set()
    for name, nid in list(by_name.items()):
        info = fetch(name, G.nodes[nid]["version"]) or {}
        if info.get("yanked"):
            G.nodes[nid]["deprecated"] = True
        for dep in runtime_dependencies(info):
            if dep in by_name and by_name[dep] != nid:
                G.add_edge(nid, by_name[dep])
                G.nodes[by_name[dep]]["direct"] = False
            elif dep not in by_name:
                missing.add(dep)
    for nid in by_name.values():
        if G.nodes[nid]["direct"]:
            G.add_edge("root", nid)
    G.graph["unpinned_requirements"] = sorted(missing)  # needed at runtime but not pinned in the file
    return G


def build_graph(ctx):
    """Tool entry point (registry binding `graph_build`) -> ToolOutput(graph=DependencyGraph, Evidence kind='graph').
    npm when package.json exists, else pip (requirements.txt)."""
    from guardian.core.models import Evidence
    from guardian.tools.registry import ToolOutput

    work = Path(ctx.work_dir or ctx.repo)
    if not (work / "package.json").is_file() and (work / "requirements.txt").is_file():
        G = build_pypi_graph(work, Path(ctx.sbom_path))
    else:
        G = build_dependency_graph(work, Path(ctx.sbom_path))
    dg = DependencyGraph(G)
    st = dg.stats()
    ev = Evidence(run_id=ctx.run_id, kind="graph", source_tool="graph_build", facts=st,
                  artifact_path=str(Path(ctx.sbom_path)))
    return ToolOutput(evidence=[ev], artifacts={"graph": dg},
                      summary=f"{st['components']} packages ({st['direct']} direct, {st['transitive']} transitive); "
                              f"edges from {st['edge_source']}")
