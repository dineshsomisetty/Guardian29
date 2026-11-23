"""Policy-as-code checks (D4-07).

`policy_check(input, config)` is the in-process evaluator the Validator calls. The same
rules exist as Rego in policies/guardian.rego for Conftest (`conftest test input.json -p policies`);
both use the same input document, built by `build_policy_input`.

Input document:
{
  "has_lockfile": bool,
  "actions": [{"file", "line", "uses"}],
  "images":  [{"file", "line", "image"}],
  "packages": [{"name", "version", "age_days": int|null, "typosquat_of": str|null}]
}
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "guardian.yaml"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")


def load_config(path: Path | str | None = None) -> dict:
    p = Path(path) if path else DEFAULT_CONFIG
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def _v(rule: str, message: str, file: str | None = None, line: int | None = None, **extra) -> dict:
    return {"rule": rule, "message": message, "file": file, "line": line, **extra}


def policy_check(doc: dict, config: dict | None = None) -> list[dict]:
    cfg = config if config is not None else load_config()
    pol, thr = cfg.get("policies", {}), cfg.get("thresholds", {})
    out: list[dict] = []

    if pol.get("require_lockfile", True) and not doc.get("has_lockfile", True):
        out.append(_v("missing_lockfile", "No lockfile committed; installs are not reproducible"))

    if pol.get("require_pinned_actions", True):
        for a in doc.get("actions", []):
            ref = a["uses"]
            if ref.startswith(("./", "docker://")):
                continue
            version = ref.split("@", 1)[1] if "@" in ref else ""
            if not _SHA.match(version):
                out.append(_v("unpinned_action", f"{ref} is not pinned to a 40-char commit SHA", a.get("file"), a.get("line")))

    if pol.get("require_pinned_base_images", True):
        for i in doc.get("images", []):
            img = i["image"]
            if img.lower() != "scratch" and not _DIGEST.search(img):
                out.append(_v("tag_only_image", f"{img} is not pinned by digest", i.get("file"), i.get("line")))

    deny = {d["name"].lower(): d.get("reason", "") for d in cfg.get("denylist", [])}
    min_age = thr.get("min_package_age_days")
    for p in doc.get("packages", []):
        n = p["name"].lower()
        if n in deny:
            out.append(_v("denylisted_package", f"{p['name']} is denylisted: {deny[n]}"))
        if p.get("typosquat_of"):
            out.append(_v("typosquat_package", f"{p['name']} looks like {p['typosquat_of']}"))
        age = p.get("age_days")
        if min_age is not None and age is not None and age < min_age:
            out.append(_v("package_too_new", f"{p['name']} was published {age} days ago (< {min_age})"))
    return out


# ---- input builder (minimal; Dev2's adapters are the richer source in the full pipeline) ----
_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE)


def build_policy_input(root: Path | str, package_names: list[str] | None = None) -> dict:
    root = Path(root)
    actions, images = [], []
    for wf in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        for i, line in enumerate(wf.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = _USES.match(line)
            if m:
                actions.append({"file": wf.relative_to(root).as_posix(), "line": i, "uses": m.group(1)})
    for df in sorted(root.glob("**/Dockerfile*")):
        if "node_modules" in df.parts:
            continue
        stages: set[str] = set()
        for i, line in enumerate(df.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = _FROM.match(line)
            if m and m.group(1) not in stages:
                images.append({"file": df.relative_to(root).as_posix(), "line": i, "image": m.group(1)})
            alias = re.search(r"\bAS\s+(\S+)\s*$", line, re.IGNORECASE)
            if alias:
                stages.add(alias.group(1))
    has_lock = any((root / f).exists() for f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt"))
    return {"has_lockfile": has_lock, "actions": actions, "images": images,
            "packages": [{"name": n} for n in package_names or []]}
