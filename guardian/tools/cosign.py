"""Container image signature verification with Cosign (D2-12, Dev2; stretch goal 3 "provenance verification").

For each `FROM` image in the target's Dockerfile:
  * known publisher (identity + OIDC issuer pinned below)  -> strict keyless verify  -> "verified" / "failed"
  * unknown publisher -> verify with any identity (proves only that SOME Sigstore signature exists, logged in
    Rekor) -> "signed_unpinned_identity" / "unsigned"
Result -> Evidence(kind="provenance"); "failed" / "unsigned" -> Finding(category=provenance_gap).
Needs network to the registry + Sigstore (Rekor, Fulcio, TUF root), all on the §14 allowlist. No Docker needed.
SLSA / in-toto attestations are NOT checked (future work, plan §16).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from guardian.tools.sbom import find_tool

# Publisher identities, from the publishers' own docs (distroless README: "cosign verify ... --certificate-oidc-
# issuer https://accounts.google.com --certificate-identity keyless@distroless.iam.gserviceaccount.com").
KNOWN_SIGNERS = {
    "gcr.io/distroless/": ("keyless@distroless.iam.gserviceaccount.com", "https://accounts.google.com"),
}
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I | re.M)


def from_images(dockerfile: Path) -> list[tuple[str, int]]:
    """External base images (image, line) - skips `scratch`, ARG-templated refs and earlier build stages."""
    text = Path(dockerfile).read_text(encoding="utf-8")
    stages: set[str] = set()
    out = []
    for m in _FROM.finditer(text):
        img, stage = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        if img.lower() != "scratch" and "$" not in img and img not in stages:
            out.append((img, line))
        if stage:
            stages.add(stage)
    return out


def verify_image(image: str, runner=None, timeout: int = 180) -> dict:
    signer = next((v for k, v in KNOWN_SIGNERS.items() if image.startswith(k)), None)
    if signer:
        id_args = ["--certificate-identity", signer[0], "--certificate-oidc-issuer", signer[1]]
    else:
        id_args = ["--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*"]
    cmd = [find_tool("cosign"), "verify", image, *id_args]
    run = runner or (lambda c: subprocess.run(c, capture_output=True, text=True, timeout=timeout))
    r = run(cmd)
    err = (r.stderr or "").strip()
    if r.returncode == 0:
        status = "verified" if signer else "signed_unpinned_identity"
    elif "no signatures found" in err or "no matching signatures" in err and not signer:
        status = "unsigned"
    else:
        status = "failed" if signer else "unknown"
    return {"image": image, "status": status, "signature_verified": status == "verified",
            "expected_identity": signer[0] if signer else None, "expected_issuer": signer[1] if signer else None,
            "transparency_log": "rekor" if r.returncode == 0 else None, "error": None if r.returncode == 0 else
            err.splitlines()[-1][:300] if err else f"rc={r.returncode}"}


def image_signatures(ctx, runner=None):
    """Tool entry point (registry binding `cosign`): verify every base image of the target's Dockerfile."""
    from guardian.core.models import Evidence, Finding, FindingCategory, Provenance, Scope
    from guardian.tools.registry import ToolOutput

    df = Path(ctx.work_dir or ctx.repo) / "Dockerfile"
    if not df.is_file():
        return ToolOutput(summary="no Dockerfile")
    findings, evidence = [], []
    for image, line in from_images(df):
        res = verify_image(image, runner)
        ev = Evidence(run_id=ctx.run_id, kind="provenance", source_tool="cosign verify", file_path="Dockerfile",
                      line=line, excerpt=f"FROM {image}", facts=res)
        evidence.append(ev)
        if res["status"] in ("unsigned", "failed"):
            findings.append(Finding(
                run_id=ctx.run_id, category=FindingCategory.PROVENANCE_GAP, detector="detector:cosign",
                title=f"Base image {image}: " + ("no Sigstore signature" if res["status"] == "unsigned"
                                                 else "signature does not match the publisher identity"),
                component_purl=f"image:{image}", scope=Scope.PROD, project="image", file_path="Dockerfile",
                line=line, evidence_ids=[ev.evidence_id],
                provenance=Provenance(signature_verified=False, evidence_ids=[ev.evidence_id])))
    st = {e.facts["image"]: e.facts["status"] for e in evidence}
    return ToolOutput(findings=findings, evidence=evidence, summary=f"cosign: {st}")
