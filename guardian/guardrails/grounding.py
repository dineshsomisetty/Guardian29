"""G4 grounding: LLM output is checked against Evidence.facts in code. Owner: Dev1.

G4.1 output must parse to the schema (caller does 1 repair retry, then escalates)
G4.2 every cited evidence_id must exist
G4.3 Claim.label is set here: VERIFIED only if field/value match cited evidence facts
G4.4 CVE/GHSA ids and purls in output must appear in evidence facts (else reject);
     versions not in evidence -> relabel INFERRED
G4.6 UNSUPPORTED claims are removed from what we keep (but logged)

Flow for one LLM answer (used by the evidence analyst; the investigator and remediation reuse the helpers):
  text --parse_batch--> RawBatch (G4.1, SchemaError on failure; the caller retries once, then escalates)
       --ground_assessment per finding--> GroundedAssessment: each RawClaim becomes a labelled `Claim`, or is
       rejected with a GroundingIssue (unknown evidence id G4.2, invented CVE/GHSA/purl G4.4, no evidence G4.6).
The LLM never decides a label. "Matching" means comparing against `Evidence.facts` (plus the evidence's file_path
and line), which tools wrote; so a claim is VERIFIED only when a tool-observed fact says the same thing.
`G4.5` (an upgrade target must come from tool evidence) is enforced where plans are built (agents/remediation.py),
using the same idea. G4.3's "field/value" check is `value_matches`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from guardian.core.models import Claim, ClaimLabel, Evidence, Priority

# ---------------------------------------------------------------- LLM output schema (G4.1)


class RawClaim(BaseModel):
    """A claim exactly as the LLM wrote it, before grounding. Becomes a `Claim` only if it passes the checks."""

    text: str
    field: str | None = None
    value: str | None = None
    evidence_ids: list[str] = []


class RawAssessment(BaseModel):
    """LLM verdict on one finding: a first-pass risk band, a short explanation and its supporting claims."""

    finding_id: str
    initial_risk: Literal["critical", "high", "medium", "low"]
    explanation: str
    claims: list[RawClaim] = []


class RawBatch(BaseModel):
    """The whole structured answer for a batch of findings (the top-level JSON object the LLM must return)."""

    assessments: list[RawAssessment]


def batch_json_schema() -> dict[str, Any]:
    """Strict JSON schema for structured output (additionalProperties false, all keys required).

    Mirrors RawBatch by hand: providers that enforce a schema need every key listed as required and nullable
    fields spelled `anyOf [type, null]`. Keep it in sync with the Raw* models above."""
    nullable_str = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    claim = {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "field": nullable_str,
            "value": nullable_str,
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["text", "field", "value", "evidence_ids"],
        "additionalProperties": False,
    }
    assessment = {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string"},
            "initial_risk": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "explanation": {"type": "string"},
            "claims": {"type": "array", "items": claim},
        },
        "required": ["finding_id", "initial_risk", "explanation", "claims"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {"assessments": {"type": "array", "items": assessment}},
        "required": ["assessments"],
        "additionalProperties": False,
    }


class SchemaError(Exception):
    """The LLM text is not valid JSON or does not fit the schema (G4.1). Carries the first 800 characters of
    the parser error, which the retry prompt shows to the model."""

    pass


def parse_batch(text: str) -> RawBatch:
    """Parse the LLM's reply into a RawBatch (G4.1); raises SchemaError instead of returning a partial result."""
    try:
        return RawBatch.model_validate(json.loads(text))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise SchemaError(str(exc)[:800]) from exc


# ---------------------------------------------------------------- fact helpers

# Identifier shapes that must be backed by evidence if they appear in LLM text (G4.4): an invented CVE number is
# the classic hallucination, and a purl names a concrete package.
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
PURL_RE = re.compile(r"\bpkg:[a-z]+/[^\s,;\"')]+", re.I)
# prerelease = dot-separated identifiers; a sentence-ending "." is not part of the version ("3.9-alpine.")
VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)(?![\w]|\.\w)")


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Nested facts -> flat (dotted.key, str(value)) pairs. List items keep the parent's key, so
    {"fixed": ["1.2", "1.3"]} gives two ("fixed", ...) pairs. None values are dropped."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list | tuple):
        for v in obj:
            out.extend(_flatten(v, prefix))
    elif obj is not None:
        out.append((prefix, str(obj)))
    return out


def _norm(s: str) -> str:
    """Normal form for comparing values: trimmed, quotes removed, lower case, no leading "v" (v1.2 == 1.2)."""
    return s.strip().strip("\"'").lower().lstrip("v") if s else s


def facts_blob(evidence: list[Evidence]) -> str:
    """All fact values (+ excerpts) as one lowercase haystack for token membership checks."""
    parts = []
    for ev in evidence:
        parts.extend(v for _, v in _flatten(ev.facts))
        if ev.excerpt:
            parts.append(ev.excerpt)
    return "\n".join(parts).lower()


def _ev_pairs(ev: Evidence) -> list[tuple[str, str]]:
    """Facts plus the evidence's own location fields (file_path, line) — both are tool-recorded."""
    pairs = _flatten(ev.facts)
    if ev.file_path:
        pairs.append(("file_path", ev.file_path))
    if ev.line is not None:
        pairs.append(("line", str(ev.line)))
    return pairs


def value_matches(ev_list: list[Evidence], field_name: str | None, value: str) -> bool:
    """Does any cited evidence state `value` (G4.3)? With a `field_name`, only facts under that key are
    compared when such a key exists (so "severity = high" cannot be satisfied by an unrelated "high" elsewhere);
    if the evidence has no such key, any fact value may match. Comparison uses `_norm`."""
    want = _norm(value)
    if not want:
        return False
    pairs = [pair for ev in ev_list for pair in _ev_pairs(ev)]
    if field_name:
        f = field_name.lower()
        keyed = [v for k, v in pairs if f in k.lower().split(".") or k.lower().endswith(f)]
        if keyed:
            return any(_norm(v) == want for v in keyed)
    return any(_norm(v) == want for _, v in pairs)


def id_tokens(text: str) -> set[str]:
    """CVE ids, GHSA ids and purls mentioned in `text`, lower-cased."""
    return {m.group(0).lower() for r in (CVE_RE, GHSA_RE, PURL_RE) for m in r.finditer(text or "")}


def version_tokens(text: str) -> set[str]:
    """Version-looking tokens in `text` (1.2, 1.2.3, 1.2.3-rc.1), lower-cased, without a leading "v"."""
    return {m.group(1).lower() for m in VERSION_RE.finditer(text or "")}


# ---------------------------------------------------------------- grounding


@dataclass
class GroundingIssue:
    """Why something was rejected or downgraded: the guardrail `rule` that fired and a readable `detail`.
    The caller turns each into a `guardrail` event (G7.2)."""

    rule: str  # G4.2 | G4.4 | G4.6
    detail: str


@dataclass
class GroundedAssessment:
    """Result of grounding one RawAssessment. `claims` are the accepted, labelled ones; `rejected` pairs each
    dropped RawClaim with the reason (kept for the audit log, never shown as fact); `issues` lists everything that
    fired, including downgrades. `explanation` is None when it mentioned ids not in evidence (G4.4)."""

    finding_id: str
    initial_risk: Priority
    explanation: str | None
    claims: list[Claim]
    rejected: list[tuple[RawClaim, GroundingIssue]] = field(default_factory=list)
    issues: list[GroundingIssue] = field(default_factory=list)


def unknown_ids_in(text: str, haystack: str) -> set[str]:
    """CVE/GHSA/purl tokens in `text` that do not occur in `haystack` (a lower-cased facts blob)."""
    return {t for t in id_tokens(text) if t not in haystack}


def ground_assessment(
    raw: RawAssessment,
    finding_evidence: list[Evidence],
    lookup: dict[str, Evidence],
    finding_facts: dict[str, Any] | None = None,
) -> GroundedAssessment:
    """Label every claim in code. `lookup` = all evidence in the run (G4.2 existence check).

    Per claim, in order: unknown evidence id -> rejected (G4.2); no evidence cited -> rejected (G4.6); an id in
    the claim that no evidence or finding field contains -> rejected (G4.4); otherwise the claim is kept as
    INFERRED, upgraded to VERIFIED only if its field/value matches the cited evidence (G4.3), and downgraded
    back to INFERRED if it quotes a version that the cited evidence does not contain (G4.4). The explanation is
    dropped (set to None) if it mentions an unknown id.

    `finding_facts`: structured fields of the Finding itself (vuln_id, aliases, purl, fixed_versions...).
    These came from tools, so ids that appear there are not "invented".
    """
    known_blob = facts_blob(finding_evidence) + "\n" + "\n".join(
        v for _, v in _flatten(finding_facts or {})
    ).lower()
    result = GroundedAssessment(
        finding_id=raw.finding_id,
        initial_risk=Priority(raw.initial_risk),
        explanation=raw.explanation,
        claims=[],
    )

    bad_ids = unknown_ids_in(raw.explanation, known_blob)
    if bad_ids:
        issue = GroundingIssue("G4.4", f"explanation mentions ids not in evidence: {sorted(bad_ids)}")
        result.issues.append(issue)
        result.explanation = None

    for rc in raw.claims:
        unknown = [e for e in rc.evidence_ids if e not in lookup]
        if unknown:
            issue = GroundingIssue("G4.2", f"cites unknown evidence ids {unknown}")
            result.rejected.append((rc, issue))
            result.issues.append(issue)
            continue
        cited = [lookup[e] for e in rc.evidence_ids]
        if not cited:
            issue = GroundingIssue("G4.6", "claim cites no evidence (unsupported, removed)")
            result.rejected.append((rc, issue))
            result.issues.append(issue)
            continue

        cited_blob = facts_blob(cited)
        claim_text = f"{rc.text} {rc.value or ''}"
        invented = {t for t in id_tokens(claim_text) if t not in cited_blob and t not in known_blob}
        if invented:
            issue = GroundingIssue("G4.4", f"claim mentions ids not in evidence: {sorted(invented)}")
            result.rejected.append((rc, issue))
            result.issues.append(issue)
            continue

        label = ClaimLabel.INFERRED
        if rc.value is not None and value_matches(cited, rc.field, rc.value):
            label = ClaimLabel.VERIFIED
        stray_versions = {v for v in version_tokens(claim_text) if v not in cited_blob}
        if stray_versions and label is ClaimLabel.VERIFIED:
            label = ClaimLabel.INFERRED
            result.issues.append(
                GroundingIssue("G4.4", f"versions {sorted(stray_versions)} not in cited evidence -> INFERRED")
            )
        result.claims.append(
            Claim(text=rc.text, field=rc.field, value=rc.value, evidence_ids=rc.evidence_ids, label=label)
        )
    return result
