"""G4 grounding: LLM output is checked against Evidence.facts in code. Owner: Dev1.

G4.1 output must parse to the schema (caller does 1 repair retry, then escalates)
G4.2 every cited evidence_id must exist
G4.3 Claim.label is set here: VERIFIED only if field/value match cited evidence facts
G4.4 CVE/GHSA ids and purls in output must appear in evidence facts (else reject);
     versions not in evidence -> relabel INFERRED
G4.6 UNSUPPORTED claims are removed from what we keep (but logged)
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
    text: str
    field: str | None = None
    value: str | None = None
    evidence_ids: list[str] = []


class RawAssessment(BaseModel):
    finding_id: str
    initial_risk: Literal["critical", "high", "medium", "low"]
    explanation: str
    claims: list[RawClaim] = []


class RawBatch(BaseModel):
    assessments: list[RawAssessment]


def batch_json_schema() -> dict[str, Any]:
    """Strict JSON schema for structured output (additionalProperties false, all keys required)."""
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
    pass


def parse_batch(text: str) -> RawBatch:
    try:
        return RawBatch.model_validate(json.loads(text))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise SchemaError(str(exc)[:800]) from exc


# ---------------------------------------------------------------- fact helpers

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
PURL_RE = re.compile(r"\bpkg:[a-z]+/[^\s,;\"')]+", re.I)
VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)(?![\w.])")


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
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
    return s.strip().strip("\"'").lower().lstrip("v") if s else s


def facts_blob(evidence: list[Evidence]) -> str:
    """All fact values (+ excerpts) as one lowercase haystack for token membership checks."""
    parts = []
    for ev in evidence:
        parts.extend(v for _, v in _flatten(ev.facts))
        if ev.excerpt:
            parts.append(ev.excerpt)
    return "\n".join(parts).lower()


def value_matches(ev_list: list[Evidence], field_name: str | None, value: str) -> bool:
    want = _norm(value)
    if not want:
        return False
    pairs = [pair for ev in ev_list for pair in _flatten(ev.facts)]
    if field_name:
        f = field_name.lower()
        keyed = [v for k, v in pairs if f in k.lower().split(".") or k.lower().endswith(f)]
        if keyed:
            return any(_norm(v) == want for v in keyed)
    return any(_norm(v) == want for _, v in pairs)


def id_tokens(text: str) -> set[str]:
    return {m.group(0).lower() for r in (CVE_RE, GHSA_RE, PURL_RE) for m in r.finditer(text or "")}


def version_tokens(text: str) -> set[str]:
    return {m.group(1).lower() for m in VERSION_RE.finditer(text or "")}


# ---------------------------------------------------------------- grounding


@dataclass
class GroundingIssue:
    rule: str  # G4.2 | G4.4 | G4.6
    detail: str


@dataclass
class GroundedAssessment:
    finding_id: str
    initial_risk: Priority
    explanation: str | None
    claims: list[Claim]
    rejected: list[tuple[RawClaim, GroundingIssue]] = field(default_factory=list)
    issues: list[GroundingIssue] = field(default_factory=list)


def unknown_ids_in(text: str, haystack: str) -> set[str]:
    return {t for t in id_tokens(text) if t not in haystack}


def ground_assessment(
    raw: RawAssessment,
    finding_evidence: list[Evidence],
    lookup: dict[str, Evidence],
    finding_facts: dict[str, Any] | None = None,
) -> GroundedAssessment:
    """Label every claim in code. `lookup` = all evidence in the run (G4.2 existence check).

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
