"""Risk analyst (Day-1 form): rank assessed findings and choose which enter the remediation loop. Owner: Dev1.

Day 1 keeps the evidence analyst's initial risk (LLM, grounded) and decides, rules-first, what can be fixed
*and verified* today: the finding categories whose fix is a patch op we have (D2-07) and whose detector can be
re-run on the patched copy (C4). One finding per category, highest risk first, up to GUARDIAN_MAX_PLANS.
CVE upgrades stay `assessed`: they need the §7 score (D1-06), a compatibility hint (D4-14) and a sandboxed
build + test (D2-08) before a human should be asked to approve them — that is Day 2.
"""

from __future__ import annotations

from guardian.core.models import Finding, FindingCategory, FindingStatus, Priority
from guardian.graph.state import GraphState, get_ctx

AGENT = "risk_analyst"
PLANNABLE = [FindingCategory.TYPOSQUAT, FindingCategory.LOCKFILE, FindingCategory.UNPINNED_CI]
_RANK = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3, None: 4}


def _key(f: Finding) -> tuple:
    legacy = (f.file_path or "").endswith(".bak")  # a live manifest beats a shipped backup
    return _RANK[f.initial_risk], legacy, PLANNABLE.index(f.category), f.title


def select(findings: list[Finding], limit: int) -> list[Finding]:
    chosen, seen = [], set()
    for f in sorted((f for f in findings if f.category in PLANNABLE and f.status is not FindingStatus.ESCALATED),
                    key=_key):
        if f.category not in seen and len(chosen) < limit:
            chosen.append(f)
            seen.add(f.category)
    return chosen


def risk_analyst_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    audit, store = rc.audit, rc.store
    findings = [f for f in (store.get_finding(i) for i in state.get("finding_ids", [])) if f]
    audit.emit(AGENT, "agent_start", f"Prioritising {len(findings)} findings for remediation")
    limit = rc.tool_ctx.settings.max_plans
    chosen = select(findings, limit)
    for f in chosen:
        f.status = FindingStatus.PLANNED
        store.update_finding(f)
    by_cat = {c.value: sum(1 for f in findings if f.category is c) for c in FindingCategory}
    deferred = by_cat.get("cve", 0)
    audit.emit("supervisor", "decision",
               f"{len(chosen)} findings -> remediation loop (one per fixable category, highest risk first, "
               f"limit GUARDIAN_MAX_PLANS={limit}); {deferred} CVE findings stay assessed until full risk scoring (D1-06) + "
               f"sandbox build/test (Day 2)",
               evidence_ids=sorted({e for f in chosen for e in f.evidence_ids}),
               data={"chosen": [{"finding_id": f.finding_id, "category": f.category.value,
                                 "risk": f.initial_risk.value if f.initial_risk else None, "title": f.title}
                                for f in chosen]})
    audit.emit(AGENT, "agent_end", f"Remediation queue: {[f.title[:60] for f in chosen]}")
    if chosen:
        audit.emit(AGENT, "handoff", f"{len(chosen)} findings -> remediation",
                   evidence_ids=sorted({e for f in chosen for e in f.evidence_ids}))
    return {"status": "planning_loop", "plan_queue": [f.finding_id for f in chosen], "current": None,
            "attempt": 0, "plan_id": None, "decision": None, "last_validation": None}
