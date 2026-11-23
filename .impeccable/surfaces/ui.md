---
version: 1
slug: "ui"
primary_target: "ui"
related_targets: []
---

Scope: Guardian CP1 dashboard (ui/), visitor mode: Operate. Audience: judges at a live projector demo, then close questioning. Task: see what is in the app, what changed, what is risky, and that agents reasoned over evidence.

## Direction contract

THESIS: Every finding is an exhibit and every agent that touched it signs its custody log. Refuses the KPI-tiles-over-table security dashboard where AI output is an unlabelled paragraph.

OWN-WORLD: Forensic intake form. Deep custody-ink navy rail (#14233F) and header band; cool form-grey ground (#F4F6F8) with white field sheets; 1px hairline form grid, no shadows, no rounded cards. Numbered field boxes (1a, 1b...). Exhibit tags with a notched top-right corner. Condensed caps labels (Barlow Condensed), form body (Public Sans), filled-in values in JetBrains Mono printed whole. State colours only for risk: critical #C8102E, high #D9822B, medium #B89B2B, low #5B6B82; VERIFIED green #2E7D5B.

STORY: The viewer sees three agents sign a custody chain, the counts of what is in the app, a graph with one red path to a vulnerable package, then opens an exhibit: facts, path, origin, integrity, and a custody log separating tool facts, VERIFIED and INFERRED claims.

FIRST VIEWPORT: 1440x900. Left 248px navy rail: GUARDIAN wordmark, case (run id, target, commit), custody chain of agents with numbered boxes and one-line results, then section nav (Graph, Exhibits, What changed, Custody log). Top of the work area: a 6-cell form strip of counts. Centre: dependency graph (roots left, direct deps, paths to findings, pseudo-nodes for CI/image/config), the selected path drawn in red, off-path nodes dimmed. Right 440px: exhibit sheet of the selected finding with numbered fields and its custody log.

FORM: Chain of Custody (forensic evidence intake form), position 3 of my ordered list, seed key fc5af4e4. Signature move: the per-finding custody log, agents signing in sequence with fact/VERIFIED/INFERRED stamps. Raises: full-length mono hashes (Datamatics); registered before/after diff rows (Botanical folio); selection dims off-path nodes (Streaming wall); one 1px hairline grid (Design annual); numbered fields as navigation (Crouwel grid).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
