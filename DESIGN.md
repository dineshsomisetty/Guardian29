---
name: Guardian
description: Chain of Custody. A forensic evidence-intake form for supply-chain findings, where every agent signs its custody log.
colors:
  custody-ink: "#14233f"
  custody-ink-raised: "#1d3157"
  ink-hairline: "#2c4069"
  on-ink: "#e6ecf4"
  on-ink-muted: "#9fb1c9"
  form-ground: "#f4f6f8"
  field-sheet: "#ffffff"
  form-line: "#d3dae3"
  form-line-soft: "#e6eaef"
  text-secondary: "#4a5b75"
  text-tertiary: "#66768e"
  critical: "#c8102e"
  critical-wash: "#fbe9ec"
  high: "#c76a12"
  high-wash: "#fbf0e4"
  medium: "#8f7614"
  medium-wash: "#f6f1dc"
  low: "#5b6b82"
  low-wash: "#eef1f5"
  verified: "#2e7d5b"
  verified-wash: "#e6f2ec"
  llm-amber: "#f3c969"
  focus-blue: "#3a6fd8"
typography:
  wordmark:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 700
    lineHeight: 0.9
    letterSpacing: "0.06em"
  count:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "clamp(1.625rem, 2.3vw, 2.25rem)"
    fontWeight: 700
    lineHeight: "2.5rem"
    letterSpacing: "0.01em"
  headline:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "1.1875rem"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 800
    lineHeight: 1.25
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Barlow Condensed, Arial Narrow, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "0.12em"
  value:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "0.7812rem"
    fontWeight: 400
    lineHeight: 1.45
rounded:
  none: "0"
spacing:
  hair: "1px"
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  rail-w: "16.5rem"
  sheet-w: "28.25rem"
  strip-h: "6.5rem"
components:
  rail:
    backgroundColor: "{colors.custody-ink}"
    textColor: "{colors.on-ink}"
    width: "16.5rem"
  field-sheet:
    backgroundColor: "{colors.field-sheet}"
    textColor: "{colors.custody-ink}"
    rounded: "{rounded.none}"
  stamp-critical:
    backgroundColor: "{colors.critical-wash}"
    textColor: "{colors.critical}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    height: "1.4rem"
    padding: "0 0.5rem"
  stamp-verified:
    backgroundColor: "{colors.verified-wash}"
    textColor: "{colors.verified}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    height: "1.4rem"
    padding: "0 0.5rem"
  segment-selected:
    backgroundColor: "{colors.custody-ink}"
    textColor: "{colors.on-ink}"
    typography: "{typography.label}"
    height: "32px"
  field-number:
    textColor: "{colors.text-tertiary}"
    rounded: "{rounded.none}"
    height: "1.25rem"
    padding: "0 4px"
---

# Design System: Guardian

## Overview

**Creative North Star: "The Intake Form"**

Guardian is a forensic evidence-intake form rendered as a dashboard. A deep custody-ink rail and header band hold the case and the chain of agents; a cool form-grey ground carries white field sheets divided by one 1px hairline grid. Every finding is an exhibit with a tag, numbered particulars, and a custody log in which each agent signs in sequence. The system refuses the KPI-tile security dashboard and the unlabelled paragraph of AI output.

Density is high and precise: condensed caps for the pre-printed form labels, a plain grotesque for form prose, and monospace for filled-in values, printed whole and never truncated. Corners are square, surfaces are flat, and nothing casts a shadow. Colour is rationed: ink and grey carry structure, and the risk hues appear only where risk is stated.

**Key Characteristics:**
- One 1px hairline grid; separation by line, never by shadow or radius.
- Three-voice type: condensed caps label, Public Sans form body, JetBrains Mono value.
- Numbered field boxes (1a, 1b) and exhibit numbers act as navigation anchors.
- Notched corners (exhibit tag top-right, graph filing tag top-left) as the only silhouette device.
- Honest labelling: fact, VERIFIED, INFERRED, rule and rejected each have a distinct stamp.

## Colors

A restrained blue-ink and cool-grey palette; the only saturated colours are risk states, the VERIFIED green, and one amber that marks LLM-produced work.

### Primary
- **Custody Ink** (#14233f): rail, header bands, primary text, selected segments, the project node, exhibit-tag border, the 1px selection marker.
- **Custody Ink Raised** (#1d3157): hover and active row on the rail; code chips on boot screen.
- **Ink Hairline** (#2c4069): 1px dividers on ink.

### Secondary
- **Verified Green** (#2e7d5b, wash #e6f2ec): the VERIFIED stamp and analyst-statement caption only.
- **LLM Amber** (#f3c969): marks the LLM step in the custody chain, the active nav bar on ink, and LLM events in the trace. Its tinted bar fills in the trace are #fcf1d4 and #d9a22a. Amber is a provenance mark, never a risk colour.

### Tertiary (risk states)
- **Critical** (#c8102e, wash #fbe9ec): critical stamps, node borders, the selected path edge (2.5px).
- **High** (#c76a12, wash #fbf0e4), **Medium** (#8f7614, wash #f6f1dc), **Low** (#5b6b82, wash #eef1f5).

### Neutral
- **Form Ground** (#f4f6f8): page ground, graph canvas, table head, exhibit column background.
- **Field Sheet** (#ffffff): every panel, cell, chip, and node body.
- **Form Line** (#d3dae3) and **Form Line Soft** (#e6eaef): the structural hairline and the interior row hairline.
- **Text Secondary** (#4a5b75) and **Text Tertiary** (#66768e): supporting text and field numbers; the latter is the lightest allowed text on white (4.6:1).
- **On Ink** (#e6ecf4) and **On Ink Muted** (#9fb1c9): text on the rail, tinted not grey.
- **Focus Blue** (#3a6fd8): focus ring and link hover only.

### Named Rules
**The Risk-Only Rule.** Red, orange, ochre and slate-low appear only to state a risk level. Structure, selection and emphasis use ink.

**The Provenance Amber Rule.** Amber means "an LLM did this". It never signals severity.

**The Tinted Neutral Rule.** Every grey is blue-tinted from the ink; no pure grey and no pure black text.

## Typography

**Label Font:** Barlow Condensed (Arial Narrow fallback)
**Form Font:** Public Sans (system-ui fallback)
**Value Font:** JetBrains Mono (ui-monospace fallback)

**Character:** The condensed caps read as the pre-printed form; Public Sans is the clerk's prose; mono is the filled-in entry. Body numerals are tabular throughout. Root size steps 16px, 18px from 1600px, 20px from 2200px, and all type is rem so the interface scales for projectors (graph node text stays in px because dagre lays it out).

### Hierarchy
- **Wordmark / Count** (Barlow Condensed 700, 1.875rem / count clamp 1.625-2.25rem, line-height 0.9 / 2.5rem): GUARDIAN wordmark, the six strip counts, summary values.
- **Headline** (Public Sans 800, 1.1875rem, 1.2, -0.01em): panel titles.
- **Title** (Public Sans 800, 1.25rem, 1.25, -0.01em): exhibit tag title.
- **Body** (Public Sans 400, 0.875rem, 1.45): statements and prose; analyst statement capped at 68ch.
- **Label** (Barlow Condensed 600-700, 0.75rem, 0.12em, uppercase): field labels, stamps, section heads (1rem, 0.1em), nav names (1rem, 0.06em), column heads.
- **Value** (JetBrains Mono 400, 0.7812rem, 1.45): ids, versions, paths, evidence; full hashes drop to 0.7188rem and wrap, never truncate.

### Named Rules
**The Three Voices Rule.** Printed form text is condensed caps, prose is Public Sans, entered data is mono. Never set a value in the form face or a label in mono.

**The Printed Whole Rule.** Hashes, ids and paths wrap; they are never ellipsised in the exhibit sheet.

## Layout

A three-column shell: rail (16.5rem), work area (flexible), exhibit sheet (28.25rem), full viewport height, with the work area stacking a 6.5rem six-cell count strip over the active view. Views (Graph, Exhibits, What changed, Custody log) share one panel-head pattern (18px 24px 14px padding, hairline underneath). Spacing is on a 4/8/12/16/24px rhythm, with row heights of 44px (findings), 38px (changes) and 32px (controls). Fields are a 30px number gutter, a 4.875rem label column and a value column; short fields pair two to a row.

Responsive: below 1360px the strip uses short labels and tighter tracking; below 1100px the shell stacks and the rail becomes a top bar with a scrolling tab row and a collapsed "Case and custody chain" disclosure; below 640px the strip is two columns.

## Elevation & Depth

Flat. There are no shadows anywhere; React Flow's default shadows are explicitly stripped. Depth comes from tonal layering (white sheets on grey ground, ink over both) and 1px hairlines. State is shown by line weight and fill: selected node gets a 1px ink outline offset 4px, like circling an exhibit; off-path nodes drop to 0.5 opacity and edges to 0.28.

### Named Rules
**The No-Shadow Rule.** Nothing carries a box-shadow. If a surface needs lifting, give it a hairline or an ink fill.

## Shapes

Square. Every border-radius is 0 on surfaces, controls, stamps, nodes and switches; the sole exception is the 6px scrollbar thumb. The silhouette devices are notches: the exhibit tag has its top-right corner cut with a 22px ink hairline diagonal, and graph filing tags (CI, image, config) have a 12px top-left notch. Finding-count chips sit on a node's top-right corner like a stamp. Dashed borders mean "not firm": dev-scope packages and INFERRED stamps. A 135-degree hairline hatch marks the empty side of an added or removed diff row.

## Components

### Stamps
Height 1.4rem, 1px currentColor border, condensed caps 0.12em. Critical/high/medium/low and VERIFIED are tinted-wash fills in their own colour; INFERRED is white with a dashed border; FACT is white in ink; RULE is white in secondary text; REJECTED is critical-red on white. Small variant 19px. Stamps enter with a short press (scale 1.15 to 1, 160ms).

### Rail and Custody Chain
Ink column. Wordmark, case block (mono id and meta), then the chain: 28px square numbered boxes joined by a 1px vertical line, role in condensed caps, one-line result beneath; an LLM step's box turns amber. Nav rows are condensed caps with a mono number and count; the current row gets Custody Ink Raised fill and a 3px amber left bar.

### Count Strip
Six cells on white, 1px soft dividers, three fixed rows (label / value / sub) so all values share a baseline.

### Findings Register
Sticky grey table head with sortable condensed-caps column buttons; 44px rows; selected row gets #eef2f8 fill and a 1px ink marker at the left edge. Filter bar uses a segmented control (selected segment fills ink), square selects, search and a square toggle.

### Exhibit Sheet
Right column on grey: notched exhibit tag, then white section sheets with a condensed-caps head and numbered field rows. Evidence ids are dotted-underlined mono links that expand an evidence drawer (grey, hairline-bordered, excerpt in a white box, facts as a hairline table).

### Custody Log
Signature component. Ordered rows: 26px ink-bordered number box, who in condensed caps, what in form text, a stamp at the right, joined by a 1px chain line. Rows sign in (translateY 6px, 280ms, 70ms stagger) and each stamp presses afterwards; a rejected row's box turns critical.

### Graph Nodes
Project: ink block with white condensed name. Package: 232x56 white box, 1px line border (dashed for dev), 1.5px risk-coloured border when it carries findings, mono name and version, finding-count chip on the corner. Pseudo-node: notched filing tag. The selected path is a 2.5px square-capped critical edge that draws on.

### What Changed
Registered before/after rows: name and version either side of a centre gutter with a stamp, hairline-divided; the after version is ink and bold, the before version is tertiary.

## Do's and Don'ts

### Do:
- **Do** separate regions with a 1px hairline (#d3dae3, or #e6eaef inside rows), not shadow, tint blocks or radius.
- **Do** keep every radius at 0 on surfaces and controls.
- **Do** set labels in Barlow Condensed uppercase with 0.1-0.12em tracking, prose in Public Sans, entered data in JetBrains Mono.
- **Do** pair every risk or claim state with a stamp that carries its word, not colour alone.
- **Do** show a long hash or id in full, wrapped, in the exhibit sheet.
- **Do** honour `prefers-reduced-motion`; animation exists only for custody signing, path draw and relay-band growth.
- **Do** use ease-out `cubic-bezier(0.16, 1, 0.3, 1)` at 120-280ms for state transitions.

### Don't:
- **Don't** add box-shadows, rounded cards, or gradient fills (the only gradients are the notch triangle and the diff hatch).
- **Don't** use risk colours for anything other than a risk level, or amber for anything other than LLM provenance.
- **Don't** introduce a second display face, or set structure in colour where ink works.
- **Don't** put KPI tiles over a table, or present AI output as an unlabelled paragraph; every claim carries fact, VERIFIED, INFERRED or rule.
