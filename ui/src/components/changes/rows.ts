import type { Changes } from "../../api/types";

export type RowKind = "major" | "changed" | "removed" | "added";

export interface DiffRow {
  name: string;
  kind: RowKind;
  before: string | null; // version or range as written in the legacy manifest
  after: string | null;
  beforePurl?: string;
  afterPurl?: string;
}

/** pkg:npm/%40types/node@26.0.1 -> { name: "@types/node", version: "26.0.1" } */
export function parsePurl(purl: string): { name: string; version: string | null } {
  const body = purl.replace(/^pkg:[^/]+\//, "").split(/[?#]/)[0];
  const at = body.lastIndexOf("@");
  const raw = at > 0 ? body.slice(0, at) : body;
  const version = at > 0 ? decodeURIComponent(body.slice(at + 1)) : null;
  let name = raw;
  try { name = decodeURIComponent(raw); } catch { /* keep raw */ }
  return { name, version };
}

const ORDER: Record<RowKind, number> = { major: 0, changed: 1, removed: 2, added: 3 };

/** One row per dependency name across the union of both manifests, registered line for line. */
export function buildRows(c: Changes): DiffRow[] {
  const rows = new Map<string, DiffRow>();
  for (const ch of c.changed) {
    rows.set(ch.name, {
      name: ch.name,
      kind: ch.major_jump ? "major" : "changed",
      before: ch.from_range ?? ch.from,
      after: ch.to_range ?? ch.to,
    });
  }
  for (const p of c.removed) {
    const { name, version } = parsePurl(p);
    if (rows.has(name)) continue;
    rows.set(name, { name, kind: "removed", before: version, after: null, beforePurl: p });
  }
  for (const p of c.added) {
    const { name, version } = parsePurl(p);
    const prev = rows.get(name);
    if (prev?.kind === "removed") {
      // listed on both sides without a "changed" entry: register as a version change
      rows.set(name, { ...prev, kind: "changed", after: version, afterPurl: p });
      continue;
    }
    if (prev) continue;
    rows.set(name, { name, kind: "added", before: null, after: version, afterPurl: p });
  }
  return [...rows.values()].sort((a, b) => ORDER[a.kind] - ORDER[b.kind] || a.name.localeCompare(b.name));
}
