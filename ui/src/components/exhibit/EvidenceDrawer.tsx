import type { Evidence } from "../../api/types";
import { factText, fileLine, toolName } from "./format";

/** Inline evidence record: facts table, quoted excerpt, provenance. Every value printed whole. */
export default function EvidenceDrawer({ domId, id, ev }: { domId: string; id: string; ev: Evidence | null | undefined }) {
  if (!ev) {
    return (
      <div className="ev-drawer" id={domId}>
        <p className="ev-missing">Evidence record <span className="value">{id}</span> was not found in this run.</p>
      </div>
    );
  }
  const facts = Object.entries(ev.facts ?? {});
  const fl = fileLine(ev);
  return (
    <div className="ev-drawer" id={domId}>
      <dl className="ev-meta">
        <div><dt className="label">Kind</dt><dd className="value">{ev.kind}</dd></div>
        <div><dt className="label">Tool</dt><dd className="value">{toolName(ev.source_tool)}</dd></div>
        <div><dt className="label">Collected</dt><dd className="value">{ev.created_at}</dd></div>
        {fl && <div><dt className="label">File:line</dt><dd className="value">{fl}</dd></div>}
        {ev.artifact_path && <div><dt className="label">Artifact</dt><dd className="value">{ev.artifact_path}</dd></div>}
        {ev.sha256 && <div><dt className="label">SHA-256</dt><dd className="value">{ev.sha256}</dd></div>}
      </dl>
      {ev.excerpt && <blockquote className="ev-excerpt value">{ev.excerpt}</blockquote>}
      {facts.length > 0 && (
        <table className="ev-facts">
          <caption className="label">Facts</caption>
          <tbody>
            {facts.map(([k, v]) => (
              <tr key={k}>
                <th scope="row">{k}</th>
                <td>{factText(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
