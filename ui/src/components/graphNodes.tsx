import { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Container, FileCog, Workflow } from "lucide-react";
import type { VisNodeData } from "../lib/layout";
import { RISK_LABEL } from "../lib/format";
import type { Risk } from "../api/types";

/** Level word plus the highest score on the item, e.g. "High 72": colour is never the only signal. */
function RiskChip({ risk, score, count }: { risk: Risk; score: unknown; count: number }) {
  const s = typeof score === "number" ? score.toFixed(0) : null;
  return (
    <span className={`g-chip r-${risk}`} title={`${RISK_LABEL[risk]} risk${s ? `, highest score ${s} of 100` : ""}, ${count} finding${count === 1 ? "" : "s"}`}>
      {RISK_LABEL[risk]}
      {s && <b className="num">{s}</b>}
    </span>
  );
}

export type GNode = Node<VisNodeData>;

const Ports = () => (
  <>
    <Handle type="target" position={Position.Left} isConnectable={false} className="gport" />
    <Handle type="source" position={Position.Right} isConnectable={false} className="gport" />
  </>
);

const ProjectNode = memo(function ProjectNode({ data }: NodeProps<GNode>) {
  return (
    <div className="gnode g-project">
      <Ports />
      <span className="g-project-kind">Project</span>
      <span className="g-project-name">{data.label}</span>
      <span className="g-project-count mono">
        {data.packages.toLocaleString()} packages
        {data.hidden > 0 && <span className="g-more num" title="Direct dependencies that are not drawn because they have no findings"> +{data.hidden} more</span>}
      </span>
    </div>
  );
});

const PackageNode = memo(function PackageNode({ data }: NodeProps<GNode>) {
  const risk = data.findings > 0 ? (data.risk ?? "low") : null;
  return (
    <div className={`gnode g-pkg${risk ? ` has-risk r-${risk}` : ""}`}>
      <Ports />
      <span className="g-row">
        <span className="g-name" title={data.label}>
          {data.label}
        </span>
        {risk && <RiskChip risk={risk} score={data.score} count={data.findings} />}
      </span>
      <span className="g-row g-meta">
        <span className="mono g-ver">{data.version ?? ""}</span>
        {data.direct && <span className="g-tag">direct</span>}
        {data.dev && <span className="g-scope dev">dev</span>}
        {data.hidden > 0 && (
          <span className="g-more num" title={`${data.hidden} more direct dependencies are not drawn. Turn off "Risk paths only" to see them.`}>
            +{data.hidden} more
          </span>
        )}
      </span>
    </div>
  );
});

const ICON = { ci: Workflow, image: Container, config: FileCog } as const;
const KIND = { ci: "CI", image: "Image", config: "Config" } as const;

const PseudoNode = memo(function PseudoNode({ data }: NodeProps<GNode>) {
  const k = data.kind as "ci" | "image" | "config";
  const Icon = ICON[k] ?? FileCog;
  const risk = data.findings > 0 ? (data.risk ?? "low") : null;
  return (
    <div className={`gnode g-pseudo${risk ? ` has-risk r-${risk}` : ""}`}>
      <Ports />
      <Icon size={14} aria-hidden />
      <span className="g-name" title={data.label}>
        {data.label}
      </span>
      <span className="g-tag">{KIND[k] ?? k}</span>
      {risk && <RiskChip risk={risk} score={data.score} count={data.findings} />}
    </div>
  );
});

const TrayNode = memo(function TrayNode({ data }: NodeProps<GNode>) {
  return (
    <div className="gnode g-tray">
      <Handle type="target" position={Position.Left} isConnectable={false} className="gport" />
      <span>
        <b>+{data.packages} more</b> direct dependencies of {data.label}, with no findings
      </span>
    </div>
  );
});

export const nodeTypes = { project: ProjectNode, package: PackageNode, pseudo: PseudoNode, tray: TrayNode };
