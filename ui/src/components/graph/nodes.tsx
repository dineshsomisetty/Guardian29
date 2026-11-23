import { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Container, FileCog, Workflow } from "lucide-react";
import type { VisNodeData } from "./layout";

export type CustodyNode = Node<VisNodeData>;

const Ports = () => (
  <>
    <Handle type="target" position={Position.Left} isConnectable={false} className="g-port" />
    <Handle type="source" position={Position.Right} isConnectable={false} className="g-port" />
  </>
);

export const ProjectNode = memo(function ProjectNode({ data }: NodeProps<CustodyNode>) {
  return (
    <div className="g-node g-project">
      <Ports />
      <span className="g-project-name">{data.label}</span>
      <span className="g-project-count">{data.packages.toLocaleString()} pkgs</span>
    </div>
  );
});

export const PackageNode = memo(function PackageNode({ data }: NodeProps<CustodyNode>) {
  const risk = data.findings > 0 ? data.risk ?? "low" : null;
  return (
    <div className={`g-node g-pkg${risk ? ` has-risk r-${risk}` : ""}${data.dev ? " is-dev" : ""}`}>
      <Ports />
      {data.direct && <span className="g-direct" title="Direct dependency">D</span>}
      <span className="g-pkg-text">
        <span className="g-pkg-name">{data.label}</span>
        {data.version && <span className="g-pkg-ver">{data.version}</span>}
      </span>
      {data.hidden > 0 && <span className="g-hidden" title={`${data.hidden} direct dependencies collapsed`}>+{data.hidden}</span>}
      {risk && (
        <span className={`g-chip r-${risk}`} title={`${data.findings} finding${data.findings === 1 ? "" : "s"}, ${risk}`}>
          {data.findings}
        </span>
      )}
    </div>
  );
});

const PSEUDO_ICON = { ci: Workflow, image: Container, config: FileCog } as const;
const PSEUDO_KIND = { ci: "CI", image: "Image", config: "Config" } as const;

export const PseudoNode = memo(function PseudoNode({ data }: NodeProps<CustodyNode>) {
  const k = data.kind as "ci" | "image" | "config";
  const Icon = PSEUDO_ICON[k];
  const risk = data.findings > 0 ? data.risk ?? "low" : null;
  return (
    <div className={`g-node g-tag${risk ? ` has-risk r-${risk}` : ""}`}>
      <Ports />
      <Icon size={15} strokeWidth={1.75} aria-hidden className="g-tag-icon" />
      <span className="g-tag-kind">{PSEUDO_KIND[k]}</span>
      <span className="g-tag-name">{data.label}</span>
      {risk && <span className={`g-chip r-${risk}`}>{data.findings}</span>}
    </div>
  );
});

export const TrayNode = memo(function TrayNode({ data }: NodeProps<CustodyNode>) {
  return (
    <div className="g-tray">
      <Handle type="target" position={Position.Left} isConnectable={false} className="g-port" />
      <span className="g-tray-title">Direct dependencies · {data.label}</span>
      <span className="g-tray-meta">{data.packages} with no findings and no risk path</span>
    </div>
  );
});

export const nodeTypes = { project: ProjectNode, package: PackageNode, pseudo: PseudoNode, tray: TrayNode };
