import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Box, Container, FileCode, GitBranch, ShieldAlert, Sparkles } from "lucide-react";
import type { Priority } from "../api/types";

export interface CustomNodeData extends Record<string, unknown> {
  id: string;
  kind: "package" | "ci" | "image" | "config" | "root";
  label: string;
  version?: string;
  scope?: "prod" | "dev" | "unknown";
  risk: Priority;
  finding_ids: string[];
  collapsedCount?: number;
  isSelected?: boolean;
  isPath?: boolean;
}

const riskBorderColors: Record<Priority, string> = {
  critical: "border-red-500 shadow-red-500/20",
  high: "border-orange-500 shadow-orange-500/20",
  medium: "border-amber-500 shadow-amber-500/20",
  low: "border-emerald-500/40 shadow-emerald-500/10",
};

const riskDotColors: Record<Priority, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-emerald-400",
};

export default function CustomGraphNode(props: NodeProps) {
  const data = props.data as unknown as CustomNodeData;
  const { kind, label, version, scope, risk, finding_ids, collapsedCount = 0, isSelected, isPath } = data;

  const renderIcon = () => {
    switch (kind) {
      case "root":
        return <Sparkles className="w-3.5 h-3.5 text-cyan-400" />;
      case "ci":
        return <GitBranch className="w-3.5 h-3.5 text-purple-400" />;
      case "image":
        return <Container className="w-3.5 h-3.5 text-blue-400" />;
      case "config":
        return <FileCode className="w-3.5 h-3.5 text-yellow-400" />;
      default:
        return <Box className="w-3.5 h-3.5 text-slate-300" />;
    }
  };

  const borderClass = isSelected
    ? "border-cyan-400 ring-2 ring-cyan-400/40 shadow-lg shadow-cyan-500/30"
    : isPath
    ? "border-blue-400 ring-1 ring-blue-400/30 shadow-md shadow-blue-500/20"
    : riskBorderColors[risk] ?? "border-slate-700";

  return (
    <div
      className={`relative px-3 py-2 rounded-lg bg-slate-900/95 backdrop-blur-sm border transition-all duration-150 cursor-pointer shadow-md min-w-[190px] max-w-[240px] ${borderClass} hover:border-cyan-400 hover:shadow-cyan-500/20`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-cyan-500 !w-2 !h-2 !border-none !-left-1"
      />

      <div className="flex items-center justify-between gap-1.5 mb-1">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="p-1 rounded bg-slate-800/80 shrink-0">{renderIcon()}</span>
          <span className="font-semibold text-xs text-slate-100 truncate">{label}</span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {finding_ids.length > 0 && (
            <span className="flex items-center gap-0.5 px-1 py-0.5 rounded text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/60">
              <ShieldAlert className="w-2.5 h-2.5" />
              {finding_ids.length}
            </span>
          )}
          <span className={`w-2 h-2 rounded-full ${riskDotColors[risk]}`} title={`Risk: ${risk}`} />
        </div>
      </div>

      <div className="flex items-center justify-between text-[10px] text-slate-400 gap-1">
        <span className="truncate font-mono">
          {version ? `v${version}` : kind === "root" ? "target" : kind}
        </span>
        <div className="flex items-center gap-1 shrink-0">
          {scope && scope !== "unknown" && (
            <span
              className={`px-1 rounded text-[9px] font-semibold uppercase ${
                scope === "prod"
                  ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800/40"
                  : "bg-slate-800 text-slate-400"
              }`}
            >
              {scope}
            </span>
          )}
          {collapsedCount > 0 && (
            <span className="px-1 rounded text-[9px] font-semibold bg-blue-950/80 text-blue-300 border border-blue-800/50">
              +{collapsedCount}
            </span>
          )}
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-cyan-500 !w-2 !h-2 !border-none !-right-1"
      />
    </div>
  );
}
