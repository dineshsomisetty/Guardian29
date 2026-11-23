import { useMemo, useState } from "react";
import dagre from "dagre";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { Filter, Search, X } from "lucide-react";
import type { GraphData, GraphNode, Priority } from "../api/types";
import CustomGraphNode, { type CustomNodeData } from "./CustomGraphNode";

interface GraphViewProps {
  graph: GraphData;
  selectedNodeId: string | null;
  onSelect: (node: GraphNode | null) => void;
}

const nodeTypes = {
  custom: CustomGraphNode,
};

export default function GraphView({ graph, selectedNodeId, onSelect }: GraphViewProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<Priority | "all" | "non-package">("all");

  const { visible, hiddenCounts } = useMemo(() => {
    const rawVisible = graph.nodes.filter(
      (node) =>
        node.kind === "root" ||
        node.kind !== "package" ||
        node.direct === true ||
        node.finding_ids.length > 0,
    );
    const visibleIdSet = new Set(rawVisible.map((n) => n.id));
    const counts = new Map<string, number>();

    for (const edge of graph.edges) {
      if (visibleIdSet.has(edge.source) && !visibleIdSet.has(edge.target)) {
        counts.set(edge.source, (counts.get(edge.source) ?? 0) + 1);
      }
    }
    return { visible: rawVisible, hiddenCounts: counts };
  }, [graph]);

  const { pathNodeIds, pathEdgeIds } = useMemo(() => {
    const nodeIds = new Set<string>();
    const edgeIds = new Set<string>();

    if (selectedNodeId) {
      const pending = [selectedNodeId];
      nodeIds.add(selectedNodeId);

      while (pending.length > 0) {
        const target = pending.pop();
        if (!target) continue;

        for (const edge of graph.edges) {
          if (edge.target === target) {
            edgeIds.add(`${edge.source}-${edge.target}`);
            if (!nodeIds.has(edge.source)) {
              nodeIds.add(edge.source);
              pending.push(edge.source);
            }
          }
        }
      }
    }

    return { pathNodeIds: nodeIds, pathEdgeIds: edgeIds };
  }, [graph.edges, selectedNodeId]);

  const filteredVisible = useMemo(() => {
    return visible.filter((node) => {
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesLabel = node.label.toLowerCase().includes(query);
        const matchesId = node.id.toLowerCase().includes(query);
        const matchesFinding = node.finding_ids.some((fid) => fid.toLowerCase().includes(query));
        if (!matchesLabel && !matchesId && !matchesFinding) return false;
      }

      if (riskFilter === "non-package") {
        return node.kind !== "package" && node.kind !== "root";
      }
      if (riskFilter !== "all") {
        return node.risk === riskFilter;
      }
      return true;
    });
  }, [visible, searchQuery, riskFilter]);

  const { nodes, edges } = useMemo(() => {
    const dag = new dagre.graphlib.Graph();
    dag.setGraph({ rankdir: "LR", ranksep: 100, nodesep: 35 });
    dag.setDefaultEdgeLabel(() => ({}));

    const visibleIds = new Set(filteredVisible.map((node) => node.id));

    filteredVisible.forEach((node) => {
      dag.setNode(node.id, { width: 210, height: 62 });
    });

    const activeEdges: Edge[] = graph.edges
      .filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
      .map((edge) => {
        const id = `${edge.source}-${edge.target}`;
        const isPath = pathEdgeIds.has(id);
        return {
          id,
          source: edge.source,
          target: edge.target,
          animated: isPath,
          style: {
            stroke: isPath ? "#38bdf8" : "#334155",
            strokeWidth: isPath ? 2.5 : 1.2,
          },
        };
      });

    activeEdges.forEach((edge) => dag.setEdge(edge.source, edge.target));
    dagre.layout(dag);

    const layoutNodes: Node[] = filteredVisible.map((node) => {
      const pos = dag.node(node.id) ?? { x: 0, y: 0 };
      const isSelected = selectedNodeId === node.id;
      const isPath = pathNodeIds.has(node.id);
      const collapsed = hiddenCounts.get(node.id) ?? 0;

      const nodeData: CustomNodeData = {
        id: node.id,
        kind: node.kind,
        label: node.label,
        version: node.version,
        scope: node.scope,
        risk: node.risk,
        finding_ids: node.finding_ids,
        collapsedCount: collapsed,
        isSelected,
        isPath,
      };

      return {
        id: node.id,
        type: "custom",
        position: { x: pos.x - 105, y: pos.y - 31 },
        data: nodeData,
      };
    });

    return { nodes: layoutNodes, edges: activeEdges };
  }, [filteredVisible, graph.edges, hiddenCounts, pathEdgeIds, pathNodeIds, selectedNodeId]);

  return (
    <div className="relative w-full h-full flex flex-col bg-slate-950">
      <div className="flex flex-wrap items-center justify-between gap-2.5 px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 z-10 backdrop-blur-md">
        <div className="flex items-center gap-2 flex-1 max-w-sm">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search packages or findings..."
              className="w-full pl-8 pr-7 py-1.5 bg-slate-800/80 border border-slate-700 rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-slate-500 flex items-center gap-1 text-[11px] font-medium mr-1">
            <Filter className="w-3 h-3" /> Filter:
          </span>
          <button
            onClick={() => setRiskFilter("all")}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "all"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            }`}
          >
            All ({visible.length})
          </button>
          <button
            onClick={() => setRiskFilter("critical")}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "critical"
                ? "bg-red-950 text-red-300 border border-red-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-red-300"
            }`}
          >
            Critical
          </button>
          <button
            onClick={() => setRiskFilter("high")}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "high"
                ? "bg-orange-950 text-orange-300 border border-orange-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-orange-300"
            }`}
          >
            High
          </button>
          <button
            onClick={() => setRiskFilter("medium")}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "medium"
                ? "bg-amber-950 text-amber-300 border border-amber-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-amber-300"
            }`}
          >
            Medium
          </button>
          <button
            onClick={() => setRiskFilter("low")}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "low"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-emerald-300"
            }`}
          >
            Low
          </button>
          <button
            onClick={() => setRiskFilter("non-package")}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              riskFilter === "non-package"
                ? "bg-purple-950 text-purple-300 border border-purple-700/60"
                : "bg-slate-800/60 text-slate-400 hover:text-purple-300"
            }`}
          >
            CI/Docker
          </button>
        </div>
      </div>

      <div className="flex-1 w-full h-full relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => {
            const rawNode = graph.nodes.find((item) => item.id === node.id) ?? null;
            onSelect(rawNode);
          }}
          onPaneClick={() => onSelect(null)}
          fitView
          minZoom={0.05}
          maxZoom={1.5}
        >
          <Background color="#1e293b" gap={20} size={1} />
          <Controls className="!bg-slate-900 !border-slate-800 !text-slate-300 [&>button]:!border-slate-800 [&>button]:!bg-slate-900 [&>button:hover]:!bg-slate-800" />
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as unknown as CustomNodeData;
              if (data?.risk === "critical") return "#ef4444";
              if (data?.risk === "high") return "#f97316";
              if (data?.risk === "medium") return "#f59e0b";
              return "#10b981";
            }}
            className="!bg-slate-900/90 !border-slate-800 rounded-md overflow-hidden !bottom-4 !right-4"
          />
        </ReactFlow>

        <div className="absolute bottom-4 left-4 flex flex-wrap items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 backdrop-blur-md text-[11px] text-slate-400 z-10 pointer-events-none">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span>Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span>High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>Low</span>
          </div>
          <div className="flex items-center gap-1.5 pl-2 border-l border-slate-700">
            <span className="w-2.5 h-0.5 bg-sky-400" />
            <span>Traced Path</span>
          </div>
        </div>
      </div>
    </div>
  );
}
