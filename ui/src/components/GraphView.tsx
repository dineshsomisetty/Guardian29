import dagre from "dagre";
import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { GraphData, GraphNode, Priority } from "../api/types";

const riskColor: Record<Priority, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
};

interface GraphViewProps {
  graph: GraphData;
  selectedNodeId: string | null;
  onSelect: (node: GraphNode | null) => void;
}

export default function GraphView({ graph, selectedNodeId, onSelect }: GraphViewProps) {
  const visible = graph.nodes.filter((node) =>
    node.kind === "root" || node.kind !== "package" || node.direct === true || node.finding_ids.length > 0,
  );
  const visibleIds = new Set(visible.map((node) => node.id));
  const hiddenCounts = new Map<string, number>();
  for (const edge of graph.edges) {
    if (visibleIds.has(edge.source) && !visibleIds.has(edge.target)) {
      hiddenCounts.set(edge.source, (hiddenCounts.get(edge.source) ?? 0) + 1);
    }
  }

  const pathNodeIds = new Set<string>();
  const pathEdgeIds = new Set<string>();
  if (selectedNodeId) {
    const pending = [selectedNodeId];
    pathNodeIds.add(selectedNodeId);
    while (pending.length > 0) {
      const target = pending.pop();
      if (!target) continue;
      for (const edge of graph.edges) {
        if (edge.target === target) {
          pathEdgeIds.add(`${edge.source}-${edge.target}`);
          if (!pathNodeIds.has(edge.source)) {
            pathNodeIds.add(edge.source);
            pending.push(edge.source);
          }
        }
      }
    }
  }

  const dag = new dagre.graphlib.Graph();
  dag.setGraph({ rankdir: "LR", ranksep: 90, nodesep: 25 });
  dag.setDefaultEdgeLabel(() => ({}));

  const nodes: Node[] = visible.map((node) => {
    dag.setNode(node.id, { width: 170, height: 42 });
    const collapsed = hiddenCounts.get(node.id) ?? 0;
    const isSelected = selectedNodeId === node.id;
    return {
      id: node.id,
      position: { x: 0, y: 0 },
      data: { label: `${node.label}${collapsed > 0 ? ` (+${collapsed} collapsed)` : ""}` },
      style: {
        border: `${isSelected ? 3 : 2}px solid ${isSelected || pathNodeIds.has(node.id) ? "#2563eb" : riskColor[node.risk]}`,
        borderRadius: 8,
        background: "#fff",
        width: 170,
      },
    };
  });

  const edges: Edge[] = graph.edges
    .filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
    .map((edge) => {
      const id = `${edge.source}-${edge.target}`;
      const highlighted = pathEdgeIds.has(id);
      return {
        id,
        source: edge.source,
        target: edge.target,
        style: { stroke: highlighted ? "#2563eb" : "#94a3b8", strokeWidth: highlighted ? 2.5 : 1 },
      };
    });

  edges.forEach((edge) => dag.setEdge(edge.source, edge.target));
  dagre.layout(dag);

  const laidOutNodes = nodes.map((node) => ({ ...node, position: dag.node(node.id) }));

  return (
    <ReactFlow
      nodes={laidOutNodes}
      edges={edges}
      onNodeClick={(_, node) => onSelect(graph.nodes.find((item) => item.id === node.id) ?? null)}
      fitView
      minZoom={0.05}
    >
      <Background />
      <Controls />
    </ReactFlow>
  );
}
