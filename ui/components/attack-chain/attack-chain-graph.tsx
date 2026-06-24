"use client";

import { useCallback, useMemo } from "react";
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  NodeProps,
  Handle,
  Position,
  MarkerType,
  Panel,
} from "reactflow";
import "reactflow/dist/style.css";
import { cn } from "@/lib/utils";
import type { AttackNode, AttackEdge, Finding } from "@/types";

// ── Custom node types ──────────────────────────────────────────────────────

const NODE_STYLES: Record<AttackNode["type"], { bg: string; border: string; icon: string; label: string }> = {
  recon:   { bg: "bg-info/10",     border: "border-info/40",     icon: "🔍", label: "Reconnaissance" },
  exploit: { bg: "bg-critical/10", border: "border-critical/40", icon: "⚡", label: "Exploitation"    },
  impact:  { bg: "bg-high/10",     border: "border-high/40",     icon: "💥", label: "Impact"          },
  pivot:   { bg: "bg-medium/10",   border: "border-medium/40",   icon: "🔄", label: "Lateral Move"    },
};

interface AttackNodeData {
  label:    string;
  nodeType: AttackNode["type"];
  finding?: Finding;
}

function AttackChainNode({ data, selected }: NodeProps<AttackNodeData>) {
  const style  = NODE_STYLES[data.nodeType];
  const f      = data.finding;

  return (
    <div
      className={cn(
        "min-w-[160px] max-w-[220px] rounded-lg border-2 p-3 shadow-lg transition-all",
        style.bg,
        style.border,
        selected && "ring-2 ring-primary ring-offset-2 ring-offset-background"
      )}
    >
      <Handle type="target" position={Position.Left}  className="!bg-border !border-background" />
      <Handle type="source" position={Position.Right} className="!bg-border !border-background" />

      <div className="flex items-center gap-2 mb-2">
        <span className="text-base">{style.icon}</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          {style.label}
        </span>
      </div>

      <p className="text-xs font-semibold leading-tight">{data.label}</p>

      {f && (
        <div className="mt-2 border-t border-border/50 pt-2 space-y-1">
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-muted-foreground">CVSS</span>
            <span className="text-[10px] font-black text-critical tabular-nums">
              {f.cvss_score.toFixed(1)}
            </span>
          </div>
          <p className="text-[10px] font-mono text-muted-foreground truncate">{f.owasp_code}</p>
        </div>
      )}
    </div>
  );
}

const nodeTypes = { attackNode: AttackChainNode };

// ── Demo chain ─────────────────────────────────────────────────────────────

const DEMO_NODES: Node<AttackNodeData>[] = [
  { id: "n1", type: "attackNode", position: { x: 0,   y: 100 }, data: { label: "Port scan & subdomain enum", nodeType: "recon" } },
  { id: "n2", type: "attackNode", position: { x: 260, y: 0   }, data: { label: "SQL Injection — search param", nodeType: "exploit", finding: { cvss_score: 9.8, owasp_code: "A03" } as Finding } },
  { id: "n3", type: "attackNode", position: { x: 260, y: 200 }, data: { label: "SSRF via webhook URL",          nodeType: "exploit", finding: { cvss_score: 8.3, owasp_code: "A10" } as Finding } },
  { id: "n4", type: "attackNode", position: { x: 520, y: 100 }, data: { label: "Admin DB access",              nodeType: "impact"  } },
  { id: "n5", type: "attackNode", position: { x: 780, y: 0   }, data: { label: "Data exfiltration",            nodeType: "impact"  } },
  { id: "n6", type: "attackNode", position: { x: 780, y: 200 }, data: { label: "Pivot to internal network",    nodeType: "pivot"   } },
];

const DEMO_EDGES: Edge[] = [
  { id: "e1-2", source: "n1", target: "n2", label: "discovers", markerEnd: { type: MarkerType.ArrowClosed } },
  { id: "e1-3", source: "n1", target: "n3", label: "discovers", markerEnd: { type: MarkerType.ArrowClosed } },
  { id: "e2-4", source: "n2", target: "n4", label: "leads to",  markerEnd: { type: MarkerType.ArrowClosed } },
  { id: "e3-4", source: "n3", target: "n4", label: "leads to",  markerEnd: { type: MarkerType.ArrowClosed } },
  { id: "e4-5", source: "n4", target: "n5", label: "enables",   markerEnd: { type: MarkerType.ArrowClosed } },
  { id: "e4-6", source: "n4", target: "n6", label: "enables",   markerEnd: { type: MarkerType.ArrowClosed } },
];

// ── Component ──────────────────────────────────────────────────────────────

interface AttackChainGraphProps {
  nodes?: Node<AttackNodeData>[];
  edges?: Edge[];
  className?: string;
}

export function AttackChainGraph({
  nodes: initialNodes = DEMO_NODES,
  edges: initialEdges = DEMO_EDGES,
  className,
}: AttackChainGraphProps) {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  return (
    <div className={cn("h-[520px] rounded-lg border bg-card overflow-hidden", className)}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        fitView
        attributionPosition="bottom-right"
        defaultEdgeOptions={{
          style: { strokeWidth: 2, stroke: "var(--color-border)" },
          labelStyle: { fontSize: 10, fill: "var(--color-muted-foreground)" },
          labelBgStyle: { fill: "var(--color-card)" },
        }}
      >
        <Background color="var(--color-border)" gap={20} size={1} />
        <Controls className="!bg-card !border-border" />
        <MiniMap
          className="!bg-card !border-border"
          nodeColor={(n) => {
            const t = (n.data as AttackNodeData).nodeType;
            if (t === "exploit") return "var(--color-critical)";
            if (t === "impact")  return "var(--color-high)";
            if (t === "pivot")   return "var(--color-medium)";
            return "var(--color-info)";
          }}
        />
        <Panel position="top-left">
          <div className="rounded-md bg-card/80 border px-3 py-2 text-xs backdrop-blur-sm">
            <p className="font-semibold mb-1">Attack Chain™</p>
            <div className="flex gap-3">
              {Object.entries(NODE_STYLES).map(([type, s]) => (
                <span key={type} className="flex items-center gap-1 text-muted-foreground">
                  {s.icon} {s.label}
                </span>
              ))}
            </div>
          </div>
        </Panel>
      </ReactFlow>
    </div>
  );
}
