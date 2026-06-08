import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ReactFlow, Background, Controls, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CapabilityNode } from "@/components/CapabilityNode";
import { pathToFlow, type FlowNodeData } from "@/lib/attackGraph";
import { SEVERITY_ORDER, type AttackPath, type Severity } from "@/lib/api/types";

function CapabilityFlowNode({ data, selected }: NodeProps) {
  const d = data as FlowNodeData;
  return <CapabilityNode data={d} selected={selected} onSelect={d.onSelect as (x: FlowNodeData) => void} />;
}
const nodeTypes = { capability: CapabilityFlowNode };

export function AttackPaths() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const [impact, setImpact] = useState<Severity | "all">("all");
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<FlowNodeData | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["attack-paths", cluster],
    queryFn: () => apiClient.listAttackPaths(cluster),
  });

  const paths = useMemo(
    () => (data?.paths ?? []).filter((p) => impact === "all" || p.severity === impact),
    [data, impact],
  );
  const activePath: AttackPath | undefined = paths.find((p) => p.id === selectedPathId) ?? paths[0];

  const { nodes, edges } = useMemo(() => {
    if (!activePath) return { nodes: [], edges: [] };
    const flow = pathToFlow(activePath);
    return {
      nodes: flow.nodes.map((n) => ({ ...n, data: { ...n.data, onSelect: setSelectedNode } })),
      edges: flow.edges,
    };
  }, [activePath]);

  if (isLoading) return <p className="text-fg-muted">Loading attack paths…</p>;
  if (isError) return <p className="text-sev-high">Could not load attack paths.</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Attack Paths</h1>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-fg-subtle">Impact</span>
          <select
            aria-label="Filter by impact"
            className="rounded-md border border-border bg-bg-raised px-2 py-1"
            value={impact}
            onChange={(e) => setImpact(e.target.value as Severity | "all")}
          >
            <option value="all">All</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      </div>

      {paths.length === 0 && <p className="text-fg-muted">No attack paths for this scope.</p>}

      {paths.length > 1 && (
        <div className="flex flex-wrap gap-2">
          {paths.map((p) => (
            <button
              key={p.id}
              onClick={() => setSelectedPathId(p.id)}
              className={`rounded border px-2 py-1 text-xs ${p.id === activePath?.id ? "border-accent text-accent" : "border-border text-fg-muted"}`}
            >
              {p.id} {p.title}
            </button>
          ))}
        </div>
      )}

      {activePath && (
        <>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={activePath.severity} />
            <span className="text-sm">{activePath.title}</span>
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="col-span-2 h-[480px] p-0">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                nodesDraggable={false}
                fitView
                nodesFocusable
                aria-label="Attack path graph"
              >
                <Background />
                <Controls />
              </ReactFlow>
            </Card>
            <Card>
              <h3 className="mb-2 text-sm font-medium text-fg-muted">Node detail</h3>
              {selectedNode ? <NodeDetail data={selectedNode} /> : (
                <p className="text-sm text-fg-subtle">Select a node to see its ATT&amp;CK technique, resource, and enabling finding.</p>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function NodeDetail({ data }: { data: FlowNodeData }) {
  return (
    <dl className="space-y-2 text-sm">
      <div>
        <dt className="text-xs uppercase text-fg-subtle">Capability</dt>
        <dd className="font-mono text-xs">{data.label}</dd>
      </div>
      {data.entryResource && (
        <div>
          <dt className="text-xs uppercase text-fg-subtle">Entry resource</dt>
          <dd className="font-mono text-xs">{data.entryResource}</dd>
        </div>
      )}
      {data.hop && (
        <>
          <div>
            <dt className="text-xs uppercase text-fg-subtle">Enabling finding</dt>
            <dd className="font-mono text-xs">{data.hop.enabledBy}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase text-fg-subtle">ATT&amp;CK technique</dt>
            <dd className="font-mono text-xs">{data.hop.technique.join(", ")}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase text-fg-subtle">Narrative</dt>
            <dd>{data.hop.narrative}</dd>
          </div>
        </>
      )}
    </dl>
  );
}
