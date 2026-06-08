import type { AttackPath, PathHop } from "./api/types";

export interface FlowNodeData {
  label: string;
  /** The hop that arrives at this capability (null for the entry node). */
  hop: PathHop | null;
  entryResource?: string;
  [key: string]: unknown;
}

export interface FlowNode {
  id: string;
  position: { x: number; y: number };
  data: FlowNodeData;
  type: "capability";
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

/** pathToFlow turns an attack path into a left-to-right node/edge graph: one
 * node per capability in the chain, edges labelled by the enabling finding +
 * ATT&CK technique. Pure and deterministic (no layout library needed). */
export function pathToFlow(path: AttackPath): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const hops = [...path.hops].sort((a, b) => a.order - b.order);
  const caps: string[] = hops.length ? [hops[0].from, ...hops.map((h) => h.to)] : [];

  const nodes: FlowNode[] = caps.map((cap, i) => ({
    id: `n${i}`,
    position: { x: i * 220, y: 0 },
    type: "capability",
    data: {
      label: cap,
      hop: i === 0 ? null : hops[i - 1],
      entryResource: i === 0 ? `${path.entry.kind} ${path.entry.namespace ? path.entry.namespace + "/" : ""}${path.entry.name}` : undefined,
    },
  }));

  const edges: FlowEdge[] = hops.map((h, i) => ({
    id: `e${i}`,
    source: `n${i}`,
    target: `n${i + 1}`,
    label: `${h.enabledBy} ${h.technique.join(", ")}`.trim(),
  }));

  return { nodes, edges };
}
