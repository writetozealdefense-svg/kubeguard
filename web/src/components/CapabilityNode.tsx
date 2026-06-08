/** A keyboard-accessible attack-graph node (WCAG 2.1 AA): a real focusable
 * button. Used both as a React Flow custom node and tested directly in jsdom. */
import type { FlowNodeData } from "@/lib/attackGraph";

export function CapabilityNode({
  data,
  selected,
  onSelect,
}: {
  data: FlowNodeData;
  selected?: boolean;
  onSelect?: (data: FlowNodeData) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect?.(data)}
      aria-pressed={selected}
      aria-label={`Capability ${data.label}${data.hop ? `, enabled by ${data.hop.enabledBy}` : ", entry point"}`}
      className={`rounded-md border px-3 py-2 text-xs font-medium ${
        selected ? "border-accent bg-accent/15 text-accent" : "border-border bg-bg-raised text-fg"
      }`}
    >
      {data.label}
    </button>
  );
}
