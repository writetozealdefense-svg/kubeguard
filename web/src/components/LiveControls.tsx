/** Header live controls (D5): a connection/scan indicator + a role-gated
 * "Scan now" button with optimistic feedback. */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useAuth } from "@/app/auth";
import { useCluster } from "@/app/cluster";
import type { LiveState } from "@/app/useScanStream";
import { Button } from "./ui/primitives";

export function LiveStatus({ live }: { live: LiveState }) {
  if (live.scanning) {
    return (
      <span className="flex items-center gap-1 text-xs text-accent" role="status" aria-live="polite">
        <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />
        Scanning… {Math.round(live.progress * 100)}%
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-xs text-fg-subtle" aria-label={live.connected ? "live" : "offline"}>
      <span className={`h-2 w-2 rounded-full ${live.connected ? "bg-sev-low" : "bg-fg-subtle"}`} />
      {live.connected ? "Live" : "Offline"}
    </span>
  );
}

export function ScanNowButton() {
  const apiClient = useApi();
  const { can } = useAuth();
  const { cluster } = useCluster();
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (clusterId: string) => apiClient.triggerScan(clusterId),
    onSuccess: () => {
      // SSE completion also invalidates; refresh the scan list optimistically.
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  if (!can("trigger_scan")) return null;
  const disabled = !cluster || mutation.isPending;

  return (
    <Button
      onClick={() => cluster && mutation.mutate(cluster)}
      disabled={disabled}
      title={cluster ? `Scan ${cluster} now` : "Select a cluster to scan"}
      aria-label="Scan now"
    >
      {mutation.isPending ? "Scanning…" : "Scan now"}
    </Button>
  );
}
