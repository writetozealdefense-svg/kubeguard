/** Live scan stream (D5). Connects to /v1/stream once and, on scan lifecycle
 * events, invalidates the relevant TanStack Query caches so the compliance,
 * trend, findings, and attack-path views auto-update without a reload. Also
 * exposes the current scan progress for the live indicator. */
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useApi } from "./apiContext";
import type { StreamEvent } from "@/lib/api/types";

export interface LiveState {
  connected: boolean;
  scanning: boolean;
  progress: number;
}

const INVALIDATE_ON_COMPLETE = ["findings", "posture", "history", "attack-paths", "clusters", "scans"];

export function useScanStream(): LiveState {
  const apiClient = useApi();
  const qc = useQueryClient();
  const [state, setState] = useState<LiveState>({ connected: false, scanning: false, progress: 0 });

  useEffect(() => {
    const ac = new AbortController();
    let mounted = true;

    const onEvent = (ev: StreamEvent) => {
      if (!mounted) return;
      switch (ev.type) {
        case "scan_started":
          setState((s) => ({ ...s, scanning: true, progress: 0 }));
          break;
        case "scan_progress":
          setState((s) => ({ ...s, scanning: true, progress: ev.progress ?? s.progress }));
          break;
        case "scan_completed":
          setState((s) => ({ ...s, scanning: false, progress: 1 }));
          for (const key of INVALIDATE_ON_COMPLETE) void qc.invalidateQueries({ queryKey: [key] });
          break;
        case "posture_updated":
          void qc.invalidateQueries({ queryKey: ["posture"] });
          break;
      }
    };

    setState((s) => ({ ...s, connected: true }));
    void apiClient.openStream(onEvent, ac.signal);

    return () => {
      mounted = false;
      ac.abort();
    };
  }, [apiClient, qc]);

  return state;
}
