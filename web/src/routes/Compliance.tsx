import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card } from "@/components/ui/primitives";
import { breachLabel, passRateLabel } from "@/lib/format";
import type { FrameworkResult } from "@/lib/api/types";

export function Compliance() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["posture", cluster],
    queryFn: () => apiClient.getPosture(cluster),
  });

  if (isLoading) return <p className="text-fg-muted">Loading compliance…</p>;
  if (isError || !data) return <p className="text-sev-high">Could not load compliance.</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Compliance</h1>
      <p className="text-xs text-fg-subtle">
        Indicative mapping of KubeGuard checks to controls — never a bare compliant verdict.
        Every figure shows its assessed denominator.
      </p>
      <div className="space-y-2">
        {data.compliance.map((fw) => (
          <FrameworkRow key={fw.framework} fw={fw} />
        ))}
      </div>
      {data.compliance[0] && <p className="text-xs text-fg-subtle">{data.compliance[0].disclaimer}</p>}
    </div>
  );
}

function FrameworkRow({ fw }: { fw: FrameworkResult }) {
  const [open, setOpen] = useState(false);
  const passed = fw.assessed - fw.breached;
  const hasBreaches = (fw.breaches?.length ?? 0) > 0;
  return (
    <Card className="p-0">
      <button
        className="flex w-full items-center justify-between px-4 py-3 text-left"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        disabled={!hasBreaches}
      >
        <div>
          <span className="text-sm font-medium">{fw.framework}</span>
          {fw.version && <span className="ml-2 text-xs text-fg-subtle">v{fw.version}</span>}
        </div>
        <div className="text-right text-sm">
          <div className="text-fg-muted">{breachLabel(fw.breached, fw.assessed)}</div>
          <div className="text-xs text-fg-subtle">{passRateLabel(passed, fw.assessed)}</div>
        </div>
      </button>
      {open && hasBreaches && (
        <div className="border-t border-border px-4 py-3">
          <h3 className="mb-2 text-xs uppercase text-fg-subtle">Breached controls &amp; the dents causing them</h3>
          <ul className="space-y-2">
            {fw.breaches!.map((b) => (
              <li key={b.controlId} className="text-sm">
                <span className="font-mono text-xs text-sev-high">{b.controlId}</span>
                {b.title && <span className="ml-2">{b.title}</span>}
                <div className="mt-0.5 flex flex-wrap gap-1">
                  {b.findings.map((fid) => (
                    <a
                      key={fid}
                      href={`/findings?search=${fid}`}
                      className="rounded border border-border px-2 py-0.5 text-xs text-accent hover:bg-bg-raised"
                    >
                      {fid} — view remediation
                    </a>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
