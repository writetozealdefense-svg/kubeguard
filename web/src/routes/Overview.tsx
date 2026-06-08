import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card, CardTitle } from "@/components/ui/primitives";
import { PassRateTrend, SeverityTrend } from "@/components/charts";
import { SEVERITY_ORDER, type Severity } from "@/lib/api/types";
import { SEVERITY_HEX, SEVERITY_LABEL, breachLabel, passRateLabel } from "@/lib/format";

export function Overview() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["posture", cluster],
    queryFn: () => apiClient.getPosture(cluster),
  });
  const { data: history } = useQuery({
    queryKey: ["history", cluster],
    queryFn: () => apiClient.getHistory(cluster),
  });

  if (isLoading) return <p className="text-fg-muted">Loading posture…</p>;
  if (isError || !data) return <p className="text-sev-high">Could not load posture.</p>;

  const { posture, compliance } = data;
  const assessed = posture.controlsAssessed;
  const passed = assessed - posture.controlsBreached;

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold">Overview</h1>

      <section aria-label="Severity summary" className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVERITY_ORDER.map((sev) => (
          <Card key={sev}>
            <CardTitle>{SEVERITY_LABEL[sev as Severity]}</CardTitle>
            <p className="mt-1 text-2xl font-semibold" style={{ color: SEVERITY_HEX[sev as Severity] }}>
              {posture.bySeverity[sev] ?? 0}
            </p>
          </Card>
        ))}
      </section>

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card>
          <CardTitle>Total findings</CardTitle>
          <p className="mt-1 text-2xl font-semibold">{posture.totalFindings}</p>
        </Card>
        <Card>
          <CardTitle>Critical attack paths</CardTitle>
          <p className="mt-1 text-2xl font-semibold text-sev-critical">{posture.criticalPaths}</p>
        </Card>
        <Card>
          <CardTitle>Overall control pass</CardTitle>
          {/* Honest metric: always passed-of-assessed, never a bare percentage. */}
          <p className="mt-1 text-lg font-semibold">{passRateLabel(passed, assessed)}</p>
        </Card>
      </section>

      {history && history.snapshots.length > 0 && (
        <section aria-label="Trends" className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Card><CardTitle>Findings by severity (trend)</CardTitle><SeverityTrend snapshots={history.snapshots} /></Card>
          <Card><CardTitle>Control pass rate (trend)</CardTitle><PassRateTrend snapshots={history.snapshots} /></Card>
        </section>
      )}

      <section aria-label="Compliance summary" className="space-y-2">
        <h2 className="text-sm font-medium text-fg-muted">Compliance (indicative mapping)</h2>
        <div className="space-y-1">
          {compliance.map((fw) => (
            <Card key={fw.framework} className="flex items-center justify-between py-2">
              <span className="text-sm">{fw.framework}</span>
              <span className="text-sm text-fg-muted">{breachLabel(fw.breached, fw.assessed)}</span>
            </Card>
          ))}
        </div>
        {compliance[0] && <p className="text-xs text-fg-subtle">{compliance[0].disclaimer}</p>}
      </section>
    </div>
  );
}
