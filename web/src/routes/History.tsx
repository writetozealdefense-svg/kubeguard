import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card, CardTitle } from "@/components/ui/primitives";
import { PassRateTrend, SeverityTrend } from "@/components/charts";
import { computeDrift } from "@/lib/drift";
import { SEVERITY_ORDER } from "@/lib/api/types";

export function History() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["history", cluster],
    queryFn: () => apiClient.getHistory(cluster),
  });

  const snaps = useMemo(() => data?.snapshots ?? [], [data]);
  const [fromId, setFromId] = useState<string>("");
  const [toId, setToId] = useState<string>("");

  useEffect(() => {
    if (snaps.length >= 2) {
      setFromId(snaps[0].scanId);
      setToId(snaps[snaps.length - 1].scanId);
    }
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  const drift = useMemo(() => {
    const a = snaps.find((s) => s.scanId === fromId);
    const b = snaps.find((s) => s.scanId === toId);
    return a && b ? computeDrift(a, b) : null;
  }, [snaps, fromId, toId]);

  if (isLoading) return <p className="text-fg-muted">Loading history…</p>;
  if (isError) return <p className="text-sev-high">Could not load history.</p>;
  if (snaps.length === 0) return <p className="text-fg-muted">No scan history yet.</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold">History / Drift</h1>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card><CardTitle>Findings by severity</CardTitle><SeverityTrend snapshots={snaps} /></Card>
        <Card><CardTitle>Control pass rate</CardTitle><PassRateTrend snapshots={snaps} /></Card>
      </div>

      <section className="space-y-3">
        <h2 className="text-sm font-medium text-fg-muted">Drift between two scans</h2>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <label className="flex items-center gap-1">
            <span className="text-fg-subtle">From</span>
            <select aria-label="Drift from scan" className="rounded border border-border bg-bg-raised px-2 py-1" value={fromId} onChange={(e) => setFromId(e.target.value)}>
              {snaps.map((s) => <option key={s.scanId} value={s.scanId}>{s.at.slice(0, 10)} · {s.scanId}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-1">
            <span className="text-fg-subtle">To</span>
            <select aria-label="Drift to scan" className="rounded border border-border bg-bg-raised px-2 py-1" value={toId} onChange={(e) => setToId(e.target.value)}>
              {snaps.map((s) => <option key={s.scanId} value={s.scanId}>{s.at.slice(0, 10)} · {s.scanId}</option>)}
            </select>
          </label>
        </div>

        {drift && (
          <Card className="space-y-3">
            <div className="flex items-center gap-2">
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${drift.improved ? "bg-sev-low/15 text-sev-low" : "bg-sev-high/15 text-sev-high"}`}>
                {drift.improved ? "Improved" : "Regressed"}
              </span>
              <span className="text-sm text-fg-muted" aria-label="drift summary">
                {drift.fixed > 0 && `${drift.fixed} control(s) fixed`}
                {drift.fixed > 0 && drift.newlyBreached > 0 && " · "}
                {drift.newlyBreached > 0 && `${drift.newlyBreached} newly breached`}
                {drift.fixed === 0 && drift.newlyBreached === 0 && "no change in breached controls"}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Delta label="Total findings" value={drift.totalFindingsDelta} goodWhenNegative />
              <Delta label="Breached controls" value={drift.breachedDelta} goodWhenNegative />
              <Delta label="Pass rate" value={Math.round(drift.passRateDelta * 100)} suffix="%" goodWhenNegative={false} />
              <Delta label="Critical" value={drift.bySeverityDelta.critical} goodWhenNegative />
            </div>
            <div className="flex flex-wrap gap-3 text-xs text-fg-muted">
              {SEVERITY_ORDER.map((s) => (
                <span key={s}>{s}: {fmt(drift.bySeverityDelta[s])}</span>
              ))}
            </div>
          </Card>
        )}
      </section>
    </div>
  );
}

function fmt(n: number): string {
  return n > 0 ? `+${n}` : `${n}`;
}

function Delta({ label, value, suffix = "", goodWhenNegative }: { label: string; value: number; suffix?: string; goodWhenNegative: boolean }) {
  const neutral = value === 0;
  const good = goodWhenNegative ? value < 0 : value > 0;
  const color = neutral ? "text-fg-muted" : good ? "text-sev-low" : "text-sev-high";
  return (
    <div>
      <div className="text-xs uppercase text-fg-subtle">{label}</div>
      <div className={`text-lg font-semibold ${color}`}>{fmt(value)}{suffix}</div>
    </div>
  );
}
