/**
 * Findings triage lane (K6): current findings overlaid with lifecycle state
 * (open / acknowledged / in-progress / resolved / risk-accepted), owner, and
 * waiver, plus an MTTR summary. Analysts set triage state; admins accept risk
 * with a justified, time-boxed waiver. The server is the trust boundary — the
 * UI only hides/disables what a role can't do.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { useAuth } from "@/app/auth";
import { Card } from "@/components/ui/primitives";
import type { FindingLifecycle, FindingState } from "@/lib/api/types";

const ROLE_RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 };
const TRIAGE_STATES: Exclude<FindingState, "risk-accepted">[] = ["open", "acknowledged", "in-progress", "resolved"];

export function Triage() {
  const apiClient = useApi();
  const qc = useQueryClient();
  const { cluster } = useCluster();
  const { session } = useAuth();
  const role = session?.role ?? "viewer";
  const canTriage = ROLE_RANK[role] >= ROLE_RANK.analyst;
  const canWaive = role === "admin";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["lifecycle", cluster],
    queryFn: () => apiClient.getLifecycle(cluster),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["lifecycle", cluster] });

  const setState = useMutation({
    mutationFn: ({ key, state }: { key: string; state: Exclude<FindingState, "risk-accepted"> }) =>
      apiClient.setFindingState(key, state),
    onSuccess: invalidate,
  });
  const revoke = useMutation({
    mutationFn: (key: string) => apiClient.revokeWaiver(key),
    onSuccess: invalidate,
  });
  const [waiverFor, setWaiverFor] = useState<FindingLifecycle | null>(null);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Triage</h1>

      {isLoading && <p className="text-fg-muted">Loading…</p>}
      {isError && <p className="text-sev-high">Could not load the triage lane.</p>}

      {data && (
        <>
          <Card className="flex flex-wrap gap-4 p-3 text-sm">
            <Stat label="Open" value={data.mttr.open} />
            <Stat label="Acknowledged" value={data.mttr.acknowledged} />
            <Stat label="In progress" value={data.mttr.inProgress} />
            <Stat label="Resolved" value={data.mttr.resolved} />
            <Stat label="Risk-accepted" value={data.mttr.riskAccepted} />
            <Stat label="MTTR (hours)" value={round(data.mttr.meanTimeToResolveHours)} />
          </Card>

          <Card className="overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead className="bg-bg-raised text-left text-xs uppercase text-fg-subtle">
                <tr>
                  <th className="px-3 py-2">Finding</th>
                  <th className="px-3 py-2">Resource</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2">Owner</th>
                  <th className="px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((it) => (
                  <tr key={it.key} className="border-t border-border align-top">
                    <td className="px-3 py-2 font-mono text-xs">{it.findingId}</td>
                    <td className="px-3 py-2 text-fg-muted">
                      {it.resource.kind} {it.resource.namespace ? `${it.resource.namespace}/` : ""}{it.resource.name}
                    </td>
                    <td className="px-3 py-2">
                      <StateBadge state={it.state} />
                      {it.waiver && (
                        <div className="mt-1 text-xs text-fg-subtle" title={it.waiver.justification}>
                          waived until {it.waiver.expiresAt.slice(0, 10)}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-fg-muted">{it.assignee ?? "—"}</td>
                    <td className="px-3 py-2">
                      {canTriage ? (
                        <div className="flex flex-wrap items-center gap-1">
                          <select
                            aria-label={`Set state for ${it.findingId}`}
                            className="rounded border border-border bg-bg-raised px-1 py-0.5 text-xs"
                            value={TRIAGE_STATES.includes(it.state as never) ? it.state : "open"}
                            onChange={(e) => setState.mutate({ key: it.key, state: e.target.value as Exclude<FindingState, "risk-accepted"> })}
                          >
                            {TRIAGE_STATES.map((s) => (
                              <option key={s} value={s}>{s}</option>
                            ))}
                          </select>
                          {canWaive && it.state !== "risk-accepted" && (
                            <button className="rounded border border-border px-2 py-0.5 text-xs" onClick={() => setWaiverFor(it)}>
                              Accept risk
                            </button>
                          )}
                          {canWaive && it.state === "risk-accepted" && (
                            <button className="rounded border border-border px-2 py-0.5 text-xs" onClick={() => revoke.mutate(it.key)}>
                              Revoke waiver
                            </button>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs text-fg-subtle">read-only</span>
                      )}
                    </td>
                  </tr>
                ))}
                {data.items.length === 0 && (
                  <tr><td colSpan={5} className="px-3 py-6 text-center text-fg-muted">No findings to triage.</td></tr>
                )}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {waiverFor && (
        <WaiverDialog
          finding={waiverFor}
          onClose={() => setWaiverFor(null)}
          onSubmit={async (justification, expiresAt) => {
            await apiClient.createWaiver(waiverFor.key, justification, expiresAt);
            setWaiverFor(null);
            invalidate();
          }}
        />
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-xs uppercase text-fg-subtle">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

function StateBadge({ state }: { state: FindingState }) {
  const tone =
    state === "resolved" ? "text-sev-low border-sev-low"
    : state === "risk-accepted" ? "text-sev-medium border-sev-medium"
    : state === "in-progress" ? "text-accent border-accent"
    : "text-fg-muted border-border";
  return <span className={`rounded border px-2 py-0.5 text-xs ${tone}`}>{state}</span>;
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}

function WaiverDialog({
  finding,
  onClose,
  onSubmit,
}: {
  finding: FindingLifecycle;
  onClose: () => void;
  onSubmit: (justification: string, expiresAt: string) => void;
}) {
  const [justification, setJustification] = useState("");
  // Default expiry: 30 days out, as a date input value.
  const [date, setDate] = useState("");
  const disabled = justification.trim() === "" || date === "";
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" role="dialog" aria-label="Accept risk">
      <Card className="w-96 space-y-3 p-4">
        <h2 className="text-sm font-semibold">Accept risk — {finding.findingId}</h2>
        <label className="block text-xs uppercase text-fg-subtle">Justification (required)</label>
        <textarea
          aria-label="Justification"
          className="w-full rounded border border-border bg-bg-raised p-2 text-sm"
          rows={3}
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
        />
        <label className="block text-xs uppercase text-fg-subtle">Expires (max 90 days)</label>
        <input
          type="date"
          aria-label="Expiry date"
          className="w-full rounded border border-border bg-bg-raised p-2 text-sm"
          value={date}
          onChange={(e) => setDate(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <button className="rounded border border-border px-3 py-1 text-sm" onClick={onClose}>Cancel</button>
          <button
            className="rounded bg-accent px-3 py-1 text-sm text-bg disabled:opacity-40"
            disabled={disabled}
            onClick={() => onSubmit(justification.trim(), new Date(date + "T00:00:00Z").toISOString())}
          >
            Accept risk
          </button>
        </div>
      </Card>
    </div>
  );
}
