import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card } from "@/components/ui/primitives";
import { Drawer } from "@/components/ui/Drawer";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SEVERITY_ORDER, type Finding, type Severity } from "@/lib/api/types";

const PAGE = 20;

export function Findings() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Finding | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["findings", cluster, severities, search, offset],
    queryFn: () =>
      apiClient.listFindings({
        cluster,
        severity: severities.length ? severities : undefined,
        search: search || undefined,
        limit: PAGE,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const toggleSev = (s: Severity) => {
    setOffset(0);
    setSeverities((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  };

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Findings</h1>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1" role="group" aria-label="Filter by severity">
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              aria-pressed={severities.includes(s)}
              className={`rounded border px-2 py-0.5 text-xs ${severities.includes(s) ? "border-accent text-accent" : "border-border text-fg-muted"}`}
            >
              {s}
            </button>
          ))}
        </div>
        <input
          aria-label="Search findings"
          placeholder="Search…"
          className="ml-auto rounded-md border border-border bg-bg-raised px-2 py-1 text-sm"
          value={search}
          onChange={(e) => {
            setOffset(0);
            setSearch(e.target.value);
          }}
        />
      </div>

      {isLoading && <p className="text-fg-muted">Loading…</p>}
      {isError && <p className="text-sev-high">Could not load findings.</p>}

      {data && (
        <>
          <Card className="overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead className="bg-bg-raised text-left text-xs uppercase text-fg-subtle">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">ID</th>
                  <th className="px-3 py-2">Title</th>
                  <th className="px-3 py-2">Resource</th>
                </tr>
              </thead>
              <tbody>
                {data.findings.map((f) => (
                  <tr
                    key={`${f.id}-${f.resource.namespace ?? ""}-${f.resource.name}`}
                    className="cursor-pointer border-t border-border hover:bg-bg-raised"
                    onClick={() => setSelected(f)}
                    tabIndex={0}
                    onKeyDown={(e) => e.key === "Enter" && setSelected(f)}
                  >
                    <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-3 py-2 font-mono text-xs">{f.id}</td>
                    <td className="px-3 py-2">{f.title}</td>
                    <td className="px-3 py-2 text-fg-muted">
                      {f.resource.kind} {f.resource.namespace ? `${f.resource.namespace}/` : ""}{f.resource.name}
                    </td>
                  </tr>
                ))}
                {data.findings.length === 0 && (
                  <tr><td colSpan={4} className="px-3 py-6 text-center text-fg-muted">No findings match.</td></tr>
                )}
              </tbody>
            </table>
          </Card>

          <div className="flex items-center justify-between text-sm text-fg-muted">
            <span>{data.total} findings</span>
            <div className="flex gap-2">
              <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className="rounded border border-border px-2 py-1 disabled:opacity-40">Prev</button>
              <button disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)} className="rounded border border-border px-2 py-1 disabled:opacity-40">Next</button>
            </div>
          </div>
        </>
      )}

      <Drawer open={selected !== null} onClose={() => setSelected(null)} title={selected ? `${selected.id} — ${selected.title}` : ""}>
        {selected && <FindingDetail finding={selected} />}
      </Drawer>
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="space-y-4 text-sm">
      <div className="flex items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="text-fg-muted">{finding.category}</span>
      </div>
      <section>
        <h3 className="text-xs uppercase text-fg-subtle">Resource</h3>
        <p className="font-mono text-xs">{finding.resource.kind} {finding.resource.namespace ? `${finding.resource.namespace}/` : ""}{finding.resource.name}</p>
      </section>
      {finding.evidence && finding.evidence.length > 0 && (
        <section>
          <h3 className="text-xs uppercase text-fg-subtle">Evidence (secrets redacted)</h3>
          <ul className="space-y-1">
            {finding.evidence.map((e, i) => (
              <li key={i} className="font-mono text-xs"><span className="text-fg-muted">{e.path}</span>{e.value ? `: ${e.value}` : ""}</li>
            ))}
          </ul>
        </section>
      )}
      <section>
        <h3 className="text-xs uppercase text-fg-subtle">Remediation</h3>
        <p>{finding.remediation.summary}</p>
        {finding.remediation.snippet && (
          <pre className="mt-1 overflow-x-auto rounded bg-bg p-2 text-xs">{finding.remediation.snippet}</pre>
        )}
      </section>
      {finding.refs && finding.refs.length > 0 && (
        <section>
          <h3 className="text-xs uppercase text-fg-subtle">Mapped controls</h3>
          <ul className="flex flex-wrap gap-1">
            {finding.refs.map((r, i) => (
              <li key={i} className="rounded border border-border px-2 py-0.5 text-xs">{r.framework} {r.id}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
