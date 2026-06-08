/** Admin-only audit log view (the API also enforces admin via RBAC). */
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/app/apiContext";
import { Card } from "@/components/ui/primitives";

export function Audit() {
  const apiClient = useApi();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit"],
    queryFn: () => apiClient.getAudit(),
    retry: false,
  });

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Audit log</h1>
      <p className="text-xs text-fg-subtle">Append-only record of privileged actions. Admin-only.</p>
      {isLoading && <p className="text-fg-muted">Loading…</p>}
      {isError && <p className="text-fg-muted">No audit entries available (admin role + backend required).</p>}
      {data && (
        <Card className="overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead className="bg-bg-raised text-left text-xs uppercase text-fg-subtle">
              <tr><th className="px-3 py-2">Time</th><th className="px-3 py-2">Subject</th><th className="px-3 py-2">Action</th><th className="px-3 py-2">Resource</th><th className="px-3 py-2">Result</th></tr>
            </thead>
            <tbody>
              {data.entries.map((e, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="px-3 py-2 text-fg-subtle">{e.at.slice(0, 19).replace("T", " ")}</td>
                  <td className="px-3 py-2">{e.subject}</td>
                  <td className="px-3 py-2 font-mono text-xs">{e.action}</td>
                  <td className="px-3 py-2 text-fg-muted">{e.resource ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className={e.result === "denied" ? "text-sev-high" : "text-sev-low"}>{e.result}</span>
                  </td>
                </tr>
              ))}
              {data.entries.length === 0 && <tr><td colSpan={5} className="px-3 py-6 text-center text-fg-muted">No entries.</td></tr>}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
