import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Card } from "@/components/ui/primitives";
import { passRateLabel, pct } from "@/lib/format";

export function Clusters() {
  const apiClient = useApi();
  const { setCluster } = useCluster();
  const navigate = useNavigate();
  const { data, isLoading, isError } = useQuery({ queryKey: ["clusters"], queryFn: () => apiClient.listClusters() });

  if (isLoading) return <p className="text-fg-muted">Loading clusters…</p>;
  if (isError || !data) return <p className="text-sev-high">Could not load clusters.</p>;

  const drillIn = (id: string) => {
    setCluster(id);
    void navigate({ to: "/" });
  };

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Clusters / Fleet</h1>
      <Card className="overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead className="bg-bg-raised text-left text-xs uppercase text-fg-subtle">
            <tr>
              <th className="px-3 py-2">Cluster</th>
              <th className="px-3 py-2">Environment</th>
              <th className="px-3 py-2">Findings</th>
              <th className="px-3 py-2">Control pass</th>
              <th className="px-3 py-2">Last scan</th>
            </tr>
          </thead>
          <tbody>
            {data.clusters.map((c) => (
              <tr
                key={c.id}
                className="cursor-pointer border-t border-border hover:bg-bg-raised"
                onClick={() => drillIn(c.id)}
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && drillIn(c.id)}
                aria-label={`Drill into ${c.name}`}
              >
                <td className="px-3 py-2 font-medium">{c.name}</td>
                <td className="px-3 py-2 text-fg-muted">{c.environment ?? "—"}</td>
                <td className="px-3 py-2">{c.totalFindings ?? 0}</td>
                <td className="px-3 py-2 text-fg-muted">{c.overallPassRate !== undefined ? pct(c.overallPassRate) : passRateLabel(0, 0)}</td>
                <td className="px-3 py-2 text-fg-subtle">{c.lastScanAt?.slice(0, 16).replace("T", " ") ?? "never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
