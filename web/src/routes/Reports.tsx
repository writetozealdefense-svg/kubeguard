import { useState } from "react";
import { useApi } from "@/app/apiContext";
import { useCluster } from "@/app/cluster";
import { Button, Card, CardTitle } from "@/components/ui/primitives";
import { saveBlob } from "@/lib/download";

type Format = "pdf" | "csv" | "sarif";

const FORMATS: { format: Format; label: string; note: string }[] = [
  { format: "pdf", label: "Co-branded PDF", note: "Engagement report: posture, compliance breach, attack chain — with honest denominators + disclaimer." },
  { format: "csv", label: "Findings CSV", note: "All findings (id, severity, resource, mapped controls). Spreadsheet-friendly." },
  { format: "sarif", label: "SARIF 2.1.0", note: "For code-scanning dashboards and SARIF-aware tooling." },
];

export function Reports() {
  const apiClient = useApi();
  const { cluster } = useCluster();
  const [busy, setBusy] = useState<Format | null>(null);
  const [error, setError] = useState<string | null>(null);

  const download = async (format: Format) => {
    setBusy(format);
    setError(null);
    try {
      const { blob, filename } = await apiClient.downloadReport(format, cluster);
      saveBlob(blob, filename);
    } catch {
      setError("Export failed — a scan is required for this scope.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Reports &amp; export</h1>
      <p className="text-xs text-fg-subtle">
        Exports cover the current scope ({cluster ?? "all clusters"}). Every report carries the
        assessed denominators and the indicative-mapping disclaimer — never a bare compliant verdict.
      </p>
      {error && <p className="text-sm text-sev-high">{error}</p>}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {FORMATS.map((f) => (
          <Card key={f.format} className="flex flex-col justify-between gap-3">
            <div>
              <CardTitle>{f.label}</CardTitle>
              <p className="mt-1 text-xs text-fg-subtle">{f.note}</p>
            </div>
            <Button onClick={() => download(f.format)} disabled={busy !== null} aria-label={`Export ${f.label}`}>
              {busy === f.format ? "Preparing…" : "Download"}
            </Button>
          </Card>
        ))}
      </div>
    </div>
  );
}
