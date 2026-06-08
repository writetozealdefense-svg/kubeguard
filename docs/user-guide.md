# KubeGuard dashboard — user guide

For AppSec engineers, analysts, and compliance officers reading the dashboard.

## Sign in
Open the dashboard URL. Use **Sign in with SSO** (if your org enabled OIDC) or
**local-admin** (air-gapped). Your role — viewer, analyst, or admin — controls
what you can do; the server enforces it.

## Pick a cluster
The top-bar **cluster switcher** scopes every lens. "All clusters" shows a merged
fleet view across your tenant. You only ever see your own tenant's data.

## The lenses
- **Overview** — severity cards, total findings, critical attack paths, the
  overall control-pass, and severity / pass-rate **trends**.
- **Findings** — the deduplicated worklist. Filter by severity and search; click
  a row for the detail drawer (evidence, remediation + snippet, mapped controls).
  Secret values are never shown — only key names.
- **Compliance** — per-framework posture; expand a framework to see the breached
  controls and the **findings ("dents") causing each**, with links to their
  remediation.
- **Attack Paths** — an interactive graph. Click (or tab + Enter) a node to see
  its ATT&CK technique, the resource, and the enabling finding. Filter by impact.
  Paths are descriptive narrative — **never runnable exploits**.
- **Clusters / Fleet** — posture per cluster; click a row to drill in.
- **History / Drift** — trends plus a **diff between any two scans**: what newly
  breached vs what was fixed.
- **Reports** — download a co-branded **PDF**, **CSV**, or **SARIF** of the
  current scope.
- **Audit** (admin) — the append-only log of privileged actions.

## Run a scan
With a cluster selected, **Scan now** (analyst+) triggers a scan; progress streams
live and the lenses refresh without a reload. Scheduled scans keep everything
current automatically.

## Reading the metrics honestly
Every compliance figure is shown as **`breached of assessed`** /
**`passed of assessed`** with an indicative-mapping disclaimer — never a bare
"compliant ✓". A control is only counted as *assessed* when every check it maps
to actually ran. See [honest-metrics.md](honest-metrics.md). Treat the mapping as
indicative triage, not an audit verdict.
