# USP integration guide

KubeGuard is a standalone tool today and a **Kubernetes module of the USP
control plane** tomorrow. Integration is built around the stable `pkg/api`
schema (see [api.md](api.md)) — the only package external consumers import.

## Integration options

### 1. Pull from the service API (recommended)

Run KubeGuard in service mode and have USP poll or trigger scans:

```
GET  /v1/scan      → triggers a scan, returns the full api.Report
GET  /v1/posture   → { posture, compliance } for dashboards
GET  /v1/findings  → []Finding for the findings lens
GET  /metrics      → Prometheus gauges (kubeguard_compliance_pass_rate, …)
```

The `api.Report` is versioned and additive within a major version, so USP can
deserialize it directly into `pkg/api` types.

### 2. Ingest SARIF / JSON from CI

In pipelines, `kubeguard scan -f json` (or `-f sarif`) emits artifacts USP can
ingest into its findings and compliance lenses. `--fail-on <sev>` gates the
build (exit 2).

### 3. Embed the engine (Go)

USP can import the analysis pipeline directly:

```go
import (
    "github.com/kubeguard/kubeguard/internal/analyzer"
    "github.com/kubeguard/kubeguard/internal/loader/offline"
)

resources, _ := offline.Load(path)
report, _ := analyzer.Analyze(resources, "zeal-default", false) // api.Report
```

(Public, stable types live in `pkg/api`; the loaders/engine are `internal/` and
may evolve — pin a version if you embed them.)

## Mapping to USP lenses

| USP lens | KubeGuard source |
|---|---|
| Findings | `Report.Findings` (`[]api.Finding`) |
| Attack paths | `Report.Paths` (`[]api.AttackPath`, ATT&CK-tagged) |
| Compliance | `Report.Compliance` (`[]api.FrameworkResult`, breached-of-assessed) |
| Posture / overview | `Report.Posture` (`api.PostureSummary`) |
| Metrics | `/metrics` (`kubeguard_compliance_pass_rate{framework}`) |

## Honest-metrics contract (must be preserved downstream)

Every compliance number carries its `assessed` denominator and the pack's
`disclaimer`. When surfacing KubeGuard data, render pass rates as **passed of
assessed** and keep the indicative-mapping disclaimer. Do not derive a bare
"compliant / non-compliant" verdict. Attack paths are descriptive narrative —
never present them as runnable exploits.
