# Dashboard observability & reliability (P3)

## Structured logging
The dashboard logs one structured `slog` line per request — `request_id`,
`method`, `path`, `status`, `bytes`, `duration_ms`, `tenant`. No secrets are
logged. Request IDs come from chi's `RequestID` middleware; propagate them from
upstream proxies via the `X-Request-Id` header.

## Metrics (`/metrics`, Prometheus)
Scrape `/metrics` (unauthenticated, for the in-cluster scraper):

| Metric | Type | Labels |
|---|---|---|
| `kubeguard_dashboard_http_request_duration_seconds` | histogram | route, method, status |
| `kubeguard_dashboard_scan_duration_seconds` | histogram | cluster, result |
| `kubeguard_dashboard_scans_total` | counter | cluster, result |
| `kubeguard_dashboard_findings` | gauge | cluster, severity |
| `kubeguard_dashboard_compliance_pass_rate` | gauge | cluster, framework |

Pass rate is **passed of assessed** (honest metrics) — never a bare 0/1 verdict.

## Tracing (OpenTelemetry) — default off
Spans wrap `RunScan` (loader → engine → persistence) and propagate through the
request context. The exporter is **off by default**; enable it with an OTLP/HTTP
endpoint:

```bash
kubeguard dashboard --otel-endpoint otel-collector:4318 ...
# or: OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4318 kubeguard dashboard ...
```

No collector is contacted unless configured. (Verified in-test with an in-memory
span recorder asserting the `dashboard.RunScan` span.)

## Health & readiness
- `GET /healthz` — liveness (always 200 while serving).
- `GET /readyz` — readiness for the load balancer.

Use these as Kubernetes `livenessProbe` / `readinessProbe`. The server performs
a graceful shutdown (in-flight requests drain, 5s timeout) on SIGINT/SIGTERM.

## Reliability
- **Retries:** a transient scan failure is retried (up to 3 attempts) before the
  job is marked failed.
- **Idempotency / no partial state:** each scan gets a fresh unique id and
  persistence is atomic (one Postgres transaction). A scan that fails — or a
  crash mid-scan — persists **no** scan or history row; only a `failed` audit
  entry is written. Verified by the chaos test
  `TestFailedScanLeavesNoPartialState`.

## SLOs & alerts
Target SLOs: API p95 < 250 ms; scan success rate ≥ 99%; availability 99.9%.
Prometheus rules in `deploy/observability/alerts.yaml`
(`DashboardHighLatency`, `DashboardScanFailures`, `ComplianceRegression`,
`DashboardDown`). Import `deploy/observability/grafana-dashboard.json` into
Grafana for the latency / scan / findings / compliance panels.
