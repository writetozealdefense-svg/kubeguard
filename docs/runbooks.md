# Operational runbooks

## On-call: triage
1. Check the alert (see `deploy/observability/alerts.yaml`).
2. `kubectl -n kubeguard get pods` — are API/web pods Ready?
3. `kubectl -n kubeguard logs deploy/kgd-kubeguard-dashboard-api` — structured
   slog lines carry `request_id`, `status`, `duration_ms`, `tenant`.
4. Scrape `/metrics` or open the Grafana dashboard for latency / scan-failure /
   pass-rate panels.

## Incident: API down (`DashboardDown`)
- `kubectl -n kubeguard rollout status deploy/kgd-kubeguard-dashboard-api`.
- If a bad release: `helm rollback kgd <prev> -n kubeguard` (digest swap; see
  [cicd.md](cicd.md)).
- If Postgres is unreachable: verify the DSN secret + network policy; the API
  fails closed (won't serve stale cross-tenant data). Restore DB if needed
  (below).

## Incident: high latency (`DashboardHighLatency`)
- Check `kubeguard_dashboard_http_request_duration_seconds` by route.
- Enable async workers (`--async-workers`) / raise API replicas or HPA max.
- If Postgres-bound, check pool saturation and DB CPU.

## Incident: scans failing (`DashboardScanFailures`)
- Scans retry 3× before failing; a failed scan persists **no** partial state.
- Check the scanner source (manifest mount / live RBAC). For live mode confirm
  the read-only ClusterRole is bound.

## Restore from backup (Postgres)
Full procedure in [persistence.md](persistence.md#backup--restore-runbook):
```bash
createdb kubeguard_restore
pg_restore --no-owner --dbname kubeguard_restore kubeguard-YYYY-MM-DD.dump
helm upgrade kgd charts/kubeguard-dashboard -n kubeguard \
  --set postgres.dsn.value="postgres://…/kubeguard_restore"   # or update the secret
```
Verify `/v1/clusters`, `/v1/scans`, `/v1/history` counts after restore.

## DPDP erasure request
A data-subject erasure removes a tenant's data irreversibly:
```go
store.DeleteTenant(ctx, "<tenant>")
```
See [privacy.md](privacy.md). Record the request in your DSAR log.

## Routine
- **Retention:** `--retention <dur>` prunes old scans/history hourly (latest kept).
- **Cert rotation:** update the TLS secret; rolling restart picks it up.
- **Key/secret rotation:** rotate `KUBEGUARD_ADMIN_TOKEN` / DSN secret, then
  `kubectl rollout restart`.
