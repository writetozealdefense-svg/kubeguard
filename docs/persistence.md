# Dashboard persistence (Postgres) — operations

The dashboard runs in-memory by default (air-gapped, zero deps). For durable,
multi-replica deployments, point it at Postgres with `--postgres`:

```bash
kubeguard dashboard \
  --cluster prod-eu=./manifests \
  --postgres "postgres://user:pass@host:5432/kubeguard?sslmode=require" \
  --retention 720h          # prune scans/history older than 30 days (optional)
```

On start it runs the embedded **goose** migrations, then persists scans
(full report as `jsonb`), per-scan history snapshots, and the audit log. The
pool is a `pgxpool` (connection pooling). Both backends satisfy the same
`Store`/`AuditLog` seams, so the API code is identical.

## Schema (migration `0001_init`)
`tenants`, `users`, `clusters`, `scans` (latest pointer + `report jsonb`),
`history`, `audit`. Every table is partitioned by `tenant`; there are **no
cross-tenant foreign keys** (NFR-3). Secret values are never stored — only
finding metadata, as redacted by the engine.

## Migrations
Applied automatically on start. To run them standalone, or to roll back:

```go
pg.Migrate(dsn)      // up to head (idempotent)
pg.MigrateDown(dsn)  // down to zero (drops all dashboard tables)
```

Up→down→up is verified clean in `internal/dashboard/pg` integration tests.

## Retention (configurable)
`--retention <duration>` runs hourly and deletes **non-latest** scans whose
`started_at` is older than `now-duration`, plus history rows older than the
cutoff. The latest scan per cluster is always kept so the lenses keep
rendering. Programmatic: `store.Retention(ctx, cutoffRFC3339)`.

## DPDP — right to erasure (hard delete)
`store.DeleteTenant(ctx, tenant)` hard-deletes **all** of a tenant's rows across
every table (clusters, scans, history, audit, users, tenant). This is the
data-subject erasure path; it is irreversible.

**Personal data stored:** the only personal data is the user identifier/email
from SSO (`users` table) and the `subject` recorded on audit entries (who took a
privileged action). No scan content contains personal data. Configure retention
to bound how long audit/history is kept.

## Backup & restore (runbook)

**Backup** (logical, per database):

```bash
pg_dump --format=custom --no-owner --file kubeguard-$(date +%F).dump \
  "postgres://user:pass@host:5432/kubeguard"
```

Schedule via a CronJob / managed-service snapshot. Store encrypted, offsite.

**Restore** into a fresh database:

```bash
createdb kubeguard_restore
pg_restore --no-owner --dbname kubeguard_restore kubeguard-2026-06-07.dump
# Point the dashboard at the restored DB; migrations are a no-op if already current.
```

**Verify after restore:** start the dashboard against the restored DSN and
confirm `/v1/clusters`, `/v1/scans`, and `/v1/history` return the expected
counts. (Demonstrated locally: scans + history survive a full process restart
against the same database.)

**Point-in-time recovery:** enable WAL archiving / use your managed provider's
PITR; the application is stateless apart from this database.

## Running the integration tests

```bash
docker run -d --name kg-pg -e POSTGRES_USER=kubeguard -e POSTGRES_PASSWORD=kubeguard \
  -e POSTGRES_DB=kubeguard -p 5433:5432 postgres:16-alpine
export KUBEGUARD_TEST_POSTGRES="postgres://kubeguard:kubeguard@localhost:5433/kubeguard?sslmode=disable"
go test ./internal/dashboard/pg/ -count=1
```

The tests skip cleanly when `KUBEGUARD_TEST_POSTGRES` is unset, so `go test ./...`
stays green without Docker. CI (Squad P6) provides a Postgres service and sets it.
