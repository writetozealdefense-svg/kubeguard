# Dashboard performance & scale (P4)

## Async scan workers
`kubeguard dashboard --async-workers N` runs scans on a pool of N workers off the
request path. `POST /v1/scans` enqueues and returns `202 {status: "queued"}`
immediately; the worker executes the (potentially slow) scan and streams progress
over SSE. The queue is bounded — when full, the API responds `503` so a flood
can't grow memory unbounded. The default (0) is synchronous. On shutdown the pool
drains in-flight jobs.

## Pagination & caching
- **Pagination** is server-side on the list endpoints (`/v1/findings`,
  `/v1/scans`) — `limit`/`offset` with an unpaginated `total`. The Postgres
  `ListScans` clamps `limit` to ≤ 1000.
- **Caching** is at the edge (the SPA's TanStack Query cache), invalidated
  precisely by SSE `scan_completed`/`posture_updated` events — so reads are served
  from cache between scans and refreshed the instant a scan lands, with no polling.
- **No N+1:** a cluster's entire report (findings, paths, compliance) is one
  `jsonb` row read; the fleet view is one query returning each cluster's latest
  report, merged in-process. There is no per-finding query.

## Measured numbers (this host)
Captured by `go test ./internal/dashboard/` (real, in CI):

| Scenario | Result | Budget |
|---|---|---|
| API read **p95**, 2,000 reqs @ 32 concurrent (`TestAPILatencyP95`) | **~4 ms** | < 120 ms |
| **5,000-pod** cluster scan: load + engine (`TestScan5kPodsWithinBudget`) | **~0.35 s** (40,050 findings) | < 30 s |
| Async worker processes a queued scan (`TestAsyncWorkerProcessesScan`) | pass | — |

## Load test (k6)
`test/load/k6-dashboard.js` ramps to 50 VUs against the read endpoints with
thresholds `p(95)<120ms` and error rate `<1%` (k6 exits non-zero on breach, so it
gates CI/staging):

```bash
BASE=http://localhost:8080 TOKEN=local-admin CLUSTER=prod-eu \
  k6 run test/load/k6-dashboard.js
```

(k6 is not installed on every dev host; it runs in the CI/staging load stage. The
local p95 above is measured by the Go harness and is the authoritative dev-time
number.)
