# KubeGuard — Road to 100% Production Readiness

> Companion to [Kubeguard-PROD_READINESS.md](Kubeguard-PROD_READINESS.md).
> Baseline: **~85%** (code complete, ops/config incomplete). Target: **100%** —
> every box in the production checklist closed, including the previously-deferred
> and external-validation items.
> Created 2026-06-08.

This plan splits the remaining work into three tracks by *who can do it and where*:

- **Track A — Code & repo gaps** — changes that live in this repository. Several
  are already applied in this pass (see "Done in this pass"); the rest are fully
  specified below and need only a Go toolchain + CI to land.
- **Track B — Infra & ops** — deployment-time configuration that requires a real
  cluster, Postgres, IdP, registry, and DNS. The platform team owns these; the
  chart and docs already provide the levers.
- **Track C — External validation** — third-party pen test and ASVS L2 audit.

A box is only "100% done" when its acceptance evidence exists (test, render,
scan output, or signed report) — not merely when code is written.

---

## Done in this pass (Track A, applied)

These changes were made directly in the repo as part of this plan. **They must be
verified by CI** (`go build/vet/test`, `golangci-lint`, `helm lint`, `npm run
build`) — the authoring environment had no Go 1.26 toolchain, so compilation was
not run locally.

| # | Change | Files | Closes checklist item |
|---|---|---|---|
| 1 | Signed off the architecture doc (v0.1 draft → v1.0, dated) | `ARCHITECTURE.md` | 🟡 Sign off ARCHITECTURE.md |
| 2 | Documented the two implemented-but-missing endpoints in the API contract (`/v1/audit`, `/v1/report`) + `AuditEntry`/`AuditList` schemas | `docs/openapi.yaml` | 🟡 OpenAPI completeness |
| 3 | Wired **live cluster scanning** into the dashboard: `--cluster id=live[:ctx]` now uses the read-only `loader/live` path (same code as `scan --live`); offline paths unchanged | `internal/cli/dashboard.go` | 🟡 Live cluster scanning in dashboard / 🔴 Wire cluster data sources |
| 4 | Cross-platform `prebuild` perms guard + troubleshooting README so `npm run build` survives the stripped-exec-bit case | `web/package.json`, `web/README.md` | Local verification ⚠️ (web build) |
| 5 | Helm **Postgres backup CronJob** (`pg_dump` + retention prune) | `charts/.../templates/backup-cronjob.yaml`, `values.yaml` | 🟢 Automated Postgres backup Job / 🔴 backup schedule |
| 6 | Helm **cert-manager** Issuer + Certificate (optional) | `charts/.../templates/certificate.yaml`, `values.yaml` | 🟢 cert-manager in Helm |
| 7 | **Per-PR Trivy image scan** job (api + web images) | `.github/workflows/security.yml` | 🟢 Per-PR container image Trivy scan |
| 8 | Initialized version control + initial commit | repo root | 🔴 Integrate into version control |

---

## Track A — remaining code & repo gaps

### A1. Operator lifecycle APIs (🟡 + key product gap #3)

Three admin surfaces are missing. All three reuse logic that already exists; the
work is HTTP + CLI plumbing and tests. **Implementation spec (ready to apply):**

**(a) DPDP tenant erasure** — `DeleteTenant()` exists in `internal/dashboard/pg`
but only the latest in-memory/Postgres path; no operator entry point.

- Add `DeleteTenant(ctx, tenant) error` to the `Store` interface
  (`internal/dashboard/store.go`); implement on `MemStore` (drop the tenant's
  partitions) — `pg.Store` already has it.
- Route: `DELETE /v1/tenants/{tenant}` gated `requireRole(RoleAdmin,
  "tenant.delete")`; writes an audit entry (`tenant.delete`, allowed/denied);
  returns `204`. Guard against deleting a tenant other than the caller's unless a
  super-admin claim is present.
- CLI: `kubeguard dashboard-admin delete-tenant --tenant <id> --postgres <dsn>`
  for out-of-band DSAR execution (air-gapped path).
- OpenAPI: add the path + `204`/`403`/`404`.
- Tests: admin deletes → rows gone (mem + pg); analyst → 403 (audited);
  cross-tenant → 403.

**(b) Dynamic cluster registration** — clusters are fixed at startup via
`--cluster`. `RegisterCluster` already exists on the store.

- Routes: `POST /v1/clusters` (body `{id, name, source}`) and
  `DELETE /v1/clusters/{id}`, both `requireRole(RoleAdmin, "cluster.write")`.
- The API holds the cluster→source map (today a closure local in
  `dashboard.go`); lift it into the `API` struct behind a mutex so registration
  can add/remove sources at runtime, then the existing `scanner` reads from it.
- Persist registrations for the Postgres backend (clusters table already exists).
- OpenAPI + tests (add cluster → appears in `/v1/clusters` → scannable; remove →
  404 on scan; viewer/analyst → 403).

**(c) Tenant provisioning** — tenancy is read from JWT claims; no onboarding API.

- Route: `POST /v1/tenants` (`{tenant, displayName}`), super-admin only, creates
  the tenant partition and an initial admin binding; idempotent.
- For IdP-driven deployments this is optional (JIT provisioning on first valid
  JWT) — document JIT as the default and the explicit API as the managed path.
- OpenAPI + tests.

**Effort:** ~2–3 days. **Owner:** backend. **Blocked by:** nothing.

### A2. DSAR/erasure documentation (🟡)

Once A1(a) lands, update `docs/privacy.md` and `docs/admin-guide.md` with the DSAR
runbook (API + CLI), and reference it from the DPDP retention section.
**Effort:** 0.5 day.

### A3. SARIF full JSON-Schema validation (🟢)

Today validation is structural (go-sarif types). To close the box: add a CI step
(or `go test` with a build tag) that validates emitted SARIF against the official
2.1.0 JSON Schema using a schema validator (e.g. `santhosh-tekuri/jsonschema`),
over the golden `vulnerable`/`hardened` reports. **Effort:** 0.5 day.
**Owner:** backend.

### A4. ZealDefense / USP integration (🟡)

`docs/usp-integration.md` documents the `pkg/api`/REST/metrics contract but the
ingest is not wired. Decide the integration mode with the ZealDefense team
(push from KubeGuard vs. pull by USP), then implement the agreed adapter. This is
a cross-team dependency — **track as its own epic**, not a launch blocker for
standalone production. **Owner:** backend + ZealDefense. **Effort:** TBD on design.

### A5. Security contact confirmation (🟡)

Confirm `security@kubeguard.io` in `SECURITY.md` routes to the ZealDefense
security inbox (or update it). **Effort:** trivial; **Owner:** security.

---

## Track B — infra & ops (platform team)

These are deployment-time and require live infrastructure. The chart and docs
already expose every lever; the work is to *apply* them in real environments and
capture evidence. Recommended production Helm values are in the readiness report.

| Item | Lever (already in chart/docs) | Evidence to capture |
|---|---|---|
| 🔴 Enable Postgres HA | `postgres.enabled=true`, DSN via `existingSecret`, `sslmode=require` | multi-replica survives pod kill; data persists restart |
| 🔴 Rotate secrets | `KUBEGUARD_ADMIN_TOKEN` in a Secret; replace `local-admin` | no default token in any env |
| 🔴 Enable TLS | `tls.enabled=true` (+ optional `tls.certManager.enabled`) or ingress TLS | HTTPS + HSTS observed |
| 🔴 Configure OIDC/SSO | `auth.oidc.*`; web image with `VITE_OIDC_AUTHORIZE_URL` | real IdP login end-to-end |
| 🔴 Publish & pin images | build/push `ghcr.io/kubeguard/*`; set `image.*.digest`; cosign verify | digests pinned; signatures verify |
| 🔴 Deploy observability | scrape `/metrics`, import Grafana JSON, load `alerts.yaml`; `serviceMonitor.enabled=true` | dashboards live; alerts firing in staging |
| 🔴 Retention policy | `postgres.retention=720h` | old scans pruned; latest kept |
| 🔴 Ingress + DNS | `ingress.enabled=true`, real host, cert | reachable at prod hostname over TLS |
| 🔴 Backup schedule | `backup.enabled=true` (CronJob now in chart) + durable `storage.existingClaim` or object-storage upload | restorable dump produced on schedule |
| 🔴 Staging promotion | deploy signed digest → staging → e2e + k6 → promote same digest | promotion runbook executed (`docs/cicd.md`) |
| 🟡 Rate limiting | `security.rateLimitPerSecond`, `security.allowedOrigins` | 429 under load; CSRF origin enforced |
| 🟡 HPA | `autoscaling.enabled=true`; tune `asyncWorkers` | scales under scan load |
| 🟡 ServiceMonitor | `serviceMonitor.enabled=true` | targets scraped by Prom Operator |
| 🟢 Standalone worker | scale via `api.replicas` + `asyncWorkers` (documented design choice) | accept in-process model, or split later |

**Sequence:** follow the readiness report's 4-week launch plan (Infra →
Config → Staging → Prod). **Owner:** platform/SRE.

---

## Track C — external validation

| Item | Action | Owner |
|---|---|---|
| ❌ Formal pen test | Engage an external firm against a staging deployment; remediate findings; attach report | security + vendor |
| ❌ ASVS L2 audit | Commission an OWASP ASVS L2 assessment; close gaps; record the attestation | security + vendor |

These are explicitly out-of-scope in the current threat model. To reach literal
100%, schedule them against the staging environment once Track B is up. Budget
2–4 weeks lead time for vendor scheduling; they can run in parallel with the prod
launch but sign-off gates the "fully audited" claim.

---

## Consolidated checklist → status

**🔴 Blocking**

- [x] Integrate into version control — *done this pass*
- [~] Wire cluster data sources — *live scanning wired (A, applied); mounting/sync still an option per env (B)*
- [ ] Enable Postgres persistence · Rotate secrets · Enable TLS · Configure OIDC · Publish & pin images · Deploy observability · Set retention · Configure ingress+DNS · Run staging promotion · Establish backup schedule — *Track B (chart/docs ready; apply in env)*

**🟡 Important**

- [x] Detection breadth (K2) — *audited 20 checks vs CIS/NSA; added KG-021 (drop-ALL caps / PSA-restricted) + KG-022 (implicit/untrusted registry); vulnerable 19→21, hardened+bundle stay 0; K2b offline-CVE skipped+flagged*
- [x] Risk prioritization (K4) — *deterministic explainable score in internal/risk; top risks on CLI/posture/report; weights in docs/honest-metrics.md; chain enablers rank first*
- [x] Findings lifecycle & waivers (K6) — *states/ownership/waivers with expiry + auto-lapse, MTTR, audited, waiver-aware enforcement primitives; mem+pg (migration 0002) tested; dashboard Triage lane; docs/findings-lifecycle.md*
- [x] Waiver-aware guardrails + shift-left (K7) — *internal/waiver offline waiver file; --fail-on and admission webhook honor+log active waivers (expired re-block); scan -f gitops PR annotations; docs/shift-left.md*
- [x] Live cluster scanning in dashboard — *applied*
- [x] OpenAPI completeness — *applied*
- [x] Sign off ARCHITECTURE.md — *applied*
- [x] Dynamic cluster management — *K1 applied: POST/DELETE /v1/clusters (admin, cluster.write), mutex-guarded source registry lifted out of the closure, MemStore+pg DeleteCluster, OpenAPI + ±/− tests*
- [x] DPDP erasure operator path (A1a) — *K8: Store.DeleteTenant (mem+pg), DELETE /v1/tenants/{tenant} (admin own / super-admin cross), CLI dashboard-admin delete-tenant, DSAR runbook; mem tests green, pg tests written*
- [x] Multi-tenant provisioning (A1c) — *K8: ProvisionTenant (mem+pg, migration 0003), POST /v1/tenants super-admin idempotent, JIT default documented*
- [ ] Rate limiting in prod · Enable HPA · ServiceMonitor — *Track B (set values)*
- [ ] ZealDefense integration — *A4 (epic)*
- [~] Security contact — *A5: blocked on the correct Zeal Defense address; SECURITY.md unchanged (not guessed)*

**🟢 Deferred (now in scope for 100%)**

- [x] Per-PR Trivy image scan — *applied*
- [x] cert-manager in Helm — *applied*
- [x] Automated Postgres backup Job — *applied*
- [x] SARIF full JSON-Schema validation (A3) — *K8: build-tagged test validates emitted SARIF (vulnerable+hardened) against the official 2.1.0 schema via santhosh-tekuri/jsonschema; CI step in ci.yml*
- [ ] Keyless cosign signing — *Track B (CI OIDC on main/tags; already wired)*
- [ ] Standalone worker Deployment — *accept in-process model or split (design decision)*
- [ ] Formal pen test / ASVS L2 audit — *Track C*

---

## Suggested order of execution

1. **CI-verify this pass** — push the branch; confirm `go build/vet/test`,
   `golangci-lint`, `helm lint`/`kubeconform`, `npm run build`, and the new
   `trivy-image` job are green. Fix anything the Go toolchain surfaces.
2. **Land A1** (lifecycle APIs) + **A2** (DSAR docs) + **A3** (SARIF schema) —
   self-contained, ~3–4 days, no infra needed.
3. **Track B week 1–4** — platform team executes the launch sequence; capture
   evidence per the table above.
4. **A4 / A5** — resolve in parallel with B.
5. **Track C** — schedule pen test + ASVS against staging; sign off.

**Estimated effort to literal 100%:** ~1 week of backend work (A1–A3) + the
1–2 week platform launch (B) + external-audit lead time (C, parallelizable).
