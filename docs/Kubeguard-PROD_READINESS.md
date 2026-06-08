# KubeGuard — Production Readiness Report

> Generated: 2026-06-08 · Status: **~85% ready** — code complete, ops/config incomplete

## Executive summary

**KubeGuard** is a Go-based Kubernetes **attack-surface, posture, and compliance** scanner
with the pipeline **detect → chain → harden**. It is offline-first, read-only against
clusters, telemetry-free, and designed for standalone use and future ZealDefense/USP
integration.

Per `docs/PROGRESS.md`, all engine squads (A–K) and dashboard/production squads
(D1–D6, P1–P7) are marked **done**. The software is production-capable, but
operational deployment, environment configuration, and a few product gaps remain
before a real production launch.

---

## Project summary

### What it does

| Capability | Detail |
|---|---|
| **Detection** | 20 built-in checks (KG-001..020), CIS/NSA-mapped, deterministic |
| **Attack paths** | Capability chaining with MITRE ATT&CK tags; narrative only, not exploits |
| **Compliance** | 6 YAML-driven frameworks (CIS, NIST 800-53, PCI DSS v4, ISO 27001, DPDP, NCA ECC) |
| **Hardening** | `kubeguard harden` emits a baseline bundle that scans to zero findings |
| **Honest metrics** | Always `breached of assessed` / `passed of assessed` with disclaimer |

### Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Inputs     │────▶│  Engine (Go)     │────▶│  Outputs    │
│  YAML/live  │     │  detect→chain→   │     │  JSON/SARIF │
│  K8s API    │     │  comply          │     │  HTML/PDF   │
└─────────────┘     └──────────────────┘     └─────────────┘
                            │
                    ┌───────┴───────┐
                    ▼               ▼
              Dashboard BFF    Prometheus / OTel
              (React SPA)      Postgres (optional)
```

### Tech stack

| Layer | Stack |
|---|---|
| **Engine** | Go 1.26, Cobra CLI, client-go, chi router |
| **Dashboard API** | BFF in `internal/dashboard`, SSE streaming, JWT/OIDC + local-admin auth |
| **Frontend** | React 18, TypeScript, Vite, Tailwind, TanStack Router/Query, React Flow, Recharts |
| **Persistence** | In-memory (default) or Postgres 16 + goose migrations |
| **Deploy** | Distroless API image, nginx-unprivileged web image, Helm chart `charts/kubeguard-dashboard` |
| **CI/CD** | 4 GitHub workflows: engine CI, dashboard CI, security gates, goreleaser releases |

### Deployment modes

| Mode | Use case |
|---|---|
| CLI / CI gate | Offline scans, pipeline gates (`--fail-on`) |
| Live / kubectl plugin | Read-only in-cluster scans |
| Service (`serve`) | Single-tenant REST + metrics |
| **Dashboard** | Multi-tenant web UI, continuous scans, exports |
| Webhook | Admission-time policy enforcement |

---

## Readiness assessment

| Area | Status | Notes |
|---|---|---|
| Core engine | ✅ Ready | 20 checks, attack paths, compliance, hardening, golden fixtures |
| Dashboard features | ✅ Ready | 6 lenses, SSE live scans, exports (PDF/CSV/SARIF), audit log |
| Security hardening | ✅ Ready | JWT/OIDC, CSP/HSTS, rate limits, govulncheck, threat model |
| Observability | ✅ Ready | Prometheus metrics, OTel (opt-in), alerts, Grafana JSON |
| Packaging | ✅ Ready | Multi-arch images, Helm chart, PDB/HPA/Ingress templates |
| CI/CD | ✅ Ready | 7-job dashboard pipeline, cosign, SBOM, kind smoke, k6 load |
| Documentation | ⚠️ Mostly ready | Admin/user guides complete; OpenAPI missing `/v1/audit` and `/v1/report` |
| **Production config** | ⚠️ Pending | Helm defaults are dev-oriented |
| **Live cluster scanning in dashboard** | ⚠️ Gap | Engine supports live; dashboard BFF does not wire it |
| **Operational automation** | ⚠️ Pending | Backups, cert rotation, staging/prod envs not in chart |
| **External validation** | ❌ Not done | Pen test, ASVS L2 audit explicitly out of scope |

---

## Production checklist

### 🔴 Blocking — must complete before production

- [ ] **Enable Postgres persistence** — `postgres.enabled=true` with DSN secret; in-memory store breaks multi-replica HA
- [ ] **Rotate secrets** — replace default `local-admin` token; store in K8s Secret (`KUBEGUARD_ADMIN_TOKEN`)
- [ ] **Enable TLS** — ingress TLS or pod-level `--tls-cert/--tls-key`; enforce `sslmode=require` on Postgres DSN
- [ ] **Configure OIDC/SSO** (if not air-gapped) — issuer, audience, JWKS URL; build web image with `VITE_OIDC_AUTHORIZE_URL`
- [ ] **Wire cluster data sources** — mount manifest paths per cluster, or implement live scanning in dashboard
- [ ] **Publish and pin images by digest** — build/push `ghcr.io/kubeguard/kubeguard` and `kubeguard-web`; verify cosign signatures
- [ ] **Deploy observability** — Prometheus scrape of `/metrics`, import Grafana dashboard, load `deploy/observability/alerts.yaml`
- [ ] **Set retention policy** — e.g. `postgres.retention: 720h` for DPDP/GDPR compliance
- [ ] **Configure ingress + DNS** — `ingress.enabled=true`, real hostname, TLS cert
- [ ] **Run staging promotion** — deploy signed digest to staging, run e2e + k6 load smoke, then promote same digest to prod
- [ ] **Establish Postgres backup schedule** — CronJob or managed PITR per [persistence.md](persistence.md) (not in Helm chart)
- [ ] **Integrate into version control** — ensure the codebase is committed and tracked in git

### 🟡 Important — should complete (workarounds exist)

- [ ] **Live cluster scanning in dashboard** — `internal/cli/dashboard.go` only uses `offline.Load()`; Helm `live.enabled` RBAC exists but scanner is not wired to `internal/loader/live`
- [ ] **Dynamic cluster management** — clusters registered only at startup via `--cluster id=path`; no API to add/remove clusters at runtime
- [ ] **DPDP erasure operator path** — `DeleteTenant()` exists in Go/Postgres only; no HTTP admin endpoint or CLI command for DSAR
- [ ] **OpenAPI completeness** — `docs/openapi.yaml` missing `/v1/audit` and `/v1/report` (implemented but undocumented in contract)
- [ ] **Multi-tenant provisioning** — tenancy comes from JWT claims; no tenant onboarding/invitation API (single `--tenant` at startup)
- [ ] **Rate limiting in prod** — set `security.rateLimitPerSecond` and `allowedOrigins` for CSRF defense-in-depth
- [ ] **Enable HPA** — `autoscaling.enabled=true` for scan-heavy workloads; tune `asyncWorkers`
- [ ] **ServiceMonitor** — `serviceMonitor.enabled=true` if using Prometheus Operator
- [ ] **ZealDefense integration** — USP control-plane ingest documented but not wired ([usp-integration.md](usp-integration.md))
- [ ] **Sign off ARCHITECTURE.md** — still marked "Draft for sign-off (v0.1)"
- [ ] **Security contact** — `security@kubeguard.io` in `SECURITY.md`; confirm for ZealDefense operations

### 🟢 Deferred / documented gaps (acceptable for v1 with disclosure)

- [ ] **SARIF full JSON-Schema validation** — structural validation only via go-sarif types
- [ ] **Formal pen test / ASVS L2 audit** — explicitly out of scope per [threat-model.md](threat-model.md)
- [ ] **Per-PR container image Trivy scan** — runs in release pipeline only, not every PR
- [ ] **Keyless cosign signing** — wired in CI; requires GitHub OIDC (Fulcio/Rekor) on main/tags
- [ ] **Standalone worker Deployment** — scans run in-process in API pod; scale via replicas + `asyncWorkers`
- [ ] **cert-manager in Helm** — TLS via manual Secret mount; no cert-manager Issuer/Certificate in chart
- [ ] **Automated Postgres backup Job** — documented runbook only

### ✅ Already complete

- [x] Engine: 20 checks, attack paths, 6 compliance frameworks, hardening bundle
- [x] Dashboard: 6 lenses + Audit + Reports, SSE live updates, React Flow attack graph
- [x] Auth: JWT RS256/ES256, JWKS, algorithm-confusion defense, RBAC (viewer/analyst/admin)
- [x] Postgres: goose migrations, retention, tenant isolation, integration tests vs Postgres 16
- [x] Security: CSP, HSTS, rate limit, CSRF Origin check, govulncheck clean, gitleaks/trivy in CI
- [x] Performance: async worker pool, p95 ≈ 4 ms API reads, 5k-pod scan ≈ 0.35 s
- [x] Helm: lint strict clean, kubeconform 11/11, PDB, non-root hardened pods
- [x] CI/CD: backend + Postgres integration + Playwright e2e + kind smoke + k6 + cosign/SBOM
- [x] Docs: admin guide, user guide, runbooks, privacy/DPDP, honest-metrics policy, threat model

---

## Recommended production Helm values

```yaml
postgres:
  enabled: true
  dsn: { existingSecret: kgd-pg }
  retention: 720h

auth:
  adminToken: { existingSecret: kgd-admin }   # break-glass only
  oidc:
    enabled: true
    issuer: https://your-idp.example.com
    audience: kubeguard
    jwksUrl: https://your-idp.example.com/.well-known/jwks.json

tls: { enabled: true, secretName: kgd-tls }
ingress: { enabled: true, className: nginx, host: kubeguard.yourdomain.com }

autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 6 }
serviceMonitor: { enabled: true }
asyncWorkers: 4
security:
  rateLimitPerSecond: 50
  allowedOrigins: ["https://kubeguard.yourdomain.com"]

image:
  api: { digest: "sha256:..." }   # pin, don't use floating tags
  web: { digest: "sha256:..." }
```

---

## Key product gaps

### 1. Dashboard live scanning not wired

The engine supports live cluster reads (`internal/loader/live`), and the Helm chart ships
read-only RBAC when `live.enabled=true`, but the dashboard command only scans offline
manifests via `offline.Load()`. For continuous production posture against live clusters,
either mount/sync manifests into the pod **or** wire live loading into the dashboard scanner
(as `serve` and `scan --live` already do).

### 2. Helm defaults are not production-safe

`postgres.enabled: false` and `tls.enabled: false` by default. Without overrides you get
ephemeral storage, HTTP-only traffic, and the default `local-admin` token risk.

### 3. No operator APIs for lifecycle management

Missing HTTP/CLI surfaces for:

- Tenant provisioning / DPDP `DeleteTenant`
- Dynamic cluster registration
- User/role management (relies entirely on IdP JWT claims)

---

## Suggested launch sequence

1. **Week 1 — Infrastructure** — Postgres HA, secrets, TLS, ingress, image publish + cosign verify
2. **Week 2 — Config** — OIDC, retention, rate limits, observability stack, backup CronJob
3. **Week 3 — Staging** — Deploy digest-pinned Helm release, run full CI smoke + manual UAT
4. **Week 4 — Prod** — Promote same digest, enable scheduled scans, on-call runbooks live

**Estimated effort:** 1–2 weeks for a skilled platform team (Postgres, IdP, and K8s cluster available).

---

## Local verification (2026-06-08)

| Check | Result |
|---|---|
| `go test ./...` | ✅ All packages passed (~4 min) |
| `golangci-lint run` | ✅ 0 issues (cold run timed out on default timeout; passes with `--timeout=10m`) |
| `npm run build` (web) | ⚠️ `tsc` permission denied on `node_modules/.bin` — fix with `chmod +x` |

CI remains the authoritative gate. See [cicd.md](cicd.md) for the full pipeline.

---

## Related docs

- [README](../README.md) · [PROGRESS.md](PROGRESS.md) · [ARCHITECTURE](../ARCHITECTURE.md)
- [deploy.md](deploy.md) · [admin-guide.md](admin-guide.md) · [auth.md](auth.md)
- [persistence.md](persistence.md) · [observability.md](observability.md) · [threat-model.md](threat-model.md)
- [runbooks.md](runbooks.md) · [cicd.md](cicd.md) · [privacy.md](privacy.md)
