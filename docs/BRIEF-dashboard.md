# Claude Code Build Brief — KubeGuard Dashboard & Productionization

Pairs with `ARCHITECTURE.md`. This brief turns KubeGuard from a CLI/engine into a
**production product with a real web dashboard**. Run the squads sequentially.

---

## Mission
Build a production web **dashboard** for KubeGuard and harden the whole tool into a
**shippable, secure, operable product**. The dashboard is the primary surface for
continuous Kubernetes posture: misconfigurations ("dents"), the attack paths they chain
into, and the compliance controls they breach — across multiple clusters, tracked over
time. It must also produce co-branded engagement reports (ZealDefense) and run in
air-gapped environments.

## Prerequisites
Assumes the engine brief is built (Squads A–K): `pkg/api` types, the
scan/attack-path/compliance engines, and a basic `kubeguard serve`. This brief consumes
the engine via `pkg/api`; it does not reimplement detection.

## Tech stack
- **Frontend** (`web/`): React 18 + TypeScript + Vite + Tailwind; TanStack Query, TanStack
  Router, Recharts, @xyflow/react (React Flow), Radix/shadcn-ui, zod. Tests: Vitest +
  Playwright (e2e).
- **Backend** (extend `internal/server/`): Go, `chi` router, OpenAPI, pgx + Postgres,
  migrations via goose, OIDC via coreos/go-oidc, JWT via golang-jwt, SSE/WebSocket,
  RBAC via casbin, Prometheus + OpenTelemetry.
- **Deploy**: distroless multi-arch images, Helm chart, cert-manager TLS, HPA.

## Conventions & guardrails (do not violate)
- Cluster access stays **read-only**; the product never mutates scanned clusters.
- **Honest metrics**: every compliance figure renders with its `assessed` denominator and
  the indicative-mapping disclaimer. No bare "compliant" badges.
- **Secrets redacted** everywhere (key name only). No secret values in the DB.
- **Air-gapped support is first-class**: OIDC optional; local-admin auth works with zero
  external deps. No telemetry/phone-home.
- **DPDP-aware**: configurable retention + delete; document personal data stored and why.
- Signed images, SBOM, pinned deps.
- Frontend talks only to KubeGuard's own API; the API is the single trust boundary.
- Accessibility: WCAG 2.1 AA.

---

## Track 1 — Production dashboard
- **D1** Frontend scaffold & design system (`web/`): Vite+TS+Tailwind, tokens, app shell,
  routing, TanStack Query, typed API client from OpenAPI, Vitest.
- **D2** Dashboard API (BFF): OpenAPI-described `/v1/clusters,scans,findings,posture,
  attack-paths,history`, server-side filter/sort/paginate, authz per route, SSE `/v1/stream`.
- **D3** Auth, tenancy & RBAC: OIDC/SSO + local-admin fallback; JWT; org→project→cluster
  tenancy; viewer/analyst/admin roles; audit log.
- **D4** Core views: Overview, Compliance, Attack Paths (React Flow), Findings,
  Clusters/Fleet, History/Drift.
- **D5** Continuous & live: scheduled + on-demand scans, SSE progress, query invalidation.
- **D6** Reporting & export: co-branded PDF, CSV, SARIF; honest denominators on PDF.

## Track 2 — Production readiness
- **P1** Persistence & migrations: Postgres schema, goose, retention/hard-delete, pooling.
- **P2** Security hardening: TLS, secret store, CSRF, CSP/HSTS, rate limit, validation,
  govulncheck/trivy/gitleaks in CI, cosign + SBOM, least-priv RBAC.
- **P3** Observability & reliability: slog+request IDs, Prometheus, OTel, health/readiness,
  graceful shutdown, retries/idempotency, SLOs + alerts + Grafana JSON.
- **P4** Performance & scale: async workers, pagination/caching, 5k-pod fixture, k6 load.
- **P5** Packaging & deploy: distroless multi-arch (api/web/worker), Helm, HA+HPA,
  air-gapped install.
- **P6** CI/CD & quality gates: lint→unit→integration→Playwright→security→load→build/sign/SBOM.
- **P7** Docs & launch readiness: OpenAPI ref, admin/user guides, runbooks, threat model,
  DPDP statement, honest-metrics policy, SECURITY.md.

## Definition of done
Multi-tenant, multi-cluster dashboard on Postgres with SSO + local auth and RBAC; live +
scheduled scans populating compliance-breach and attack-path views with drift; co-branded
PDF/CSV/SARIF export with honest denominators; observable, performant, deployable via signed
Helm with SBOM, air-gapped-capable, DPDP-aware; CI/CD with e2e + security gates; complete
docs. Cluster access read-only throughout; no secret values stored or shown.

## How to drive the runner
Per squad: implement → `go build/vet/lint/test` + `npm build/lint/test` → run the squad's
acceptance (incl. Playwright where relevant) → commit → advance only when green. Update
`docs/PROGRESS.md` each squad. Never weaken a test to pass a gate.
