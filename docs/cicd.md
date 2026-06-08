# CI/CD & release (P6)

## Pipeline (`.github/workflows/dashboard-ci.yml`)
On every PR and push to main, these gates run (failures block the merge):

| Job | Gate |
|---|---|
| `backend` | `go build/vet/test ./...` + golangci-lint |
| `integration-postgres` | pg suite against a Postgres 16 **service** (migrations up→down→up, round-trip, retention, DPDP) |
| `frontend` | `npm ci` → gen:api → lint → build → vitest → **Playwright e2e** (login, scan, compliance drill-down, attack-path click, export) |
| `helm` | `helm lint --strict` + `kubeconform` on the rendered chart |
| `deploy-kind` | build images, load into **kind**, `helm install`, smoke `/healthz` |
| `load-smoke` | run the dashboard + **k6** against the read endpoints (p95<120ms threshold) |
| `images` | CycloneDX SBOM + multi-arch build + **cosign keyless sign** (main/tags, GitHub OIDC) |

Engine CI (`ci.yml`) and security gates (`security.yml`: govulncheck/gitleaks/
trivy/npm-audit/SBOM) run alongside. Binary releases are cut by `release.yml`
(goreleaser: 4-target matrix, CycloneDX SBOM, cosign signing, SLSA provenance).

## Database migrations
Migrations are embedded and applied automatically when the API connects to
Postgres (`pg.Open` → goose up). The `integration-postgres` job exercises
up→down→up so a bad migration fails CI before release. No manual migration step
is required on deploy; for a controlled rollout run `pg.Migrate(dsn)` as a Helm
pre-upgrade hook / Job if you prefer to gate the rollout on a clean migration.

## Staging → prod promotion
1. Merge to `main` → `images` job builds, SBOMs, and signs the multi-arch images
   (immutable digests).
2. Deploy the digest to **staging** (`helm upgrade` with `image.*.digest=...`);
   run the e2e + load smoke against staging.
3. Promote the **same digest** to prod (`helm upgrade --install`). Promotion is a
   digest change only — no rebuild — so staging and prod run identical bits.

## Zero-downtime deploy
The API Deployment uses `maxUnavailable: 0, maxSurge: 1` with `/readyz` gating,
behind a PodDisruptionBudget. `helm upgrade` rolls pods one at a time; in-flight
requests drain on the 5s graceful-shutdown window.

## Rollback
```bash
helm history kgd -n kubeguard
helm rollback kgd <PREVIOUS_REVISION> -n kubeguard   # re-pins the prior digest
```
The app is stateless apart from Postgres, so a rollback is a digest swap.
**Migrations are additive** (new tables/columns, `IF NOT EXISTS`) — a rollback of
the app does not require a DB down-migration. If a destructive migration is ever
introduced, gate it behind an expand/contract sequence so the previous app
version still runs against the new schema.

## Cosign verification (consumers)
```bash
cosign verify ghcr.io/kubeguard/kubeguard:<tag> \
  --certificate-identity-regexp '^https://github.com/kubeguard/kubeguard' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Keyless signing requires the CI OIDC identity (Fulcio/Rekor); it runs in the
`images` job, not on a dev host.
