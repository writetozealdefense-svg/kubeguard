# KubeGuard dashboard — threat model

Scope: the dashboard backend-for-frontend (`kubeguard dashboard`), its web UI,
and the Postgres datastore. The engine itself is offline, read-only, and
covered by `docs/security-model.md`. This is a starting threat model (STRIDE),
kept current as the product hardens.

## Assets
- Kubernetes posture data (findings, attack paths, compliance) — tenant-scoped.
- The audit log (who triggered what) — integrity-critical.
- Auth secrets: OIDC signing keys (external), the local-admin bearer token, the
  Postgres DSN/credentials.
- Read-only cluster credentials (kubeconfig / workload identity).

## Trust boundaries
1. Browser ⇄ dashboard API — the **single trust boundary**. All authz is
   enforced server-side; the UI only hides/disables by role.
2. Dashboard ⇄ Postgres — credentialed, ideally TLS + private network.
3. Dashboard ⇄ Kubernetes API — **read-only** (get/list/watch only, see
   `deploy/rbac-readonly.yaml`); the product never mutates a scanned cluster.
4. Dashboard ⇄ OIDC IdP — JWKS fetch + token verification (default off).

## STRIDE → mitigations (as built)

| Threat | Vector | Mitigation (squad) |
|---|---|---|
| **Spoofing** | Forged/none-alg JWT; stolen token | Real RS256/ES256 verification, JWKS, iss/aud/exp, **rejects `none`/HS\*** (D3). Local-admin token via env/secret, never in image (P2). |
| **Tampering** | Mutating a cluster; altering audit | Cluster access read-only RBAC (H); audit log append-only, never updated/deleted (D3/P1). |
| **Repudiation** | "I didn't trigger that scan" | Append-only audit of every privileged action — allowed **and** denied — with subject + tenant (D3). |
| **Information disclosure** | Cross-tenant reads; secret leakage; XSS | Every query tenant-scoped; cross-tenant returns nothing (D2/D3/P1). Secret **values never stored or returned** — evidence is key-names only. Strict CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` (P2). |
| **Denial of service** | Request floods; huge bodies | Per-tenant token-bucket rate limiting; 1 MiB body cap (`413`); `ReadHeaderTimeout` (P2). |
| **Elevation of privilege** | Viewer triggering scans; CSRF | Server-side RBAC (viewer→403, audited); bearer-token auth (not cookies) + Origin allowlist on unsafe methods as defense-in-depth (D3/P2). |

## Transport & secrets
- TLS via `--tls-cert/--tls-key`; HSTS emitted when TLS is on.
- Secrets read from env (`KUBEGUARD_ADMIN_TOKEN`, `KUBEGUARD_POSTGRES_DSN`) or a
  mounted secret — **never baked into the image or committed**. CI runs gitleaks.
- Input validation: zod validates every API response in the client; the server
  validates request bodies (required fields, format enum, capped size, clamped
  pagination).

## Supply chain
- `govulncheck`, `gitleaks`, `trivy` (fs + config + secret), and `npm audit`
  gate CI (`.github/workflows/security.yml`). Dependencies are pinned.
- CycloneDX SBOMs for the Go binary (cyclonedx-gomod) and `web/` (syft).
- Release artifacts are cosign-signed with SLSA provenance (goreleaser, Squad K).

## Known gaps / deferred (honest)
- **Keyless (Fulcio/Rekor) image signing** needs CI OIDC — wired in goreleaser,
  validated as config locally; exercised in the release pipeline (Squad K/P6).
- Container image vulnerability scanning runs against built images in the
  release pipeline (P6), not on every PR.
- A formal pen-test / full ASVS L2 audit is out of scope of this pass; the
  access-control, transport, and supply-chain items above are covered.
