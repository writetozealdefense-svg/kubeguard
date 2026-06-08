# Security Policy

## Reporting a vulnerability
Please report security issues **privately** — do not open a public issue.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this repo, or
- email **security@kubeguard.io** with details and reproduction steps.

We aim to acknowledge within **3 business days** and to provide a remediation
timeline after triage. Please give us reasonable time to fix before public
disclosure; we will credit reporters who wish to be named.

## Scope
In scope: the engine, the dashboard API/BFF, the web UI, the Helm chart, and the
release artifacts. Out of scope: issues requiring a compromised cluster-admin, or
in third-party dependencies already tracked upstream (we run `govulncheck`,
`trivy`, and `gitleaks` in CI — see [`.github/workflows/security.yml`]).

## Product security posture
- **Read-only** against scanned clusters; never mutates them.
- **Offline-first, no telemetry.**
- **Secrets are never stored or displayed** (key names only).
- Auth: real JWT verification (RS256/ES256, JWKS, `none`/HS\* rejected), RBAC,
  append-only audit. See [docs/threat-model.md](docs/threat-model.md).
- Supply chain: CycloneDX SBOMs, cosign signing, SLSA provenance on releases.

## Supported versions
Security fixes target the latest released minor version. Pin images by digest and
verify signatures (see [docs/cicd.md](docs/cicd.md#cosign-verification-consumers)).
