# KubeGuard

> Kubernetes attack-surface, posture & compliance scanner. **detect → chain → harden.**

KubeGuard reads declarative Kubernetes resources, **detects** misconfigurations,
**chains** them into ATT&CK-tagged attack paths, and emits **hardening**
guidance. It is **offline-first**, **read-only** against clusters, and **free of
telemetry**.

Full design: [ARCHITECTURE.md](ARCHITECTURE.md) · build progress:
[docs/PROGRESS.md](docs/PROGRESS.md) · quickstart: [QUICKSTART.md](QUICKSTART.md).

## What it does

```
$ kubeguard scan -i test/fixtures/vulnerable.yaml
[critical] KG-001  Privileged container            (Deployment payments/checkout)
[critical] KG-002  Sensitive hostPath mount         (Deployment payments/checkout)
[critical] KG-011  Binding grants cluster-admin …   (ClusterRoleBinding …)
...
Attack paths: 1
[critical] AP-001  Cluster-admin takeover via checkout
  1. InternetIngress    → NetworkReachable     [KG-018 T1190]
  2. NetworkReachable   → ContainerEscape       [KG-001 T1611]
  3. ContainerEscape    → NodeAccess            [KG-002 T1611]
  4. NodeAccess         → ServiceAccountToken   [KG-015 T1552.001]
  5. ServiceAccountToken→ ClusterAdmin          [KG-011 T1078]
  6. ClusterAdmin       → LateralMovement       [KG-017 T1021]
Compliance (indicative mapping — breached of assessed):
  CIS Kubernetes Benchmark   8 breached of 9 assessed (11% pass)
  ...
```

- **20 built-in checks** (CIS/NSA-mapped), deterministic, evidence-backed.
- **Capability-based attack paths** with MITRE ATT&CK technique IDs.
- **9 compliance frameworks** (CIS, NIST 800-53, PCI DSS v4.0, ISO 27001:2022,
  DPDP 2023, NCA ECC-1, NCSC CAF 4.0, Cyber Essentials, UK GDPR / DPA 2018) as
  data-driven packs — adding one is a YAML drop-in.
- **Reporters:** console (colour), JSON, SARIF 2.1.0, self-contained HTML
  dashboard, and **`evidence`** — an offline auditor evidence pack (HTML + JSON)
  per framework; file/SQLite **history** for drift.
- **`harden`** emits a least-privilege baseline that scans to **zero** findings.

## Deployment modes

| Mode | Command | Docs |
|---|---|---|
| **CLI** (offline) | `kubeguard scan -i <path> -f console\|json\|sarif\|html\|evidence` | [QUICKSTART](QUICKSTART.md) |
| **CI gate** | `kubeguard scan -i <path> --fail-on high` (exit 2) | [QUICKSTART](QUICKSTART.md) |
| **kubectl plugin** | `kubectl kubeguard scan --live` | [kubectl-plugin.md](docs/kubectl-plugin.md) |
| **Live** (read-only) | `kubeguard scan --live` | [security-model.md](docs/security-model.md) |
| **Service** | `kubeguard serve` (REST + dashboard + `/metrics`) | [api.md](docs/api.md) |
| **Dashboard** (multi-tenant web) | `kubeguard dashboard` + `web/` SPA | [admin-guide](docs/admin-guide.md) · [user-guide](docs/user-guide.md) |
| **Admission webhook** | `kubeguard webhook` | [webhook.md](docs/webhook.md) |

USP control-plane integration: [docs/usp-integration.md](docs/usp-integration.md).

## Multi-tenant dashboard

A production web dashboard backed by Postgres with SSO + local auth and RBAC;
six live lenses (Overview, Findings, Compliance, Attack Paths, Clusters,
History) plus Reports and Audit; continuous + scheduled scans streaming over SSE;
co-branded PDF/CSV/SARIF export. Read-only and honest-metrics throughout.

```bash
kubeguard dashboard --cluster prod=./manifests        # BFF API on :8080
cd web && npm install && npm run dev                  # web UI (proxies to :8080)
# or: helm install kgd ./charts/kubeguard-dashboard
```

Docs: [admin-guide](docs/admin-guide.md) · [user-guide](docs/user-guide.md) ·
[deploy](docs/deploy.md) · [auth](docs/auth.md) · [persistence](docs/persistence.md) ·
[observability](docs/observability.md) · [performance](docs/performance.md) ·
[security/threat-model](docs/threat-model.md) · [CI-CD](docs/cicd.md) ·
[runbooks](docs/runbooks.md) · [privacy/DPDP](docs/privacy.md) ·
[honest-metrics](docs/honest-metrics.md) · [OpenAPI](docs/openapi.yaml) ·
[SECURITY](SECURITY.md).

## Install

```bash
go build -o kubeguard ./cmd/kubeguard           # or download a signed release
helm install kubeguard ./charts/kubeguard       # service mode
```

Go 1.26+, no cgo. Builds for linux/amd64, linux/arm64, windows/amd64,
darwin/arm64. Releases are cosign-signed with a CycloneDX SBOM and SLSA
provenance ([security-model.md](docs/security-model.md)).

## Development

```bash
make check   # build + vet + lint + test (the squad acceptance gate)
```

## Honest metrics & safety

Compliance pass-rates are always reported as `breached of assessed` /
`passed of assessed` with an indicative-mapping disclaimer — never a bare
"compliant / non-compliant" verdict. Attack paths are descriptive narrative
(ATT&CK-tagged), **never runnable exploits**. Live and webhook modes never
mutate the cluster. See [docs/security-model.md](docs/security-model.md).
