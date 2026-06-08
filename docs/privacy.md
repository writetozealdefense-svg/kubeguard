# Data retention & privacy (DPDP-aware)

KubeGuard is **offline-first** and **telemetry-free** — it never phones home.
This page states what data it stores and how to exercise data-subject rights.

## What personal data is stored
KubeGuard scans Kubernetes configuration, which is not personal data. The only
personal data the dashboard stores is **identity from your SSO/IdP**:

| Data | Where | Why |
|---|---|---|
| User id / `sub` (and email if present in the token) | `users` (SSO) | authenticate + authorize |
| Actor `subject` on audit entries | `audit` | accountability for privileged actions |

No scan content, finding, or report contains personal data. **Secret values are
never stored** — evidence carries key names only.

## Lawful basis & minimization
Identity is processed for access control and audit (legitimate interest /
contractual necessity for operating the platform). Nothing beyond what's needed
for authn/z and an audit trail is collected.

## Retention
Configurable. `--retention <duration>` prunes scans and history older than the
window hourly (the latest scan per cluster is always kept so lenses keep
rendering). Set it to bound how long history and the associated `subject` audit
records persist. With no retention set, data is kept until manually pruned.

## Right to erasure (DPDP / GDPR-style)
A tenant's data is hard-deleted irreversibly across every table:
```go
store.DeleteTenant(ctx, "<tenant>")
```
This removes clusters, scans, history, **audit**, users, and the tenant row.
There is no soft-delete or tombstone. Log the request in your DSAR register.

## Access, portability
- **Access/portability:** a tenant's data is exportable via the Reports lens
  (CSV/SARIF/PDF) and the `/v1/*` API.
- **Isolation:** all data is tenant-partitioned with no cross-tenant foreign
  keys; a query never returns another tenant's data.

## Data location & encryption
KubeGuard runs on infrastructure **you** own — data never leaves your boundary.
Use TLS in transit (`--tls-cert/--tls-key` or ingress TLS) and your provider's
at-rest encryption / KMS for the Postgres volume. (Server-side KMS strategy is
deployment-specific and left to the operator.)
