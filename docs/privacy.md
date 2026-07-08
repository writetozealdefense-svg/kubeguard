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

## Right to erasure — DSAR runbook (DPDP / GDPR-style)

A tenant's data is hard-deleted **irreversibly** across every table (clusters,
scans, history, findings lifecycle, **audit**, users, and the tenant row). There
is no soft-delete or tombstone. Two execution paths:

**1. API (managed):** `DELETE /v1/tenants/{tenant}`.
- A tenant-scoped **admin** may erase **their own** tenant.
- Erasing **any other** tenant requires a **super-admin** principal (a
  `role: super-admin` JWT claim). A tenant admin attempting a cross-tenant
  erasure gets `403`.
- The erasure is recorded in the **acting principal's** tenant, so a super-admin's
  proof-of-erasure survives the purge of the target tenant. Response: `204`.

**2. CLI (out-of-band / air-gapped):** for a DSAR executed directly against the
store with no HTTP surface:
```sh
kubeguard dashboard-admin delete-tenant --tenant <id> \
  --postgres 'postgres://…?sslmode=require'   # or KUBEGUARD_POSTGRES_DSN
```
Prints `erased all data for tenant "<id>"` on success. Run this from an operator
host and capture the command + output in your DSAR register.

**Runbook steps:**
1. Verify the requester's identity and the tenant id out-of-band.
2. Record the request in the DSAR register (requester, tenant, date, ticket).
3. Execute the erasure (API as super-admin, or the CLI on an operator host).
4. Confirm: `GET /v1/clusters` for the tenant returns none, and a fresh scan of
   any former cluster 404s. In Postgres:
   `SELECT count(*) FROM clusters WHERE tenant='<id>';` → 0.
5. File the proof-of-erasure (the super-admin audit entry, or the CLI output) in
   the register. Note the erasure is irreversible — restoring the tenant means a
   fresh re-provision, not recovery.

The **only** personal data erased is the tenant's identity/audit rows (§"What
personal data is stored"); scan content contains none.

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
