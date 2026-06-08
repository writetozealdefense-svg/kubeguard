# Dashboard authentication, tenancy & RBAC

The dashboard API (`kubeguard dashboard`) is the single trust boundary: every
`/v1` route authenticates the caller and authorizes by role server-side. The web
UI only hides/disables what a role cannot do — it never enforces security.

## Modes

### Local-admin (default, air-gapped)
Works with **zero external dependencies**. A single bearer token maps to an admin
principal in one tenant. No IdP, no network.

```bash
kubeguard dashboard --cluster prod-eu=./manifests --admin-token "$(openssl rand -hex 24)"
# Call the API:  Authorization: Bearer <admin-token>
```

If `--admin-token` is omitted it defaults to `local-admin` (dev only — set a real
secret in any shared environment).

### OIDC / SSO (ready-to-connect seam, DEFAULT OFF)
Real JWT verification: asymmetric signatures only (RS256/ES256, verified against
the IdP's JWKS), enforced `iss`/`aud`/`exp`, and algorithm-confusion defense
(the `none` algorithm and HMAC `HS*` are rejected). Tenancy and role come from
JWT claims.

**Enable step** — provide the issuer + JWKS URL (and audience):

```bash
kubeguard dashboard \
  --cluster prod-eu=./manifests \
  --oidc-issuer        https://idp.example.com \
  --oidc-audience      kubeguard \
  --oidc-jwks-url      https://idp.example.com/.well-known/jwks.json \
  --oidc-tenant-claim  tenant \
  --oidc-role-claim    role
```

When set, OIDC is tried first and the local-admin token remains as a break-glass
fallback (`ChainAuth`). With OIDC **unset**, no IdP is ever contacted.

Frontend: set `VITE_OIDC_AUTHORIZE_URL` at build time to show the "Sign in with
SSO" button; the IdP redirects back to `/auth/callback#token=<jwt>`.

## Tenancy
Data is partitioned by tenant (org). Every query is scoped to the authenticated
principal's tenant; cross-tenant reads return nothing. Clusters belong to a
tenant; org → project → cluster narrows within it.

## Roles (RBAC)
| Role | Can |
|---|---|
| `viewer` | read all lenses (findings, posture, attack paths, history) |
| `analyst` | viewer **+** trigger scans (`POST /v1/scans`) |
| `admin` | analyst **+** read the audit log (`GET /v1/audit`) |

A viewer calling `POST /v1/scans` gets `403` and the denial is recorded in the
append-only audit log. Unknown/absent roles default to `viewer` (least privilege).

## Audit log
Every privileged action (e.g. `scan.trigger`) writes an append-only
`AuditEntry{at, subject, tenant, action, resource, result}`. Entries are
tenant-scoped, admin-readable, and never updated or deleted. Squad P1 persists
the log to Postgres behind the `AuditLog` interface.
