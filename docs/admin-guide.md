# KubeGuard admin guide

For operators installing, upgrading, and running the KubeGuard dashboard. A new
operator should be able to stand it up using only this page and the links in it.

## 1. Choose a mode
| Mode | When | Reference |
|---|---|---|
| CLI / CI gate | one-off or pipeline scans | [QUICKSTART](../QUICKSTART.md) |
| Live (read-only) / kubectl plugin | point-in-time cluster check | [security-model](security-model.md), [kubectl-plugin](kubectl-plugin.md) |
| Service (`serve`) | single-tenant REST + metrics | [api.md](api.md) |
| **Dashboard** | multi-tenant web UI, continuous | this guide + [deploy](deploy.md) |
| Admission webhook | block bad pods at admission | [webhook](webhook.md) |

## 2. Install the dashboard (Helm)
```bash
helm install kgd charts/kubeguard-dashboard -n kubeguard --create-namespace \
  --set clusters[0].id=prod --set clusters[0].path=/manifests/prod
```
Full image build, values, TLS/OIDC/Postgres, HA, and **air-gapped** steps:
[deploy.md](deploy.md). Pod hardening (non-root, read-only rootfs, drop ALL) is
on by default.

## 3. Pick a backend
- **In-memory** (default): ephemeral, zero deps, fine for a single replica or a
  demo.
- **Postgres** (`postgres.enabled=true`): durable, multi-replica. Schema, the
  embedded migrations, retention, and **backup/restore** are in
  [persistence.md](persistence.md).

## 4. Configure auth
Local-admin token (air-gapped) and/or OIDC/SSO. Roles: viewer / analyst / admin.
Setup + enable-step: [auth.md](auth.md).

## 5. Operate
- **Observability:** scrape `/metrics`, import the Grafana dashboard, load the
  alert rules — [observability.md](observability.md).
- **Performance/scale:** async workers, the 5k-pod budget, k6 —
  [performance.md](performance.md).
- **Upgrade / rollback / promotion:** [cicd.md](cicd.md). Upgrades are a
  zero-downtime rolling deploy; rollback is `helm rollback`.
- **Incidents & restore:** [runbooks.md](runbooks.md).
- **Security posture of the product itself:** [threat-model.md](threat-model.md);
  report issues per [SECURITY.md](../SECURITY.md).

## 6. Upgrade
```bash
helm upgrade kgd charts/kubeguard-dashboard -n kubeguard \
  --set image.api.digest=sha256:... --set image.web.digest=sha256:...
```
Migrations apply automatically on start (additive/expand-contract; a rollback
needs no DB down-migration). Promote the **same digest** staging→prod.

## 7. Data & privacy
What personal data is stored, retention, and DPDP erasure: [privacy.md](privacy.md).
