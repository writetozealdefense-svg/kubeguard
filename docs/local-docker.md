# Run KubeGuard locally with Docker

A one-command local environment: **Postgres + dashboard API + web UI**, with two
bundled fixtures standing in for clusters. Nothing is published or sent anywhere —
the stack is fully offline on a private Docker network.

## Prerequisites

- Docker Engine 24+ with the Compose v2 plugin (`docker compose version`).
- ~1.5 GB free disk for images; the first build takes a few minutes (Go + npm).

## Quick start

```bash
cp .env.example .env          # optional — defaults work out of the box
docker compose up --build     # or: make up   (runs detached)
```

Then open the dashboard:

| URL | What |
|---|---|
| http://localhost:8088 | Dashboard UI — **log in with token `local-admin`** |
| http://localhost:8080/healthz | API health check |
| http://localhost:8080/metrics | Prometheus metrics |
| `localhost:5432` | Postgres (user/pass/db all `kubeguard`) |

On the login screen choose **local admin** and paste the token
(`local-admin`, or whatever you set as `KUBEGUARD_ADMIN_TOKEN`).

Stop with `Ctrl-C` (foreground) or `make down`. `make rebuild` wipes the Postgres
volume and starts fresh.

## What's running

```
browser ──▶ web (nginx :8088) ──/v1, /healthz, /readyz──▶ api (:8080) ──▶ postgres (:5432)
                static SPA            reverse proxy            kubeguard dashboard
```

The API registers two stand-in clusters from `test/fixtures/`:

| Cluster | Fixture | Expect |
|---|---|---|
| `prod-eu` | `vulnerable.yaml` | findings, a critical attack path, compliance breaches |
| `staging-us` | `hardened.yaml` | clean — 100% of assessed controls pass |

An initial scan runs on boot, and `--schedule "*/5 * * * *"` re-scans every five
minutes so the History/Drift and trend views populate over time. Scans, history,
and the audit log persist in Postgres across restarts.

## Common tasks

```bash
make up        # build + start detached
make logs      # tail all service logs
make ps        # service status
make down      # stop (keeps the Postgres volume)
make rebuild   # stop + wipe DB volume + start fresh
```

Hit the API directly (bearer token required on `/v1`):

```bash
curl -s -H "Authorization: Bearer local-admin" \
  http://localhost:8080/v1/posture?cluster=prod-eu | jq .

# Export a report (sarif | csv | pdf)
curl -s -H "Authorization: Bearer local-admin" \
  "http://localhost:8080/v1/report?cluster=prod-eu&format=sarif" -o prod-eu.sarif
```

Inspect the database:

```bash
docker compose exec postgres psql -U kubeguard -d kubeguard -c '\dt'
```

## Run without Postgres (ephemeral)

The dashboard runs fully in-memory if no DSN is provided. In
`docker-compose.yml`, comment out (1) the `postgres` service, (2) the api
`depends_on:` block, and (3) the api `KUBEGUARD_POSTGRES_DSN` env line. Then
`docker compose up --build`. Data resets on every restart.

## Scan a real cluster instead of fixtures

The API image supports read-only live scanning. Mount your kubeconfig and
register a `live` source:

```yaml
# under services.api in docker-compose.yml
    volumes:
      - ./test/fixtures:/fixtures:ro
      - ${HOME}/.kube:/home/nonroot/.kube:ro     # read-only kubeconfig
    environment:
      KUBECONFIG: /home/nonroot/.kube/config
    command:
      - "dashboard"
      - "--addr=:8080"
      - "--cluster=my-cluster=live"              # or live:<context>
      # ...
```

The loader only ever issues `list` calls — it never writes to the cluster.
Make sure your kubeconfig context is reachable from inside the container
(a `kind`/`minikube` API server on `127.0.0.1` needs `host.docker.internal`
or host networking).

## Configuration

All knobs live in `.env` (see `.env.example`): the admin token, Postgres
credentials, and the three host ports (`WEB_PORT`, `API_PORT`, `POSTGRES_PORT`).
Change a port there if `8088`/`8080`/`5432` is already taken.

## Troubleshooting

- **Port already in use** — set `WEB_PORT`/`API_PORT`/`POSTGRES_PORT` in `.env`.
- **UI loads but calls fail / 502** — the `api` service isn't healthy yet; check
  `make logs`. The web tier proxies to `api:8080` over the compose network.
- **`api` exits immediately** — usually a bad `--cluster` path or an unreachable
  DSN. `docker compose logs api` shows the exact error.
- **Login rejected** — the token you type must match `KUBEGUARD_ADMIN_TOKEN`
  (default `local-admin`).
- **Slow first build / huge context** — ensure `.dockerignore` is present so
  `node_modules` and `dist` aren't sent to the daemon.

> This is a **development** stack: `sslmode=disable`, a well-known admin token,
> and bundled fixtures. For real deployments use the Helm chart
> (`charts/kubeguard-dashboard`) and the production values in
> [Kubeguard-PROD_READINESS.md](Kubeguard-PROD_READINESS.md).
