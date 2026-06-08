# Deploying the KubeGuard dashboard

## Images
Two images, both built multi-arch (linux/amd64, linux/arm64):

| Image | Dockerfile | Base | Notes |
|---|---|---|---|
| `kubeguard` (API + worker) | `./Dockerfile` | `gcr.io/distroless/static:nonroot` | the Go binary; same image serves the API and the in-process worker pool |
| `kubeguard-web` | `./web/Dockerfile` | `nginxinc/nginx-unprivileged` | static SPA + hardened `nginx.conf`. (distroless has no static-file server, so the web tier uses the unprivileged-nginx minimal image — non-root, no extra packages.) |

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/kubeguard/kubeguard:1.0.0 .
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/kubeguard/kubeguard-web:1.0.0 ./web
```

Worker note: the worker runs **in-process** in the API pod (`--async-workers N`).
A standalone worker Deployment is not split out because the scan queue is
in-process; scale throughput with API replicas + workers.

## Helm install
```bash
helm install kgd charts/kubeguard-dashboard -n kubeguard --create-namespace \
  --set clusters[0].id=prod --set clusters[0].path=/manifests/prod
```

Common production values:
```yaml
postgres: { enabled: true, dsn: { existingSecret: kgd-pg }, retention: 720h }
auth:
  adminToken: { existingSecret: kgd-admin }
  oidc: { enabled: true, issuer: https://idp, audience: kubeguard, jwksUrl: https://idp/.well-known/jwks.json }
tls: { enabled: true, secretName: kgd-tls }
autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 6 }
serviceMonitor: { enabled: true }
ingress: { enabled: true, className: nginx, host: kubeguard.example.com }
```

Pod hardening is on by default: non-root (uid 65532), read-only root filesystem,
`drop: [ALL]`, `seccompProfile: RuntimeDefault`. The API uses a zero-downtime
rolling update (`maxUnavailable: 0`) and a PodDisruptionBudget for HA.

The chart is `helm lint --strict` clean and the rendered manifests pass
`kubeconform` (11/11 valid; the ServiceMonitor CRD is skipped without its schema).

## Air-gapped install
1. Mirror the two images into the air-gapped registry; retag in values
   (`image.api.repository` / `image.web.repository`), pin by digest.
2. Keep `image.pullPolicy=IfNotPresent` (default) and pre-load images on nodes.
3. OIDC is optional — use the **local-admin** token (a Secret), no external IdP.
4. No telemetry/phone-home; OTel tracing is off unless `otel.endpoint` is set.
5. Bundle Postgres via your in-cluster operator or a mirrored `postgres:16` image.

## Local smoke (kind)
```bash
kind create cluster
docker build -t kubeguard:dev . && kind load docker-image kubeguard:dev
docker build -t kubeguard-web:dev ./web && kind load docker-image kubeguard-web:dev
helm install kgd charts/kubeguard-dashboard -n kubeguard --create-namespace \
  --set image.api.repository=kubeguard --set image.api.tag=dev \
  --set image.web.repository=kubeguard-web --set image.web.tag=dev \
  --set clusters[0].id=demo --set clusters[0].path=/manifests
kubectl -n kubeguard rollout status deploy/kgd-kubeguard-dashboard-api
kubectl -n kubeguard port-forward svc/kgd-kubeguard-dashboard-web 8080:8080
```
This kind flow runs in CI (Squad P6, `deploy-kind` job).
