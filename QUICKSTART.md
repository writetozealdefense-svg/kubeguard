# KubeGuard quickstart

## Build

```bash
go build -o kubeguard ./cmd/kubeguard
./kubeguard version
```

Put the binary on your `PATH` (e.g. `mv kubeguard /usr/local/bin/`) so the
`kubeguard ...` commands below resolve, or download a cosign-signed release
(see [docs/security-model.md](docs/security-model.md)). Cross-compiles to
linux/amd64, linux/arm64, windows/amd64, darwin/arm64 (no cgo).

## 1. Offline scan (CLI)

```bash
kubeguard scan -i ./manifests                       # console
kubeguard scan -i ./manifests -f json  -o out.json
kubeguard scan -i ./manifests -f sarif -o out.sarif # for code scanning
kubeguard scan -i ./manifests -f html  -o report.html
kubeguard scan -i ./manifests -f evidence -o ./evidence  # per-framework auditor evidence packs (HTML+JSON)
kubeguard scan -i ./manifests --assume-breach       # model an in-cluster foothold
kubeguard scan -i ./manifests -p cis                # CIS-aligned profile
```

Try the bundled fixtures:

```bash
kubeguard scan -i test/fixtures/vulnerable.yaml        # 19 findings, cluster-admin chain
kubeguard scan -i test/fixtures/hardened.yaml          # 0 findings
```

## 2. CI gate

```bash
kubeguard scan -i ./manifests --fail-on high   # exit 2 if any finding >= high
kubeguard scan -i ./manifests --history kg.sqlite   # track drift over time
```

## 3. Live cluster (read-only) & kubectl plugin

```bash
kubeguard scan --live                                  # uses your kubeconfig
kubectl kubeguard scan --live --fail-on high           # as a kubectl plugin
```

See [docs/kubectl-plugin.md](docs/kubectl-plugin.md).

## 4. Service mode (REST + dashboard + metrics)

```bash
kubeguard serve --live --schedule "0 * * * *" --history /data/kg.sqlite
# GET /v1/posture, /v1/findings, /metrics, /healthz, /readyz, and the dashboard at /
```

Or via Helm: `helm install kubeguard ./charts/kubeguard`. See [docs/api.md](docs/api.md).

## 5. Admission webhook

```bash
kubectl apply -f deploy/webhook.yaml
kubectl label namespace my-app kubeguard.io/enforce=true
```

Denies privileged / hostPath / run-as-root pods. See [docs/webhook.md](docs/webhook.md).

## 6. Generate a hardened baseline

```bash
kubeguard harden -o kubeguard-baseline
kubectl apply -f kubeguard-baseline/
kubeguard scan -i kubeguard-baseline/    # 0 findings
```
