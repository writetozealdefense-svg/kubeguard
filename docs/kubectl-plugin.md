# KubeGuard kubectl plugin

`kubectl-kubeguard` is the KubeGuard CLI packaged as a kubectl plugin. Once the
binary is on your `PATH`, `kubectl` discovers it and exposes it as
`kubectl kubeguard`.

## Install

```bash
go build -o kubectl-kubeguard ./cmd/kubectl-kubeguard
# place it anywhere on PATH, e.g.
mv kubectl-kubeguard /usr/local/bin/

kubectl plugin list        # should list kubectl-kubeguard
```

(GoReleaser publishes prebuilt, cosign-signed `kubectl-kubeguard` binaries for
linux/amd64, linux/arm64, windows/amd64, and darwin/arm64 — see
[security-model.md](security-model.md).)

## Use

Scan the current kube-context **read-only**:

```bash
kubectl kubeguard scan --live
kubectl kubeguard scan --live --context staging -f sarif -o kube.sarif
kubectl kubeguard scan --live --fail-on high          # CI gate against a cluster
```

`--live` reads the same resources the offline loader understands (workloads,
RBAC, services, network policies) using your kubeconfig credentials. KubeGuard
only ever **lists** these resources — it never creates, patches, or deletes
anything (ARCHITECTURE.md §3, §5.2).

### Least-privilege access

To run KubeGuard with a dedicated read-only identity instead of your own
credentials, apply [`deploy/rbac-readonly.yaml`](../deploy/rbac-readonly.yaml),
which grants `get`/`list`/`watch` on exactly the kinds KubeGuard reads.

The offline mode (`-i <path>`) remains available through the plugin too, e.g.
`kubectl kubeguard scan -i ./manifests -f html -o report.html`.
