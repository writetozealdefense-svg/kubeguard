# KubeGuard admission webhook

A validating admission webhook that **denies pods** violating the restricted
profile (ARCHITECTURE.md §14). It reuses the detection engine, so the webhook
and the scanner never diverge. It is **read-only** — it admits or denies and
never mutates the pod.

## What it denies

A pod is denied if any container or pod spec trips a deny-worthy check:

| Check | Violation |
|---|---|
| KG-001 | privileged container |
| KG-002 | sensitive hostPath mount (e.g. docker.sock) |
| KG-003 / KG-004 / KG-005 | hostNetwork / hostPID / hostIPC |
| KG-006 | runs as root (no `runAsNonRoot` / `runAsUser: 0`) |
| KG-008 | dangerous added capabilities (e.g. `SYS_ADMIN`) |

The denial message lists the offending check ids and titles.

## Enable

Prerequisite: [cert-manager](https://cert-manager.io) is installed (it issues
the webhook's serving certificate and injects the CA bundle).

```bash
# 1. Deploy the webhook (Namespace, SA, cert-manager Issuer+Certificate,
#    Deployment, Service, and the ValidatingWebhookConfiguration).
kubectl apply -f deploy/webhook.yaml

# 2. Opt a namespace into enforcement.
kubectl label namespace my-app kubeguard.io/enforce=true

# 3. Verify: a privileged pod is rejected.
kubectl -n my-app run bad --image=nginx --privileged
#   Error from server: admission webhook "pods.kubeguard.io" denied the request:
#   kubeguard denied pod: KG-001 Privileged container
```

## fail-open vs fail-closed

- **fail-closed** (default): if the webhook is unreachable or cannot evaluate a
  pod, the request is **denied**. Set by the binary flag `--fail-open=false` and
  the webhook's `failurePolicy: Fail`.
- **fail-open**: pass `--fail-open` to the container and set
  `failurePolicy: Ignore` in `deploy/webhook.yaml` to admit on failure.

The two settings are independent: `failurePolicy` governs apiserver→webhook
connectivity; `--fail-open` governs in-handler evaluation/decode errors.

## Scope

The webhook only acts on namespaces labelled `kubeguard.io/enforce=true` and
only on pod `CREATE`. Adjust `namespaceSelector` / `rules` in
`deploy/webhook.yaml` as needed.
