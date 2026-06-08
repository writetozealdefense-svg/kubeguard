# KubeGuard security model

KubeGuard is a security tool, so its own behaviour is constrained by design
(ARCHITECTURE.md §3).

## Guarantees

- **Read-only against clusters.** Live and webhook modes only `list` (and the
  webhook admits/denies). KubeGuard never creates, patches, or deletes cluster
  resources. The only writes it performs are to its own history store and, in a
  future CRD-status mode, its own status. The shipped RBAC
  ([`deploy/rbac-readonly.yaml`](../deploy/rbac-readonly.yaml)) grants only
  `get`/`list`/`watch`.
- **Offline-first core.** Detection, attack-path chaining, and compliance run
  with no network access. Tests run fully offline (no network, no live cluster).
- **No telemetry / no phone-home.** Ever. No usage beacons, no remote config.
- **Secret redaction.** Secret values are never logged or emitted; secret-in-env
  evidence is redacted to the key name only.
- **No exploit payloads.** Attack paths are descriptive (ATT&CK-tagged narrative
  + the finding that enables each hop) — never runnable exploits, shells, or
  weaponized manifests.
- **Honest metrics.** Compliance pass-rate is always reported as
  `breached of assessed` / `passed of assessed` with the indicative-mapping
  disclaimer. Never a bare compliant/non-compliant verdict; `passRate` is `0`
  when `assessed == 0`.
- **Deterministic output.** Findings and paths sort stably; no wall-clock
  timestamps in JSON/SARIF/HTML except a single `generatedAt`.

## Supply chain

Releases are built with GoReleaser and:

- **signed** with cosign (keyless, GitHub OIDC) — signatures + certificates
  published alongside artifacts and `checksums.txt`;
- shipped with a **CycloneDX SBOM** per archive (Syft);
- accompanied by **SLSA build provenance** (SLSA L3 via the SLSA GitHub
  generator).

Verify a release artifact:

```bash
cosign verify-blob \
  --certificate kubeguard_<ver>_linux_amd64.tar.gz.pem \
  --signature  checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/kubeguard/kubeguard.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

## Webhook trust

The admission webhook serves TLS from certificates issued by cert-manager; the
CA bundle is injected into the `ValidatingWebhookConfiguration`. It is
fail-closed by default (`failurePolicy: Fail` + `--fail-open=false`).

## Threat model boundaries (non-goals)

KubeGuard reasons over declarative resource state, not live syscalls — it is not
a runtime/eBPF agent. It does not execute, prove, or weaponize the attack paths
it reports.
