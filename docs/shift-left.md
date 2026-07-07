# Shift-left guardrails: one policy story (K7)

The same detection engine and the same active profile enforce posture at every
stage a change moves through — pre-commit, pull request, and admission — so a
misconfiguration is caught as early as possible and, if it slips through, is
stopped at the cluster door. Every stage is **read-only, offline, and
waiver-aware**.

```
 pre-commit ──▶ CI / pull request ──▶ GitOps / admission
  (fast fail)     (SARIF + PR gate)      (webhook denies)
        \___________ same engine, same profile, same waivers ___________/
```

## 1. Pre-commit (fastest feedback)

Run the scan against the manifests you're about to commit; fail the commit on a
severity gate:

```sh
kubeguard scan -i deploy/ --fail-on high
```

Wire it as a pre-commit hook so a developer sees the finding before it ever
leaves their machine.

## 2. Pull request / CI

Two complementary surfaces on every PR:

- **SARIF → GitHub code scanning** — upload the SARIF report so findings appear
  in the repo's Security tab and inline on the diff:
  ```sh
  kubeguard scan -i deploy/ -f sarif -o kubeguard.sarif
  # then: github/codeql-action/upload-sarif@v3 with sarif_file: kubeguard.sarif
  ```
- **PR annotations (GitOps mode)** — emit GitHub Actions workflow-command
  annotations so findings show as inline error/warning/notice checks even without
  code-scanning enabled:
  ```sh
  kubeguard scan -i deploy/ -f gitops
  ```
  Severity maps to the annotation level (critical/high → `::error`, medium →
  `::warning`, low/info → `::notice`), plus a one-line summary notice.

Gate the merge with `--fail-on <severity>` (exit code 2 fails the job).

## 3. GitOps / admission

The validating admission webhook enforces the restricted profile at the cluster
door: it **admits** a hardened pod and **denies** a privileged / hostPath /
host-namespace / run-as-root / dangerous-capability pod with the offending check
ids in the message. It is strictly read-only — admit or deny, never mutate.

```sh
kubeguard webhook --cert-dir /etc/certs --waivers /etc/kubeguard/waivers.yaml
```

See `docs/webhook.md` for install (cert-manager) and fail-open/closed semantics.

## Waiver-aware everywhere

A finding under a **valid, unexpired waiver** must not re-block — but the
suppression must never be silent. KubeGuard has two waiver surfaces that share
the same model:

- **Online (dashboard / K6):** store-backed lifecycle waivers, approved by an
  admin with a justification and an expiry, tracked per finding identity, audited.
  See `docs/findings-lifecycle.md`.
- **Offline (guardrails / K7):** an operator-supplied **waiver file** so the CLI
  gate and the webhook honor a waiver with no store or network — the offline-first
  path for CI runners and air-gapped admission controllers.

The offline waiver file (`--waivers <file>`, YAML or JSON):

```yaml
waivers:
  - id: KG-001
    resource: { kind: Deployment, namespace: payments, name: checkout }  # optional; any field omitted = wildcard
    justification: "Legacy sidecar; migration tracked in JIRA-1234."       # required
    expires: "2026-12-31T00:00:00Z"                                        # required, RFC3339
```

Behaviour (identical in `--fail-on` and the webhook):

- A finding matched by an **active** waiver is excluded from the gate / admission
  denial, and the application is **logged** (CLI: a `waived: …` line on stderr;
  webhook: an admission **warning**). The finding still appears in the report —
  only the *gate* ignores it.
- An **expired** waiver stops applying: the finding **re-blocks**. Nothing needs
  to run; expiry is evaluated against `now` at each check.
- The file is validated on load (strict: unknown keys rejected; justification and
  a parseable expiry are mandatory), so a malformed waiver file fails loudly
  rather than silently suppressing everything.

This keeps enforcement honest: waivers are explicit, justified, expiring, and
always visible in the logs — never a silent allowlist.
