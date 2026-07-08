# Custom policy-as-code (K3)

KubeGuard ships 22 built-in checks; **custom policies** let you add org-specific
rules as **data** — no fork, no recompile. A policy pack is a YAML file of CEL
expressions loaded at scan time; matches become standard findings that flow
through the same report, `--fail-on` gate, SARIF/GitOps output, and dashboard
lifecycle as the built-ins.

```sh
kubeguard scan -i manifests/ --policy examples/policies/            # a dir of packs
kubeguard scan -i manifests/ --policy team-policies.yaml           # a single pack
```

## Why CEL (⟐ decision)

The expression engine is **CEL** (`google/cel-go`): pure-Go and fully **offline**
(honouring the offline-first, no-telemetry constitution), and the **same language
Kubernetes uses** for ValidatingAdmissionPolicy — so the syntax is already
familiar to platform engineers. Rego/OPA would add a heavier runtime and a second
policy language for no benefit here.

## Pack format

```yaml
apiVersion: kubeguard.io/policy/v1        # required, exact
policies:
  - id: ORG-REG-1                         # unique; becomes the finding id
    title: "Images must come from the approved registry"
    severity: high                        # critical|high|medium|low|info
    category: supply-chain                # free-form; groups the finding
    target: container                     # container | workload (default workload)
    match: '!container.image.startsWith("registry.internal/")'  # CEL, true = VIOLATION
    remediation: "Push to registry.internal/ and reference it there."
    refs:
      - { framework: "Internal", id: "SEC-SUPPLY-1", title: "Approved registries" }
```

Loading is **strict**: an unknown key, a bad `apiVersion`, an invalid severity, a
`match` that doesn't compile, or a `match` that isn't boolean all fail the scan
with a clear error — a typo can't silently disable a rule.

## Evaluation targets & variables

`match` returns **true on a violation**. It is evaluated:

- **`target: workload`** — once per workload, with `workload` in scope.
- **`target: container`** — once per container, with `container` **and**
  `workload` in scope (a finding per matching container).

Variables are resolved to Kubernetes defaults so expressions read naturally:

| `workload.*` | | `container.*` | |
|---|---|---|---|
| `kind`, `name`, `namespace` | strings | `name`, `image`, `role` | strings |
| `serviceAccountName` | string | `privileged` | bool |
| `hostNetwork`, `hostPID`, `hostIPC` | bool | `runAsUser` | int (`-1` if unset) |
| `automountServiceAccountToken` | bool | `runAsNonRoot`, `readOnlyRootFilesystem` | bool |
| `labels` | map | `allowPrivilegeEscalation` | bool (default `true`) |
| `containers` | list of container objects | `capsAdd`, `capsDrop`, `envSecretKeys` | list |
| | | `seccompProfile` | string |
| | | `hasLimits` | bool |

## Examples

Three worked policies ship in [`examples/policies/example-policies.yaml`](../examples/policies/example-policies.yaml):
approved-registry (container), team-ownership-label (workload), and no-root
(container). All three fire on the vulnerable fixture:

```sh
kubeguard scan -i test/fixtures/vulnerable.yaml --policy examples/policies/
```

## CEL tips

- Booleans: `workload.hostNetwork`, `container.privileged`.
- Strings: `container.image.startsWith("…")`, `.endsWith`, `.contains`, `.matches("regex")`.
- Lists: `"NET_RAW" in container.capsAdd`, `!("ALL" in container.capsDrop)`,
  `container.capsAdd.exists(c, c.startsWith("SYS_"))`, `size(container.envSecretKeys) > 0`.
- Maps: `"team" in workload.labels`, `workload.labels["env"] == "prod"`.
- A `match` that references a field absent on a given resource simply doesn't
  match there (it never aborts the scan).

## Where custom findings show up

Custom findings sort and render exactly like built-ins: console, JSON, SARIF,
`-f gitops` PR annotations, the dashboard, and the `--fail-on` gate (and they can
be waived like any finding). They do **not** affect compliance framework
denominators — those map only to the built-in check ids — so custom policies
extend detection without distorting the honest-metrics posture.
