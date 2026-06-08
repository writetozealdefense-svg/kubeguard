# KubeGuard — Architecture

> **Status:** Signed off — v1.0 (2026-06-08). This document is the single source of truth for the
> KubeGuard build. Every squad implements *strictly* to the section(s) cited in its goal.
> Where the mission brief and this document disagree, this document wins. All engine squads
> (A–K) and dashboard/production squads (D1–D6, P1–P7) have shipped against it; subsequent
> changes are tracked via version control and follow the change-control process in §18.

---

## 1. Mission & scope

KubeGuard is a production Kubernetes **attack-surface, posture & compliance** tool written in
Go. Its job is a three-stage pipeline:

```
detect  →  chain  →  harden
```

- **detect** — run a fixed set of built-in checks (§7) over a Kubernetes resource set and emit
  deterministic, evidence-backed findings.
- **chain** — compose findings into capability-based attack paths (§8), tagged with MITRE
  ATT&CK techniques, surfacing the shortest path to high-value outcomes (node breakout,
  cluster-admin, lateral movement).
- **harden** — emit a least-privilege baseline bundle and per-finding fix snippets (§11) that,
  when applied, drive findings and paths to zero.

KubeGuard ships **today** as a standalone tool in five deployment modes (§2) and is designed to
become a **Kubernetes module of the USP control plane tomorrow** via a stable, documented
`pkg/api` schema (§12.4).

### 1.1 Non-goals

- It is **not** a runtime/eBPF agent. It reasons over declarative resource state, not live
  syscalls.
- It does **not** execute, prove, or weaponize attack paths. Paths are *descriptive*
  (ATT&CK-tagged narrative + the enabling finding per hop), never runnable exploits (§3).
- It does **not** mutate clusters. Live and webhook modes are strictly read-only (§3, §5.2,
  §14).

---

## 2. Deployment modes

| Mode | Entry | Description | Squad |
|---|---|---|---|
| **CLI** | `kubeguard scan -i <path>` | Offline scan of files/dirs/snapshots → console/json/sarif/html | C, F |
| **CI** | `kubeguard scan --fail-on <sev>` | Same engine, non-zero exit on gate breach for pipelines | F |
| **kubectl plugin** | `kubectl kubeguard scan` | Thin wrapper over live mode | H |
| **Live** | `kubeguard scan --live` | Read-only ingest from a cluster via client-go | H |
| **Service** | `kubeguard serve` | Scheduler + REST + dashboard + metrics + history | I |
| **Webhook** | `kubeguard webhook` | Validating admission webhook enforcing the active profile | J |

All modes share one engine. Modes never fork detection logic.

---

## 3. Design principles & guardrails (non-negotiable)

1. **Read-only against clusters.** Live and webhook modes never create/patch/delete cluster
   resources. The *only* writes KubeGuard performs are (a) appending to its own history store
   and (b) setting status on its own CRD (service mode). No exceptions.
2. **Offline-first core.** The detection, chaining, and compliance engines run with zero network
   access. Tests run offline (no network, no live cluster).
3. **No telemetry / no phone-home.** Ever. No usage beacons, no remote config fetches.
4. **Deterministic output.** Findings sort stably by **severity desc → category asc → id asc**.
   Attack paths sort by **severity desc → hop-count asc → id asc**. No wall-clock timestamps in
   JSON/SARIF/HTML payloads *except* a single explicit `generatedAt` field at the document root.
5. **No exploit payloads.** Attack paths describe *what a finding enables*, ATT&CK-tagged. We
   never emit runnable commands, shells, or weaponized manifests.
6. **Secret redaction.** Never log or emit secret *values*. Secret-in-env evidence is redacted to
   the **key name only** (e.g. `env: AWS_SECRET_ACCESS_KEY [redacted]`).
7. **Honest metrics.** Compliance pass-rate is *always* emitted with its assessed denominator
   (`breached of assessed`, `passed of assessed`) and the indicative-mapping disclaimer (§9.4).
   Never output a bare `compliant` / `non-compliant` verdict.
8. **No panics in library code.** Errors wrap context with `fmt.Errorf("...: %w", err)`. Panics
   are reserved for genuinely unreachable invariants. The CLI maps errors to non-zero exit codes
   (§17.3).
9. **Cross-platform, no cgo.** Builds for `linux/amd64`, `linux/arm64`, `windows/amd64`,
   `darwin/arm64`. SQLite via `modernc.org/sqlite` (pure Go), never cgo.

---

## 4. Data model (`pkg/api` + `internal/model`)

Public, USP-facing types live in **`pkg/api`** and are version-stable (§12.4). Internal working
types (graph nodes, normalized pod views) live in **`internal/model`**. The rule: anything an
external consumer (USP, JSON/SARIF readers, the dashboard contract) depends on is in `pkg/api`;
everything else is `internal/`.

### 4.1 Core resource types (`internal/model`)

```go
// Resource is the minimal envelope for any loaded Kubernetes object.
type Resource struct {
    APIVersion string
    Kind       string
    Namespace  string            // "" for cluster-scoped
    Name       string
    UID        string            // synthesized if absent: "<ns>/<kind>/<name>"
    Labels     map[string]string
    Annotations map[string]string
    Raw        map[string]any    // decoded YAML/JSON, for evidence extraction
}

// Workload is the normalized view across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob.
type Workload struct {
    Resource
    Replicas           int
    ServiceAccountName string          // resolved; "default" if unset
    PodSpec            PodSpecView      // normalized
}

// PodSpecView flattens the security-relevant surface of a pod template.
type PodSpecView struct {
    HostNetwork  bool
    HostPID      bool
    HostIPC      bool
    Volumes      []VolumeView         // incl. hostPath
    Containers   []ContainerView      // init + regular + ephemeral merged, role-tagged
    AutomountSAToken *bool            // nil = cluster default (true)
    PodSecurityContext SecurityContextView
}

type ContainerView struct {
    Name            string
    Image           string
    Role            string            // "init" | "container" | "ephemeral"
    Privileged      bool
    AllowPrivEsc    *bool
    RunAsUser       *int64
    RunAsNonRoot    *bool
    ReadOnlyRootFS  *bool
    CapsAdd         []string
    CapsDrop        []string
    SeccompProfile  string            // "", "RuntimeDefault", "Unconfined", "Localhost"
    EnvSecretKeys   []string          // names only; values never captured
    Limits          ResourceLimitsView
}
```

`VolumeView` flags `HostPath` and its `Path` (so `/var/run/docker.sock` is detectable).
RBAC types: `ServiceAccount`, `Role`, `ClusterRole` (`Rules []PolicyRule`), `RoleBinding`,
`ClusterRoleBinding`. `Service` carries `Type`, `Selector`, `Ports`. `NetworkPolicy` carries
`PodSelector`, `PolicyTypes`, ingress/egress rule presence.

### 4.2 Output types (`pkg/api`)

```go
type Severity string // "critical" | "high" | "medium" | "low" | "info"

type Finding struct {
    ID          string       `json:"id"`          // check id, e.g. "KG-001"
    Title       string       `json:"title"`
    Severity    Severity     `json:"severity"`
    Category    string       `json:"category"`    // §7.1 categories
    Resource    ResourceRef  `json:"resource"`
    Evidence    []Evidence   `json:"evidence"`    // field path + redacted value
    Remediation Remediation  `json:"remediation"` // text + snippet ref
    Grants      []Capability `json:"grants"`      // primitives this finding hands an attacker
    Refs        []ControlRef `json:"refs"`        // CIS/NSA/ATT&CK identifiers
}

type AttackPath struct {
    ID        string      `json:"id"`
    Title     string      `json:"title"`
    Severity  Severity    `json:"severity"`
    Hops      []PathHop   `json:"hops"`           // ordered
    Summary   string      `json:"summary"`        // narrative, no payloads
}

type PathHop struct {
    Order     int          `json:"order"`
    From      Capability   `json:"from"`          // capability held before the hop
    To        Capability   `json:"to"`            // capability gained
    EnabledBy string       `json:"enabledBy"`     // finding ID that enables this hop
    Technique []string     `json:"technique"`     // ATT&CK IDs, e.g. ["T1611"]
    Narrative string       `json:"narrative"`
}

type Report struct {
    GeneratedAt string         `json:"generatedAt"` // RFC3339; the ONLY timestamp
    Source      string         `json:"source"`
    Profile     string         `json:"profile"`
    Findings    []Finding      `json:"findings"`
    Paths       []AttackPath   `json:"paths"`
    Posture     PostureSummary `json:"posture"`     // §9
    Compliance  []FrameworkResult `json:"compliance"`
}
```

`Capability` is the primitive enum (§8.1). `ControlRef` is `{framework, id, title}`.

---

## 5. Loader (`internal/loader`)

### 5.1 Offline sources (Squad B)

The loader accepts a path (`-i`) and ingests, in priority order:

- a **directory** (recursively, `*.yaml`/`*.yml`/`*.json`),
- a **multi-document YAML** file (`---` separated),
- a `kind: List` object (unwrapped into its `items`),
- a **snapshot JSON** (an array of resources, or `{"items":[...]}`) — the format live/service
  mode persists.

Decoding uses `sigs.k8s.io/yaml`. Unknown kinds are loaded as generic `Resource` (kept for
namespace/NetworkPolicy accounting) but not normalized into workloads. Decode errors are wrapped
with the file + document index and are fatal to that document only (partial loads are reported,
not silently dropped).

### 5.2 Live source (Squad H)

`internal/loader/live` uses `k8s.io/client-go` with a **read-only** client (list/get/watch only).
It enumerates the same kinds the offline loader normalizes, converts them to `Resource`, and
hands off to the identical graph builder. The read-only RBAC `ClusterRole` ships in `deploy/`.
A `fake.NewSimpleClientset` path is used for unit tests — no real cluster in CI.

---

## 6. Resource graph (`internal/graph`)

The graph is a typed inventory plus resolved relationships, built once and queried by every
engine.

- **Normalization:** Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob all collapse to a
  `Workload` with a single `PodSpecView`. (CronJob → jobTemplate → podTemplate; others →
  template.spec.)
- **Resolutions:**
  - `Pod/Workload → ServiceAccount` (by `serviceAccountName`, defaulting to `default`).
  - `ServiceAccount → []Role/ClusterRole` via `RoleBinding`/`ClusterRoleBinding` subjects
    (matching `kind: ServiceAccount` + name + namespace).
  - `Service → []Workload` via label-selector match.
  - `Namespace → []NetworkPolicy` (presence + whether a default-deny exists).

Graph queries are pure functions over the built graph; no engine mutates it.

---

## 7. Detection engine & checks (`internal/checks`)

### 7.1 Categories

`workload-hardening`, `host-access`, `rbac`, `network`, `exposure`, `supply-chain`.

### 7.2 Registry & profiles

Each check implements:

```go
type Check interface {
    Meta() CheckMeta // id, title, severity, category, refs, grants
    Run(g *graph.Graph) []api.Finding
}
```

Checks self-register into a registry. **Profiles** select/override the active set:

- **`cis`** — checks mapped to CIS Kubernetes Benchmark controls, CIS-aligned severities.
- **`zeal-default`** — KubeGuard's opinionated default: all 20 checks, attack-path-aware
  severities (this is the default profile).

A profile is data (`{include:[], exclude:[], severityOverrides:{}}`), not code.

### 7.3 The 20 built-in checks

Each finding carries **severity, evidence, remediation, grants (§8.1 primitives), and refs**
(CIS section and/or NSA/CISA Kubernetes Hardening Guide, plus ATT&CK where a check directly
enables a technique). Severities below are `zeal-default`.

| ID | Title | Sev | Category | Grants (primitive) | Refs (indicative) |
|---|---|---|---|---|---|
| KG-001 | Privileged container | critical | host-access | `ContainerEscape`, `NodeAccess` | CIS 5.2.1; NSA "Pod Security"; ATT&CK T1611 |
| KG-002 | Sensitive hostPath mount (e.g. docker.sock, `/`, `/var/run`) | critical | host-access | `HostFilesystemAccess`, `ContainerEscape` | CIS 5.2.x; NSA; T1611 |
| KG-003 | hostNetwork enabled | high | host-access | `HostNetworkAccess` | CIS 5.2.4; NSA |
| KG-004 | hostPID enabled | high | host-access | `HostProcessAccess` | CIS 5.2.3; NSA |
| KG-005 | hostIPC enabled | medium | host-access | `HostIPCAccess` | CIS 5.2.3; NSA |
| KG-006 | Container runs as root | medium | workload-hardening | `RootInContainer` | CIS 5.2.6; NSA |
| KG-007 | allowPrivilegeEscalation not disabled | medium | workload-hardening | `PrivEscWithinContainer` | CIS 5.2.5; NSA |
| KG-008 | Dangerous added capabilities (SYS_ADMIN, NET_ADMIN, …) | high | workload-hardening | `ContainerEscape` (SYS_ADMIN) / `HostNetworkAccess` (NET_ADMIN) | CIS 5.2.8/5.2.9; NSA; T1611 |
| KG-009 | Root filesystem not read-only | low | workload-hardening | — | CIS 5.2.x; NSA |
| KG-010 | No CPU/memory limits | low | workload-hardening | `ResourceExhaustion` | CIS 5.x; NSA |
| KG-011 | Binding grants cluster-admin (or `*` cluster role) to a SA/group | critical | rbac | `ClusterAdmin` | CIS 5.1.1; NSA "RBAC"; T1078 |
| KG-012 | Wildcard RBAC rule (verbs/resources/apiGroups `*`) | high | rbac | `BroadAPIAccess` | CIS 5.1.3; NSA |
| KG-013 | RBAC allows reading Secrets (get/list/watch secrets) | high | rbac | `SecretRead` | CIS 5.1.2; NSA; T1552 |
| KG-014 | RBAC allows pod create / exec / attach | high | rbac | `PodCreate` (→ SA escalation, node scheduling) | CIS 5.1.x; NSA; T1610 |
| KG-015 | ServiceAccount token auto-mounted | medium | rbac | `ServiceAccountToken` | CIS 5.1.5/5.1.6; NSA |
| KG-016 | Workload uses the `default` ServiceAccount | low | rbac | — | CIS 5.1.5; NSA |
| KG-017 | Namespace has no NetworkPolicy (no default-deny) | medium | network | `LateralMovement` | CIS 5.3.2; NSA "Network Separation" |
| KG-018 | Service exposed via LoadBalancer/NodePort | medium (NodePort) / high (LoadBalancer fronting a vulnerable workload) | exposure | `InternetIngress` | NSA; ATT&CK T1190 |
| KG-019 | Image uses mutable tag (`:latest` / no digest) | low | supply-chain | — | CIS 5.x; NSA |
| KG-020 | Seccomp profile not RuntimeDefault | low | workload-hardening | — | CIS 5.2.x; NSA; PSA "restricted" |

> Severity of KG-018 is computed: `high` when the selected workload also carries a host-access or
> RBAC-escalation finding (i.e. the LB fronts a dangerous pod), else `medium`. This is what lifts
> the vulnerable fixture's exposure into the CRITICAL chain without inflating benign LBs.

Every check id has a **positive and a negative** test case (Squad C acceptance).

---

## 8. Attack-path engine (`internal/attack`)

### 8.1 Capability (primitive) model

Attacks are modeled as transitions between capabilities an attacker holds. Primitives:

```
InternetIngress         reachable from outside the cluster
NetworkReachable        reachable from another in-cluster workload
ContainerEscape         can break out of the container
NodeAccess              code execution on the node / kubelet identity
HostFilesystemAccess    read/write host paths
HostNetworkAccess       host network namespace
HostProcessAccess       host PID namespace
ServiceAccountToken     holds a mountable SA token
SecretRead              can read Secrets
PodCreate               can create/exec pods
BroadAPIAccess          wildcard API verbs/resources
ClusterAdmin            full control of the cluster
LateralMovement         can reach other workloads unrestricted
ResourceExhaustion      can starve node resources
```

### 8.2 Chaining

Each check declares the primitives it `grants` (§7.3). The engine builds an edge whenever a
finding's grant satisfies the *precondition* of a transition rule, threading the resource graph
(e.g. a privileged pod's escape only chains to that pod's *resolved SA token* → its *resolved
RBAC*). Rules (illustrative, full table in `internal/attack/rules.go`):

| From | Finding enables | To | ATT&CK |
|---|---|---|---|
| `InternetIngress` | KG-018 (LB→vulnerable workload) | reach workload | T1190 |
| reach workload | KG-001 / KG-002 / KG-008(SYS_ADMIN) | `ContainerEscape`→`NodeAccess` | T1611 |
| `NodeAccess` + KG-015 | SA token harvestable | `ServiceAccountToken` | T1552.001 |
| `ServiceAccountToken` + KG-013 | read secrets | `SecretRead` | T1552 |
| `ServiceAccountToken` + KG-014 | create pods | `PodCreate` | T1610 |
| `ServiceAccountToken` + KG-011 | bound to cluster-admin | `ClusterAdmin` | T1078 |
| any in-cluster foothold + KG-017 | no NetworkPolicy | `LateralMovement` | T1021 |

Path **severity** = the max severity primitive reached (`ClusterAdmin`/`NodeAccess` ⇒ critical).

### 8.3 `--assume-breach`

Seeds the engine with `NetworkReachable` on every workload (skips the InternetIngress
precondition), modeling an attacker who already has a foothold in the cluster. Paths are
recomputed from that seed.

### 8.4 Expected oracle results (golden, §16.1)

- **vulnerable** → one CRITICAL chain:
  `Internet → (KG-018) checkout-lb → checkout pod → (KG-001+KG-002) escape→node → (KG-015)
  SA token → (KG-011/KG-013/KG-014) cluster-admin + secrets + pod-create → (KG-017) lateral`,
  ordered primitives `InternetIngress→ContainerEscape→NodeAccess→ServiceAccountToken→ClusterAdmin→LateralMovement`,
  techniques `T1190, T1611, T1552.001, T1078, T1021`.
- **partially-hardened** → a CRITICAL *host-access* chain (still privileged) but **no
  cluster-admin** path (RBAC fixed).
- **hardened** → **zero** paths.

---

## 9. Compliance engine (`internal/compliance`)

### 9.1 Framework packs (data-driven, `frameworks/*.yaml`)

Adding/removing a framework requires **no code change** — only a YAML pack. Shipped packs: **CIS
Kubernetes Benchmark, NIST 800-53, PCI DSS v4.0, ISO 27001:2022, DPDP 2023, NCA ECC-1**. Pack
schema:

```yaml
id: pci-dss-v4
title: "PCI DSS v4.0"
version: "4.0"
disclaimer: "Indicative mapping only; not a certification or audit."
controls:
  - id: "6.4.1"
    title: "Public-facing web apps protected against attacks"
    mapsTo: ["KG-018", "KG-001"]   # KubeGuard check IDs
    assessable: true               # false ⇒ excluded from denominator
```

A pack loader **rejects malformed packs** (missing id/controls, unknown schema keys, control with
empty `mapsTo` while `assessable:true`) with a wrapped error (Squad E acceptance).

### 9.2 Posture math (honest denominators)

For each framework:

```
assessed  = controls where assessable==true AND every mapped check ran
breached  = assessed controls with ≥1 mapped finding present
passed    = assessed - breached
passRate  = passed / assessed          (0 if assessed==0)
```

Controls mapping to checks that didn't run (e.g. profile-excluded) are **not assessed** and never
inflate or deflate the rate.

### 9.3 Output

```go
type FrameworkResult struct {
    Framework  string   `json:"framework"`
    Assessed   int      `json:"assessed"`
    Breached   int      `json:"breached"`
    Passed     int      `json:"passed"`
    PassRate   float64  `json:"passRate"`
    Breaches   []ControlBreach `json:"breaches"` // control id + offending finding ids
    Disclaimer string   `json:"disclaimer"`
}
```

### 9.4 Disclaimer

Every framework result and every rendered pass-rate carries the pack's `disclaimer` and is phrased
as `breached of assessed` / `passed of assessed`. KubeGuard never prints a bare
`compliant`/`non-compliant`. Expected oracle: vulnerable shows breached controls per framework;
hardened shows `assessed == passed` (100% of assessed).

---

## 10. Reporters & history

### 10.1 Reporters (`internal/report`, Squad F)

- **console** — TTY colour (auto-off when not a TTY / `NO_COLOR`), grouped by severity.
- **json** — the `api.Report` (§4.2), stable key order, single `generatedAt`.
- **sarif** — `github.com/owenrumney/go-sarif`; validates against the SARIF 2.1.0 schema
  (Squad F acceptance). One rule per check id; findings → results with `level` mapped from
  severity.
- **html** — a single self-contained file (inlined CSS/JS, SVG charts, no external fetch) with
  tabs **Overview / Compliance / Attack-Paths / Findings**, SVG trend charts from history, and
  clickable path nodes.

### 10.2 History store (`internal/history`, Squad F)

Drift tracking with two backends behind one interface:

- **file** — append-only JSONL of `{generatedAt, source, profile, counts, passRates}`.
- **sqlite** — `modernc.org/sqlite` (pure Go), schema `scans(id, generated_at, source, profile)`
  + `metrics(scan_id, key, value)`.

`--watch` re-scans on change; `--fail-on <sev>` sets the gate. Running the three fixtures into one
history must show control-pass trending up (Squad F acceptance).

---

## 11. Remediation / hardening (`internal/harden`, Squad G)

`kubeguard harden -o <dir>` emits a **baseline bundle**:

- Pod Security Admission labels (`restricted`),
- default-deny + DNS-allow `NetworkPolicy`,
- least-privilege RBAC (scoped Role + RoleBinding, no wildcards, no cluster-admin),
- Kyverno + Gatekeeper policy equivalents,
- a hardened `Deployment` template,
- a `CHECKLIST.md`.

Acceptance: emitted manifests are valid YAML and pass **`kubeconform`**; feeding the hardened
template back through the engine yields **0 findings**. Additionally, every finding carries a
**per-finding fix snippet** rendered into JSON/HTML.

---

## 12. Service mode & USP integration (Squad I)

### 12.1 `kubeguard serve`
- **scheduler** — cron-driven scans (robfig/cron),
- **REST** — `GET /v1/scan` (trigger), `GET /v1/findings`, `GET /v1/posture`,
- **dashboard** — serves the HTML report,
- **history** — SQLite,
- **observability** — `/metrics` (Prometheus), `/healthz`, `/readyz`.

### 12.2 Metrics
A Prometheus gauge `kubeguard_compliance_pass_rate{framework=...}` and
`kubeguard_findings_total{severity=...}`.

### 12.3 Acceptance
Integration test boots the server, triggers a scan over a fixture, asserts `/v1/posture` JSON and
the pass-rate gauge.

### 12.4 `pkg/api` stability (the USP contract)
`pkg/api` holds the versioned schema USP ingests: `Report`, `Finding`, `AttackPath`,
`FrameworkResult`, `Capability`, `Severity`. Changes are additive within a major version; the
schema is documented in `docs/api.md`. This is the only package external consumers import.

---

## 13. Directory layout (authoritative)

```
kubeguard/
├── ARCHITECTURE.md
├── README.md
├── go.mod  go.sum
├── .golangci.yml
├── .goreleaser.yaml
├── .github/workflows/ci.yml
├── cmd/
│   └── kubeguard/main.go            # cobra root only
├── pkg/
│   └── api/                         # PUBLIC, stable USP-facing types
│       ├── types.go
│       └── doc.go
├── internal/
│   ├── cli/                         # cobra commands: root, version, scan, harden, serve, webhook
│   ├── model/                       # core + normalized types (§4.1)
│   ├── loader/
│   │   ├── offline/                 # dir, multi-doc, List, snapshot
│   │   └── live/                    # client-go, read-only (Squad H)
│   ├── graph/                       # typed inventory + resolutions (§6)
│   ├── checks/                      # the 20 checks + registry + profiles (§7)
│   ├── attack/                      # capability model + chaining (§8)
│   ├── compliance/                  # pack loader + posture math (§9)
│   ├── report/                      # console/json/sarif/html (§10.1)
│   ├── history/                     # file + sqlite (§10.2)
│   ├── harden/                      # baseline bundle + snippets (§11)
│   ├── server/                      # serve: scheduler/REST/metrics (§12)
│   └── webhook/                     # validating admission webhook (§14)
├── frameworks/                      # *.yaml compliance packs (§9.1)
├── deploy/                          # read-only RBAC, webhook+cert-manager, helm refs
├── charts/kubeguard/                # Helm chart (Squad K)
├── docs/                            # api.md, quickstart, security-model, USP-integration, PROGRESS.md
└── test/
    └── fixtures/                    # vulnerable/partially-hardened/hardened.yaml + golden/
```

**Rule:** public types only in `pkg/api`; everything else under `internal/`. `cmd/` is a thin
entrypoint; command logic lives in `internal/cli`.

---

## 14. Admission webhook (`internal/webhook`, Squad J)

A `controller-runtime` **validating** webhook that denies pods violating the active profile (e.g.
privileged, hostPath, runs-as-root under `restricted`). TLS via cert-manager. `fail-open` /
`fail-closed` is configurable (default fail-closed for the restricted profile). Strictly
read-only: it admits/denies, never mutates. Acceptance via **envtest or fake**: admit a hardened
pod, deny a privileged one with a clear reason. Webhook + RBAC manifests in `deploy/`.

---

## 15. Packaging & release (Squad K)

- **Helm chart** `charts/kubeguard` — `helm lint` clean.
- **goreleaser** — cross-compile matrix (§3.9), **cosign** signing, **CycloneDX SBOM**, **SLSA
  provenance**. Release dry-run produces signed artifacts + SBOM.
- **docs** cover all five deployment modes and the honest-metrics policy.

---

## 16. Testing, fixtures & determinism

### 16.1 Golden fixtures (created in Squad A, used by all later squads)

`test/fixtures/{vulnerable,partially-hardened,hardened}.yaml` — the **payments/checkout** app in
three states. Expected oracle results asserted in tests:

| Fixture | Findings | Paths | Posture |
|---|---|---|---|
| **vulnerable** | ~17, ≥1 CRITICAL | 1 CRITICAL: Internet→LB→privileged pod (docker.sock node breakout)→SA token→RBAC (secrets + pod-create / cluster-admin)→no-NetworkPolicy lateral | low control-pass |
| **partially-hardened** | ~8 | CRITICAL host-access path (still privileged); **no cluster-admin path** | mid |
| **hardened** | 0 | 0 | 100% of assessed |

The vulnerable fixture must contain at minimum: `checkout` Deployment (privileged container,
hostPath `/var/run/docker.sock`, automount token, `:latest` image, no limits, runs as root),
`checkout-sa` ServiceAccount, a ClusterRoleBinding of `checkout-sa` to `cluster-admin` (and/or a
ClusterRole granting `secrets` get/list + `pods` create), a `checkout-lb` Service
(`type: LoadBalancer`, selecting the checkout pods), and **no** NetworkPolicy in the namespace.

### 16.2 Test conventions
Table-driven, golden-file based, **offline** (no network, no live cluster). `go test ./...` must
pass before a squad is "done". Target **≥80% coverage on engine packages** (`checks`, `attack`,
`compliance`, `graph`, `loader`).

### 16.3 Determinism
Golden JSON/SARIF are byte-stable given a fixture: stable sort (§3.4), no map-iteration order
leakage (sort keys before emit), single `generatedAt` injected by the caller (tests pass a fixed
value).

---

## 17. CLI, exit codes & flags

### 17.1 Commands
`kubeguard version | scan | harden | serve | webhook` (+ `kubectl-kubeguard` plugin shim, Squad H).

### 17.2 Key flags (`scan`)
`-i/--input <path>`, `-f/--format console|json|sarif|html`, `-o/--output <file>`,
`-p/--profile cis|zeal-default`, `--assume-breach`, `--fail-on critical|high|medium|low`,
`--live`, `--watch`, `--history <file|sqlite path>`.

### 17.3 Exit codes
`0` ok / gate not breached · `1` runtime error · `2` `--fail-on` threshold breached. (`--fail-on
high` ⇒ exit 2 on vulnerable, 0 on hardened — Squad F acceptance.)

---

## 18. Build order & per-squad acceptance (gates)

Build strictly in order; do not start a squad until the prior squad's acceptance passes. Each
squad: implement → `go build ./... && go vet ./... && golangci-lint run && go test ./...` → run
the squad's acceptance check against the fixtures → commit → advance. Keep `docs/PROGRESS.md`
updated per squad (shipped / deferred).

| Squad | Deliverable | Acceptance gate |
|---|---|---|
| **A** Scaffold | layout §13, cobra+version, slog, lint cfg, CI matrix, 3 fixtures | build/vet/lint clean; `kubeguard version` prints; CI green |
| **B** Loader+Graph | §4–§6 | all 3 fixtures load; checkout-sa→cluster-admin+secrets/pods resolved; checkout-lb→checkout mapped |
| **C** Detection | §7 (20 checks), registry, profiles, `scan -f console\|json` | vulnerable → golden finding set; deterministic; ±/− test per check |
| **D** Attack paths | §8, `--assume-breach` | vulnerable → documented CRITICAL chain w/ ordered primitives + ATT&CK; partial → host-access only; hardened → none (golden) |
| **E** Compliance | §9, 6 packs | per-framework breached-of-assessed; hardened 100%; malformed-pack rejected; new pack = no code |
| **F** Reporters+history | §10, `--fail-on`,`--watch` | SARIF schema-valid; HTML offline renders chain+breach; trend up across fixtures; fail-on exits 2/0 |
| **G** Harden | §11 | manifests valid + `kubeconform`; hardened template → 0 findings; per-finding fix in JSON/HTML |
| **H** Live+plugin | §5.2, `--live`, kubectl plugin | read-only RBAC in deploy/; live unit-tested w/ fake clientset; documented usage |
| **I** Service→USP | §12 | server boots, scans fixture, `/v1/posture` + pass-rate gauge asserted; `pkg/api` documented |
| **J** Webhook | §14 | envtest/fake admits hardened, denies privileged w/ reason; manifests in deploy/ |
| **K** Packaging+docs | §15 | helm lint clean; release dry-run → signed artifacts + SBOM; docs cover 5 modes + honest metrics |

### Definition of done (whole project)
`go test ./...` green; lint/vet clean; the three fixtures produce the documented findings, chains,
and posture; CLI/CI/HTML/SARIF/service/webhook functional; signed release with SBOM; `pkg/api`
stable and documented for USP; every compliance number carries its denominator and disclaimer;
live/webhook modes never mutate the cluster.
