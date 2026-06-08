# KubeGuard API & schema (`pkg/api`)

`pkg/api` is the **stable, public schema** KubeGuard emits and that the USP
control plane ingests (ARCHITECTURE.md §4.2, §12.4). It imports nothing from
`internal/*`. Changes are **additive within a major version**.

## REST endpoints (`kubeguard serve`)

| Method · Path | Returns | Notes |
|---|---|---|
| `GET /v1/scan` | `Report` (JSON) | triggers a fresh scan and returns it |
| `GET /v1/findings` | `[]Finding` | findings from the latest scan |
| `GET /v1/posture` | `{ posture: PostureSummary, compliance: []FrameworkResult }` | latest posture |
| `GET /v1/report` | `Report` | the full latest report |
| `GET /` | HTML | self-contained dashboard |
| `GET /metrics` | Prometheus text | see gauges below |
| `GET /healthz` | `ok` | liveness |
| `GET /readyz` | `ready` / 503 | ready once the first scan completes |

Endpoints that read the latest scan return **503** until the first scan
completes. Recurring scans are driven by `--schedule` (cron).

### Prometheus metrics

| Metric | Type | Labels |
|---|---|---|
| `kubeguard_compliance_pass_rate` | gauge | `framework` — passed of assessed (0–1) |
| `kubeguard_findings_total` | gauge | `severity` |
| `kubeguard_attack_paths_total` | gauge | — |

## Core types

### `Report`
```jsonc
{
  "generatedAt": "RFC3339",   // the ONLY timestamp in the document
  "source": "string",          // input path or "live cluster"
  "profile": "zeal-default|cis",
  "findings":   [Finding],
  "paths":      [AttackPath],
  "posture":    PostureSummary,
  "compliance": [FrameworkResult]
}
```

### `Finding`
```jsonc
{
  "id": "KG-001", "title": "string",
  "severity": "critical|high|medium|low|info",
  "category": "workload-hardening|host-access|rbac|network|exposure|supply-chain",
  "resource": { "kind": "...", "namespace": "...", "name": "..." },
  "evidence": [ { "path": "spec...", "value": "redacted-as-needed" } ],
  "remediation": { "summary": "...", "snippet": "yaml fix" },
  "grants": ["Capability", ...],   // attacker primitives this finding hands over
  "refs":   [ { "framework": "CIS|NSA|ATT&CK", "id": "...", "title": "..." } ]
}
```

### `AttackPath` / `PathHop`
```jsonc
{
  "id": "AP-001", "title": "Cluster-admin takeover via checkout",
  "severity": "critical",
  "entry": { "kind": "Deployment", "namespace": "...", "name": "..." },
  "hops": [
    { "order": 1, "from": "InternetIngress", "to": "NetworkReachable",
      "enabledBy": "KG-018", "technique": ["T1190"], "narrative": "..." }
  ],
  "summary": "Entry .... Chain: ... . Techniques: ... ."
}
```
`Capability` primitives and the chaining rules are in ARCHITECTURE.md §8.
Paths are **descriptive narrative only** — never runnable exploits.

### `FrameworkResult` / `PostureSummary`
```jsonc
// FrameworkResult — always carries its assessed denominator + disclaimer.
{
  "framework": "PCI DSS v4.0", "version": "4.0",
  "assessed": 5, "breached": 5, "passed": 0, "passRate": 0.0,
  "breaches": [ { "controlId": "6.4.1", "title": "...", "findings": ["KG-018"] } ],
  "disclaimer": "Indicative mapping ... not a certification or audit."
}

// PostureSummary
{
  "totalFindings": 19,
  "bySeverity": { "critical": 4, "high": 7, "medium": 4, "low": 4 },
  "criticalPaths": 1,
  "controlsAssessed": 32, "controlsBreached": 31,
  "overallPassRate": 0.0313
}
```

## Honest-metrics contract

Every compliance number is reported as `breached of assessed` / `passed of
assessed` with the pack's `disclaimer`. KubeGuard never emits a bare
`compliant`/`non-compliant` verdict, and `passRate` is `0` when `assessed == 0`.
