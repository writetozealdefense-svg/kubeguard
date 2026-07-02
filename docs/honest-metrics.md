# Honest-metrics policy

KubeGuard never reports a bare "compliant ✓ / non-compliant ✗" verdict. This is a
deliberate, enforced policy — in the engine, the API, the dashboard, and every
export.

## The rules
1. **Always show the denominator.** Compliance is reported as
   `breached of assessed` and `passed of assessed`, never a lone percentage or a
   pass/fail badge.
2. **Assessed means actually evaluated.** A control counts as *assessed* only when
   **every** KubeGuard check it maps to actually ran against the input. Controls
   we couldn't evaluate are excluded from the denominator — not silently passed.
   Collection gaps are disclosed, never hidden.
3. **The mapping is indicative.** Every compliance figure carries the disclaimer:
   *"Indicative control mapping only — not a certification or audit."* The mapping
   is triage guidance, not an auditor's opinion.
4. **Attack paths are narrative, never exploits.** Paths are ATT&CK-tagged
   descriptions of how findings chain — they are not runnable exploit code.
5. **No silent truncation.** When a result set is capped (top-N, scenario limits),
   that truncation is disclosed.
6. **Secrets are redacted everywhere.** Evidence shows the key name/path, never a
   secret value, in the UI, API, logs, and reports.

## Where it's enforced
- Engine: `breached of assessed` math with honest denominators (compliance
  engine).
- API: `/v1/posture` carries `assessed`, `breached`, `passed`, `passRate`, and
  the disclaimer per framework.
- Dashboard: every figure renders via `passRateLabel`/`breachLabel`
  (`N of M passed`), and the disclaimer is shown on Overview, Compliance, and the
  PDF/CSV/SARIF exports.
- Metrics: `kubeguard_dashboard_compliance_pass_rate` is `passed/assessed`.

## Risk prioritization is deterministic and explainable

The risk score that ranks findings ("show me the 5 that matter, not the 200") is
a **plain published weighted sum** — no ML, no opaque model. Every point a
finding earns is recorded as a *factor* on its score, so the "why" is always
attached and the score is byte-for-byte reproducible run-to-run. The score reuses
signals the engine already computes; it invents no new data.

**Weights (single source of truth: `internal/risk/risk.go`):**

| Factor | Points | When it applies |
|---|---|---|
| severity | critical 50 / high 30 / medium 15 / low 5 / info 0 | always (base weight) |
| attack-path-enabler | +25 | the finding enables a hop in ≥1 attack path |
| internet-exposed | +20 | that path is reachable from the public internet |
| blast-radius | +30 / +20 / +10 | the path reaches ClusterAdmin / NodeAccess / SA-token or SecretRead — **strongest reached only** (not summed, so a full chain isn't triple-counted) |
| breadth | +2 per extra workload, capped +10 | the same check fires on multiple workloads |

`score = Σ factors`. Ties break by severity rank, then finding id — a stable
order. The top risks appear on the `scan` console ("Top risks … why: …"), on
`GET /v1/posture` (`topRisks`), and in the report. Because the factors *are* the
score, an engineer (or auditor) can always see exactly why a finding ranked where
it did. Consumers that render only the top N must disclose that truncation (rule
5); the full ranked list is always available in the API/report.

## Why
A security tool that overstates assurance is worse than none — it manufactures
false confidence. KubeGuard optimizes for an honest, auditable signal an engineer
can act on, and for evidence an auditor can trust because it shows its work.
