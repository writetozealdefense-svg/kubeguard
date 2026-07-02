# Findings lifecycle, ownership & waivers (K6)

KubeGuard tracks a triage state per **finding identity** — a stable key over
`cluster + check id + resource` — so state persists as scans come and go. This
turns a scanner into a posture-management workflow: triage, assign, accept risk
with an expiry, and measure MTTR, all audited.

## States

`open → acknowledged → in-progress → resolved`, plus `risk-accepted` (reached
only by approving a waiver). Analysts (and above) set the triage states and the
assignee; setting any triage state clears an existing waiver. Resolving stamps
`resolvedAt` (used for MTTR); moving off resolved clears it.

## Waivers (risk acceptance)

A waiver is an **admin-approved, time-boxed, justified** risk acceptance:

- **Justification is mandatory** and **expiry is required** and capped at the
  server's max waiver duration (**90 days by default**, configurable).
- **Who approves** is the configured approver role (**admin by default**).
  "Analyst proposes, admin approves": an analyst gets `403` on the waiver route.
- On expiry the waiver **auto-lapses**: the finding's effective state reverts to
  `open` and it **re-surfaces** as blocking. Nothing needs to run — expiry is
  computed at read time from `expiresAt`.
- An admin can revoke a waiver early (`DELETE …/waiver`), re-opening the finding.

Defaults are set via `LifecycleConfig{ WaiverApproverRole, MaxWaiverDuration }`
on the dashboard API.

## Waiver-aware enforcement

Enforcement must not re-block a finding under a valid, unexpired waiver, but must
still record that it was waived. The dashboard exposes:

- `API.WaivedKeys(tenant, cluster, now)` — the set of actively-waived finding
  keys at `now`.
- `dashboard.BlockingFindings(cluster, findings, waived)` — partitions a report's
  findings into **blocking** (unwaived) and **waived** (suppressed-but-logged).

These are the primitives the guardrails (admission webhook, `--fail-on`) consume
in K7 so a valid waiver suppresses a block while the waiver is logged, and an
expired waiver re-blocks.

## MTTR & distribution

`GET /v1/lifecycle` returns the triage lane (every current finding overlaid with
its state/owner/waiver, waiver expiry applied) plus an MTTR summary: counts by
effective state and the **mean time-to-resolve** = mean(`resolvedAt − firstSeen`)
over resolved findings that carry both timestamps. Honest: findings missing a
timestamp are excluded from the mean rather than counted as zero. `firstSeen` is
stamped when a finding is first detected (seeded on each scan), so MTTR measures
detection→resolution.

## Audit

Every state change, waiver create, waiver revoke, and every *denied* attempt
writes an append-only audit entry (`finding.triage`, `finding.waiver`,
`finding.waiver.revoke`) via the existing audit store — tenant-scoped, never
holding secret values.

## API

| Route | Role | Purpose |
|---|---|---|
| `GET /v1/lifecycle?cluster=` | viewer+ | triage lane + MTTR |
| `POST /v1/lifecycle/{key}/state` | analyst+ | set state / assignee (not risk-accepted) |
| `POST /v1/lifecycle/{key}/waiver` | admin (configurable) | accept risk with justification + expiry |
| `DELETE /v1/lifecycle/{key}/waiver` | admin (configurable) | revoke waiver, re-open |

The dashboard **Triage** view renders the lane, MTTR tiles, role-gated state
controls, and an Accept-risk dialog (mandatory justification + expiry). Both
in-memory and Postgres stores persist lifecycle rows (migration `0002`); DPDP
tenant erasure and cluster deletion cascade to lifecycle rows.
