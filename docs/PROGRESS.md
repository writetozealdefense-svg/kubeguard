# KubeGuard build progress

Tracked squad-by-squad per ARCHITECTURE.md §18. A squad is "done" only when
`go build ./... && go vet ./... && golangci-lint run && go test ./...` are all
clean and the squad's acceptance gate passes against the fixtures.

## KSPM extension — Phase 0 baseline verification (2026-07-02, branch `road-to-100`)

First compile + gate run on a real Go 1.26 toolchain (the original authoring env
had none). Results:

- **Toolchain:** go1.26.4, node v24.14.1, docker 29.0.1 — all present.
- **`go build ./...`** clean. **`go vet ./...`** clean.
- **`golangci-lint run`** — surfaced 2 revive issues in `internal/report/asff.go`
  (from the prior aws+mea commit): `BuildASFF` returned an unexported type, and
  `asffTruncate` shadowed the builtin `max`. Fixed (exported `ASFFFinding`,
  renamed param to `maxLen`); lint now **0 issues**.
- **`go test ./... -cover`** — all packages pass. Engine packages meet the ≥80%
  floor: analyzer 90.9, attack 87.1, checks 88.4, compliance 96.1, graph 96.8,
  harden 85.3, history 80.0, loader/live 90.7, loader/offline 88.2, report 83.4,
  server 90.4, webhook 82.1, dashboard 83.8. (`-race` unavailable on this host —
  no cgo/gcc; CI runs it on Linux. cli 46.2 and pg 0.0 are command-glue / skipped
  without a DSN, not engine packages.)
- **Golden acceptance:** `scan vulnerable.yaml` → 19 findings (4 critical) + 1
  CRITICAL cluster-admin chain (matches the oracle). `scan hardened.yaml` → 0
  findings. `--fail-on high` on vulnerable → exit 2. `harden -o … && scan` the
  bundle → 0 findings.
- **Web gate:** `npm ci`, `npm run build`, `npm test` (47 passed / 12 files),
  `npm run lint` (0 warnings) — all clean.
- **Full stack (`docker compose`):** api + postgres + web all healthy —
  `/healthz`, `/readyz`, `/metrics` (Prometheus gauges), the web UI, and the
  nginx→API proxy all return 200. Fixed a web-image crash-loop: the hardened
  nginx-unprivileged image couldn't envsubst a root-owned baked `conf.d`; now
  shipped as a template written at runtime by the non-root user. (Local host
  ports remapped in `.env` to avoid collisions with other running stacks.)

**Verdict:** baseline green. Proceeding into the KSPM workstreams (K1–K10).

## KSPM K1 — Asset inventory & coverage + dynamic cluster registration (done)

- **[EXTEND] Assessment-coverage %:** `graph.Coverage()` classifies every
  discovered resource as assessable (a kind the engine normalizes + checks
  reason over) or skipped (tallied by kind, reason = no built-in check),
  yielding an honest `assessable/discovered` rate. Surfaced as
  `api.Report.Coverage` (additive pointer — golden sub-object comparisons
  unaffected), on the `scan` console output ("Assessment coverage: N of M …"),
  and on `GET /v1/posture` (`coverage` object; OpenAPI `CoverageBreakdown`).
- **[EXTEND] Dynamic cluster registration (was A1b):** the cluster→source map is
  lifted out of the `--cluster` closure into a mutex-guarded `sourceRegistry`
  (`internal/cli/clustersource.go`) implementing the new
  `dashboard.ClusterRegistrar` seam; the scanner reads the live set.
  `POST /v1/clusters {id,name,source}` and `DELETE /v1/clusters/{id}` are gated
  `requireRole(RoleAdmin,"cluster.write")`, audited, and disabled (501) when no
  registrar is wired. `DeleteCluster` added to the `Store` interface + `MemStore`
  + `pg.Store` (cascades scans/history). OpenAPI paths + `RegisterClusterRequest`
  schema added.
- **Acceptance:** `internal/dashboard/clusters_test.go` — add→appears→scannable,
  delete→404-on-scan, analyst→403 on both writes, malformed source→400 (no
  dangling cluster), no-registrar→501, full audit trail (write/delete/denied).
  `internal/graph/coverage_test.go` — assessable/skipped/rate + empty inventory.
  OpenAPI still validates. `make check` equivalent green (build/vet/lint/test);
  goldens unchanged.
- ⟐ No decision items in K1; K2b/K3/K4 decisions handled in their workstreams.

## KSPM K4 — Deterministic, explainable risk prioritization (done)

- **[EXTEND] Risk scoring** (`internal/risk`): a plain published weighted sum
  over signals the engine already computes — severity, attack-path enablement,
  internet exposure, blast radius (SA-token→node→cluster-admin, strongest-only),
  and multi-workload breadth. Every point is recorded as a `RiskFactor`, so the
  score's "why" is always attached and it is byte-reproducible run-to-run. No ML,
  no hidden term.
- Exposed as additive `api.Report.TopRisks` (references findings by id — the
  findings golden is untouched), on the `scan` console ("Top risks … why: …"),
  on `GET /v1/posture` (`topRisks`; also recomputed over the merged fleet view),
  and in OpenAPI (`RiskScore`/`RiskFactor`).
- ⟐ DECISION (scoring formula): chose a transparent additive model with the
  weights published in `docs/honest-metrics.md`; blast-radius awards the strongest
  reached outcome only (not summed) to avoid triple-counting a full chain.
- **Acceptance:** on `vulnerable.yaml` the cluster-admin-chain enablers (KG-011,
  KG-001, KG-002, KG-018) rank at the very top, each rendering its factors;
  `internal/risk/risk_test.go` asserts enablers outrank same-resource low
  findings, reproducibility, factor-sum == score (no hidden term), and the
  breadth bonus. risk pkg coverage 87.5%. Full gate green; goldens unchanged.

## KSPM K6 — Findings lifecycle, ownership, waivers, MTTR (done — the biggest gap)

- **[NEW] Lifecycle model** (`internal/dashboard/lifecycle.go`): states
  open/acknowledged/in-progress/resolved/risk-accepted keyed by a stable
  `LifecycleKey` (hash of cluster+check+resource) so state persists across scans;
  ownership/assignee; `Waiver{justification, approvedBy, createdAt, expiresAt}`
  with `Active(now)`; `EffectiveState`/`IsActivelyWaived` (expiry auto-lapses and
  the finding re-surfaces); `ComputeMTTR` (counts by effective state + mean
  resolvedAt−firstSeen, honestly excluding rows missing timestamps).
- **[NEW] Store**: `SeedFindings`/`GetLifecycle`/`ListLifecycle`/`UpsertLifecycle`
  on the `Store` interface + MemStore + pg (migration `0002_finding_lifecycle`,
  waiver as jsonb). DeleteCluster and DPDP DeleteTenant cascade to lifecycle rows.
  RunScan seeds firstSeen at first detection.
- **[NEW] API** (waiver-aware, audited): `GET /v1/lifecycle` (triage lane + MTTR,
  waiver expiry applied), `POST /v1/lifecycle/{key}/state` (analyst+),
  `POST /v1/lifecycle/{key}/waiver` (admin, justification required, 90-day cap),
  `DELETE …/waiver` (admin). Every change + denial audited. OpenAPI paths +
  schemas added; spec still validates.
- **[NEW] Waiver-aware enforcement primitives**: `API.WaivedKeys` and
  `dashboard.BlockingFindings` partition blocking vs waived-but-logged findings —
  consumed by K7 guardrails.
- **[NEW] Dashboard Triage view** (`web/src/routes/Triage.tsx`): MTTR tiles,
  role-gated state controls, admin Accept-risk dialog (mandatory justification +
  expiry), waiver display; client methods + zod types + mock; nav + route.
- ⟐ DECISION: waiver approver = RoleAdmin, max duration = 90 days, both
  configurable via `LifecycleConfig`.
- **Acceptance:** `internal/dashboard/lifecycle_test.go` (seed→open, triage+MTTR,
  analyst-can't/admin-can waive, expiry re-surfaces, validation, revoke, complete
  audit trail, BlockingFindings partition); `pg_test.go TestPgFindingLifecycle`
  runs green against **real Postgres** (seed idempotent, state+waiver jsonb
  round-trip, tenant isolation, DeleteCluster cascade). Web: 4 Triage tests
  (render+MTTR, viewer read-only, analyst sets state, admin Accept-risk). Full
  gate green (Go build/vet/lint/test; web build/lint/51 tests); goldens unchanged.

| Squad | Status | Notes |
|---|---|---|
| A — Scaffold | ✅ done | module, §13 layout, cobra + `version`, slog, `.golangci.yml`, CI matrix, 3 golden fixtures |
| B — Loader + Resource Graph | ✅ done | model types, offline loader (dir/multi-doc/List/snapshot), typed graph + resolutions; coverage graph 85.6% / loader 88.2% |
| C — Detection engine + checks | ✅ done | 20 checks (KG-001..020) + registry + cis/zeal-default profiles; `scan -f console\|json`; golden JSON (vulnerable=19 findings, 4 critical); checks coverage 88.4% |
| D — Attack-path engine | ✅ done | capability chaining + ATT&CK tags + `--assume-breach`; golden paths (vulnerable=cluster-admin chain, partial=host-access, hardened=none); coverage 87.1% |
| E — Compliance engine | ✅ done | 6 data-driven packs (CIS/NIST/PCI/ISO/DPDP/NCA), honest breached-of-assessed math, strict pack-loader; vulnerable=breaches, hardened=100%; coverage 94.9% |
| F — Reporters + history | ✅ done | console colour + JSON + SARIF (2.1.0) + self-contained HTML dashboard; file+SQLite history (trend up); `--fail-on` (exit 2/0), `--watch`; coverage report 85.8% / history 80.0% |
| G — Remediation / hardening | ✅ done | `harden -o <dir>` baseline bundle (PSA/netpol/RBAC/Kyverno/Gatekeeper/Deployment/checklist); kubeconform-clean; bundle→0 findings; per-finding snippets in JSON/HTML; coverage 85.3% |
| H — Live mode + kubectl plugin | ✅ done | read-only client-go loader, `scan --live`, kubectl-kubeguard plugin, deploy/rbac-readonly.yaml; fake-clientset tested (read-only asserted); coverage 90.7% |
| I — Service mode → USP | ✅ done | `serve`: cron scheduler, REST /v1/scan,findings,posture,report, HTML dashboard, /metrics (pass-rate gauge), /healthz+/readyz, SQLite history; docs/api.md; server 90.4% |
| J — Admission webhook | ✅ done | controller-runtime validating webhook (reuses checks), fail-open/closed; admits hardened, denies privileged/hostPath with reason; deploy/webhook.yaml (cert-manager) + docs; coverage 82.1% |
| K — Packaging & docs | ✅ done | Helm chart `helm lint`-clean; goreleaser (4-target matrix × 2 binaries, CycloneDX SBOM, cosign keyless signing, SLSA provenance) `goreleaser check`-clean + snapshot build green; docs cover all 5 modes + webhook + honest metrics; whole-project gate green, all engine pkgs ≥80% (graph 96.8%) |

## Squad A — Scaffold

**Shipped**
- Go module `github.com/kubeguard/kubeguard` (Go 1.26).
- Full directory layout (ARCHITECTURE.md §13) with package stubs.
- Cobra root command + `version` (slog-based structured logging, `--log-level`).
- `.golangci.yml` (v2), `.gitattributes` (LF normalization), `.gitignore`, `Makefile`.
- GitHub Actions CI: build · vet · test (race + coverage) · golangci-lint · cross-compile
  matrix (linux/amd64, linux/arm64, windows/amd64, darwin/arm64).
- Three golden fixtures: `test/fixtures/{vulnerable,partially-hardened,hardened}.yaml`.

**Deferred**
- `pkg/api` types land in Squad C (kept to a doc stub for now to avoid premature churn).
- Real engine logic per package arrives in its owning squad.

## Squad B — Loader + Resource Graph

**Shipped**
- `internal/model`: core envelope + normalized Workload/PodSpec/Container/RBAC/Service/
  NetworkPolicy views (ARCHITECTURE.md §4.1).
- `internal/loader/offline`: `Load(path)` handling directories, multi-doc YAML, `kind: List`,
  `{"items":[...]}`, and top-level snapshot JSON arrays (§5.1).
- `internal/graph`: typed inventory + normalization across Pod/Deployment/StatefulSet/
  DaemonSet/Job/CronJob and resolutions Pod→SA, SA→Role/ClusterRole (via bindings),
  Service→workload (selector), Namespace→NetworkPolicy / default-deny (§6).

**Acceptance** — all 3 fixtures load; `checkout-sa` → cluster-admin binding + secrets/pods
rules; `checkout-lb` → `checkout` workload. Coverage: graph 85.6%, loader 88.2%.

**Deferred** — live loader is Squad H; `pkg/api` output types are Squad C.

## Squad C — Detection engine + checks

**Shipped**
- `pkg/api`: stable output types — `Severity`, `Capability` (the §8.1 primitives), `Finding`,
  `Evidence`, `Remediation`, `ControlRef`, `Report` (ARCHITECTURE.md §4.2).
- `internal/checks`: all 20 built-in checks (KG-001..KG-020), each with severity, evidence,
  remediation, granted primitives, and CIS/NSA/ATT&CK refs; `Registry()`, data-driven
  `Profile` (`cis`, `zeal-default`), and deterministic `Scan` (severity→category→id→resource).
- `internal/report`: minimal console + JSON renderers (SARIF/HTML/colour come in Squad F).
- `internal/cli`: `scan -i <path> -f console|json -p <profile> -o <file>`.

**Acceptance** — vulnerable → golden `test/fixtures/golden/vulnerable.findings.json` (19
findings, 4 critical) including the full chain set (KG-001/002/011/013/014/015/017/018);
hardened → 0; partially-hardened → no KG-011. Every check has ±/− tests; order is deterministic.
Coverage: checks 88.4%.

**Deferred** — `--fail-on`/exit-2 gate, SARIF, HTML, colour, history → Squad F.

## Squad D — Attack-path engine

**Shipped**
- `pkg/api`: `AttackPath` + `PathHop` types; `Report.Paths` (additive).
- `internal/attack`: capability-model chaining over the graph (entry → escape → node →
  SA token → RBAC escalation → lateral), ATT&CK technique tagging, and `--assume-breach`
  (seeds in-cluster reachability for every workload) (ARCHITECTURE.md §8).
- `internal/graph/rbac.go`: shared RBAC rule predicates + SA-capability helpers
  (`SAIsClusterAdmin`/`SACanReadSecrets`/`SACanCreatePods`), now used by both the checks
  and attack engines (de-duplicated from Squad C).
- `internal/cli`/`internal/report`: `scan --assume-breach`; console renders the path tree.

**Acceptance** — vulnerable → 1 CRITICAL cluster-admin chain (primitives + ATT&CK
T1190/T1611/T1552.001/T1078/T1021, enablers KG-018/001/002/015/011/017); partially-hardened →
host-access chain to NodeAccess with no cluster-admin; hardened → 0. Golden-asserted
(`vulnerable.paths.json`, `partially-hardened.paths.json`). Coverage 87.1%.

## Squad E — Compliance engine

**Shipped**
- `frameworks/*.yaml`: 9 data-driven packs — CIS Kubernetes Benchmark, NIST 800-53 r5,
  PCI DSS v4.0, ISO 27001:2022, India DPDP 2023, Saudi NCA ECC-1, NCSC CAF 4.0,
  NCSC Cyber Essentials, UK GDPR / DPA 2018 — embedded via
  `frameworks/embed.go` (`go:embed`), so the binary is self-contained (ARCHITECTURE.md §9.1).
- `internal/compliance`: strict pack loader (`UnmarshalStrict` → rejects unknown keys /
  malformed packs) + validation; posture math with honest denominators (a control is assessed
  only if every mapped check ran; `breached of assessed`, `passRate = passed/assessed`);
  `Summarize` posture aggregate; always carries the indicative-mapping disclaimer (§9.2–9.4).
- `pkg/api`: `FrameworkResult`, `ControlBreach`, `PostureSummary`; `Report.Posture` +
  `Report.Compliance` (additive).
- `internal/cli` + `report`: scan emits per-framework `breached of assessed` + disclaimer.

**Acceptance** — vulnerable → breached controls per framework (golden
`vulnerable.compliance.json`); hardened → 100% of assessed across all 9; malformed packs
rejected; adding a pack = a YAML drop-in (no code change). Coverage 94.9%.

**UK packs (additive)** — `ncsc-caf-4.yaml` (NCSC CAF 4.0; C1/C2 detection
`assessable:false`), `cyber-essentials.yaml` (NCSC Cyber Essentials; security-update-
management + malware-protection `assessable:false` — not derivable from static
manifests, so excluded from the denominator), and `uk-gdpr-dpa-2018.yaml`
(UK GDPR Art.5(1)(f) / Art.32). Tests assert every `mapsTo` resolves to a real
check id and that `assessable:false` controls stay out of the denominator. Golden
`vulnerable.compliance.json` was intentionally regenerated to include the three
frameworks (now 9); pack-count assertions updated in compliance/analyzer/server tests.

## Squad F — Reporters + history

**Shipped**
- `internal/report`: console (TTY colour, `NO_COLOR`-aware), JSON, SARIF 2.1.0
  (`go-sarif`, one rule per fired check), and a self-contained offline HTML dashboard
  (Overview/Compliance/Attack-Paths/Findings tabs, SVG pass-rate trend, clickable path nodes).
- **Evidence packs** (`-f evidence -o <dir>`): `compliance.BuildEvidence` +
  `report.EvidenceHTML`/`EvidenceJSON` write one self-contained offline HTML file
  plus a JSON sibling per framework, listing each assessed control, its mapped
  checks, and the breaching findings (resource ref, redacted evidence, ATT&CK
  techniques, remediation) with `breached/passed/assessed`, pass rate, and the
  disclaimer. Reuses `pkg/api` types (`EvidencePack`/`EvidenceControl` compose
  `Finding`). Deterministic — single `generatedAt`. Golden-asserted against
  `vulnerable.evidence.json` / `hardened.evidence.json` (new fixtures).
- `internal/history`: `Store` interface with file (JSONL) and SQLite (`modernc.org/sqlite`,
  no cgo) backends; `FromReport` summary; drift via `--history`.
- `internal/cli`: `scan -f console|json|sarif|html`, `--fail-on` (exit 2 via coded error),
  `--history`, `--watch`; TTY colour auto-detect.

**Acceptance** — SARIF parses & validates structurally; HTML renders the chain + compliance
breach view offline; three fixtures into one history trend control-pass upward (both backends);
`--fail-on high` exits 2 on vulnerable, 0 on hardened. Coverage report 85.8%, history 80.0%.

**Deferred** — full JSON-Schema validation of SARIF is structural (parsed via go-sarif types
+ field assertions) rather than against the 200KB schema doc.

## Squad G — Remediation / hardening

**Shipped**
- `internal/harden`: `Generate`/`Write` emit the baseline bundle — namespace PSA (restricted),
  default-deny + DNS NetworkPolicies, dedicated SA (no auto-mount), least-privilege RBAC,
  hardened Deployment (non-root, read-only rootfs, drop ALL, seccomp RuntimeDefault, limits,
  digest-pinned image), ClusterIP Service, Kyverno + Gatekeeper policies, and `CHECKLIST.md`.
- `internal/cli`: `harden -o <dir>` with `--namespace/--app/--image/--service-account`.
- Per-finding fix snippets: central `remediationSnippets` map → `Finding.Remediation.Snippet`,
  rendered in JSON and the HTML findings table.
- CI: a `harden-validate` job runs the bundle through `kubeconform`.

**Acceptance** — bundle is valid YAML and passes `kubeconform` (8 valid / 0 invalid locally);
loading the bundle through the engine yields **0 findings**; remediation snippets present in
JSON/HTML. Coverage 85.3%.

## Squad H — Live mode + kubectl plugin

**Shipped**
- `internal/loader/live`: read-only ingest via client-go (`Load(ctx, clientset)` lists
  workloads/RBAC/services/network policies and normalizes them into the same model.Resource
  set as the offline loader); `NewClientset` from kubeconfig. Lists only — never writes.
- `internal/cli`: `scan --live [--context <ctx>]`; `-i` and `--live` are mutually exclusive
  entry points (`--watch` is rejected with `--live`).
- `cmd/kubectl-kubeguard`: kubectl plugin entrypoint (cross-compiled in CI).
- `deploy/rbac-readonly.yaml`: least-privilege read-only RBAC.
- `docs/kubectl-plugin.md`: install + usage.

**Acceptance** — live path unit-tested with `fake.NewSimpleClientset` (vulnerable objects →
expected findings; every recorded API action asserted to be `list`); read-only RBAC manifest
shipped; usage documented. No real cluster required. Coverage 90.7%.

## Squad I — Service mode → USP

**Shipped**
- `internal/analyzer`: shared detect→chain→comply pipeline (`Analyze`), used by both `scan`
  and `serve` so they produce identical reports.
- `internal/server`: REST (`/v1/scan`, `/v1/findings`, `/v1/posture`, `/v1/report`), HTML
  dashboard (`/`), Prometheus `/metrics`, `/healthz` + `/readyz`, optional cron scheduler,
  optional SQLite/file history, graceful shutdown.
- `internal/cli`: `serve --addr --input|--live --schedule --history --profile`.
- `docs/api.md`: the stable `pkg/api` schema + REST/metrics contract for USP ingest.

**Acceptance** — integration test boots the server, triggers a scan over a fixture, asserts
`/v1/posture` JSON and the `kubeguard_compliance_pass_rate` gauge; readiness flips after the
first scan. Server coverage 90.4%, analyzer 90.9%.

## Squad J — Admission webhook

**Shipped**
- `internal/webhook`: a controller-runtime validating `Validator` that reuses the detection
  engine on the incoming pod and denies on a deny-set (privileged, hostPath, hostNet/PID/IPC,
  run-as-root, dangerous caps). Read-only (admit/deny only); fail-open/closed configurable.
- `internal/cli`: `webhook --port --cert-dir --path --fail-open` (controller-runtime webhook
  server; TLS from `--cert-dir`).
- `deploy/webhook.yaml`: Namespace, SA, cert-manager Issuer + Certificate, Deployment, Service,
  and the `ValidatingWebhookConfiguration` (CA injected via cert-manager).
- `docs/webhook.md`: enable steps + fail-open/closed semantics.

**Acceptance** — handler tested with fake admission requests: hardened pod admitted, privileged
and hostPath pods denied with the offending check ids in the message; decode failure honors
fail-open vs fail-closed. Manifests kubeconform-clean. Coverage 82.1%. No envtest/cluster needed.

## Squad K — Packaging & docs

**Shipped**
- `charts/kubeguard`: Helm chart for service mode (Deployment with `/healthz`+`/readyz` probes,
  Service, optional ServiceMonitor, optional PVC, read-only RBAC gated on `live`, SA, hardened
  securityContext: non-root + read-only rootfs + drop ALL; image tag-or-digest). `helm lint`
  clean (0 failed, 0 warnings, `--strict`); `helm template` renders valid manifests.
- `.goreleaser.yaml`: cross-compile matrix (linux/amd64, linux/arm64, windows/amd64, darwin/arm64)
  for both `kubeguard` and `kubectl-kubeguard` (CGO_ENABLED=0, version/commit/date ldflags wired
  to `internal/cli`), CycloneDX SBOM (syft), cosign keyless signing of checksums + artifacts.
  `goreleaser check` clean; `goreleaser build --snapshot` produces all 4×2 binaries; snapshot
  release emits archives + CycloneDX 1.6 SBOMs + signed checksums.
- `.github/workflows/release.yml`: tag-triggered (`v*`) release — installs Go/syft/cosign, runs
  goreleaser, and a SLSA generator job produces provenance over the artifact hashes
  (`contents`/`id-token`/`packages: write`).
- Docs: `QUICKSTART.md` (runnable getting-started), `docs/security-model.md` (offline-first,
  read-only guarantees, supply-chain story, honest-metrics policy), `docs/usp-integration.md`
  (service/`pkg/api`/REST/metrics → USP control plane); README mode table covers all five modes
  + webhook; every documented command/flag verified against `internal/cli`.

**Acceptance** — `helm lint` clean; `goreleaser check` clean + snapshot dry-run yields signed
artifacts + SBOM; docs cover all five deployment modes and the honest-metrics policy. Whole-project
gate green (`go build`/`vet`/`test ./...`); all engine packages ≥80% coverage (graph raised
70.6% → 96.8% in this squad).

**Deferred** — real (non-snapshot) cosign signing requires CI OIDC (Fulcio/Rekor); validated
locally as config-only since `cosign` isn't installed on the dev host.

---

# Dashboard & Productionization (docs/BRIEF-dashboard.md)

Track 1 (D1–D6) builds the production web dashboard; Track 2 (P1–P7) hardens the tool
into a shippable product. Per-squad gate: `npm build/lint/test` (frontend) and
`go build/vet/test` (backend) clean + the squad's acceptance, then commit.

| Squad | Status | Notes (evidence-based) |
|---|---|---|
| D1 — Frontend scaffold & design system | ✅ done | `web/` Vite+TS+Tailwind; dark theme + severity tokens; app shell (nav, tenant chip, cluster switcher, auth-aware header); TanStack Router+Query; zod-validated typed API client; OpenAPI contract (`docs/openapi.yaml`) → `openapi-typescript` codegen; **compile-time assertion that the zod client types match the OpenAPI types derived from `pkg/api`**. `npm run build` + `lint` (0 warnings) + `test` (14 passed) clean; shell renders off the mocked API |
| D2 — Dashboard API (BFF) | ✅ done | `internal/dashboard`: chi router serving `/v1/clusters,scans,findings,posture,attack-paths,history` + SSE `/v1/stream`, described by `docs/openapi.yaml` (validated in-test via kin-openapi). Multi-tenant store; server-side finding filter/sort/paginate; fail-closed auth + role-gating (viewer cannot POST /v1/scans → 403). `kubeguard dashboard` command wires it over the offline scanner. Live-verified across 2 clusters; 11 integration tests + OpenAPI validation green; lint 0 issues |
| D3 — Auth, tenancy & RBAC | ✅ done | Real JWT verification (RS256/ES256, JWKS-over-HTTP, iss/aud/exp, **algorithm-confusion defense** — rejects `none`/HS\*); `ChainAuth` = OIDC seam (default off) + air-gapped local-admin fallback; viewer/analyst/admin RBAC (viewer→403 on scan trigger); **append-only audit log** (allowed+denied, tenant-scoped, admin-only). Frontend: local-admin + SSO-seam login, JWT decode, role-gated nav, persisted session. 14 Go auth/audit tests + 25 Vitest + **3 Playwright e2e (real Chromium)** green; lint clean. `docs/auth.md` enable-step |
| D4 — Core views | ✅ done | All six lenses render real API data for ≥2 clusters: Overview (severity cards + honest pass + Recharts trends), Findings (server-filtered table + detail drawer w/ evidence/remediation/controls), Compliance (per-framework breach + expandable breached-controls→dents + remediation links), **Attack Paths (React Flow graph, keyboard-accessible clickable nodes → ATT&CK/resource/enabling-finding)**, Clusters/Fleet (drill-in), History/Drift (trend charts + correct two-scan diff). Plus admin-only Audit view. 40 Vitest + **7 Playwright e2e (real Chromium, incl. graph keyboard nav)**; build+lint clean |
| D5 — Continuous & live experience | ✅ done | Shared `RunScan` (on-demand POST + cron `Scheduler`) streams scan lifecycle over SSE and writes a history snapshot each run; `kubeguard dashboard --schedule` re-scans every cluster. Frontend: fetch-streaming SSE client (carries the bearer token), `useScanStream` invalidates the posture/findings/history/attack-path caches on completion (views auto-update, no reload), RBAC-gated **Scan now** + live status pill. Go scheduler tests + 44 Vitest (incl. live integration) + 9 Playwright e2e green; live-smoke streamed all 4 event types. lint clean |
| D6 — Reporting & export | ✅ done | `GET /v1/report?format=sarif\|csv\|pdf` exports the current scope. SARIF reuses the engine's validated 2.1.0 reporter; CSV is findings metadata; **PDF is a real co-branded engagement report** (go-pdf/fpdf) with brand/tenant header, posture + per-framework `breached of assessed`, attack-path chain, and the honest-metrics disclaimer. `--brand` co-brands (e.g. ZealDefense). Frontend Reports view downloads each (token-carrying fetch → blob). 5 Go export tests (SARIF parses, CSV rows, PDF valid+honest, endpoint content-types/auth/tenant) + Vitest + 2 Playwright download e2e; live-verified all 3 formats. lint clean |
| P1 — Persistence & migrations | ✅ done | `internal/dashboard/pg`: Postgres-backed `Store`+`AuditLog` (pgxpool, tenant-partitioned, report-as-jsonb) behind the same seams as the in-memory store; embedded **goose** migrations (tenants/users/clusters/scans/history/audit); configurable **retention** (`--retention`, keeps latest) + **DPDP hard-delete** (`DeleteTenant`); `kubeguard dashboard --postgres`. **Verified against real Postgres 16 (Docker)**: 5 integration tests (up/down/up clean, round-trip + tenant isolation, latest-replaces, retention prune, DPDP delete) + a live restart smoke proving scans/history survive. Scan IDs made restart-collision-safe. Backup/restore runbook in `docs/persistence.md`. Tests skip without a DSN so `go test ./...` stays green. lint clean |
| P2 — Security hardening | ✅ done | Defensive middleware (all live-verified): strict **CSP**/`X-Frame-Options`/`nosniff`/`Referrer-Policy`/CORP on every response, **HSTS** under TLS; **per-tenant rate limiting** (token bucket → 429); **CSRF** Origin-allowlist on unsafe methods (bearer-token API is already CSRF-resistant); 1 MiB **body cap** (413); server+zod **input validation**. `--tls-cert/--tls-key` (HTTPS+HSTS); secrets from env (`KUBEGUARD_ADMIN_TOKEN`/`_POSTGRES_DSN`), never in image. **`govulncheck` run live — found & fixed a real vuln** (x/net→v0.55.0), now clean. CI security gates (`security.yml`: govulncheck/gitleaks/trivy/npm-audit/CycloneDX SBOM). `docs/threat-model.md` (STRIDE); least-priv read-only RBAC shipped. 5 security tests + live smoke; lint clean |
| P3 — Observability & reliability | ✅ done | Structured `slog` per-request (request_id/method/path/status/duration/tenant); **Prometheus `/metrics`** — http latency histogram, scan duration, scans_total, findings-by-severity gauge, **per-framework compliance pass-rate gauge** (live-verified); **OTel** spans around RunScan (exporter default off, `--otel-endpoint`); `/healthz`+`/readyz`, graceful shutdown; **scan retries + atomic persistence** (failed/crashed scan leaves no partial rows). SLOs + Prometheus `alerts.yaml` + Grafana dashboard JSON + `docs/observability.md`. 5 obs/reliability tests (metrics, recorded span, chaos no-corruption, retry recovers); lint clean |
| P4 — Performance & scale | ✅ done | **Async scan worker pool** (`--async-workers`): POST enqueues → `202 queued`, worker runs + SSE-streams, bounded queue (`503` when full), drains on shutdown. Server-side pagination; client (TanStack) caching invalidated by SSE; **no N+1** (whole report = one jsonb read). **Measured (in CI tests): API read p95 ≈ 4 ms** (target <120ms) over 2k reqs @ 32 concurrent; **5,000-pod scan ≈ 0.35 s** (40,050 findings, budget 30s). k6 load script (`test/load/k6-dashboard.js`, p95<120ms threshold) for CI/staging; `docs/performance.md`. lint clean |
| P5 — Packaging & deploy | ✅ done | Multi-arch **distroless** API/worker image (`Dockerfile`, same binary) + hardened **nginx-unprivileged** web image (`web/Dockerfile` + `nginx.conf` w/ CSP + SSE proxy). **Helm chart `charts/kubeguard-dashboard`**: API+web Deployments, Service(s), Secret, read-only RBAC (live), HPA, **PDB (HA)**, ServiceMonitor, Ingress; values for OIDC/local-auth/Postgres/TLS/retention/rate-limit/replicas; non-root + read-only-rootfs + drop-ALL + RuntimeDefault; zero-downtime rolling. **`helm lint --strict` clean; `kubeconform` 11/11 valid**. Air-gapped install path in `docs/deploy.md`; kind smoke documented (runs in CI P6) |
| P6 — CI/CD & quality gates | ✅ done | `dashboard-ci.yml` (7 jobs): backend build/vet/test/lint · **integration vs Postgres service** (migrate up→down→up + round-trip) · frontend lint/build/vitest/**Playwright e2e** · helm lint + kubeconform · **kind deploy smoke** · **k6 load smoke** · images SBOM + **cosign keyless sign** (main/tags via OIDC). Composes with `ci.yml`, `security.yml`, `release.yml` (goreleaser sign+SBOM+SLSA). DB-migration, staging→prod digest-promotion, zero-downtime, and rollback runbook in `docs/cicd.md`. All 4 workflow YAMLs validated |
| P7 — Docs & launch readiness | ✅ done | Full doc set: OpenAPI ref (`openapi.yaml`), **admin-guide**, **user-guide**, **runbooks** (on-call/incident/restore), **privacy/DPDP** statement, **honest-metrics policy**, threat-model, persistence/observability/performance/cicd/auth/deploy guides; **SECURITY.md** + **LICENSE** (Apache-2.0); README front-door updated with the dashboard mode + docs index. A new operator can install (admin-guide→deploy) and a new analyst can run+interpret a scan (user-guide) from the docs alone; all six modes + the metrics policy documented |

## Squad D1 — Frontend scaffold & design system

**Shipped**
- `web/`: React 18 + TypeScript + Vite + Tailwind app. Design tokens (dark theme, severity
  palette CRITICAL→INFO) in `tailwind.config.ts`; accessible primitives (Card/Button/Badge,
  visible focus rings).
- App shell (`app/Shell.tsx`): primary nav, tenant chip, **cluster/tenant switcher** (reads
  `/v1/clusters`), auth-aware header (role chip, sign-out). TanStack Router (code-based tree)
  + TanStack Query.
- Typed API client (`lib/api/client.ts`) with an injectable transport seam; **every response
  validated against zod schemas** (`lib/api/types.ts`) that mirror `pkg/api`. Honest-metric
  formatters (`passed of assessed`, never a bare %).
- Contract gate: `docs/openapi.yaml` (BFF contract derived from `pkg/api`) → `npm run gen:api`
  (`openapi-typescript`) → `lib/api/contract.ts` asserts at compile time the zod types are
  assignable to the generated OpenAPI types. A backend drift fails `tsc -b`.
- Overview view renders real posture (severity cards, total, critical paths, honest overall
  pass with denominator, per-framework breach + disclaimer). D2–D4 lenses stubbed.

**Acceptance** — `npm run build` (tsc -b incl. contract assertion + vite) clean; `npm run lint`
0 warnings; `npm run test` 14 passed (client contract-validation, honest-metric formatters,
shell+Overview render off the mocked API). Frontend talks only to KubeGuard's own API.

## Squad D2 — Dashboard API (BFF)

**Shipped**
- `internal/dashboard`: a chi-router backend-for-frontend. Endpoints `/v1/clusters`,
  `/v1/scans` (list + analyst-gated POST trigger), `/v1/findings` (server-side severity/
  category/framework/namespace/search filter, severity|id|category sort, limit/offset
  paginate), `/v1/posture`, `/v1/attack-paths`, `/v1/history`, and SSE `/v1/stream`
  (scan lifecycle + posture-updated events). Read-only — runs the engine via an injectable
  `Scanner`, never mutates a cluster.
- Tenant-partitioned `MemStore` (P1 swaps Postgres behind the `Store` seam); merged fleet
  view across a tenant's clusters. Fail-closed `Authenticator` (StaticAuth for D2; D3 adds
  OIDC) + `requireRole` middleware — a viewer POSTing `/v1/scans` gets 403; cross-tenant
  data is never returned. Deterministic clock/id injection (NFR-11).
- `docs/openapi.yaml` describes the surface; the frontend codegens its client from it and a
  Go test validates it with kin-openapi. `kubeguard dashboard --cluster id=<path>` runs the
  BFF over the offline loader+analyzer with a local-admin token (air-gapped).

**Acceptance** — OpenAPI validates (kin-openapi test); 11 integration tests cover pagination,
filtering, sort, authz (viewer→403 on scan trigger), tenant isolation, honest posture
denominators, history accumulation, and **an SSE `scan_completed` event on scan completion**.
Live-verified across two clusters (vulnerable + hardened): 401 without token, server-side
filtered/sorted findings, 100%-of-assessed posture with disclaimers. `go build/vet/test` +
`golangci-lint` clean.

## Squad D3 — Auth, tenancy & RBAC

**Shipped**
- `internal/dashboard/jwt.go`: real bearer-token verification (golang-jwt v5) — asymmetric
  algorithms only (RS256/ES256/384/512), enforced issuer/audience/expiry, and an
  **algorithm-confusion defense** that rejects `none` and HMAC `HS*` (an attacker can't sign
  with the public key as an HMAC secret). Claims → `Principal{tenant, role}`; absent role
  defaults to viewer. `NewJWKSKeyfunc` fetches+caches the IdP JWKS (go-jose) by `kid`.
- `ChainAuth`: OIDC/SSO (default off) tried first, air-gapped `StaticAuth` local-admin
  fallback second. `kubeguard dashboard` exposes `--oidc-issuer/-audience/-jwks-url/
  -tenant-claim/-role-claim` (all off unless set — no IdP contacted otherwise).
- `audit.go`: append-only, tenant-partitioned `AuditLog`. Every privileged action
  (`scan.trigger`, allowed **and** denied) writes an entry; `GET /v1/audit` is admin-only.
- Frontend: `auth.tsx` persists the session, decodes JWT claims (display only), exposes
  local-admin + SSO-seam login; `Login`/`AuthCallback` routes; the shell role-gates the
  admin-only Audit nav. The API client carries the live session token.
- `docs/auth.md`: modes, OIDC enable-step, tenancy, RBAC table, audit semantics.

**Acceptance** — Go (14 tests): valid RS256/ES256 accepted; expired/wrong-iss/wrong-aud/
`none`/HS-confusion/missing-tenant rejected; JWKS-over-HTTP end-to-end (stand-in IdP, no
external net); ChainAuth fallback; viewer→403 on scan trigger (audited); cross-tenant data
never returned; allowed+denied audit entries, admin-only, tenant-scoped. Frontend: 25 Vitest
(login both modes, role gating, persistence) + **3 Playwright e2e in real Chromium** (login →
admin nav; viewer hides Audit; SSO seam). `go`/`npm` build+lint+test all clean.

## Squad D4 — Core views

**Shipped** — six role lenses, all reading live API data, with a cluster-aware mock so
they render for ≥2 clusters (prod-eu vulnerable, staging-us hardened) off `VITE_USE_MOCK`:
- **Overview**: severity cards, total/critical-paths, honest overall pass (`passed of
  assessed`), and Recharts severity + pass-rate **trends**.
- **Findings**: server-side filtered/sorted/paginated table (severity toggles, search) with a
  detail **drawer** (evidence — secrets redacted, remediation + snippet, mapped controls).
- **Compliance**: per-framework breach (with denominator + disclaimer), expandable to the
  breached controls and the dents (findings) causing each, with "view remediation" links.
- **Attack Paths**: interactive **React Flow** graph (`pathToFlow` builder). Nodes are
  keyboard-accessible focusable buttons; selecting one shows its ATT&CK technique, resource,
  and enabling finding. Impact + cluster filters.
- **Clusters/Fleet**: posture-per-cluster table; row drills into the cluster.
- **History/Drift**: severity + pass-rate trend charts and a correct two-scan **drift diff**
  (`computeDrift` — newly-breached vs fixed, per-severity deltas, improved/regressed).
- **Audit**: admin-only privileged-action log view (server also enforces admin).

**Acceptance** — 40 Vitest (drift correctness vs fixtures, graph builder, accessible node,
findings filter+drawer, compliance expand, fleet, audit) + **7 Playwright e2e in real Chromium**
including the attack-graph node **clicked and activated via keyboard** (Enter → ATT&CK detail).
`npm run build`/`lint`/`test` clean. Frontend talks only to KubeGuard's own API.

## Squad D5 — Continuous & live experience

**Shipped**
- `internal/dashboard`: `API.RunScan` factors the scan flow (publish SSE lifecycle → run
  read-only Scanner → persist report + **history snapshot** → audit) shared by the on-demand
  `POST /v1/scans` and a cron `Scheduler` (robfig/cron). `kubeguard dashboard --schedule
  "<cron>"` re-scans every registered cluster, so the compliance/trend/attack-path views are
  continuously populated with no user action. Scheduled runs are audited as `scheduler`.
- Frontend: `client.openStream` reads `/v1/stream` via **fetch streaming** (carries the
  bearer token, unlike EventSource) with a pure `parseSSE` frame parser. `useScanStream`
  invalidates the findings/posture/history/attack-paths/clusters/scans query caches on
  `scan_completed` (lenses auto-refresh **without reload**) and tracks live progress. Header
  gains a live status pill and an RBAC-gated, optimistic **Scan now** button.
- Mock gains an in-memory event bus so `VITE_USE_MOCK` streams the same lifecycle the real
  BFF does (dev + e2e behave like production).

**Acceptance** — Go: a scheduled scan writes exactly one history snapshot, emits
`scan_completed`, and is audited. Frontend: 44 Vitest (incl. an end-to-end live test:
select cluster → Scan now → "Scanning…" → settles to Live as caches invalidate) + 9
Playwright e2e in real Chromium (live progress; viewer has no Scan now). Live smoke against
the real binary streamed `scan_started`/`scan_progress`/`scan_completed`/`posture_updated`
and grew scans+history. build/lint/test clean.

## Squad D6 — Reporting & export

**Shipped**
- `internal/dashboard/export.go` + `GET /v1/report?cluster=&format=sarif|csv|pdf`:
  - **SARIF** reuses the engine's validated `report.SARIF` (2.1.0).
  - **CSV** — findings metadata (id, severity, category, resource, mapped controls); never
    secret values.
  - **PDF** — a real co-branded engagement report (go-pdf/fpdf): brand+tenant header, posture
    summary with assessed denominators, per-framework `breached of assessed`, the attack-path
    chain narrative, and the honest-metrics disclaimer footer. `--brand` sets the title
    (ZealDefense engagement deliverable); tenant comes from the verified principal.
  - Endpoint sets correct `Content-Type` + `Content-Disposition`, is tenant-scoped (404 for a
    scope with no scan), auth-required, and 400s on an unknown format.
- Frontend: `client.downloadReport` fetches the export as a blob carrying the bearer token (a
  plain `<a>` can't), `saveBlob` triggers the browser download, and a **Reports** view offers
  PDF/CSV/SARIF with the honest-metrics note.

**Acceptance** — 5 Go tests (CSV parses to header+rows; SARIF round-trips through go-sarif at
2.1.0; PDF is `%PDF`, carries brand/tenant/`breached of`/chain/disclaimer; endpoint
formats+auth+tenant+bad-format). Frontend: Vitest (token carried, filename parsed from
disposition, view renders + click downloads) + **2 Playwright download e2e** (SARIF + CSV).
Live smoke from the binary returned a 4 KB valid PDF, CSV rows, and SARIF 2.1.0. lint clean.

## Squad P1 — Persistence & migrations

**Shipped**
- `internal/dashboard/pg`: a Postgres-backed `Store` + `AuditLog` (pgx + `pgxpool`
  connection pooling). Every table is tenant-partitioned with no cross-tenant FKs (NFR-3);
  the full scan report is stored as `jsonb` and reconstructed on read. Implements the same
  interfaces as the in-memory store, so the API/CLI are backend-agnostic (refactored
  `Config.Store`/`API.store` to the `Store` interface; exported `MergeReports` for the fleet
  view; added `RegisterCluster` to the interface).
- Embedded **goose** migration `0001_init` (tenants, users, clusters, scans w/ latest
  pointer, history, audit) applied automatically on start; `Migrate`/`MigrateDown` helpers.
- **Configurable retention** (`--retention <dur>`, hourly job; prunes non-latest scans +
  old history, always keeps the latest) and **DPDP hard-delete** (`DeleteTenant` erases all
  of a tenant's rows). `kubeguard dashboard --postgres <dsn>` selects the backend.
- Restart-safe scan IDs (counter + crypto-random suffix) so a persisted store never collides
  on the scans PK across process restarts.
- `docs/persistence.md`: schema, backend selection, migrations, retention, DPDP erasure +
  what personal data is stored and why, and a pg_dump/pg_restore backup/restore runbook.

**Acceptance** — verified against **real Postgres 16 in Docker** (genuinely run, not stubbed):
5 integration tests pass — migrate up→down→up clean; full cluster/scan/report/history/audit
round-trip with tenant isolation; latest report replaces previous; retention prunes old &
keeps latest; DPDP `DeleteTenant` leaves no residual. A live restart smoke confirmed scans +
history survive a fresh process against the same DB. Tests `t.Skip` without
`KUBEGUARD_TEST_POSTGRES`, so `go test ./...` stays green offline. build/vet/lint clean.

## Squad P2 — Security hardening

**Shipped**
- `internal/dashboard/security.go` middleware (live-verified): strict response headers
  (`Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, CORP) on every route; **HSTS** when served over TLS;
  **per-tenant token-bucket rate limiting** (→ `429`); **CSRF** Origin allowlist on unsafe
  methods (the bearer-token API is inherently CSRF-resistant — this is defense-in-depth);
  1 MiB request-body cap (`413`).
- Input validation: the client validates every response with zod and now validates the
  scan-trigger `clusterId` shape before sending; the server independently bounds/sanitizes it.
- TLS: `--tls-cert/--tls-key` serve HTTPS and enable HSTS. Secrets read from env
  (`KUBEGUARD_ADMIN_TOKEN`, `KUBEGUARD_POSTGRES_DSN`) — never baked into an image or committed.
- Supply chain: **`govulncheck` was run live and surfaced a real reachable vuln**
  (GO-2026-5026 in `golang.org/x/net`); fixed by upgrading to v0.55.0 — re-scan clean.
  `.github/workflows/security.yml` gates CI on govulncheck + gitleaks + trivy (fs/misconfig/
  secret) + `npm audit`, and emits CycloneDX SBOMs (cyclonedx-gomod + syft).
- `docs/threat-model.md` (STRIDE, trust boundaries, mitigations, honest gaps). Least-privilege
  read-only scanner RBAC already shipped in `deploy/rbac-readonly.yaml`.

**Acceptance** — 5 Go security tests (headers always set; HSTS only when enabled; CSRF
allow/deny by Origin; per-tenant rate limit isolates tenants; oversized body → 413). Live
smoke confirmed the headers and rate-limit (`200,200,429,429`). `govulncheck` clean after the
fix. Frontend build/lint/test (47) + backend build/vet/test/lint all clean.

**Deferred (honest, documented enable-steps):** keyless (Fulcio/Rekor) image signing needs CI
OIDC — wired in goreleaser (Squad K), exercised in the release pipeline (P6); per-image trivy
vuln scan runs in the release pipeline, not on every PR.
