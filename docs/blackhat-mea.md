# KubeGuard @ Black Hat MEA — Full-Swing KSPM Plan

> Target: showcase KubeGuard as a complete **Kubernetes Security Posture
> Management (KSPM)** platform at Black Hat MEA (Riyadh, KSA). This doc captures
> what is built, the regional positioning, the live booth demo, and the
> prioritized gap to "full swing."

---

## 1. What KubeGuard already is (as-built)

A production-grade KSPM engine, offline-first and read-only against clusters:

| Pillar | Status | Detail |
|---|---|---|
| **Detect** | ✅ | 20 built-in checks (KG-001..020), CIS/NSA-mapped, deterministic |
| **Chain** | ✅ | Capability-based **attack paths**, MITRE ATT&CK-tagged (Internet→LB→privileged pod→node→cluster-admin) |
| **Harden** | ✅ | `kubeguard harden` emits a baseline bundle that scans back to **0 findings** |
| **Comply** | ✅ | **11 frameworks** (see §2), honest `breached of assessed` denominators |
| **Report** | ✅ | console / json / **sarif** / **asff** / html / evidence packs (PDF/CSV via dashboard) |
| **Serve** | ✅ | `serve` mode: scheduler + REST + Prometheus `/metrics` + history |
| **Dashboard** | ✅ | Multi-tenant React SPA + BFF, JWT/OIDC + RBAC, React-Flow attack graph, Postgres |
| **Enforce** | ✅ | Validating admission webhook (fail-closed on `restricted`) |
| **Ship** | ✅ | Multi-arch distroless images, Helm charts (HPA/PDB/Ingress), cosign + SBOM in CI |

Five deployment modes share one engine: **CLI · CI gate · kubectl plugin · Service · Webhook**.

---

## 2. The regional wedge — MEA compliance story

This is the differentiator for a Riyadh audience. KubeGuard now ships the
**MEA regulatory trifecta** alongside the global standards, all as data-driven
YAML packs (adding a framework is zero code — `frameworks/*.yaml`):

**Regional (MEA):**
- 🇸🇦 **Saudi NCA ECC-1** — Essential Cybersecurity Controls
- 🇸🇦 **SAMA CSF** — Saudi Central Bank Cyber Security Framework *(new)*
- 🇦🇪 **UAE IA / NESA** — Information Assurance Standards *(new)*

**Global:** CIS Kubernetes Benchmark · NIST 800-53 Rev.5 · PCI DSS v4.0 · ISO/IEC
27001:2022 · UK GDPR/DPA · NCSC Cyber Essentials · NCSC CAF 4.0 · India DPDP 2023.

Every framework result carries the **honest-metrics** disclaimer: indicative
mapping, `breached of assessed`, never a bare compliant/non-compliant verdict.
For regulated banking/fintech in KSA/UAE, "here is your live SAMA / NCA / UAE-IA
posture from one scan" is the booth hook.

---

## 3. The 10-minute booth demo

A single scripted loop that lands the whole value prop:

1. **Scan a vulnerable cluster** (`kubeguard scan --live -f html`) — one command,
   17+ findings appear instantly.
2. **Walk the attack path** on the React-Flow graph — Internet → LoadBalancer →
   privileged pod (docker.sock) → node breakout → SA token → cluster-admin →
   lateral. Each hop ATT&CK-tagged. *This is the "wow".*
3. **Show regional compliance** — flip to the Compliance lens: live **SAMA CSF /
   NCA ECC / UAE IA** pass-rates with breached controls drilling to findings.
4. **Harden** — `kubeguard harden`, re-apply, re-scan → **0 findings, 0 paths,
   100% of assessed**. Before/after in 30 seconds.
5. **Prove the integration story** — same scan `-f asff` streams into **AWS
   Security Hub**; `-f sarif` into GitHub/DefectDojo; webhook blocks the bad pod
   at admission.

Booth artifacts to prep: the `thamespay-vulnerable` fixture, a pre-seeded
dashboard tenant, and the AWS ephemeral-scan harness (sibling repo) for a
"provision → scan → auto-destroy" cloud demo that leaves no bill behind.

---

## 4. Gap to "full swing" — prioritized

Landed this pass: **ASFF/Security Hub reporter** + **SAMA CSF & UAE IA packs**
(all tests green, goldens regenerated).

### P0 — demo-critical (do before the show)
- [ ] **Security Hub publisher** — opt-in `kubeguard publish --security-hub` that
      calls `BatchImportFindings` (the ASFF *format* is done; this adds the SDK
      network path behind an explicit flag, keeping the core offline).
- [ ] **Wire live scanning into the dashboard** — engine + RBAC exist; the BFF
      still only loads offline manifests (`internal/cli/dashboard.go`). Needed for
      a live continuous-posture demo.
- [ ] **Booth demo dataset + reset script** — deterministic vulnerable→hardened
      fixtures and a one-key reset between visitors.
- [ ] **Production Helm values profile** — `postgres.enabled`, TLS, OIDC, pinned
      digests (per `Kubeguard-PROD_READINESS.md`).

### P1 — credibility / AWS-native KSPM
- [ ] **IRSA / EKS Pod Identity → IAM analysis** — map ServiceAccounts to AWS IAM
      roles and extend attack paths into cloud IAM (the EKS-specific escalation
      pure-RBAC analysis misses). Highest AWS differentiation.
- [ ] **EKS multi-cluster discovery** + **CIS EKS Benchmark** pack.
- [ ] **ECR / Inspector CVE correlation** — fills the deliberate no-image-CVE gap.

### P2 — booth polish
- [ ] One-pager + comparison slide (KubeGuard vs generic scanners: attack-path
      chaining + MEA compliance + honest metrics).
- [ ] Recorded fallback demo (GIF/video) for network-flaky booth Wi-Fi.
- [ ] QR → self-serve `helm install` + sample report.

---

## 5. Why this wins the room

- **Attack paths, not just a checklist** — most booth scanners dump findings;
  KubeGuard shows the *chain to cluster-admin*, ATT&CK-tagged.
- **Regional compliance out of the box** — SAMA / NCA / UAE-IA live, honest
  denominators, auditor evidence packs.
- **Trust posture** — offline-first, read-only, no telemetry/phone-home, signed
  artifacts + SBOM. Exactly what a security-conscious MEA buyer wants to hear.
