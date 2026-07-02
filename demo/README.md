# KubeGuard conference demo — UK posture & auditor evidence

A self-contained, **offline** demo built around a fictional London fintech,
**Thames Pay**. It leads with the UK/GRC story — NCSC CAF 4.0, Cyber Essentials,
UK GDPR / DPA 2018 — and ends by exporting an **auditor evidence pack**.

Nothing is deployed to a cluster. KubeGuard reads the manifests in
[`manifests/`](manifests) and reports findings, attack paths, and compliance
posture. The output is deterministic, so the demo runs the same every time and
needs no network.

| | |
|---|---|
| **Vulnerable** ([`manifests/`](manifests)) | 53 findings · 6 critical · 2 attack paths · 0% of assessed controls pass |
| **Hardened** ([`manifests-hardened/`](manifests-hardened)) | 0 findings · 0 attack paths · 100% of assessed controls pass |

The two states are the **same platform** before and after remediation — the
before/after is the GRC payoff.

> **Want a live cluster?** There's an optional **live AWS variant** that scans a
> real (ephemeral, locked-down) kind cluster instead of files — same engine, same
> story. See [§ Optional: live AWS variant](#optional-live-aws-variant) below and
> [`aws/README.md`](aws/README.md). The offline flow above stays the reliable core
> and fallback.

---

## Pre-flight (do this before you walk on stage)

```bash
# From the repo root. Build once so the demo never waits on a compile.
go build -o kubeguard ./cmd/kubeguard      # Windows: go build -o kubeguard.exe ./cmd/kubeguard

# Smoke-test both states and the exporter (throwaway output dir).
./kubeguard scan -i demo/manifests | tail -15
./kubeguard scan -i demo/manifests-hardened | tail -12
./kubeguard scan -i demo/manifests -f evidence -o /tmp/kg-demo && ls /tmp/kg-demo
```

Checklist:
- [ ] `kubeguard` binary built and on `PATH` (or use `go run ./cmd/kubeguard`).
- [ ] Terminal font large; `NO_COLOR` unset so severities are coloured.
- [ ] A browser ready to open the exported `*.evidence.html` files.
- [ ] `demo/evidence/` is generated live during the demo — safe to delete beforehand.

> Fallback: everything is offline and deterministic. If a command misbehaves,
> re-run it verbatim — there is no cluster, network, or clock dependency beyond
> the single `generatedAt` timestamp.

---

## The script (~10 minutes)

Replace `./kubeguard` with `go run ./cmd/kubeguard` if you skipped the build.

### 1 · Frame it (0:00–1:00)
> "This is Thames Pay, a London payments platform. I have its Kubernetes
> manifests — no cluster, no agent. KubeGuard is offline-first and read-only.
> Let's see what an attacker, and an auditor, would find."

```bash
./kubeguard scan -i demo/manifests
```

### 2 · Detect → chain (1:00–3:00)
Scroll to the **Summary** and **Attack paths**.

> "53 findings, 6 critical. But findings are noise without a story. KubeGuard
> chains them into ATT&CK-tagged attack paths."

Read **AP-002** aloud — it is the headline:

```
[critical] AP-002  Cluster-admin takeover via checkout
  1. InternetIngress  → NetworkReachable   [KG-018 T1190]  Internet-facing Service exposes checkout
  2. NetworkReachable → ContainerEscape    [KG-001 T1611]  Privileged container allows breakout
  3. ContainerEscape  → NodeAccess         [KG-002 T1611]  docker.sock breakout → node
  4. NodeAccess       → ServiceAccountToken [KG-015 T1552.001] Auto-mounted SA token harvested
  5. ServiceAccountToken → ClusterAdmin    [KG-011 T1078]  checkout-sa is bound to cluster-admin
  6. ClusterAdmin     → LateralMovement     [KG-017 T1021]  No NetworkPolicy → lateral movement
```

> "Internet to cluster-admin in six hops — and every hop is descriptive
> narrative, never runnable exploit code."

### 3 · Comply, the UK lens (3:00–5:30)
Scroll to **Compliance**.

```bash
./kubeguard scan -i demo/manifests | grep -A12 "Compliance ("
```

> "Nine frameworks. For a London audience, three matter: **NCSC CAF 4.0**,
> **Cyber Essentials**, and **UK GDPR / DPA 2018**."

Land the honest-metrics point on **Cyber Essentials**:

> "Notice Cyber Essentials reads **3 breached of 3 assessed** — not 5. KubeGuard
> can't see patch currency or anti-malware from static manifests, so those two
> controls are marked *not assessable* and **excluded from the denominator**.
> We don't silently pass what we didn't test. In a field full of tools that
> overstate assurance, we refuse to."

### 4 · Export the evidence pack (5:30–8:00) — the headline feature
```bash
./kubeguard scan -i demo/manifests -f evidence -o demo/evidence
ls demo/evidence
```

> "One self-contained HTML file plus a machine-readable JSON sibling, per
> framework. This is what you hand the auditor."

Open the UK GDPR pack in a browser:

```bash
# macOS: open ; Linux: xdg-open ; Windows: start
open demo/evidence/uk-gdpr-dpa-2018.evidence.html
```

Walk one control top to bottom:
> "Article 5(1)(f), integrity and confidentiality — **breached**. Here are the
> KubeGuard checks it maps to, and for each breaching finding: the exact
> resource, the **redacted** evidence path, the **ATT&CK** technique, and the
> remediation. The counts and the indicative-mapping disclaimer travel with it.
> No external assets, no telemetry, no secret values — it opens on an air-gapped
> laptop."

Show the JSON sibling for the GRC tooling crowd:

```bash
./kubeguard scan -i demo/manifests -f evidence -o demo/evidence >/dev/null
grep -E '"framework"|"assessed"|"breached"|"passRate"|"controlId"' demo/evidence/cyber-essentials.evidence.json | head
```

> "Same data, machine-readable — `assessed: 3`, the honest denominator, carried
> straight through to JSON."

### 5 · Harden → re-evidence (8:00–9:30)
> "Same platform, remediated: least-privilege RBAC, non-root, dropped
> capabilities, default-deny NetworkPolicies, the privileged node agent removed."

```bash
./kubeguard scan -i demo/manifests-hardened | tail -12
./kubeguard scan -i demo/manifests-hardened -f evidence -o demo/evidence-hardened
```

> "Zero findings, zero attack paths, **100% of assessed** across all nine
> frameworks — and the denominators are unchanged. Cyber Essentials is still
> *3 assessed*, now 3 passed. The evidence pack regenerates clean. That's the
> auditor's before-and-after, generated from the same source of truth."

### 6 · Close (9:30–10:00)
> "Offline. Read-only. Deterministic. And honest — every number is *breached of
> assessed* with an indicative-mapping disclaimer, never a green tick we can't
> stand behind. KubeGuard isn't just a scanner; it's an audit-evidence engine."

---

## One-screen cheat-sheet

```bash
go build -o kubeguard ./cmd/kubeguard

# Vulnerable: detect → chain → comply
./kubeguard scan -i demo/manifests

# Auditor evidence packs (HTML + JSON per framework)
./kubeguard scan -i demo/manifests -f evidence -o demo/evidence

# Hardened: 0 findings, 100% of assessed
./kubeguard scan -i demo/manifests-hardened
./kubeguard scan -i demo/manifests-hardened -f evidence -o demo/evidence-hardened

# Other reporters, if asked
./kubeguard scan -i demo/manifests -f json   -o demo/report.json
./kubeguard scan -i demo/manifests -f html   -o demo/report.html
./kubeguard scan -i demo/manifests -f sarif  -o demo/report.sarif
```

## Optional: live AWS variant

Same demo, but KubeGuard scans a **real cluster** — an ephemeral, locked-down
single-node kind cluster on one EC2 host — instead of files. Full automation and
safety/cost notes are in [`aws/README.md`](aws/README.md); this is how it slots
into the talk.

**Pre-provision before you walk on** (the cluster is up; on stage you only scan):

```bash
cd demo/aws
cp config.env.example config.env                       # set SSH_KEY
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
#   presenter_cidr = "$(curl -s https://checkip.amazonaws.com)/32" ; key_name = <your EC2 key>
./up.sh        # ~3-5 min: provision + kind + apply Thames Pay manifests
./scan.sh      # dry-run once to see the live output before stage
```

**On stage**, swap the offline opener (§1–§2) for the live scan, then continue
into compliance + evidence (§3–§4) exactly as before:

```bash
cd demo/aws && ./scan.sh        # live read-only scan + evidence packs → out/evidence/
```

**After the talk:**

```bash
./down.sh      # terraform destroy — "and it's gone"
```

What's true and worth saying — and **what's different from the offline run**:

- The Thames Pay findings and the **internet → cluster-admin** attack chain are
  all here: *one engine, now reading a live cluster via the read-only Kubernetes
  API*. KubeGuard mutates nothing.
- It assessed the **whole cluster, not just your app**. So you'll *also* see it
  flag the cluster's own system components — e.g. a **privileged, host-networked
  `kube-proxy`** — and every system namespace with no default-deny NetworkPolicy.
  That's the point: against a real cluster it reports the real, complete posture.
- **Therefore the live finding count is higher than the offline 53, and the
  compliance denominators grow** to cover the system workloads. Don't promise
  "exactly 53" on stage — say "the same app findings, *plus* the cluster's own
  posture." Honest metrics still hold: breached-of-assessed, nothing it couldn't
  evaluate is silently passed.
- Nothing needs to be **Running**: kind won't pull the placeholder images, yet
  every Deployment/RBAC object is fully assessed — KubeGuard reasons over declared
  intent.

> I build the automation; I don't provision anything for you. `up.sh` runs with
> *your* AWS credentials and creates only an ephemeral, SSH-from-your-IP-only host.

## What's in the vulnerable set

All 20 built-in checks (KG-001…020) fire across three namespaces:

| File | Workload | Highlights |
|---|---|---|
| [`10-payments-checkout.yaml`](manifests/10-payments-checkout.yaml) | `checkout` Deployment + RBAC | privileged, docker.sock, hostNetwork/PID, cluster-admin binding, wildcard+secrets+pods RBAC, internet LoadBalancer |
| [`20-frontend-web.yaml`](manifests/20-frontend-web.yaml) | `web` Deployment | default ServiceAccount, hostIPC, NodePort exposure |
| [`30-data-ledger.yaml`](manifests/30-data-ledger.yaml) | `ledger` StatefulSet + RBAC | secrets-reading Role, auto-mounted token, personal-data namespace |
| [`40-node-agent.yaml`](manifests/40-node-agent.yaml) | `node-agent` DaemonSet | privileged, full host-root mount, host namespaces |

> These manifests are deliberately insecure **demo data**, not directives, and
> must never be applied to a real cluster.
