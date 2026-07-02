# Live AWS demo — provision → scan → tear down

Stands up an **ephemeral, locked-down** single-node Kubernetes cluster (kind on
one EC2 host) in AWS, applies the deliberately vulnerable **Thames Pay**
manifests, lets **KubeGuard scan it live and read-only**, exports the per-
framework auditor evidence packs, and tears everything down.

> This deploys *intentionally vulnerable* workloads. The design keeps them
> **private and ephemeral** — read the Safety section before you run it.

## What gets created

```
your laptop ──SSH (port 22, your IP only)──▶  EC2 (Ubuntu, t3.large)
                                                 └─ kind cluster "kg-demo"
                                                      └─ Thames Pay (vulnerable)
KubeGuard runs ON the host over SSH → scans the cluster via kubeconfig (read-only)
```

- Dedicated VPC + subnet, **security group allows SSH from your IP only**.
- **No public LoadBalancers; the Kubernetes API is never exposed** (reached only
  over SSH on the box).
- Auto power-off after `ttl_minutes` (cost safety-net) + optional AWS Budget alert.
- `down.sh` (`terraform destroy`) removes everything.

## Safety (read this)

- **Never widen `presenter_cidr` to `0.0.0.0/0`.** Terraform rejects it. An open
  SSH rule on a vulnerable host is the one thing we must avoid.
- Use a **throwaway/sandbox AWS account** with no production data or peering.
- The vulnerable workloads have no real data and no public ingress; KubeGuard
  itself is read-only and offline. The only exposure is SSH to your IP.
- Tear down promptly. The TTL power-off is a net, not a substitute for `down.sh`.

## Cost

A `t3.large` is ~£0.08/hr in London; a VPC/SG/IGW are free. A 1–2 hour
pre-provision-then-teardown session is **well under £1**. Set
`notification_email` to get an AWS Budget alert as a backstop.

## Prerequisites

- AWS CLI configured (`aws sts get-caller-identity` works), **Terraform ≥ 1.5**,
  Go, `ssh`/`scp`, and an existing **EC2 key pair** in the target region.
- These scripts are bash (macOS/Linux, or WSL/Git-Bash on Windows).

## One-time setup

```bash
cd demo/aws
cp config.env.example config.env                      # set SSH_KEY to your .pem
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
#   set presenter_cidr = "$(curl -s https://checkip.amazonaws.com)/32"
#   set key_name       = <your EC2 key pair name>
```

## Run it

```bash
# BEFORE the talk — provision + cluster + manifests (~3-5 min):
./up.sh

# Dry-run once to confirm the stage output (Thames Pay findings + the cluster's
# own system posture; all 9 frameworks):
./scan.sh

# ON STAGE — the single command:
./scan.sh

# AFTER the talk — remove everything:
./down.sh
```

`scan.sh` prints the live console report and writes the evidence packs to
`demo/aws/out/evidence/` — open `uk-gdpr-dpa-2018.evidence.html`,
`ncsc-caf-4.evidence.html`, and `cyber-essentials.evidence.html` in a browser.

## Stage patter (the live-cluster beats)

1. **"This is a real cluster in AWS, not a file."** Run `./scan.sh`.
2. **The same Thames Pay findings and the internet → cluster-admin attack chain**
   you saw offline are all here — *one engine, file or live*, reading via the
   read-only Kubernetes API. KubeGuard mutates nothing.
3. **"And it assessed the whole cluster, not just my app."** You'll also see it
   flag the cluster's own system components — e.g. a privileged, host-networked
   `kube-proxy` — and system namespaces with no default-deny NetworkPolicy. So the
   live finding count is **higher than the offline 53** and the denominators grow.
   Say *"the same app findings, plus the cluster's real posture,"* not "exactly
   53." Honest metrics still hold.
4. **"Nothing even needs to be Running."** kind won't pull the placeholder images,
   yet every Deployment/RBAC object is fully assessed — KubeGuard reasons over
   declared intent.
5. Land the UK/honest-metrics + evidence-pack story exactly as in
   [`../README.md`](../README.md) §3–§4, now sourced from a live cluster.
6. `./down.sh` — "and it's gone."

## Troubleshooting

- **SSH times out** → `presenter_cidr` is stale (your IP changed / you're on a
  different network). Re-set it and `terraform -chdir=terraform apply` again.
- **`scan.sh` shows 0 findings** → the bootstrap didn't apply manifests; re-run
  `ssh ... '~/kg/bootstrap-cluster.sh'` (or just `./up.sh`, it's idempotent).
- **Forgot to tear down?** The host powers off after `ttl_minutes`; still run
  `./down.sh` to release the EBS volume and VPC.
