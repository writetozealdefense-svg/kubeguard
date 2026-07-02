#!/usr/bin/env bash
# Cloud-init for the KubeGuard demo host. Installs Docker, kind, and kubectl,
# then signals readiness. The kind cluster itself and the manifests are applied
# by up.sh over SSH (kept out of cloud-init so they're easy to debug live).
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io curl ca-certificates jq

systemctl enable --now docker
usermod -aG docker ubuntu

# kind
curl -fsSLo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x /usr/local/bin/kind

# kubectl (pinned to a recent stable)
curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.30.2/bin/linux/amd64/kubectl"
chmod +x /usr/local/bin/kubectl

# Cost safety-net: power the box off after the TTL even if teardown is forgotten.
# (Compute billing stops on power-off; `down.sh` removes the rest.)
systemd-run --on-active=${ttl_minutes}min systemctl poweroff || true

# Readiness marker polled by up.sh.
touch /var/lib/cloud/kg-ready
