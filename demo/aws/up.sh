#!/usr/bin/env bash
# Provision the locked-down EC2 host, cross-compile KubeGuard for Linux, upload
# it with the vulnerable manifests, and bring up the kind cluster.
#
# Run this BEFORE your talk. On stage you only run scan.sh. Afterwards: down.sh.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"
source ./config.env

echo "==> [1/5] terraform apply (provisioning host)..."
terraform -chdir=terraform init -input=false >/dev/null
terraform -chdir=terraform apply -auto-approve
IP="$(terraform -chdir=terraform output -raw public_ip)"
echo "    host: $IP"

SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "${SSH_USER}@${IP}")
SCP=(scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new)

echo "==> [2/5] waiting for SSH + cloud-init (Docker/kind/kubectl install)..."
for i in $(seq 1 60); do
  if "${SSH[@]}" "test -f /var/lib/cloud/kg-ready" 2>/dev/null; then
    echo "    host ready"
    break
  fi
  sleep 10
  [ "$i" -eq 60 ] && { echo "    timed out waiting for host"; exit 1; }
done

echo "==> [3/5] cross-compiling KubeGuard for linux/amd64..."
( cd "$REPO_ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -o "$HERE/kubeguard-linux-amd64" ./cmd/kubeguard )

echo "==> [4/5] uploading binary + manifests + bootstrap..."
"${SSH[@]}" "mkdir -p ~/kg/manifests"
"${SCP[@]}" "$HERE/kubeguard-linux-amd64" "${SSH_USER}@${IP}:~/kg/"
"${SCP[@]}" "$REPO_ROOT"/demo/manifests/*.yaml "${SSH_USER}@${IP}:~/kg/manifests/"
"${SCP[@]}" "$HERE/bootstrap-cluster.sh" "${SSH_USER}@${IP}:~/kg/"
"${SSH[@]}" "chmod +x ~/kg/kubeguard-linux-amd64 ~/kg/bootstrap-cluster.sh"

echo "==> [5/5] creating kind cluster + applying vulnerable manifests..."
"${SSH[@]}" "~/kg/bootstrap-cluster.sh"

echo
echo "Ready. Dry-run the scan now to confirm the stage output:"
echo "    ./scan.sh"
echo "When finished:  ./down.sh"
