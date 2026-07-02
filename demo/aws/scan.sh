#!/usr/bin/env bash
# The on-stage command: KubeGuard scans the LIVE kind cluster read-only over SSH,
# then exports the per-framework auditor evidence packs and pulls them back here.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
source ./config.env

IP="$(terraform -chdir=terraform output -raw public_ip)"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "${SSH_USER}@${IP}")
SCP=(scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new)

echo "============================================================"
echo " KubeGuard — LIVE read-only scan of kind cluster on $IP"
echo "============================================================"
# Read-only. KubeGuard reads declared resources via kubeconfig; it never mutates.
"${SSH[@]}" "cd ~/kg && ./kubeguard-linux-amd64 scan --live"

echo
echo "==> exporting auditor evidence packs (HTML + JSON per framework)..."
"${SSH[@]}" "cd ~/kg && rm -rf evidence && ./kubeguard-linux-amd64 scan --live -f evidence -o evidence"

mkdir -p out
rm -rf out/evidence
"${SCP[@]}" -r "${SSH_USER}@${IP}:~/kg/evidence" out/ >/dev/null
echo "    evidence pulled to demo/aws/out/evidence/"
echo "    open out/evidence/uk-gdpr-dpa-2018.evidence.html  (and ncsc-caf-4 / cyber-essentials)"
