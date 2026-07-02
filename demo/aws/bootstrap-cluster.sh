#!/usr/bin/env bash
# Runs ON the demo host (uploaded by up.sh). Creates a single-node kind cluster
# and applies the vulnerable Thames Pay manifests. Idempotent.
set -euo pipefail

CLUSTER=kg-demo
KG_DIR="$HOME/kg"

# kind runs fine under sudo; use it to avoid docker-group re-login races.
if ! sudo kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "[bootstrap] creating kind cluster '$CLUSTER'..."
  sudo kind create cluster --name "$CLUSTER" --wait 120s
else
  echo "[bootstrap] cluster '$CLUSTER' already exists"
fi

mkdir -p "$HOME/.kube"
sudo kind get kubeconfig --name "$CLUSTER" > "$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"

echo "[bootstrap] applying vulnerable Thames Pay manifests..."
kubectl apply -f "$KG_DIR/manifests/"

echo "[bootstrap] --- namespaces ---"
kubectl get ns | grep thamespay || true
echo "[bootstrap] --- workloads (specs are what KubeGuard reads; pods need not be Running) ---"
kubectl get deploy,statefulset,daemonset -A | grep thamespay || true
echo "[bootstrap] done"
