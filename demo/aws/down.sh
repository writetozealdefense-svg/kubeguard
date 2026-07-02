#!/usr/bin/env bash
# Tear EVERYTHING down: instance, VPC, security group, budget. Run after the talk.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> terraform destroy (removing all demo AWS resources)..."
terraform -chdir=terraform destroy -auto-approve

# Local artifacts from the run.
rm -f kubeguard-linux-amd64
rm -rf out

echo "Done. Verify nothing lingers:"
echo "    terraform -chdir=terraform show    # should be empty"
echo "    aws ec2 describe-instances --filters Name=tag:project,Values=kubeguard-demo --query 'Reservations[].Instances[].State.Name'"
