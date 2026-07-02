# Ephemeral, locked-down EC2 host for the KubeGuard live demo.
#
# It runs a single-node kind cluster (created by up.sh) with the deliberately
# vulnerable "Thames Pay" manifests applied, then KubeGuard scans it read-only.
#
# SAFETY: the only inbound rule is SSH from var.presenter_cidr (your IP /32).
# The Kubernetes API is NEVER exposed — the cluster is reached only over SSH on
# the box. There are no public LoadBalancers. The instance powers itself off
# after var.ttl_minutes as a cost safety-net, and `down.sh` (terraform destroy)
# removes everything.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = local.tags
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id
  tags   = local.tags
}

resource "aws_subnet" "demo" {
  vpc_id                  = aws_vpc.demo.id
  cidr_block              = "10.42.1.0/24"
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_route_table" "demo" {
  vpc_id = aws_vpc.demo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }
  tags = local.tags
}

resource "aws_route_table_association" "demo" {
  subnet_id      = aws_subnet.demo.id
  route_table_id = aws_route_table.demo.id
}

# SSH only, from the presenter's IP only. Nothing else is reachable.
resource "aws_security_group" "demo" {
  name        = "kubeguard-demo"
  description = "KubeGuard demo: SSH from presenter only; no other inbound"
  vpc_id      = aws_vpc.demo.id

  ingress {
    description = "SSH from presenter"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.presenter_cidr]
  }

  egress {
    description = "All outbound (pull images, install tooling)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_instance" "demo" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.demo.id
  vpc_security_group_ids      = [aws_security_group.demo.id]
  key_name                    = var.key_name
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/user-data.sh", {
    ttl_minutes = var.ttl_minutes
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = merge(local.tags, { Name = "kubeguard-demo" })
}

# Optional cost guardrail: a small monthly budget that emails at 80%.
resource "aws_budgets_budget" "demo" {
  count        = var.notification_email == "" ? 0 : 1
  name         = "kubeguard-demo"
  budget_type  = "COST"
  limit_amount = var.budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.notification_email]
  }
}

locals {
  tags = {
    project         = "kubeguard-demo"
    "auto-teardown" = "true"
    ephemeral       = "true"
  }
}
