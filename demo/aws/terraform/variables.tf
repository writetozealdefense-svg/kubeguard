variable "region" {
  description = "AWS region. Defaults to London for the event."
  type        = string
  default     = "eu-west-2"
}

variable "presenter_cidr" {
  description = "CIDR allowed to SSH in — set to YOUR.IP/32. Find it with: curl -s https://checkip.amazonaws.com"
  type        = string
  # No default on purpose: an open SSH rule on an intentionally-vulnerable host
  # is exactly what we must avoid. You must set this.
  validation {
    condition     = can(cidrhost(var.presenter_cidr, 0)) && var.presenter_cidr != "0.0.0.0/0"
    error_message = "presenter_cidr must be a real CIDR and must not be 0.0.0.0/0."
  }
}

variable "key_name" {
  description = "Name of an existing EC2 key pair in the region (for SSH)."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type. t3.large (2 vCPU / 8 GiB) comfortably runs a small kind cluster."
  type        = string
  default     = "t3.large"
}

variable "ttl_minutes" {
  description = "Auto power-off after this many minutes, as a cost safety-net. Set generously above your talk slot."
  type        = number
  default     = 360
}

variable "notification_email" {
  description = "If set, creates a small AWS Budget that emails this address at 80% of budget_limit_usd. Leave empty to skip."
  type        = string
  default     = ""
}

variable "budget_limit_usd" {
  description = "Monthly budget cap (USD) for the optional cost alert."
  type        = string
  default     = "20"
}
