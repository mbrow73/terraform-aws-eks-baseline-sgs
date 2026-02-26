variable "account_id" {
  description = "AWS Account ID where resources will be deployed"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}


variable "vpc_id" {
  description = "VPC ID where security groups will be created"
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "VPC ID must be a valid VPC ID (vpc-xxxxxxxx)."
  }
}

variable "baseline_profiles" {
  description = "List of baseline profiles to deploy: vpc-endpoints, eks-standard, eks-internet. EKS profiles auto-enable vpc-endpoints."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for profile in var.baseline_profiles :
      contains(["vpc-endpoints", "eks-standard", "eks-internet"], profile)
    ])
    error_message = "Valid profiles: vpc-endpoints, eks-standard, eks-internet."
  }

  validation {
    condition     = !(contains(var.baseline_profiles, "eks-standard") && contains(var.baseline_profiles, "eks-internet"))
    error_message = "eks-standard and eks-internet are mutually exclusive. Choose one."
  }
}

variable "environment" {
  description = "Environment name for the <company>-app-env corporate mandatory tag (e.g. dev, staging, prod)"
  type        = string
}


variable "tags" {
  description = "Additional tags to apply to all resources. Corporate mandatory tags are automatically included - you do not need to pass them here."
  type        = map(string)
  default     = {}
}

