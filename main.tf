# AWS Security Group Platform - Baseline Security Groups
# Conditional deployment of baseline security group profiles based on account configuration

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  # Corporate mandatory tags — static values hardcoded so consumers don't need to know them
  mandatory_tags = {
    "<company>-app-env"             = var.environment
    "<company>-data-classification" = "internal"
    "<company>-app-carid"           = "600001725"
    "<company>-ops-supportgroup"    = "Security_Operations_Support"
    "<company>-app-supportgroup"    = "Security_Operations_Support"
    "<company>-provisioner-repo"    = "placeholder"
    "<company>-iam-access-control"  = "netsec"
    "<company>-provisioner-workspace" = "600001725-${var.environment}-sg-${var.account_id}"
  }

  # Consumer tags + mandatory corporate tags (mandatory always wins)
  common_tags = merge(var.tags, local.mandatory_tags)

  # Convert profile list to set for easier lookup
  enabled_profiles = toset(var.baseline_profiles)

  # Check if specific profiles are enabled
  # Both EKS profiles implicitly require vpc-endpoints — auto-enable it
  enable_vpc_endpoints = (
    contains(local.enabled_profiles, "vpc-endpoints") ||
    contains(local.enabled_profiles, "eks-standard") ||
    contains(local.enabled_profiles, "eks-internet")
  )
  enable_eks_standard = contains(local.enabled_profiles, "eks-standard")
  enable_eks_internet = contains(local.enabled_profiles, "eks-internet")
}

# Look up VPC details from the provided VPC ID
data "aws_vpc" "selected" {
  id = var.vpc_id
}

locals {
  vpc_id    = data.aws_vpc.selected.id
  vpc_cidrs = [for assoc in data.aws_vpc.selected.cidr_block_associations : assoc.cidr_block]
}

#
# Baseline Profile Modules - Conditionally deployed based on configuration
#

# VPC Endpoints Profile
# Auto-enabled when eks-standard is selected (SG chaining dependency)
module "vpc_endpoints" {
  count  = local.enable_vpc_endpoints ? 1 : 0
  source = "./profiles/vpc-endpoints"

  vpc_id      = local.vpc_id
  vpc_cidrs   = local.vpc_cidrs
  account_id  = var.account_id
  common_tags = local.common_tags
}

# EKS Standard Profile (intranet only)
# Depends on vpc-endpoints for SG chaining (auto-enabled above)
module "eks_standard" {
  count  = local.enable_eks_standard ? 1 : 0
  source = "./profiles/eks-standard"

  vpc_id              = local.vpc_id
  vpc_endpoints_sg_id = module.vpc_endpoints[0].vpc_endpoints_security_group_id
  account_id          = var.account_id
  common_tags         = local.common_tags
}

# EKS Internet Profile (intranet + internet paths)
# Depends on vpc-endpoints for SG chaining (auto-enabled above)
module "eks_internet" {
  count  = local.enable_eks_internet ? 1 : 0
  source = "./profiles/eks-internet"

  vpc_id              = local.vpc_id
  vpc_endpoints_sg_id = module.vpc_endpoints[0].vpc_endpoints_security_group_id
  account_id          = var.account_id
  common_tags         = local.common_tags
}