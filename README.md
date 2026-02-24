# terraform-aws-eks-baseline-sgs

Zero-trust EKS baseline security groups with SG chaining. Published to TFE private registry.

## Overview

This module deploys platform-owned, immutable security groups for EKS clusters. Teams consume it — they don't modify it. All rule changes go through PR review against this repo.

Three profiles, pick one:

| Profile | Use Case | SGs Created | Auto-includes |
|---------|----------|-------------|---------------|
| `eks-standard` | Intranet-only EKS clusters | 4 (cluster, workers, istio nodes, intranet NLB) | vpc-endpoints |
| `eks-internet` | Internet + intranet EKS clusters | 6 (above + internet istio nodes, internet NLB) | vpc-endpoints |
| `vpc-endpoints` | Non-EKS accounts needing VPCE access | 1 (VPC endpoint SG) | — |

`eks-standard` and `eks-internet` are **mutually exclusive** — pick one per account.

Both EKS profiles **automatically deploy vpc-endpoints** (SG chaining dependency). You don't need to add it.

## Usage

### Intranet-only EKS account

```hcl
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = "111222333444"
  vpc_id            = module.vpc.vpc_id
  environment       = "prod"
  baseline_profiles = ["eks-standard"]

  tags = {
    Team        = "payments"
    Environment = "prod"
  }
}

# Attach to EKS node group launch template
resource "aws_launch_template" "workers" {
  # ...
  vpc_security_group_ids = [
    module.baseline_sgs.eks_workers_security_group_id,
    module.baseline_sgs.istio_nodes_security_group_id,
  ]
}

# Attach to intranet NLB
resource "aws_lb" "intranet" {
  # ...
  security_groups = [module.baseline_sgs.intranet_nlb_security_group_id]
}
```

### Internet-facing EKS account

```hcl
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = "555666777888"
  vpc_id            = module.vpc.vpc_id
  environment       = "prod"
  baseline_profiles = ["eks-internet"]

  tags = {
    Team        = "frontend"
    Environment = "prod"
  }
}

# Internet-facing NLB
resource "aws_lb" "internet" {
  # ...
  security_groups = [module.baseline_sgs.inet_internet_nlb_security_group_id]
}

# Intranet NLB
resource "aws_lb" "intranet" {
  # ...
  security_groups = [module.baseline_sgs.inet_intranet_nlb_security_group_id]
}

# Worker nodes — attach all relevant SGs
resource "aws_launch_template" "workers" {
  # ...
  vpc_security_group_ids = [
    module.baseline_sgs.inet_eks_workers_security_group_id,
    module.baseline_sgs.inet_istio_intranet_nodes_security_group_id,
    module.baseline_sgs.inet_istio_inet_nodes_security_group_id,
  ]
}
```

### Shared services account (VPC endpoints only)

```hcl
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = "999000111222"
  vpc_id            = module.vpc.vpc_id
  environment       = "prod"
  baseline_profiles = ["vpc-endpoints"]

  tags = {
    Team        = "platform"
    Environment = "prod"
  }
}

# Attach to VPC endpoints
resource "aws_vpc_endpoint" "s3" {
  # ...
  security_group_ids = [module.baseline_sgs.vpc_endpoints_security_group_id]
}
```

### AFT Integration

In your AFT account customizations, call this module to deploy baseline SGs during account provisioning:

```hcl
# aft-account-customizations/EKS-INTRANET/terraform/main.tf
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = var.account_id
  vpc_id            = module.vpc.vpc_id
  environment       = var.environment
  baseline_profiles = ["eks-standard"]

  tags = {
    Team        = var.team_name
    Environment = var.environment
    ManagedBy   = "aft"
  }
}

# Export SG IDs for downstream consumers
output "baseline_sg_ids" {
  value = {
    cluster  = module.baseline_sgs.eks_cluster_security_group_id
    workers  = module.baseline_sgs.eks_workers_security_group_id
    istio    = module.baseline_sgs.istio_nodes_security_group_id
    nlb      = module.baseline_sgs.intranet_nlb_security_group_id
    vpce     = module.baseline_sgs.vpc_endpoints_security_group_id
  }
}
```

```hcl
# aft-account-customizations/EKS-INTERNET/terraform/main.tf
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = var.account_id
  vpc_id            = module.vpc.vpc_id
  environment       = var.environment
  baseline_profiles = ["eks-internet"]

  tags = {
    Team        = var.team_name
    Environment = var.environment
    ManagedBy   = "aft"
  }
}

output "baseline_sg_ids" {
  value = {
    cluster       = module.baseline_sgs.inet_eks_cluster_security_group_id
    workers       = module.baseline_sgs.inet_eks_workers_security_group_id
    istio_intra   = module.baseline_sgs.inet_istio_intranet_nodes_security_group_id
    nlb_intra     = module.baseline_sgs.inet_intranet_nlb_security_group_id
    istio_inet    = module.baseline_sgs.inet_istio_inet_nodes_security_group_id
    nlb_inet      = module.baseline_sgs.inet_internet_nlb_security_group_id
    vpce          = module.baseline_sgs.vpc_endpoints_security_group_id
  }
}
```

```hcl
# aft-account-customizations/SHARED-SERVICES/terraform/main.tf
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = var.account_id
  vpc_id            = module.vpc.vpc_id
  environment       = var.environment
  baseline_profiles = ["vpc-endpoints"]

  tags = {
    Team        = "platform"
    Environment = var.environment
    ManagedBy   = "aft"
  }
}

output "baseline_sg_ids" {
  value = {
    vpce = module.baseline_sgs.vpc_endpoints_security_group_id
  }
}
```

### Cross-account prefix list sharing

If accounts need to reference prefix lists from other accounts:

```hcl
module "baseline_sgs" {
  source  = "app.terraform.io/ORGNAME/eks-baseline-sgs/aws"
  version = "1.0.0"

  account_id        = "111222333444"
  vpc_id            = module.vpc.vpc_id
  environment       = "prod"
  baseline_profiles = ["eks-standard"]

  share_prefix_lists_with_accounts = [
    "555666777888",
    "999000111222",
  ]
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `account_id` | AWS Account ID (12-digit) | `string` | — | yes |
| `vpc_id` | VPC ID or `"auto"` for discovery | `string` | `"auto"` | no |
| `region` | AWS region (for prefix list overrides) | `string` | `"us-east-1"` | no |
| `baseline_profiles` | Profiles to deploy | `list(string)` | `[]` | yes |
| `environment` | Environment name for `<company>-app-env` tag | `string` | — | yes |
| `tags` | Additional tags (corporate mandatory tags are auto-included) | `map(string)` | `{}` | no |
| `share_prefix_lists_with_accounts` | Account IDs for RAM prefix list sharing | `list(string)` | `[]` | no |

## Outputs

### VPC Endpoints Profile
| Name | Description |
|------|-------------|
| `vpc_endpoints_security_group_id` | VPC endpoints SG ID |

### EKS Standard Profile
| Name | Description |
|------|-------------|
| `eks_cluster_security_group_id` | EKS control plane SG |
| `eks_workers_security_group_id` | EKS worker nodes SG |
| `istio_nodes_security_group_id` | Istio gateway nodes SG |
| `intranet_nlb_security_group_id` | Intranet NLB SG |

### EKS Internet Profile
| Name | Description |
|------|-------------|
| `inet_eks_cluster_security_group_id` | EKS control plane SG |
| `inet_eks_workers_security_group_id` | EKS worker nodes SG |
| `inet_istio_intranet_nodes_security_group_id` | Intranet istio nodes SG |
| `inet_intranet_nlb_security_group_id` | Intranet NLB SG |
| `inet_istio_inet_nodes_security_group_id` | Internet istio nodes SG |
| `inet_internet_nlb_security_group_id` | Internet NLB SG |

### Prefix Lists
| Name | Description |
|------|-------------|
| `prefix_lists` | Map of all managed prefix list IDs |

## Architecture

See [BASELINE-PROFILES.md](./BASELINE-PROFILES.md) for detailed SG rules and chaining diagrams.

**Key design principles:**
- **SG chaining over CIDRs** — cross-SG rules reference security group IDs, not subnets
- **Full mTLS** — strict istio mTLS means all traffic routes through envoy. Minimal ports needed.
- **Standalone rule resources** — `aws_vpc_security_group_*_rule` to avoid circular dependencies
- **VPC endpoint access via endpoint policies + IAM** — not SGs (risk acceptance documented)

## Versioning

This module uses semantic versioning. Pin to a specific version in consumers:

```hcl
version = "1.0.0"   # exact pin
version = "~> 1.0"  # patch updates only
```

**Updating baselines:**
1. PR against this repo with rule changes
2. Platform team reviews + approves
3. Merge → new version tag
4. Update version pin in consuming modules (canary one account first)

## Testing

Tests run with `mock_provider` — no AWS credentials needed:

```bash
cd tests/
terraform test
```
