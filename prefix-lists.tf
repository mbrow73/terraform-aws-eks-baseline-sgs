# Managed Prefix Lists
# Creates AWS Managed Prefix Lists from centralized YAML configuration

locals {
  prefix_lists = yamldecode(file("${path.module}/prefix-lists.yaml")).prefix_lists
}

# Corporate Networks
resource "aws_ec2_managed_prefix_list" "corporate_networks" {
  name           = local.prefix_lists.corporate-networks.name
  address_family = local.prefix_lists.corporate-networks.address_family
  max_entries    = local.prefix_lists.corporate-networks.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.corporate-networks.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.corporate-networks.tags, {
    Name = local.prefix_lists.corporate-networks.name
  })
}

# WAF/SaaS Providers
resource "aws_ec2_managed_prefix_list" "waf_saas_providers" {
  name           = local.prefix_lists.waf-saas-providers.name
  address_family = local.prefix_lists.waf-saas-providers.address_family
  max_entries    = local.prefix_lists.waf-saas-providers.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.waf-saas-providers.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.waf-saas-providers.tags, {
    Name = local.prefix_lists.waf-saas-providers.name
  })
}

# RAM sharing for cross-account prefix list access
resource "aws_ram_resource_share" "prefix_lists" {
  count                     = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  name                      = "baseline-sgs-prefix-lists-${var.account_id}"
  allow_external_principals = false

  tags = merge(local.common_tags, {
    Name    = "baseline-sgs-prefix-lists"
    Purpose = "cross-account-sharing"
  })
}

resource "aws_ram_resource_association" "prefix_lists" {
  for_each = length(var.share_prefix_lists_with_accounts) > 0 ? {
    corporate_networks = aws_ec2_managed_prefix_list.corporate_networks.arn
    waf_saas_providers = aws_ec2_managed_prefix_list.waf_saas_providers.arn
  } : {}

  resource_arn       = each.value
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_principal_association" "accounts" {
  count              = length(var.share_prefix_lists_with_accounts)
  principal          = var.share_prefix_lists_with_accounts[count.index]
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}
