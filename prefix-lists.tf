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

# WAF NAT IPs
resource "aws_ec2_managed_prefix_list" "waf_nat_ips" {
  name           = local.prefix_lists.waf-nat-ips.name
  address_family = local.prefix_lists.waf-nat-ips.address_family
  max_entries    = local.prefix_lists.waf-nat-ips.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.waf-nat-ips.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.waf-nat-ips.tags, {
    Name = local.prefix_lists.waf-nat-ips.name
  })
}

