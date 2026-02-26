# EKS Internet Profile Variables

variable "vpc_id" {
  description = "VPC ID where security groups will be created"
  type        = string
}

variable "vpc_endpoints_sg_id" {
  description = "Security group ID of the VPC endpoints SG (from vpc-endpoints baseline profile)"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "corporate_networks_pl_id" {
  description = "ID of the corporate-networks managed prefix list"
  type        = string
}

variable "waf_nat_ips_pl_id" {
  description = "ID of the waf-nat-ips managed prefix list"
  type        = string
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
