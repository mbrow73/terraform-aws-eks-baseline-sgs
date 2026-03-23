# AWS Security Group Platform - EKS Internet Profile
#
# Internet-facing EKS clusters with both intranet and internet paths.
# Zero-trust SG chaining with client IP preservation on NLBs.
#
# 6 security groups:
#   1. baseline-eks-cluster          (control plane ENIs)
#   2. baseline-eks-workers          (worker nodes - serves both istio paths)
#   3. baseline-istio-intranet-nodes (intranet istio gateways)
#   4. baseline-intranet-nlb         (corporate/on-prem NLB)
#   5. baseline-istio-inet-nodes     (internet istio gateways)
#   6. baseline-internet-nlb         (internet-facing NLB)
#
# Traffic flows:
#   Internet: WAF NAT IPs → IGW → GWLBe → Internet NLB → Istio inet nodes → Workers
#   Intranet: Corporate PL → Intranet NLB → Istio intranet nodes → Workers
#   On-prem:  Inet cluster → GWLBe core → TGW → on-prem (routed, no SG needed)
#
# NLBs are transparent (client IP preservation ON). Source IPs are preserved
# through the entire chain, so istio SGs accept from the original source
# (WAF prefix list or corporate prefix list), not the NLB IPs.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -------------------------------------------------------
# Data Sources
# -------------------------------------------------------

# -------------------------------------------------------
# Security Group Shells (no inline rules - avoids cycles)
# -------------------------------------------------------

resource "aws_security_group" "eks_cluster" {
  name_prefix = "baseline-eks-cluster-"
  description = "EKS control plane - API server + kubelet/webhook egress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-eks-cluster"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "eks_workers" {
  name_prefix = "baseline-eks-workers-"
  description = "EKS worker nodes - serves both intranet and internet istio paths"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-eks-workers"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "istio_intranet_nodes" {
  name_prefix = "baseline-istio-intranet-"
  description = "Istio intranet gateways - corporate/on-prem traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-istio-intranet-nodes"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "intranet_nlb" {
  name_prefix = "baseline-intranet-nlb-"
  description = "Intranet NLB - corporate/on-prem ingress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-intranet-nlb"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "istio_inet_nodes" {
  name_prefix = "baseline-istio-inet-"
  description = "Istio internet gateways - WAF/internet traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-istio-inet-nodes"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "internet_nlb" {
  name_prefix = "baseline-internet-nlb-"
  description = "Internet NLB - WAF NAT IP ingress (client IP preserved)"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-internet-nlb"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

# =======================================================
# CLUSTER - Control Plane ENIs
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "cluster_from_workers_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from worker nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_istio_intranet_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from intranet istio nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_istio_inet_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from internet istio nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_corporate_443" {
  security_group_id = aws_security_group.eks_cluster.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Kubernetes API from corporate networks (kubectl)"
  tags = var.common_tags
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on worker nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_istio_intranet_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on intranet istio nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_istio_inet_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on internet istio nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhooks on worker nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_15017" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook"
  tags = var.common_tags
}

# =======================================================
# WORKERS - Shared Worker Nodes (serves both istio paths)
# =======================================================

# --- Ingress (control plane) ---

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_10250" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_15017" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook from control plane"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhook callbacks from control plane"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: self) ---

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from istio-intranet) ---

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_intranet_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_intranet_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_intranet_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_intranet_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_intranet_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from istio-inet) ---

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_inet_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_inet_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_inet_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_inet_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_inet_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# --- Egress (control plane + infra) ---

resource "aws_vpc_security_group_egress_rule" "workers_to_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_to_vpce_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints (ECR, S3, STS, CloudWatch)"
  tags = var.common_tags
}

# Workers → on-prem addons via TGW
resource "aws_vpc_security_group_egress_rule" "workers_to_onprem_443" {
  security_group_id = aws_security_group.eks_workers.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS to on-prem services (addons, config) via TGW"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: self) ---

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to istio-intranet) ---

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_intranet_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_intranet_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_intranet_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_intranet_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_intranet_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to istio-inet) ---

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_inet_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_inet_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_inet_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_inet_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_inet_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# =======================================================
# ISTIO INTRANET NODES - Corporate/On-Prem Path
# =======================================================

# --- Ingress (from intranet NLB) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_8080" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP from intranet NLB"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_8443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS from intranet NLB"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_15021" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check from NLB"
  tags = var.common_tags
}

# --- Ingress (control plane) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_cluster_10250" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_cluster_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Webhook callbacks from control plane"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: self) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_self_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_self_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from workers) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from istio-inet) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_istio_inet_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_istio_inet_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_istio_inet_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_istio_inet_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_mesh_in_istio_inet_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# --- Egress (control plane + infra) ---

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_cluster_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_vpce_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: self) ---

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_self_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_self_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to workers) ---

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to istio-inet) ---

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_istio_inet_tcp_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_istio_inet_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_istio_inet_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_istio_inet_tcp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_mesh_out_istio_inet_udp_dns" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# =======================================================
# INTRANET NLB - Corporate/On-Prem
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "intranet_nlb_from_corporate_443" {
  security_group_id = aws_security_group.intranet_nlb.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from corporate networks"
  tags = var.common_tags
}

# --- Egress (to istio-intranet nodes) ---

resource "aws_vpc_security_group_egress_rule" "intranet_nlb_to_istio_8080" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP to istio intranet gateway nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "intranet_nlb_to_istio_8443" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS to istio intranet gateway nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "intranet_nlb_to_istio_15021" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check to intranet gateway nodes"
  tags = var.common_tags
}

# =======================================================
# ISTIO INTERNET NODES - WAF/Internet Path
# Client IP preserved through NLB - source is WAF NAT IPs
# =======================================================

# --- Ingress (source = WAF NAT IPs, preserved through transparent NLB) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_8080" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = var.waf_nat_ips_pl_id
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  description       = "HTTP from WAF (client IP preserved through NLB)"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_8443" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = var.waf_nat_ips_pl_id
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
  description       = "HTTPS from WAF (client IP preserved through NLB)"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_15021" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = var.waf_nat_ips_pl_id
  from_port         = 15021
  to_port           = 15021
  ip_protocol       = "tcp"
  description       = "Istio health check from NLB (WAF source)"
  tags = var.common_tags
}

# --- Ingress (control plane) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_cluster_10250" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_cluster_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Webhook callbacks from control plane"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: self) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_self_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_self_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from workers) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Ingress (inter-node mesh: from istio-intranet) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_istio_intranet_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_istio_intranet_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_istio_intranet_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_istio_intranet_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_mesh_in_istio_intranet_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# --- Egress (control plane + infra) ---

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_cluster_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_vpce_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: self) ---

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_self_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-inet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_self_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-inet nodes"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to workers) ---

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
  tags = var.common_tags
}

# --- Egress (inter-node mesh: to istio-intranet) ---

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_istio_intranet_tcp_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_istio_intranet_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_istio_intranet_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_istio_intranet_tcp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio-intranet nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_mesh_out_istio_intranet_udp_dns" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio-intranet nodes"
  tags = var.common_tags
}

# =======================================================
# INTERNET NLB - WAF NAT IP Ingress
# NLB is transparent - this SG is for the NLB ENIs.
# Client IP preservation ON, so source = WAF NAT IPs.
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "internet_nlb_from_waf_443" {
  security_group_id = aws_security_group.internet_nlb.id
  prefix_list_id    = var.waf_nat_ips_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from WAF NAT IPs"
  tags = var.common_tags
}

# --- Egress (to istio-inet nodes) ---

resource "aws_vpc_security_group_egress_rule" "internet_nlb_to_istio_8080" {
  security_group_id            = aws_security_group.internet_nlb.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP to istio internet gateway nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "internet_nlb_to_istio_8443" {
  security_group_id            = aws_security_group.internet_nlb.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS to istio internet gateway nodes"
  tags = var.common_tags
}

resource "aws_vpc_security_group_egress_rule" "internet_nlb_to_istio_15021" {
  security_group_id            = aws_security_group.internet_nlb.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check to internet gateway nodes"
  tags = var.common_tags
}
