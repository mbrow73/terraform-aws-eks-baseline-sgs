# AWS Security Group Platform - EKS Standard Profile
#
# Zero-trust EKS security groups with SG chaining.
# Uses aws_vpc_security_group_*_rule resources to avoid circular dependencies.
#
# 4 security groups:
#   1. baseline-eks-cluster     (control plane ENIs)
#   2. baseline-eks-workers     (worker node group)
#   3. baseline-istio-nodes     (dedicated istio gateway nodes)
#   4. baseline-intranet-nlb    (corporate/on-prem NLB)

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
    Profile = "eks-standard"
  })
}

resource "aws_security_group" "eks_workers" {
  name_prefix = "baseline-eks-workers-"
  description = "EKS worker nodes - zero-trust intra-cluster"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-eks-workers"
    Type    = "baseline"
    Profile = "eks-standard"
  })
}

resource "aws_security_group" "istio_nodes" {
  name_prefix = "baseline-istio-nodes-"
  description = "Istio dedicated gateway nodes - NLB ingress + mesh egress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-istio-nodes"
    Type    = "baseline"
    Profile = "eks-standard"
  })
}

resource "aws_security_group" "intranet_nlb" {
  name_prefix = "baseline-intranet-nlb-"
  description = "Intranet NLB - corporate/on-prem ingress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-intranet-nlb"
    Type    = "baseline"
    Profile = "eks-standard"
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
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_istio_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from istio gateway nodes"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_corporate_443" {
  security_group_id = aws_security_group.eks_cluster.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Kubernetes API from corporate networks (kubectl)"
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on worker nodes (logs, exec, metrics)"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_istio_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on istio gateway nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhooks on worker nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_15017" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook"
}

# =======================================================
# WORKERS - Worker Node Group
# =======================================================

# --- Ingress (control plane) ---

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_10250" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet (logs, exec, metrics)"
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_15017" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook from control plane"
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhook callbacks from control plane"
}

# --- Ingress (inter-node mesh: self) ---

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_self_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
}

# --- Ingress (inter-node mesh: from istio) ---

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "workers_mesh_in_istio_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio nodes"
}

# --- Egress (control plane + infra) ---

resource "aws_vpc_security_group_egress_rule" "workers_to_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
}

resource "aws_vpc_security_group_egress_rule" "workers_to_vpce_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints (ECR, S3, STS, CloudWatch)"
}

# Workers → on-prem addons via TGW
resource "aws_vpc_security_group_egress_rule" "workers_to_onprem_443" {
  security_group_id = aws_security_group.eks_workers.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS to on-prem services (addons, config) via TGW"
}

# --- Egress (inter-node mesh: self) ---

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_self_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
}

# --- Egress (inter-node mesh: to istio) ---

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_tcp_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_tcp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_udp_ephemeral" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_tcp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "workers_mesh_out_istio_udp_dns" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio nodes"
}

# =======================================================
# ISTIO NODES - Dedicated Istio Gateway Nodes
# =======================================================

# --- Ingress (from NLB) ---

resource "aws_vpc_security_group_ingress_rule" "istio_from_nlb_8080" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP from intranet NLB"
}

resource "aws_vpc_security_group_ingress_rule" "istio_from_nlb_8443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS from intranet NLB"
}

resource "aws_vpc_security_group_ingress_rule" "istio_from_nlb_15021" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check from NLB"
}

# --- Ingress (control plane) ---

resource "aws_vpc_security_group_ingress_rule" "istio_from_cluster_10250" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
}

resource "aws_vpc_security_group_ingress_rule" "istio_from_cluster_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Webhook callbacks from control plane"
}

# --- Ingress (inter-node mesh: self) ---

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_self_tcp_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_self_udp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio nodes"
}

# --- Ingress (inter-node mesh: from workers) ---

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
}

resource "aws_vpc_security_group_ingress_rule" "istio_mesh_in_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
}

# --- Egress (control plane + infra) ---

resource "aws_vpc_security_group_egress_rule" "istio_to_cluster_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
}

resource "aws_vpc_security_group_egress_rule" "istio_to_vpce_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints (ECR, S3, STS, CloudWatch)"
}

# --- Egress (inter-node mesh: self) ---

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_self_tcp_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_self_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_self_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_self_tcp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_self_udp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from istio nodes"
}

# --- Egress (inter-node mesh: to workers) ---

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_workers_tcp_443" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: HTTPS between workers"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_workers_tcp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: non-privileged TCP from workers"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_workers_udp_ephemeral" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: non-privileged UDP from workers"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_workers_tcp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "Inter-node mesh: DNS (TCP) from workers"
}

resource "aws_vpc_security_group_egress_rule" "istio_mesh_out_workers_udp_dns" {
  security_group_id            = aws_security_group.istio_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "Inter-node mesh: DNS (UDP) from workers"
}

# =======================================================
# INTRANET NLB - Corporate/On-Prem
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "nlb_from_corporate_443" {
  security_group_id = aws_security_group.intranet_nlb.id
  prefix_list_id    = var.corporate_networks_pl_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from corporate networks"
}

# --- Egress (to istio nodes) ---

resource "aws_vpc_security_group_egress_rule" "nlb_to_istio_8080" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP to istio gateway nodes"
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_istio_8443" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS to istio gateway nodes"
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_istio_15021" {
  security_group_id            = aws_security_group.intranet_nlb.id
  referenced_security_group_id = aws_security_group.istio_nodes.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check to gateway nodes"
}
