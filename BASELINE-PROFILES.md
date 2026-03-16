# Baseline Security Group Profiles

## eks-standard (Intranet Only)

> 5 security groups, 66 rules. Zero `0.0.0.0/0`. All cross-SG traffic uses security group references. HTTPS-only — no port 80. Inter-node mesh uses 443 + non-privileged ports (1024-65535) + DNS — privileged ports blocked between nodes.

### Security Groups

| Security Group | Description |
|---|---|
| `baseline-vpc-endpoints` | VPC interface endpoints - ingress from local VPC only |
| `baseline-eks-cluster` | EKS control plane - API server + kubelet/webhook egress |
| `baseline-eks-workers` | Worker nodes - inter-node mesh with non-privileged port range |
| `baseline-istio-nodes` | Istio intranet gateways - NLB ingress + mesh to workers |
| `baseline-intranet-nlb` | Intranet NLB - corporate/on-prem ingress |

### Rules

#### baseline-vpc-endpoints

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | VPC CIDR | HTTPS to interface endpoints |

#### baseline-eks-cluster

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `eks-workers` SG | Kubernetes API from workers |
| ingress | 443 | tcp | ← `istio-nodes` SG | Kubernetes API from istio |
| ingress | 443 | tcp | ← `corporate-networks` PL | kubectl from corporate |
| egress | 443 | tcp | → `eks-workers` SG | Admission webhooks |
| egress | 10250 | tcp | → `eks-workers` SG | Kubelet (logs, exec, metrics) |
| egress | 10250 | tcp | → `istio-nodes` SG | Kubelet on istio nodes |
| egress | 15017 | tcp | → `eks-workers` SG | Istiod sidecar injection webhook |

#### baseline-eks-workers

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| | | | **Control plane** | |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15017 | tcp | ← `eks-cluster` SG | Istiod sidecar injection |
| ingress | 443 | tcp | ← `eks-cluster` SG | Admission webhook callbacks |
| | | | **Inter-node mesh (self)** | |
| ingress | 443 | tcp | ← self | HTTPS between workers |
| ingress | 1024-65535 | tcp | ← self | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← self | Non-privileged UDP |
| ingress | 53 | tcp | ← self | DNS (TCP) |
| ingress | 53 | udp | ← self | DNS (UDP) |
| | | | **Inter-node mesh (from istio)** | |
| ingress | 443 | tcp | ← `istio-nodes` SG | HTTPS from istio nodes |
| ingress | 1024-65535 | tcp | ← `istio-nodes` SG | Non-privileged TCP from istio |
| ingress | 1024-65535 | udp | ← `istio-nodes` SG | Non-privileged UDP from istio |
| ingress | 53 | tcp | ← `istio-nodes` SG | DNS (TCP) from istio |
| ingress | 53 | udp | ← `istio-nodes` SG | DNS (UDP) from istio |
| | | | **Egress** | |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → `corporate-networks` PL | On-prem addons via TGW |
| egress | 443 | tcp | → self | HTTPS between workers |
| egress | 1024-65535 | tcp | → self | Non-privileged TCP |
| egress | 1024-65535 | udp | → self | Non-privileged UDP |
| egress | 53 | tcp | → self | DNS (TCP) |
| egress | 53 | udp | → self | DNS (UDP) |
| egress | 443 | tcp | → `istio-nodes` SG | HTTPS to istio nodes |
| egress | 1024-65535 | tcp | → `istio-nodes` SG | Non-privileged TCP to istio |
| egress | 1024-65535 | udp | → `istio-nodes` SG | Non-privileged UDP to istio |
| egress | 53 | tcp | → `istio-nodes` SG | DNS (TCP) to istio |
| egress | 53 | udp | → `istio-nodes` SG | DNS (UDP) to istio |

#### baseline-istio-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| | | | **NLB ingress** | |
| ingress | 8443 | tcp | ← `intranet-nlb` SG | HTTPS from NLB |
| ingress | 8080 | tcp | ← `intranet-nlb` SG | HTTP from NLB |
| ingress | 15021 | tcp | ← `intranet-nlb` SG | Health check from NLB |
| | | | **Control plane** | |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| | | | **Inter-node mesh (self)** | |
| ingress | 443 | tcp | ← self | HTTPS between istio nodes |
| ingress | 1024-65535 | tcp | ← self | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← self | Non-privileged UDP |
| ingress | 53 | tcp | ← self | DNS (TCP) |
| ingress | 53 | udp | ← self | DNS (UDP) |
| | | | **Inter-node mesh (from workers)** | |
| ingress | 443 | tcp | ← `eks-workers` SG | HTTPS from workers |
| ingress | 1024-65535 | tcp | ← `eks-workers` SG | Non-privileged TCP from workers |
| ingress | 1024-65535 | udp | ← `eks-workers` SG | Non-privileged UDP from workers |
| ingress | 53 | tcp | ← `eks-workers` SG | DNS (TCP) from workers |
| ingress | 53 | udp | ← `eks-workers` SG | DNS (UDP) from workers |
| | | | **Egress** | |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → self | HTTPS between istio nodes |
| egress | 1024-65535 | tcp | → self | Non-privileged TCP |
| egress | 1024-65535 | udp | → self | Non-privileged UDP |
| egress | 53 | tcp | → self | DNS (TCP) |
| egress | 53 | udp | → self | DNS (UDP) |
| egress | 443 | tcp | → `eks-workers` SG | HTTPS to workers |
| egress | 1024-65535 | tcp | → `eks-workers` SG | Non-privileged TCP to workers |
| egress | 1024-65535 | udp | → `eks-workers` SG | Non-privileged UDP to workers |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) to workers |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) to workers |

#### baseline-intranet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `corporate-networks` PL | HTTPS from corporate |
| egress | 8080 | tcp | → `istio-nodes` SG | HTTP to istio gateway |
| egress | 8443 | tcp | → `istio-nodes` SG | HTTPS to istio gateway |
| egress | 15021 | tcp | → `istio-nodes` SG | Istio health check |

---

## eks-internet (Internet + Intranet)

> 7 security groups, ~130 rules. Zero `0.0.0.0/0`. HTTPS-only — no port 80. NLB client IP preservation enabled. Inter-node mesh uses 443 + non-privileged ports (1024-65535) + DNS — privileged ports blocked between nodes.

> Traffic flow: WAF NAT IPs → IGW → GWLBe (transparent) → Internet NLB → Istio inet → Workers

> Mutually exclusive with `eks-standard`. Pick one per account.

### Security Groups

| Security Group | Description |
|---|---|
| `baseline-vpc-endpoints` | VPC interface endpoints - ingress from local VPC only |
| `baseline-eks-cluster` | EKS control plane - shared, serves both istio paths |
| `baseline-eks-workers` | Worker nodes - shared, mesh with both istio node groups |
| `baseline-istio-intranet-nodes` | Istio intranet gateways - corporate/on-prem traffic |
| `baseline-intranet-nlb` | Intranet NLB - corporate prefix list ingress |
| `baseline-istio-inet-nodes` | Istio internet gateways - WAF/internet traffic |
| `baseline-internet-nlb` | Internet NLB - WAF NAT IP ingress (client IP preserved) |

### Rules

#### baseline-vpc-endpoints

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | VPC CIDR | HTTPS to interface endpoints |

#### baseline-eks-cluster

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `eks-workers` SG | Kubernetes API from workers |
| ingress | 443 | tcp | ← `istio-intranet-nodes` SG | Kubernetes API from intranet istio |
| ingress | 443 | tcp | ← `istio-inet-nodes` SG | Kubernetes API from internet istio |
| ingress | 443 | tcp | ← `corporate-networks` PL | kubectl from corporate |
| egress | 443 | tcp | → `eks-workers` SG | Admission webhooks |
| egress | 10250 | tcp | → `eks-workers` SG | Kubelet on workers |
| egress | 10250 | tcp | → `istio-intranet-nodes` SG | Kubelet on intranet istio |
| egress | 10250 | tcp | → `istio-inet-nodes` SG | Kubelet on internet istio |
| egress | 15017 | tcp | → `eks-workers` SG | Istiod sidecar injection |

#### baseline-eks-workers

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| | | | **Control plane** | |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15017 | tcp | ← `eks-cluster` SG | Istiod sidecar injection |
| ingress | 443 | tcp | ← `eks-cluster` SG | Admission webhook callbacks |
| | | | **Inter-node mesh (self)** | |
| ingress | 443 | tcp | ← self | HTTPS between workers |
| ingress | 1024-65535 | tcp | ← self | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← self | Non-privileged UDP |
| ingress | 53 | tcp | ← self | DNS (TCP) |
| ingress | 53 | udp | ← self | DNS (UDP) |
| | | | **Inter-node mesh (from istio-intranet)** | |
| ingress | 443 | tcp | ← `istio-intranet-nodes` SG | HTTPS from intranet istio |
| ingress | 1024-65535 | tcp | ← `istio-intranet-nodes` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `istio-intranet-nodes` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `istio-intranet-nodes` SG | DNS (TCP) |
| ingress | 53 | udp | ← `istio-intranet-nodes` SG | DNS (UDP) |
| | | | **Inter-node mesh (from istio-inet)** | |
| ingress | 443 | tcp | ← `istio-inet-nodes` SG | HTTPS from internet istio |
| ingress | 1024-65535 | tcp | ← `istio-inet-nodes` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `istio-inet-nodes` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `istio-inet-nodes` SG | DNS (TCP) |
| ingress | 53 | udp | ← `istio-inet-nodes` SG | DNS (UDP) |
| | | | **Egress** | |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → `corporate-networks` PL | On-prem addons via TGW |
| egress | 443 | tcp | → self | HTTPS between workers |
| egress | 1024-65535 | tcp | → self | Non-privileged TCP |
| egress | 1024-65535 | udp | → self | Non-privileged UDP |
| egress | 53 | tcp | → self | DNS (TCP) |
| egress | 53 | udp | → self | DNS (UDP) |
| egress | 443 | tcp | → `istio-intranet-nodes` SG | HTTPS to intranet istio |
| egress | 1024-65535 | tcp | → `istio-intranet-nodes` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `istio-intranet-nodes` SG | Non-privileged UDP |
| egress | 53 | tcp | → `istio-intranet-nodes` SG | DNS (TCP) |
| egress | 53 | udp | → `istio-intranet-nodes` SG | DNS (UDP) |
| egress | 443 | tcp | → `istio-inet-nodes` SG | HTTPS to internet istio |
| egress | 1024-65535 | tcp | → `istio-inet-nodes` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `istio-inet-nodes` SG | Non-privileged UDP |
| egress | 53 | tcp | → `istio-inet-nodes` SG | DNS (TCP) |
| egress | 53 | udp | → `istio-inet-nodes` SG | DNS (UDP) |

#### baseline-istio-intranet-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| | | | **NLB ingress** | |
| ingress | 8443 | tcp | ← `intranet-nlb` SG | HTTPS from NLB |
| ingress | 8080 | tcp | ← `intranet-nlb` SG | HTTP from NLB |
| ingress | 15021 | tcp | ← `intranet-nlb` SG | Health check from NLB |
| | | | **Control plane** | |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| | | | **Inter-node mesh (self)** | |
| ingress | 443 | tcp | ← self | HTTPS between intranet istio |
| ingress | 1024-65535 | tcp | ← self | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← self | Non-privileged UDP |
| ingress | 53 | tcp | ← self | DNS (TCP) |
| ingress | 53 | udp | ← self | DNS (UDP) |
| | | | **Inter-node mesh (from workers)** | |
| ingress | 443 | tcp | ← `eks-workers` SG | HTTPS from workers |
| ingress | 1024-65535 | tcp | ← `eks-workers` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `eks-workers` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `eks-workers` SG | DNS (TCP) |
| ingress | 53 | udp | ← `eks-workers` SG | DNS (UDP) |
| | | | **Inter-node mesh (from istio-inet)** | |
| ingress | 443 | tcp | ← `istio-inet-nodes` SG | HTTPS from internet istio |
| ingress | 1024-65535 | tcp | ← `istio-inet-nodes` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `istio-inet-nodes` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `istio-inet-nodes` SG | DNS (TCP) |
| ingress | 53 | udp | ← `istio-inet-nodes` SG | DNS (UDP) |
| | | | **Egress** | |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → self | HTTPS between intranet istio |
| egress | 1024-65535 | tcp | → self | Non-privileged TCP |
| egress | 1024-65535 | udp | → self | Non-privileged UDP |
| egress | 53 | tcp | → self | DNS (TCP) |
| egress | 53 | udp | → self | DNS (UDP) |
| egress | 443 | tcp | → `eks-workers` SG | HTTPS to workers |
| egress | 1024-65535 | tcp | → `eks-workers` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `eks-workers` SG | Non-privileged UDP |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) |
| egress | 443 | tcp | → `istio-inet-nodes` SG | HTTPS to internet istio |
| egress | 1024-65535 | tcp | → `istio-inet-nodes` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `istio-inet-nodes` SG | Non-privileged UDP |
| egress | 53 | tcp | → `istio-inet-nodes` SG | DNS (TCP) |
| egress | 53 | udp | → `istio-inet-nodes` SG | DNS (UDP) |

#### baseline-intranet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `corporate-networks` PL | HTTPS from corporate |
| egress | 8080 | tcp | → `istio-intranet-nodes` SG | HTTP to istio gateway |
| egress | 8443 | tcp | → `istio-intranet-nodes` SG | HTTPS to istio gateway |
| egress | 15021 | tcp | → `istio-intranet-nodes` SG | Istio health check |

#### baseline-istio-inet-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| | | | **NLB ingress** | |
| ingress | 8443 | tcp | ← `waf-nat-ips` PL | HTTPS from WAF (client IP preserved) |
| ingress | 8080 | tcp | ← `waf-nat-ips` PL | HTTP from WAF (client IP preserved) |
| ingress | 15021 | tcp | ← `waf-nat-ips` PL | Health check from NLB (WAF source) |
| | | | **Control plane** | |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| | | | **Inter-node mesh (self)** | |
| ingress | 443 | tcp | ← self | HTTPS between internet istio |
| ingress | 1024-65535 | tcp | ← self | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← self | Non-privileged UDP |
| ingress | 53 | tcp | ← self | DNS (TCP) |
| ingress | 53 | udp | ← self | DNS (UDP) |
| | | | **Inter-node mesh (from workers)** | |
| ingress | 443 | tcp | ← `eks-workers` SG | HTTPS from workers |
| ingress | 1024-65535 | tcp | ← `eks-workers` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `eks-workers` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `eks-workers` SG | DNS (TCP) |
| ingress | 53 | udp | ← `eks-workers` SG | DNS (UDP) |
| | | | **Inter-node mesh (from istio-intranet)** | |
| ingress | 443 | tcp | ← `istio-intranet-nodes` SG | HTTPS from intranet istio |
| ingress | 1024-65535 | tcp | ← `istio-intranet-nodes` SG | Non-privileged TCP |
| ingress | 1024-65535 | udp | ← `istio-intranet-nodes` SG | Non-privileged UDP |
| ingress | 53 | tcp | ← `istio-intranet-nodes` SG | DNS (TCP) |
| ingress | 53 | udp | ← `istio-intranet-nodes` SG | DNS (UDP) |
| | | | **Egress** | |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → self | HTTPS between internet istio |
| egress | 1024-65535 | tcp | → self | Non-privileged TCP |
| egress | 1024-65535 | udp | → self | Non-privileged UDP |
| egress | 53 | tcp | → self | DNS (TCP) |
| egress | 53 | udp | → self | DNS (UDP) |
| egress | 443 | tcp | → `eks-workers` SG | HTTPS to workers |
| egress | 1024-65535 | tcp | → `eks-workers` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `eks-workers` SG | Non-privileged UDP |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) |
| egress | 443 | tcp | → `istio-intranet-nodes` SG | HTTPS to intranet istio |
| egress | 1024-65535 | tcp | → `istio-intranet-nodes` SG | Non-privileged TCP |
| egress | 1024-65535 | udp | → `istio-intranet-nodes` SG | Non-privileged UDP |
| egress | 53 | tcp | → `istio-intranet-nodes` SG | DNS (TCP) |
| egress | 53 | udp | → `istio-intranet-nodes` SG | DNS (UDP) |

#### baseline-internet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `waf-nat-ips` PL | HTTPS from WAF NAT IPs |
| egress | 8080 | tcp | → `istio-inet-nodes` SG | HTTP to istio internet gateway |
| egress | 8443 | tcp | → `istio-inet-nodes` SG | HTTPS to istio internet gateway |
| egress | 15021 | tcp | → `istio-inet-nodes` SG | Istio health check |

---

## vpc-endpoints (Standalone)

> 1 security group, 1 rule. Standalone profile for non-EKS accounts. Auto-included with both EKS profiles.

### Security Groups

| Security Group | Description |
|---|---|
| `baseline-vpc-endpoints` | VPC interface endpoints - ingress from local VPC only |

### Rules

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | VPC CIDR | HTTPS to interface endpoints |

---

## Design Principles

- **SG chaining over CIDRs** — cross-SG rules reference security group IDs, not subnets
- **Non-privileged inter-node mesh** — ports 1-442 and 444-1023 blocked between nodes. Prevents lateral movement to SSH, SMTP, and other system services from compromised pods
- **Explicit control plane rules** — kubelet (10250), webhooks (443, 15017) stay as dedicated rules from the cluster SG
- **Standalone rule resources** — `aws_vpc_security_group_*_rule` to avoid circular dependencies
- **VPC endpoint access via endpoint policies + IAM** — not SGs (risk acceptance documented)
