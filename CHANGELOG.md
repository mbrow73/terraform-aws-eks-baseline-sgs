# Changelog

## Unreleased

## v1.1.0 — Inter-Node Mesh Hardening

### Changed
- **Inter-node traffic model**: Replaced individual port rules (15006, 15012, 10250-self, DNS-self) between node groups with a hardened mesh pattern: `443 + TCP 1024-65535 + UDP 1024-65535 + TCP/UDP 53`
- Blocks all privileged ports (1-442, 444-1023) between nodes — prevents lateral movement to SSH (22), SMTP (25), and other system services if a pod is compromised
- Control plane ↔ node rules remain explicit (10250, 443, 15017 from cluster SG)
- NLB → Istio ingress remains on specific ports (8080, 8443, 15021)

### Added
- NLB egress rules to Istio node groups (8080, 8443, 15021) — previously missing from both `eks-standard` and `eks-internet` profiles
- Full mesh cross-references between all node groups in `eks-internet` profile (workers ↔ istio-intranet ↔ istio-inet)

### Removed
- Individual self-referencing rules for envoy (15006), xDS (15012), kubelet-self (10250), and CoreDNS-self (53) — all covered by the 1024-65535 range
- `istio_self_15021` readiness probe rules — covered by 1024-65535 range
- HTTP/80 ingress rule from `vpc-endpoints` security group — S3 gateway endpoints are route-table based and don't use security groups; S3 interface endpoints only need HTTPS/443

## v1.0.0

Initial release.

### Profiles
- `eks-standard` — 4 SGs for intranet-only EKS clusters with SG chaining
- `eks-internet` — 6 SGs for internet + intranet EKS clusters
- `vpc-endpoints` — standalone VPC endpoint SG (also auto-deploys with EKS profiles)

### Features
- Zero-trust SG chaining (no CIDR-based cross-SG rules)
- 5 managed prefix lists (corporate, WAF, VPCE, CI/CD, monitoring)
- Cross-account prefix list sharing via RAM
- VPC auto-discovery or explicit ID
- Mutually exclusive EKS profile validation
- Terraform test suite (mock_provider, no AWS creds needed)
