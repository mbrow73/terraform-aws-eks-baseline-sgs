# Changelog

## Unreleased

### Removed
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
