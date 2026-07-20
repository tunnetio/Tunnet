# Comparison with Alternatives

Tunnet is built to compete with several established products across different use cases. Here is an honest comparison.

## vs Tailscale

Tailscale is the primary competitor. Both products create an encrypted mesh overlay
network where machines get internal IPs and can reach each other directly.

Tunnet's differentiator is that the **entire stack is open source** - including the
control plane, management API, and dashboard. Tailscale's coordination server is
proprietary. Headscale exists as a community alternative, but it is a reimplementation
that lags behind.

Tunnet uses QUIC via iroh instead of WireGuard. This gives native multiplexed streams,
built-in NAT traversal, and relay fallback without userspace WireGuard workarounds.

Both Tunnet and Tailscale offer a Kubernetes operator with ingress, egress, and
subnet routing. Tunnet's operator adds CRDs for public tunnels (`TunnetTunnel`) and internal service
exposure (`TunnetIngress`) as native Kubernetes resources.

Tailscale offers embeddable SDKs via `tsnet` (Go) and `libtailscale` (C). Tunnet
offers SDKs for Node.js/Bun and Rust.

Tailscale is ahead in maturity, platform coverage, enterprise features, and
battle-tested reliability. Tunnet is honest about this gap.

## vs ngrok

ngrok provides public tunnels to local services. Tunnet's `tunnet tunnel` does
the same thing - give a local port a public HTTPS URL through a relay.

ngrok also has a mature Kubernetes operator that provides ingress via standard
Ingress resources and Gateway API, plus embeddable SDKs in Go, Rust, Python,
JavaScript, and Java.

Tunnet's advantage is that tunnels are part of a broader mesh network. You get
public endpoints AND private mesh connectivity AND file transfer AND SSH - all
under one identity system. Plus, you can self-host the relay infrastructure.
ngrok does not offer mesh networking, file transfer, or SSH with session recording.

## vs Cloudflare Tunnel / Access / Mesh

Cloudflare offers multiple overlapping products. Cloudflare Tunnel exposes internal
services. Cloudflare Mesh (formerly WARP Connector) provides full mesh networking
with private IPs, bidirectional traffic, subnet routing, and high availability.
Access provides zero-trust authentication. Browser-rendered SSH with session
recording is available through Access.

Tunnet's `tunnet tunnel` competes with Cloudflare Tunnel. `tunnet mesh` competes
with Cloudflare Mesh. `tunnet serve` with ACLs competes with Cloudflare Access.

The key differences: Tunnet is fully self-hosted and open source with no vendor
dependency. Cloudflare Mesh routes all traffic through Cloudflare's edge network
(no direct P2P), while Tunnet supports direct peer-to-peer connections. Tunnet's
Direct mode works without any server at all.

## vs WireGuard (raw)

Raw WireGuard requires manual key exchange, manual IP allocation, and manual configuration. Tunnet automates all of this with enrollment, a control plane, and automatic peer discovery. Tunnet also adds features WireGuard does not have: DNS, service exposure, public tunnels, file transfer, and SSH.

## Feature matrix

| Feature | Tunnet | Tailscale | ngrok | Cloudflare |
|---------|--------|-----------|-------|------------|
| Mesh VPN | Yes | Yes | No | Yes (Mesh) |
| Open control plane | Yes | No | No | No |
| Public tunnels | Yes | Funnel | Yes | Yes (Tunnel) |
| Traffic inspection / replay | Yes | No | Yes | No |
| Internal services | Serve | Serve | No | Access |
| File transfer | Send | Taildrop | No | No |
| SSH (identity-based) | Yes | Yes | No | Yes (browser-rendered) |
| Session recording | Yes | Yes | No | Yes (SSH sessions) |
| Device posture | Yes | Yes | No | Yes (WARP / Zero Trust) |
| Self-hosted relay | Yes | DERP (self-hostable) | No | No |
| Kubernetes operator | Yes | Yes | Yes | Community¹ |
| Embeddable SDKs | JS, Rust | Go, C | Go, Rust, Python, JS, Java | No² |
| SSO / OIDC | Yes | Yes | Yes | Yes |
| ACL policies | Yes | Yes | Partial³ | Yes |
| Policy as Code | Yes | Limited⁴ | No | Limited⁵ |
| Audit logs (self-hosted) | Yes | Yes (vendor-hosted) | Partial | Yes |
| P2P mode (no server) | Direct mode | No | No | No |
| License | AGPL-3.0 | Proprietary | Proprietary | Proprietary |

> ¹ Cloudflare provides official Kubernetes deployment guides for cloudflared but no first-party operator CRDs - community operators exist.
> ² Cloudflare has API SDKs (Go, TypeScript, Python) but no embeddable tunnel/mesh SDK for in-process connectivity.
> ³ ngrok has authtoken ACLs and RBAC but not network-level mesh ACL policies.
> ⁴ Tailscale ACLs are HuJSON with optional test blocks; Terraform is a single monolithic ACL resource.
> ⁵ Cloudflare Zero Trust is API/Terraform-driven but split across many products and resources.

## Policy as Code matrix

Declarative policy, GitOps, and Terraform compared to mesh / zero-trust peers:

| | Tunnet | Tailscale | NetBird | Cloudflare ZT | ZeroTier | Firezone |
| --- | --- | --- | --- | --- | --- | --- |
| Offline validation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Traffic simulation | ✅ CLI+API | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multi-file policy | ✅ built-in | 🟡 community | ❌ | ❌ | ❌ | ❌ |
| Granular TF resources | ✅ per entity | ❌ monolithic | ✅ | ✅ but fragmented | 🟡 minimal | ❌ |
| Monolithic TF mode | ✅ also | ✅ only this | ❌ | ❌ | ❌ | ❌ |
| GitOps + PR diffs | ✅ semantic | 🟡 basic | ❌ | ❌ | ❌ | ❌ |
| Export → Terraform | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Drift detection | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Policy test framework | ✅ | 🟡 test blocks | ❌ | ❌ | ❌ | ❌ |
| Policy formats | HCL+JSON+YAML | HuJSON only | JSON (API) | JSON (API) | JSON (API) | N/A |
| Self-hosted | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ |
| OIDC CI auth | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Go SDK | ✅ | ✅ | ❌ official | ✅ | ✅ | ❌ |
| Policy rollback | ✅ built-in | ❌ git only | ❌ | ❌ | ❌ | ❌ |

Details and workflows: [Policy as Code](/guide/policy-as-code).
