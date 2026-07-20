# Tunnet

![badge](https://shieldcn.dev/badge/Status-In%20development.svg?theme=amber&split=true)
[![badge](https://shieldcn.dev/badge/Read%20the%20Docs-abcde3.svg?variant=ghost&logo=readthedocs)](https://docs.tunnet.io)
[![badge](https://shieldcn.dev/badge/Join%20Discord.svg?brand=discord)](https://discord.gg/y5bNc3MYKz)

**Open-source private mesh networking.** Connect machines into one encrypted network - then SSH, serve internal apps, publish public tunnels, transfer files, and wire Kubernetes into the same fabric. One identity. One policy engine. One stack you can fully self-host.

## Why Tunnet

Commercial mesh products are excellent but most of them keep the coordination server closed. Tunnet ships the **agent, control plane, management API, dashboard, and relays** in this repository. You can read every line, self-host everything, and never depend on a proprietary coordination service or a lagging third-party reimplementation.

You also get more than a VPN. Instead of stitching Tailscale + ngrok + scp + a bastion, Tunnet puts mesh, public tunnels, internal services, file transfer, identity SSH, device posture, and Kubernetes under **one identity and one ACL system**.

## What you get

| Capability | What it replaces | Docs |
| --- | --- | --- |
| **Mesh network** | Tailscale, NetBird, Cloudflare WARP | [Mesh](https://docs.tunnet.io/products/mesh/) |
| **Serve** | Cloudflare Access / Tailscale Serve | [Serve](https://docs.tunnet.io/products/serve/) |
| **Tunnel** | ngrok, Cloudflare Tunnel | [Tunnel](https://docs.tunnet.io/products/tunnel/) |
| **Send** | Taildrop / ad-hoc file hops | [Send](https://docs.tunnet.io/products/send/) |
| **SSH** | Key distribution + bastions | [SSH](https://docs.tunnet.io/products/ssh/) |
| **Device posture** | MDM / EDR policy gates | [Posture](https://docs.tunnet.io/products/posture/) |
| **Self-hosted relay** | Vendor edge networks | [Relay](https://docs.tunnet.io/products/relay/) |
| **Kubernetes operator** | Custom VPN + Ingress glue | [Kubernetes](https://docs.tunnet.io/integrations/kubernetes/) |
| **Policy as Code** | HuJSON ACLs + ad-hoc GitOps | [Policy as Code](https://docs.tunnet.io/guide/policy-as-code) |
| **Audit logs** | SIEM-only or closed admin trails | [Audit Logs](https://docs.tunnet.io/guide/concepts/audit-logs) |
| **Node / Rust / Go SDKs** | Embedding tunnels + management API | [SDK](https://docs.tunnet.io/sdk/) |

### Mesh that feels like a LAN

Each enrolled machine gets an overlay IP and a hostname. Ordinary tools (`ping`, `curl`, `ssh`, browsers) just work. PeerDNS, subnet routes, exit nodes, and HA gateways are built in.

### Kubernetes on the mesh

The Tunnet Operator connects a cluster to your network with CRDs: advertise cluster CIDRs, publish Services to peers (`TunnetIngress`), expose public HTTPS (`TunnetTunnel`), reach mesh hosts from inside the cluster (`TunnetEgress`), and optionally inject sidecars. Same Serve/Tunnel products you already use - native to Kubernetes.

[Kubernetes integration](https://docs.tunnet.io/integrations/kubernetes/)

### Embed Tunnet in your apps

Ship a mesh node inside the process. No separate agent required for app-to-app traffic:

- [Node.js / Bun](https://docs.tunnet.io/sdk/js/)
- [Rust](https://docs.tunnet.io/sdk/rust/)

Open streams to peers, accept inbound connections, transfer files, and compose with your existing HTTP stack.

For management automation (policy, groups, ACLs) see the [Go management SDK](https://docs.tunnet.io/sdk/#go-management-sdk).

### Two modes, one product

- [Managed](https://docs.tunnet.io/modes/managed/) - control plane, dashboard, SSO/OIDC, centralized policies, Policy as Code (HCL/JSON/YAML, Terraform, GitOps), audit logs, tunnels, SSH recording. Built for teams.
- [Direct](https://docs.tunnet.io/modes/direct/) - zero-server P2P mesh for individuals and small groups.

### Policy as Code

Author ACLs, groups, tags, SSH, and posture in Git. Validate and simulate offline, post semantic diffs on PRs, apply with drift detection, export to Terraform, and roll back revisions - without giving up the dashboard.

[Policy as Code guide](https://docs.tunnet.io/guide/policy-as-code)

## How Tunnet compares

| | Tunnet | Tailscale | ngrok | Cloudflare |
| --- | --- | --- | --- | --- |
| Mesh VPN | Yes | Yes | No | Yes (Mesh) |
| Open control plane | **Yes** | No | No | No |
| Public tunnels | Yes | Funnel | Yes | Yes (Tunnel) |
| Internal services (Serve) | Yes | Serve | No | Access |
| P2P file transfer | Yes | Taildrop | No | No |
| Identity SSH + recording | Yes | Yes | No | Yes (browser) |
| Device posture | Yes | Yes | No | Yes (Zero Trust) |
| Self-hosted relay | Yes | DERP (self-hostable) | No | No |
| Serverless P2P mode | **Direct** | No | No | No |
| Kubernetes operator | Yes | Yes | Yes | Community¹ |
| Embeddable SDKs | JS, Rust | Go, C | Go, Rust, Python, JS, Java | No² |
| Policy as Code | **Yes** | Limited | No | Limited |
| Audit logs | **Yes** (self-hostable) | Yes | Partial | Yes |
| License | AGPL-3.0 | Proprietary | Proprietary | Proprietary |

> ¹ Cloudflare has official K8s deployment guides for Tunnel but the operators are community-maintained.
> ² Cloudflare offers API SDKs (Go, TS, Python) but no embeddable tunnel SDK.

Honest caveat: Tailscale and Cloudflare are more mature in enterprise polish and battle-tested scale. Tunnet’s bet is **full openness + one integrated stack**. Details: [Comparison guide](https://docs.tunnet.io/guide/comparison).

## Get started

| Path | Link |
| --- | --- |
| Install the agent | [Installation](https://docs.tunnet.io/guide/installation) |
| Managed quick start | [Quick start (Managed)](https://docs.tunnet.io/guide/quickstart-managed) |
| Direct quick start | [Quick start (Direct)](https://docs.tunnet.io/guide/quickstart-direct) |
| Self-host the stack | [Self-hosting](https://docs.tunnet.io/self-hosting/) |
| CLI reference | [CLI](https://docs.tunnet.io/cli/) |
| Full docs | [docs.tunnet.io](https://docs.tunnet.io) |

```bash
# Linux / macOS
curl -fsSL https://github.com/tunnetio/Tunnet/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell as Administrator)
irm https://github.com/tunnetio/Tunnet/releases/latest/download/install.ps1 | iex
```

## License

AGPL-3.0. See [LICENSE](LICENSE). [Commercial licenses](COMMERCIAL-LICENSE.md) are available when AGPL does not fit.
