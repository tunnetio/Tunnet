# TunTun

![badge](https://shieldcn.dev/badge/Status-In%20development.svg?theme=amber&split=true)
[![badge](https://shieldcn.dev/badge/Read%20the%20Docs-abcde3.svg?variant=ghost&logo=readthedocs)](https://tuntun.orielhaim.com)
[![badge](https://shieldcn.dev/badge/Join%20Discord.svg?brand=discord)](https://discord.gg/y5bNc3MYKz)

TunTun connects your machines into a private network. Install an agent on each device and it gets an internal IP address. After that, ordinary tools just work: SSH, ping, curl, a browser pointed at an internal service. You do not need to teach every application about tunnels or VPNs. The network is the network.

Everything is open source. Not just the agent - the control plane, the management API, the dashboard, the relay infrastructure. You can read every line, self-host the entire stack, and know exactly what your network is doing.

## What TunTun does

TunTun is not a single tool. It is a collection of networking primitives under one identity system and one access policy engine.

**Mesh network** - Encrypted peer-to-peer connectivity over QUIC (iroh). Machines get mesh IPs, resolve each other by hostname via PeerDNS, and communicate directly. Subnet routes expose devices without agents. Exit nodes route internet traffic through a chosen peer. This is the Tailscale / NetBird / Cloudflare WARP competitor.

**Serve** - Expose a local port to other machines on your mesh with an internal hostname and TLS from your org's CA. ACLs restrict who can reach it. This competes with Cloudflare Access and Tailscale Serve.

**Tunnel** - Give a local port a public HTTPS URL through a self-hosted relay. Webhooks, demos, permanent services - no inbound firewall rules. Path-based redirects and TCP port mappings included. This is the ngrok and Cloudflare Tunnel competitor.

**Send** - Transfer files and directories peer-to-peer over the mesh. BLAKE3-verified via iroh-blobs, consent-based, with multicast to tagged machines.

**SSH** - Identity-based SSH to peers with no keys to distribute. Auth tied to TunTun identity and organization policies. Session recording, re-auth enforcement, and full audit trails.

**Relay** - Self-hosted edge servers for public tunnels. ACME support, bring your own certs, full control over your tunnel infrastructure.

## Two modes

TunTun operates in two modes for fundamentally different audiences.

**Managed mode** is for organizations. It includes a control plane, management API, web dashboard, SSO/OIDC, centralized access policies, audit logs, tunnel and relay infrastructure, SSH session recording, and a REST API with API key support.

**Direct mode** is for individuals and small groups who want zero infrastructure. It creates a P2P mesh where membership is stored in an iroh-docs CRDT, peer discovery uses the Mainline DHT, and transport auth proves knowledge of a pre-shared key. No server needed.

When you outgrow Direct mode, `tuntun upgrade-to-managed` migrates your network to the full control plane without losing connectivity.

## Quick start

### Install the agent

**Linux / macOS**

```bash
curl -fsSL https://github.com/orielhaim/TunTun/releases/latest/download/install.sh | sh
```

**Windows** (PowerShell as Administrator)

```powershell
irm https://github.com/orielhaim/TunTun/releases/latest/download/install.ps1 | iex
```

Verify with `tuntun --version`. Later upgrades: `tuntun update`.

### Managed mode

```bash
# Start the stack (from a TunTun checkout)
docker compose up -d

# Or run manually:
#   ./target/release/tuntun-control
#   bun run dev:management
#   bun run dev:dash
```

Open the dashboard at `http://localhost:5173`. Create an account and organization. Generate an enrollment token.

```bash
# On each machine
sudo tuntun enroll --control-url http://your-host:8080 --token TOKEN
sudo tuntun service start
```

### Direct mode

```bash
# Machine A - create a network
sudo tuntun create --name my-net --secret "a-strong-passphrase"
sudo tuntun service start

# Generate an invite
tuntun invite --name my-net

# Machine B - join
sudo tuntun join <INVITE_CODE>
sudo tuntun service start
```

### Verify

```bash
tuntun status --peers
tuntun ping other-machine
```

## Features at a glance

```bash
# Mesh
tuntun status --peers          # Network overview
tuntun ping <peer>             # Mesh RTT
tuntun dns status              # PeerDNS resolver state
tuntun route list              # Subnet / hostname / exit routes
tuntun route add 192.168.1.0/24  # Advertise a LAN
tuntun diag                    # Full diagnostics
tuntun netcheck                # Quick connectivity check
tuntun update                  # Upgrade from GitHub Releases
tuntun update --check          # Check for a newer release

# Serve - internal services
tuntun serve 3000              # Expose to mesh with TLS
tuntun serve status
tuntun serve off 3000

# Tunnel - public endpoints
tuntun tunnel 3000             # Public HTTPS via relay
tuntun tunnel status
tuntun tunnel off 3000

# Send - file transfer
tuntun send ./data.tar.gz db-server
tuntun send ./build tag:ci     # Multicast to tagged machines
tuntun send list               # Pending offers
tuntun send accept <id>
tuntun send config --consent auto_accept

# SSH - identity-based
tuntun ssh db-server
tuntun ssh db-server -u root
tuntun ssh db-server -- uname -a
tuntun ssh sessions
tuntun ssh recordings
tuntun ssh play <session_id>

# Direct mode
tuntun create --name net --secret "pass"
tuntun join <INVITE_CODE>
tuntun invite --name net
tuntun connect --name session --secret "shared"
tuntun requests / accept / deny / kick
tuntun firewall list / add / remove
tuntun upgrade-to-managed

# Service management
tuntun service install / start / stop / restart / status

# Auth
tuntun login --management-url http://localhost:3000
tuntun logout
```

## Node SDK

```bash
bun add @tuntun/sdk
```

```ts
import { TunTunNode } from "@tuntun/sdk";

const node = await TunTunNode.create({ controlUrl: "http://control:8080" });

const peers = await node.listPeers();
const stream = await node.openStream("api-server", 8080);
const response = await node.fetch("http://api-server:3000/health");
await node.sendFile("./data.csv", "db-server", "daily export");
await node.close();
```

## Relays

Self-host your own public tunnel edge:

```bash
tuntun-relay register --control-url http://control:8080 --token TOKEN
tuntun-relay run
```

Point DNS at the relay, configure ACME or bring your own certificates, and create tunnels with `tuntun tunnel` or from the dashboard. See `tuntun-relay --help` for all options.

## Requirements

Rust 1.96+, Bun, and PostgreSQL. The agent needs root/admin privileges to create a TUN interface (Linux and macOS require root; Windows requires Administrator with the Wintun driver installed).

## License

AGPL-3.0. See [LICENSE](LICENSE) for details. Commercial licenses are available for use cases where the AGPL does not fit.

## Contributing

Contributions require a signed Contributor License Agreement. See [CLA.md](CLA.md).
