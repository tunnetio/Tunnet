# Configuration

Agent settings live in a single file: `tunnet.toml` in the state directory. Secrets (identity seed, network PSK, doc tickets, login tokens) are **not** in this file - they are sealed separately. See [Encryption & Secrets](/guide/concepts/encryption).

## State directory

| Path | Typical location |
|------|------------------|
| User / CLI | `~/.local/state/tunnet` (Linux/macOS) or `%LOCALAPPDATA%\tunnet` (Windows) |
| OS service | `/var/lib/tunnet` (Linux) or `%PROGRAMDATA%\tunnet` (Windows) |

Override with `--state-dir` or `TUNNET_STATE_DIR`.

```
<state-dir>/
  tunnet.toml              # public config
  state.json               # public enrollment / network metadata
  state.enc                # encrypted secrets
  state.enc.meta           # seal tier + key wrapping metadata
    docs/<network-uuid>/     # per-network iroh-docs store
  direct_invites/
  direct_pending/
  firewall_pending/
  update/                  # auto-update pending binary + health marker
```

The agent creates `tunnet.toml` on first create/join/enroll if it is missing.

## Example

```toml
[node]
hostname = "laptop"

[direct.homelab]
open = false
keep-alive = false

[direct.homelab.firewall]
enabled = true
version = 1
rules = [
  { direction = "in", protocol = "tcp", action = "allow", ports = [22, "443-444"], peer = "db-server" },
]

[direct.homelab.dns]
magic-ip = "the gateway peer address
tld = "tunnet"
upstream = ["1.1.1.1", "8.8.8.8"]

[direct.gaming]
open = true
keep-alive = true

[connect]
allow = []

[logging]
level = "info"
format = "text"

# Dual keys: only set a key to override org remote policy (Managed).
[network]
mdns = false
# lan-discovery = false
# tunnel-mtu = 1280
# service-relay = true

# Dual keys for auto-update (omit to inherit org policy / defaults).
[update]
# enabled = true
# check-interval-hours = 6
health-window-secs = 30

# Local-only (never remotely writable).
[control]
# url = "https://control.example.com"
# listen-port = 41641
```

## Layers (Managed)

```
local tunnet.toml  >  network agentPolicy  >  org agentPolicy  >  defaults
```

Org defines defaults under **Organization → Agent policy**. A network can override under **Network → Policy**. The agent for a membership receives the inherited network policy. Dual keys in `tunnet.toml` still win locally.

Posture definitions and enforcement settings follow the same inheritance: `network_id` null = org default; set = network override.

## Sections

### `[node]`

| Key | Description |
|-----|-------------|
| `hostname` | Local hostname advertised on the mesh |

### `[direct.<name>]`

One block per Direct network. Keyed by network name.

| Key | Description |
|-----|-------------|
| `open` | Auto-admit peers with a valid invite (no approval queue) |
| `keep-alive` | Keep peer connections always open (default: on-demand) |

#### Firewall (`[direct.<name>.firewall]`)

| Key | Description |
|-----|-------------|
| `enabled` | Local firewall engine (default `true`) |
| `version` | Policy version |
| `rules` | Array of rule objects |

Each rule:

| Field | Values |
|-------|--------|
| `direction` | `in` or `out` |
| `protocol` | `tcp`, `udp`, `icmp`, or `any` |
| `action` | `allow`, `deny`, or `reject` |
| `port` / `ports` | Single port, or range string like `"443-444"` |
| `peer` | Optional hostname or endpoint hex (omit = any) |

You can also manage rules with `tunnet firewall`. Edits to TOML take effect after `tunnet reload` (or an agent restart).

#### DNS (`[direct.<name>.dns]`)

| Key | Default | Description |
|-----|---------|-------------|
| `magic-ip` | `the gateway peer address | PeerDNS listener address on the TUN |
| `tld` | `tunnet` | DNS suffix for peer hostnames |
| `upstream` | `1.1.1.1`, `8.8.8.8` | Forwarders for non-mesh queries |

### `[connect]`

| Key | Description |
|-----|-------------|
| `allow` | Pre-approved contact IDs for ephemeral `tunnet connect` |

### `[logging]`

| Key | Values |
|-----|--------|
| `level` | `trace`, `debug`, `info`, `warn`, `error`, `off` |
| `format` | `text` or `json` |

### `[network]` (dual - local overrides remote)

Only keys you set override org remote policy. Omitted keys inherit remote / defaults.

| Key | Default | Description |
|-----|---------|-------------|
| `mdns` | `true` | LAN mDNS address discovery |
| `lan-discovery` | `true` | LAN peer discovery |
| `tunnel-mtu` | `1280` | Preferred tunnel MTU |
| `service-relay` | `false` | Relay LAN DNS-SD services across the mesh |

### `[update]` (dual for `enabled` / `check-interval-hours`)

Automatic binary updates from GitHub Releases. See [tunnet update](/cli/update).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | inherit / `false` | When set, overrides org auto-update |
| `check-interval-hours` | inherit / `6` | When set, overrides org poll interval |
| `health-window-secs` | `30` | Local-only: revert if new binary is unstable |

### `[control]` (local-only)

| Key | Description |
|-----|-------------|
| `url` | Control plane URL (self-hosted) |
| `listen-port` | Optional listen port override |

## Validate and reload

```bash
tunnet validate
tunnet validate --config /path/to/tunnet.toml

# Apply firewall / DNS / logging / keep-alive without dropping connections
tunnet reload
```

`validate` exits non-zero on errors. `reload` requires a running agent.
