# Configuration

Agent settings live in a single file: `tuntun.toml` in the state directory. Secrets (identity seed, network PSK, doc tickets, login tokens) are **not** in this file - they are sealed separately. See [Encryption & Secrets](/guide/concepts/encryption).

## State directory

| Path | Typical location |
|------|------------------|
| User / CLI | `~/.local/state/tuntun` (Linux/macOS) or `%LOCALAPPDATA%\tuntun` (Windows) |
| OS service | `/var/lib/tuntun` (Linux) or `%PROGRAMDATA%\tuntun` (Windows) |

Override with `--state-dir` or `TUNTUN_STATE_DIR`.

```
<state-dir>/
  tuntun.toml              # public config
  state.json               # public enrollment / network metadata
  state.enc                # encrypted secrets
  state.enc.meta           # seal tier + key wrapping metadata
  ip_overrides.json        # peer IP overrides (Direct multi-network)
  docs/<network-uuid>/     # per-network iroh-docs store
  direct_invites/
  direct_pending/
  firewall_pending/
  update/                  # auto-update pending binary + health marker
```

The agent creates `tuntun.toml` on first create/join/enroll if it is missing.

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
magic-ip = "100.100.100.53"
tld = "tuntun"
upstream = ["1.1.1.1", "8.8.8.8"]

[direct.gaming]
open = true
keep-alive = true

[connect]
allow = []

[logging]
level = "info"
format = "text"

[mdns]
enabled = true

[update]
enabled = false
check-interval-hours = 6
health-window-secs = 30
```

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

You can also manage rules with `tuntun firewall`. Edits to TOML take effect after `tuntun reload` (or an agent restart).

#### DNS (`[direct.<name>.dns]`)

| Key | Default | Description |
|-----|---------|-------------|
| `magic-ip` | `100.100.100.53` | PeerDNS listener address on the TUN |
| `tld` | `tuntun` | DNS suffix for peer hostnames |
| `upstream` | `1.1.1.1`, `8.8.8.8` | Forwarders for non-mesh queries |

### `[connect]`

| Key | Description |
|-----|-------------|
| `allow` | Pre-approved contact IDs for ephemeral `tuntun connect` |

### `[logging]`

| Key | Values |
|-----|--------|
| `level` | `trace`, `debug`, `info`, `warn`, `error`, `off` |
| `format` | `text` or `json` |

### `[mdns]`

| Key | Description |
|-----|-------------|
| `enabled` | LAN address discovery via mDNS (Direct mode) |

### `[update]`

Automatic binary updates from GitHub Releases. See [tuntun update](/cli/update).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Periodically check and apply updates |
| `check-interval-hours` | `6` | Poll interval |
| `health-window-secs` | `30` | If the new binary crashes/restarts within this window, revert |

## Validate and reload

```bash
tuntun validate
tuntun validate --config /path/to/tuntun.toml

# Apply firewall / DNS / logging / keep-alive without dropping connections
tuntun reload
```

`validate` exits non-zero on errors. `reload` requires a running agent.
