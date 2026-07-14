# tuntun run

Start the TunTun agent. Creates the virtual TUN interface, connects to peers, and begins handling mesh traffic, serves, tunnels, file transfers, and policies.

## Usage

```bash
sudo tuntun run [options]
```

## Options

| Option | Env | Default | Description |
|--------|-----|---------|-------------|
| `--ifname` | `TUNTUN_IFNAME` | `tuntun0` | TUN interface name |
| `--poll-secs` | `TUNTUN_POLL_SECS` | `30` | Snapshot poll interval |
| `--metrics-bind` | `TUNTUN_METRICS_BIND` | `127.0.0.1:9100` | Prometheus metrics endpoint |
| `--disable-gossip` | `TUNTUN_DISABLE_GOSSIP` | `false` | Disable gossip presence |
| `--recorder` | `TUNTUN_RECORDER` | `false` | Enable SSH session recording |

## Requirements

The agent needs root/admin privileges to create the TUN interface. On Linux, this means running with `sudo`. On Windows, run as Administrator with the Wintun driver installed.

## Behavior

The agent first unlocks sealed secrets (`state.enc`) and loads public state (`state.json`) plus `tuntun.toml`. In Managed mode, it connects to the control plane via WebSocket and receives the network snapshot. In Direct mode, it joins each network's iroh-docs membership document and discovers peers via DHT.

It then creates the TUN interface, configures routing and DNS, starts the iroh endpoint, and enters its main event loop - handling packets, maintaining peer connections, and syncing configuration. If `[update].enabled` is set in `tuntun.toml`, it also runs the auto-update loop.
