# CLI Reference

The `tuntun` CLI is the primary interface for interacting with TunTun from the command line. It combines agent management, network operations, and all product features in a single binary.

## Global flags

| Flag | Env | Description |
|------|-----|-------------|
| `--state-dir <path>` | `TUNTUN_STATE_DIR` | Agent state directory (default: `~/.local/state/tuntun`) |
| `--json-logs` | `TUNTUN_JSON_LOGS` | Output structured JSON logs |

## Command overview

| Command | Description |
|---------|-------------|
| `tuntun enroll` | Register this machine with the control plane |
| `tuntun run` | Start the agent (TUN + mesh) |
| `tuntun up` | Bring TUN/DNS/routes up (daemon must be running) |
| `tuntun down` | Tear down TUN/DNS/routes; keep mesh alive |
| `tuntun service` | Install / control the OS service |
| `tuntun reset --yes` | Wipe local agent state |
| `tuntun status` | Agent / network status |
| `tuntun ping` | Mesh RTT over QUIC |
| `tuntun dns status` | PeerDNS configuration and cache |
| `tuntun route` | Subnet / hostname / exit routes |
| `tuntun diag` | Full connectivity diagnostics |
| `tuntun netcheck` | Quick pass/fail connectivity check |
| `tuntun serve` | Expose a local port on the mesh |
| `tuntun tunnel` | Expose a local port via a public relay |
| `tuntun send` | P2P file transfer over the mesh |
| `tuntun ssh` | Identity-based SSH to a peer |
| `tuntun login` | Sign in to management (device auth) |
| `tuntun logout` | Clear stored management tokens |
| `tuntun create` | Create a Direct (P2P) network |
| `tuntun join` | Join a Direct network with an invite |
| `tuntun invite` | Create an invite code |
| `tuntun connect` | Ephemeral 2-peer connection |
| `tuntun requests` | List pending join requests |
| `tuntun accept` | Accept a join request |
| `tuntun deny` | Deny a join request |
| `tuntun kick` | Remove a peer from a Direct network |
| `tuntun firewall` | Manage the local Direct firewall |
| `tuntun upgrade-to-managed` | Migrate from Direct to Managed |
| `tuntun update` | Upgrade the agent from GitHub Releases |
