# CLI Reference

The `tunnet` CLI is the primary interface for interacting with Tunnet from the command line. It combines agent management, network operations, and all product features in a single binary.

## Global flags

| Flag | Env | Description |
|------|-----|-------------|
| `--state-dir <path>` | `TUNNET_STATE_DIR` | Agent state directory (default: `~/.local/state/tunnet`) |
| `--json-logs` | `TUNNET_JSON_LOGS` | Output structured JSON logs |

## Command overview

| Command | Description |
|---------|-------------|
| `tunnet enroll` | Register this machine with the control plane |
| `tunnetd` / `tunnet service` | Start the agent daemon (TUN + mesh) |
| `tunnet up` | Bring TUN/DNS/routes up (daemon must be running) |
| `tunnet down` | Tear down TUN/DNS/routes; keep mesh alive |
| `tunnet service` | Install / control the OS service |
| `tunnet reset --yes` | Wipe local agent state |
| `tunnet status` | Agent / network status |
| `tunnet ping` | Mesh RTT over QUIC |
| `tunnet dns status` | PeerDNS configuration and cache |
| `tunnet route` | Subnet / hostname / exit routes |
| `tunnet diag` | Full connectivity diagnostics |
| `tunnet netcheck` | Quick pass/fail connectivity check |
| `tunnet serve` | Expose a local port on the mesh |
| `tunnet tunnel` | Expose a local port via a public edge |
| `tunnet-edge` | Separate binary: public tunnel edge server |
| `tunnet-relay` | Separate binary: iroh connectivity relay (mesh DERP) |
| `tunnet send` | P2P file transfer over the mesh |
| `tunnet ssh` | Identity-based SSH (OpenSSH wrapper; sessions / recordings / config) |
| `tunnet ssh-keyscan` | Print or refresh mesh SSH host keys |
| `tunnet posture` | Collect / evaluate device posture attributes |
| `tunnet login` | Sign in to management (device auth) |
| `tunnet logout` | Clear stored management tokens |
| `tunnet validate` | Validate `tunnet.toml` |
| `tunnet reload` | Hot-reload firewall / DNS / logging from `tunnet.toml` |
| `tunnet create` | Create a Direct (P2P) network |
| `tunnet join` | Join a Direct network with an invite |
| `tunnet invite` | Create an invite code |
| `tunnet leave` | Leave one Direct network |
| `| `tunnet connect` | Ephemeral 2-peer connection (contact id) |
| `tunnet requests` | List pending join requests |
| `tunnet accept` | Accept a join request |
| `tunnet deny` | Deny a join request |
| `tunnet kick` | Remove a peer from a Direct network |
| `tunnet firewall` | Manage the local Direct firewall |
| `tunnet policy` | [Managed Policy as Code](/cli/policy) - validate, apply, export, rollback |
| `tunnet coordinator-policy` | Direct-mode coordinator firewall (see [Direct commands](/cli/direct#tunnet-coordinator-policy)) |
| `tunnet keep-alive` | Keep a Direct peer connection always open |
| `tunnet upgrade-to-managed` | Migrate from Direct to Managed |
| `tunnet update` | Upgrade the agent from GitHub Releases |
