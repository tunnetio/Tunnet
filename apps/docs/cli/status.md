# tuntun status

Show agent and network status.

## Usage

```bash
tuntun status [--peers]
```

## Options

| Option | Description |
|--------|-------------|
| `--peers` | Include detailed peer connection information |

## Output

Shows the agent's endpoint ID, assigned mesh IP(s), network name(s), mode (managed/direct), and control plane connectivity. In Direct mode with multiple networks, all joined networks are listed. With `--peers`, also lists connected peers with their IPs, hostnames, and connection status.
