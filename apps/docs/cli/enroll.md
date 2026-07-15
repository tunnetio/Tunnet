# tuntun enroll

Register this machine with a TunTun control plane.

## Usage

```bash
sudo tuntun enroll --control-url <URL> --token <TOKEN>
sudo tuntun enroll --control-url <URL> --org <SLUG>
```

## Options

| Option | Env | Description |
|--------|-----|-------------|
| `--control-url` | `CONTROL_PLANE_URL` | Control plane URL (required) |
| `--token` | `TUNTUN_ENROLL_TOKEN` | One-time enrollment token |
| `--org` | `TUNTUN_ORG_SLUG` | Organization slug (quick enroll, requires approval) |
| `--network` | `TUNTUN_NETWORK` | Network ID or name (defaults to "default") |
| `--hostname` | `TUNTUN_HOSTNAME` | Hostname for this machine |
| `--wait-secs` | - | Quick enroll approval timeout (default: 600) |

## Token enrollment

With `--token`, the machine is immediately admitted to the network:

```bash
sudo tuntun enroll \
  --control-url http://control:8080 \
  --token eyJ...
```

## Quick enrollment

With `--org`, the machine enters a pending state and waits for admin approval:

```bash
sudo tuntun enroll \
  --control-url http://control:8080 \
  --org my-company \
  --wait-secs 300
```

## Notes

Enrollment only needs to happen once per machine. After enrollment, run `tuntun run` to start the agent. If the machine is already enrolled, the command will error. Use `tuntun reset --yes` to wipe state before re-enrolling.
