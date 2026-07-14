# tuntun update

Upgrade the installed `tuntun` binary from GitHub Releases.

```bash
sudo tuntun update
```

On Linux this downloads the new release and reloads the service gracefully. Pass `--restart` for a full restart. On Windows the service always restarts.

## Options

| Flag | Description |
|------|-------------|
| `--check` | Only report whether a newer release exists |
| `--force` | Reinstall even when already on the latest version |
| `--restart` | Hard-restart the service after installing |
| `--version <tag>` | Install a specific release (e.g. `v0.3.1`) |

```bash
tuntun update --check
sudo tuntun update --version v0.3.1
sudo tuntun update --restart
```

Check the current version with `tuntun --version`.

## Automatic updates

Enable periodic checks in [`tuntun.toml`](/guide/configuration):

```toml
[update]
enabled = true
check-interval-hours = 6
health-window-secs = 30
```

When enabled, the running agent polls GitHub Releases on the configured interval and applies updates itself. After installing a new binary it keeps the previous one under `update/tuntun.prev`. If the new process exits or restarts again within `health-window-secs`, TunTun reverts to the previous binary.

Manual `tuntun update` and automatic `[update]` share the same download path; only the trigger differs.
