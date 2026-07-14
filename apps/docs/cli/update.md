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

Check the current version with `tuntun --version`
