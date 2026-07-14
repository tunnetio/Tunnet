# tuntun reload

Reload firewall, DNS, logging, and keep-alive settings from `tuntun.toml` without dropping mesh connections. The agent must be running.

```bash
tuntun reload
```

Prefer this over a full restart after editing config. Use `tuntun validate` first to catch errors. See [Configuration](/guide/configuration).
