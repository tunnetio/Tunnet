# PeerDNS

PeerDNS is TunTun's internal DNS resolver. It lets you use hostnames instead of IP addresses to reach peers and hostname-routed services on the mesh.

## How it works

The agent runs a DNS stub resolver that intercepts queries for names ending in the network's DNS suffix (default: `.tuntun`). When you query `db-server.tuntun`, the resolver looks up the peer named `db-server` in the routing table and returns its mesh IP.

For hostnames that do not match any peer, the resolver checks hostname routes. These are services advertised through gateway machines that map a hostname to a mesh IP.

Non-matching queries are forwarded to configured upstream resolvers (default: 1.1.1.1 and 8.8.8.8).

## Configuration

**Managed mode** - the DNS suffix is configured in **Settings → Organization** in the dashboard. You can also configure upstream resolvers per network.

**Direct mode** - configure per network in [`tuntun.toml`](/guide/configuration):

```toml
[direct.homelab.dns]
magic-ip = "100.100.100.53"
tld = "tuntun"
upstream = ["1.1.1.1", "8.8.8.8"]
```

Apply changes with `tuntun reload`.

## CLI

```bash
tuntun dns status
```

This shows the current DNS configuration, cache state, and resolved entries.
