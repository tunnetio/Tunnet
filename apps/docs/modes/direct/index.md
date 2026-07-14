# Direct Mode

Direct mode creates a P2P mesh network with no control plane, no server, and no infrastructure. It is a fully decentralized alternative where peers coordinate through CRDTs and discover each other via the Mainline DHT.

A single agent can join **multiple Direct networks** at once. Managed mode and Direct mode cannot be mixed.

## When to use Direct mode

Use Direct mode when you want to connect a few machines with zero infrastructure, when you cannot or do not want to run servers, for temporary or ephemeral connections, or for personal use where SSO and dashboards are unnecessary.

## How it works

Direct mode stores network membership in an [iroh-docs](https://github.com/n0-computer/iroh-docs) document - a CRDT that replicates across all peers. When a new peer joins, it writes its entry to the document, and the entry propagates to all other peers automatically. Each network gets its own docs store under `docs/<network-uuid>/`.

Peer discovery uses the Mainline DHT. A topic is derived from the network name and secret. Peers publish their iroh endpoint IDs to this topic and discover each other.

Transport authentication uses a pre-shared key (PSK). Before accepting any application-level connection, peers perform a PSK handshake to prove they know the network secret. This prevents unauthorized machines from communicating even if they discover the peer addresses.

Public settings (firewall, DNS, keep-alive, open mode) live in [`tuntun.toml`](/guide/configuration) under `[direct.<name>]`. Network secrets are sealed in `state.enc`.

## Multiple networks

```bash
# First network
sudo tuntun create --name homelab --secret "passphrase"
sudo tuntun service start

# Join or create another without resetting
sudo tuntun join <INVITE_CODE>
# or
sudo tuntun create --name gaming --secret "other-secret"
```

When more than one network is active, pass the network name to commands that need it (`tuntun invite homelab`, `tuntun kick gaming <peer>`, `tuntun firewall add --network homelab …`).

Join order matters: if two peers in different networks share the same derived mesh IP (birthday collision), the **first-joined** network wins for outbound routing. Fix collisions with:

```bash
tuntun override-ip --peer <hostname-or-endpoint> --ip 10.7.0.50 --network gaming
```

Leave one network (not the last - use `tuntun reset --yes` for that):

```bash
tuntun leave --network gaming
```

## Commands

```bash
# Create a network (become coordinator)
sudo tuntun create --name my-net --secret "passphrase"

# Generate an invite code
tuntun invite my-net

# Join with an invite code
sudo tuntun join <INVITE_CODE>

# Ephemeral 2-peer connection (contact id)
tuntun connect <tt_…>
tuntun connect allow <tt_…>
tuntun connect pending

# Manage join requests (coordinator)
tuntun requests my-net
tuntun accept my-net <endpoint_id>
tuntun deny my-net <endpoint_id>

# Kick a peer
tuntun kick my-net <endpoint_id>

# Leave / IP override
tuntun leave --network my-net
tuntun override-ip --peer other-host --ip 10.7.0.42 --network my-net

# Firewall (also editable in tuntun.toml)
tuntun firewall show
tuntun firewall add --network my-net in allow -p tcp --port 22 --peer other-host
tuntun firewall remove 0
```

## Direct mode firewall

Direct mode includes a local firewall engine. Since there is no central policy server, each peer manages its own rules (per network, in `tuntun.toml` or via `tuntun firewall`). Coordinators can publish a suggested policy with `tuntun policy`; peers accept or reject pending suggestions.

After editing `tuntun.toml`, run `tuntun reload` (or restart the agent).

## Limitations

Direct mode does not include a web dashboard, SSO/OIDC, centralized access policies, public tunnels, relay infrastructure, or API key management. For these features, upgrade to Managed mode (requires a single Direct network on the machine).
