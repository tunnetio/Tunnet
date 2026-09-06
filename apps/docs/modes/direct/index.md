# Direct Mode

Direct mode creates a P2P mesh network with no control plane, no server, and no infrastructure. It is a fully decentralized alternative where peers coordinate through CRDTs and discover each other via the Mainline DHT.

A single agent can join **multiple Direct networks** at once. Managed mode and Direct mode cannot be mixed.

## When to use Direct mode

Use Direct mode when you want to connect a few machines with zero infrastructure, when you cannot or do not want to run servers, for temporary or ephemeral connections, or for personal use where SSO and dashboards are unnecessary.

## How it works

Direct mode stores network membership in an [iroh-docs](https://github.com/n0-computer/iroh-docs) document - a CRDT that replicates across all peers. When a new peer joins, it writes its entry to the document, and the entry propagates to all other peers automatically. Each network gets its own docs store under `docs/<network-uuid>/`.

Peer discovery uses the Mainline DHT. A topic is derived from the network name and secret. Peers publish their iroh endpoint IDs to this topic and discover each other.

Transport authentication uses **signed grants**, **epochs**, and **revocations** stored in the membership document (or an **invite bootstrap** for the first join). Before accepting application-level ALPN connections, peers verify a coordinator-issued grant at the current network epoch, or a valid invite proof. Revoked peers are rejected even if they still know the join secret. This prevents unauthorized machines from communicating even if they discover peer addresses.

Public settings (firewall, DNS, keep-alive, open mode) live in [`tunnet.toml`](/guide/configuration) under `[direct.<name>]`. Network secrets are sealed in `state.enc`.

## Multiple networks

```bash
# First network
sudo tunnet create --name homelab --secret "passphrase"
sudo tunnet service start

# Join or create another without resetting
sudo tunnet join <INVITE_CODE>
# or
sudo tunnet create --name gaming --secret "other-secret"
```

When more than one network is active, pass the network name to commands that need it (`tunnet invite homelab`, `tunnet kick gaming <peer>`, `tunnet firewall add --network homelab …`).

Join order matters: if two peers in different networks share the same derived mesh IP (birthday collision), the **overlapping Direct networks are rejected.  Fix collisions with:

```bash
```

Leave one network (not the last - use `tunnet reset --yes` for that):

```bash
tunnet leave --network gaming
```

## Commands

```bash
# Create a network (become coordinator)
sudo tunnet create --name my-net --secret "passphrase"

# Generate an invite code
tunnet invite my-net

# Join with an invite code
sudo tunnet join <INVITE_CODE>

# Ephemeral 2-peer connection (contact id)
tunnet connect <tt_…>
tunnet connect allow <tt_…>
tunnet connect pending

# Manage join requests (coordinator)
tunnet requests my-net
tunnet accept my-net <endpoint_id>
tunnet deny my-net <endpoint_id>

# Kick a peer
tunnet kick my-net <endpoint_id>

# Leave / IP override
tunnet leave --network my-net

# Firewall (also editable in tunnet.toml)
tunnet firewall show
tunnet firewall add --network my-net in allow -p tcp --port 22 --peer other-host
tunnet firewall remove 0
```

## Direct mode firewall

Direct mode includes a local firewall engine. Since there is no central policy server, each peer manages its own rules (per network, in `tunnet.toml` or via `tunnet firewall`). Coordinators can publish a suggested policy with `tunnet policy`; peers accept or reject pending suggestions.

After editing `tunnet.toml`, run `tunnet reload` (or restart the agent).

## Limitations

Direct mode does not include a web dashboard, SSO/OIDC, centralized access policies, public tunnels, edge infrastructure, or API key management. For these features, upgrade to Managed mode (requires a single Direct network on the machine).
