# Direct Mode Commands

These commands manage Direct (P2P) networks that operate without a control plane. An agent can belong to multiple Direct networks; when more than one is joined, pass the network name where noted.

Secrets are sealed at rest by default. Pass `--no-encrypt-state` on `create` / `join` only for containers/CI. See [Configuration](/guide/configuration) and [Encryption](/guide/concepts/encryption).

## tuntun create

Create a new Direct network and become the coordinator. Safe to run again to add another Direct network (Managed mode must be reset first).

```bash
sudo tuntun create --name <name> --secret <passphrase>
sudo tuntun create --name <name> --open          # auto-admit valid invites
sudo tuntun create --name <name>                 # random secret is printed
```

## tuntun join

Join an existing Direct network with an invite code. Can be used while already in other Direct networks.

```bash
sudo tuntun join <INVITE_CODE>
sudo tuntun join <INVITE_CODE> --auto-accept-firewall
```

## tuntun invite

Generate an invite code for others to join.

```bash
tuntun invite [<network>]
tuntun invite homelab --reusable --expires 24h
```

## tuntun leave

Leave one Direct network. Cannot leave the last network - use `tuntun reset --yes` instead.

```bash
tuntun leave --network <name>
tuntun leave <name>
```

Restart or reload the service after leaving so the agent drops that network's docs and routes.

## tuntun override-ip

Override a peer's mesh IP when birthday collisions occur across Direct networks. First-joined network wins outbound by default; use this to force a specific IP for a peer.

```bash
tuntun override-ip --peer <hostname-or-endpoint> --ip <ipv4> [--network <name>]
```

## tuntun connect

Ephemeral two-peer connection via contact IDs (`tt_…`), not network name/secret.

```bash
tuntun connect <tt_…>
tuntun connect allow <tt_…>
tuntun connect pending
tuntun connect accept <tt_…>
tuntun connect deny <tt_…>
tuntun connect rotate
```

Pre-approve contact IDs permanently in `tuntun.toml` under `[connect].allow`.

## tuntun requests / accept / deny

Manage pending join requests (coordinator only).

```bash
tuntun requests [<network>]
tuntun accept [<network>] <endpoint_id>
tuntun deny [<network>] <endpoint_id>
```

## tuntun kick

Remove a peer from the network.

```bash
tuntun kick [<network>] <endpoint_id>
```

## tuntun firewall

Manage local firewall rules for Direct mode. Rules are also stored under `[direct.<name>.firewall]` in `tuntun.toml`.

```bash
tuntun firewall show
tuntun firewall off
tuntun firewall add [--network <name>] <in|out> <allow|deny|reject> [-p tcp] [--port 22] [--peer <host>]
tuntun firewall remove <index>
tuntun firewall reset
tuntun firewall flush-conntrack
tuntun firewall pending
tuntun firewall accept
tuntun firewall reject-suggestion
```

## tuntun policy

Coordinator firewall policy published to peers.

```bash
tuntun policy show
tuntun policy set <file.toml>
tuntun policy clear
```

## tuntun keep-alive

Keep a peer connection always open (disables on-demand dialing for that host).

```bash
tuntun keep-alive <hostname>
tuntun keep-alive <hostname> --off
```

Also configurable per network in `tuntun.toml` with `keep-alive = true`.

## tuntun upgrade-to-managed

Migrate from Direct to Managed mode. The machine must be on a single Direct network.

```bash
tuntun upgrade-to-managed \
  --control-url http://control:8080 \
  --token TOKEN
```
