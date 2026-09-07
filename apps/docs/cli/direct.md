# Direct Mode Commands

These commands manage Direct (P2P) networks that operate without a control plane. An agent can belong to multiple Direct networks; when more than one is joined, pass the network name where noted.

Secrets are sealed at rest by default. Pass `--no-encrypt-state` on `create` / `join` only for containers/CI. See [Configuration](/guide/configuration) and [Encryption](/guide/concepts/encryption).

## tunnet create

Create a new Direct network and become the coordinator. Safe to run again to add another Direct network (Managed mode must be reset first).

```bash
sudo tunnet create --name <name> --secret <passphrase>
sudo tunnet create --name <name> --open          # auto-admit valid invites
sudo tunnet create --name <name>                 # random secret is printed
```

## tunnet join

Join an existing Direct network with an invite code. Can be used while already in other Direct networks.

```bash
sudo tunnet join <INVITE_CODE>
sudo tunnet join <INVITE_CODE> --auto-accept-firewall
```

## tunnet invite

Generate an invite code for others to join.

```bash
tunnet invite [<network>]
tunnet invite homelab --reusable --expires 24h
```

## tunnet leave

Leave one Direct network. Cannot leave the last network - use `tunnet reset --yes` instead.

```bash
tunnet leave --network <name>
tunnet leave <name>
```

Restart or reload the service after leaving so the agent drops that network's docs and routes.


## tunnet connect

Ephemeral two-peer connection via contact IDs (`tt_…`), not network name/secret.

```bash
tunnet connect <tt_…>
tunnet connect allow <tt_…>
tunnet connect pending
tunnet connect accept <tt_…>
tunnet connect deny <tt_…>
tunnet connect rotate
```

Pre-approve contact IDs permanently in `tunnet.toml` under `[connect].allow`.

## tunnet requests / accept / deny

Manage pending join requests (coordinator only).

```bash
tunnet requests [<network>]
tunnet accept [<network>] <endpoint_id>
tunnet deny [<network>] <endpoint_id>
```

## tunnet kick

Remove a peer from the network.

```bash
tunnet kick [<network>] <endpoint_id>
```

## tunnet firewall

Manage local firewall rules for Direct mode. Rules are also stored under `[direct.<name>.firewall]` in `tunnet.toml`.

```bash
tunnet firewall show
tunnet firewall off
tunnet firewall add [--network <name>] <in|out> <allow|deny|reject> [-p tcp] [--port 22] [--peer <host>]
tunnet firewall remove <index>
tunnet firewall reset
tunnet firewall flush-conntrack
tunnet firewall pending
tunnet firewall accept
tunnet firewall reject-suggestion
```

## tunnet coordinator-policy

Coordinator firewall policy published to peers (Direct mode only).

```bash
tunnet coordinator-policy show
tunnet coordinator-policy set <file.toml>
tunnet coordinator-policy clear
```

For Managed access policy as code (HCL/JSON/YAML, apply, GitOps), see [tunnet policy](/cli/policy).

## tunnet keep-alive

Keep a peer connection always open (disables on-demand dialing for that host).

```bash
tunnet keep-alive <hostname>
tunnet keep-alive <hostname> --off
```

Also configurable per network in `tunnet.toml` with `keep-alive = true`.

## tunnet upgrade-to-managed

Migrate from Direct to Managed mode. The machine must be on a single Direct network.

```bash
tunnet upgrade-to-managed \
  --control-url http://control:8080 \
  --token TOKEN
```
