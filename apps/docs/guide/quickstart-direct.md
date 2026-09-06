# Quick Start - Direct Mode

Direct mode creates a peer-to-peer mesh network with **no control plane, no server, no infrastructure**. Membership is stored in a CRDT document (iroh-docs), peer discovery uses the Mainline DHT, and transport auth uses signed grants (or invite bootstrap) before application protocols are accepted.

This mode is ideal for individuals, small groups, or situations where you cannot or do not want to run any servers. One agent can join multiple Direct networks.

## 0. Install the agent

On every machine that will join the mesh make sure to install the agent first: [Installation](/guide/installation).

## 1. Create a network

On the first machine:

```bash
sudo tunnet create --name my-network --secret "a-strong-passphrase"
sudo tunnet service start
```

The machine creates a new Direct network, becomes its coordinator, writes `tunnet.toml`, and seals the network secret in `state.enc`.

## 2. Generate an invite

```bash
tunnet invite my-network
```

This outputs an invite code that encodes the iroh-docs document ID, network topic, and bootstrap material for the first join.

## 3. Join from another machine

```bash
sudo tunnet join <INVITE_CODE>
sudo tunnet service start
```

The new peer connects via the DHT, completes invite bootstrap, receives a signed grant from the coordinator, and joins the membership document. Both machines get mesh IPs and can communicate.

## 4. Verify

```bash
tunnet status --peers
tunnet ping other-machine
```

## Multiple networks

Create or join additional Direct networks without resetting:

```bash
sudo tunnet create --name gaming --secret "another-secret"
# or
sudo tunnet join <OTHER_INVITE>
```

When more than one network is active, pass the network name to management commands (`tunnet invite gaming`, `tunnet requests gaming`, …).

If mesh IPs collide across networks, the overlapping Direct networks are rejected.  Override with:

```bash
```

Leave a network (not the last one):

```bash
tunnet leave --network gaming
```

## Configuration

Firewall, DNS, logging, and auto-update live in `tunnet.toml`. After editing:

```bash
tunnet validate
tunnet reload
```

See [Configuration](/guide/configuration).

## Managing Direct networks

`tunnet requests` lists pending join requests if you are the coordinator. `tunnet accept` and `tunnet deny` handle those requests. `tunnet kick` removes a peer. `tunnet firewall` manages local rules. Full reference: [Direct Mode Commands](/cli/direct).

## Ephemeral two-peer connections

For a quick connection without a full network membership document, exchange contact IDs:

```bash
# Machine A (shows contact id in status / connect rotate)
tunnet connect allow <tt_from_b>
tunnet connect <tt_from_b>

# Machine B
tunnet connect <tt_from_a>
```

## Upgrading to Managed

When you outgrow Direct mode and need a dashboard, SSO, or centralized policies (leave extra networks first so only one remains):

```bash
tunnet upgrade-to-managed \
  --control-url http://your-control-host:8080 \
  --token YOUR_ENROLLMENT_TOKEN
```

This migrates your network to Managed mode without losing connectivity.
