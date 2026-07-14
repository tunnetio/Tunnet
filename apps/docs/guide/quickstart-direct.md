# Quick Start - Direct Mode

Direct mode creates a peer-to-peer mesh network with **no control plane, no server, no infrastructure**. Membership is stored in a CRDT document (iroh-docs), peer discovery uses the Mainline DHT, and transport auth proves knowledge of a pre-shared key.

This mode is ideal for individuals, small groups, or situations where you cannot or do not want to run any servers. One agent can join multiple Direct networks.

## 0. Install the agent

On every machine that will join the mesh make sure to install the agent first: [Installation](/guide/installation).

## 1. Create a network

On the first machine:

```bash
sudo tuntun create --name my-network --secret "a-strong-passphrase"
sudo tuntun service start
```

The machine creates a new Direct network, becomes its coordinator, writes `tuntun.toml`, and seals the network secret in `state.enc`.

## 2. Generate an invite

```bash
tuntun invite my-network
```

This outputs an invite code that encodes the iroh-docs document ID, a network topic, and the pre-shared key.

## 3. Join from another machine

```bash
sudo tuntun join <INVITE_CODE>
sudo tuntun service start
```

The new peer connects via the DHT, proves it knows the PSK, and joins the membership document. Both machines get mesh IPs and can communicate.

## 4. Verify

```bash
tuntun status --peers
tuntun ping other-machine
```

## Multiple networks

Create or join additional Direct networks without resetting:

```bash
sudo tuntun create --name gaming --secret "another-secret"
# or
sudo tuntun join <OTHER_INVITE>
```

When more than one network is active, pass the network name to management commands (`tuntun invite gaming`, `tuntun requests gaming`, …).

If mesh IPs collide across networks, the first-joined network wins outbound traffic. Override with:

```bash
tuntun override-ip --peer other-machine --ip 10.7.0.50 --network gaming
```

Leave a network (not the last one):

```bash
tuntun leave --network gaming
```

## Configuration

Firewall, DNS, logging, and auto-update live in `tuntun.toml`. After editing:

```bash
tuntun validate
tuntun reload
```

See [Configuration](/guide/configuration).

## Managing Direct networks

`tuntun requests` lists pending join requests if you are the coordinator. `tuntun accept` and `tuntun deny` handle those requests. `tuntun kick` removes a peer. `tuntun firewall` manages local rules. Full reference: [Direct Mode Commands](/cli/direct).

## Ephemeral two-peer connections

For a quick connection without a full network membership document, exchange contact IDs:

```bash
# Machine A (shows contact id in status / connect rotate)
tuntun connect allow <tt_from_b>
tuntun connect <tt_from_b>

# Machine B
tuntun connect <tt_from_a>
```

## Upgrading to Managed

When you outgrow Direct mode and need a dashboard, SSO, or centralized policies (leave extra networks first so only one remains):

```bash
tuntun upgrade-to-managed \
  --control-url http://your-control-host:8080 \
  --token YOUR_ENROLLMENT_TOKEN
```

This migrates your network to Managed mode without losing connectivity.
