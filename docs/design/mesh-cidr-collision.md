# Tunnet Direct collides with Tailscale on 100.64.0.0/10

## Summary

Tunnet Direct hardcodes its mesh range to `100.64.0.0/10`. Tailscale uses the same range. On a host running both, they fight in the kernel routing table and *both* degrade, with no diagnostic from either side. The user sees "connected" on both products and traffic that does not work.

This document records the reproduction, the diagnosis, and a proposed fix. The diagnostics half is cheap and touches no wire format. The configurable-CIDR half touches `Genesis` and needs maintainer agreement before it is built.

## Evidence

Measured on a Linux host running Tailscale and joined to Direct network `my-network` as coordinator at `100.95.248.22`.

Both products hold an address inside the same `/10`:

```
tailscale0       UNKNOWN  100.122.80.25/32   fd7a:115c:a1e0::1c32:5019/128
tunnet0          UNKNOWN  100.95.248.22/10   100.100.100.53/32
```

### Mechanism 1: Tunnet's connected route swallows Tailscale's range

Tunnet installs a connected `/10` in the main table. Tailscale resolves peers through `ip rule` priority 5270 into table 52, which holds only `/32` host routes for currently-known peers:

```
5270:   from all lookup 52
32766:  from all lookup main

$ ip route show table 52
100.91.18.19 dev tailscale0
100.100.100.100 dev tailscale0
100.119.237.128 dev tailscale0

$ ip route show | grep 100.64
100.64.0.0/10 dev tunnet0 proto kernel scope link src 100.95.248.22
```

Table 52 pins three addresses. The remaining ~4 million addresses of Tailscale's own range fall through to main and land on `tunnet0`. Confirmed with unprivileged route lookups:

```
$ ip route get 100.122.80.26     # one past Tailscale's own address
100.122.80.26 dev tunnet0 src 100.95.248.22
$ ip route get 100.64.0.1
100.64.0.1 dev tunnet0 src 100.95.248.22
$ ip route get 100.127.255.254
100.127.255.254 dev tunnet0 src 100.95.248.22
```

Any Tailscale destination that table 52 does not currently pin would be delivered to Tunnet, which has no peer for it and drops it.

**This is a latent structural hazard, not a currently-firing one.** At the time of measurement Tailscale had three peers and table 52 pinned all three, so no Tailscale traffic was actually being leaked. The exposure appears when table 52 does not cover a destination: a peer that is offline or not yet discovered, a peer removed from the netmap, or a subnet route. The routing overlap is real and permanent; the leakage is intermittent.

### The `no_route` counter is NOT evidence of this, and citing it was wrong

The original report cited `tunnet_dropped_packets_total{reason="no_route"}` at ~94,000 and climbing (measured later at 1,273,378) as proof that Tunnet was eating Tailscale traffic. **A packet capture disproves this.** Over a 25s window the counters moved by 202 (v4) and 102 (v6), and the capture accounts for essentially all of it:

```
== top IPv4 destinations seen on tunnet0 ==
    198 224.76.78.75
== top IPv4 sources ==
     99 100.95.248.22
     99 100.100.100.53

IP 100.95.248.22.32889  > 224.76.78.75.20808: UDP, length 107
IP 100.100.100.53.58429 > 224.76.78.75.20808: UDP, length 107
IP6 fe80::d859:...:9d97.47207 > ff12::8080.20808: UDP, length 119
```

Zero CGNAT destinations were captured. Every dropped packet was **multicast**, and the sender is identified:

```
UNCONN 0 0 100.95.248.22:32889  users:(("ableton-linkd",pid=4015,fd=29))
UNCONN 0 0 100.100.100.53:58429 users:(("ableton-linkd",pid=4015,fd=32))
```

`ableton-linkd` (Ableton Link, `224.76.78.75:20808`) enumerates every interface address and beacons on each, including both of `tunnet0`'s. Tunnet correctly cannot route multicast, drops it, and counts it as `no_route`. The 1.27M figure is benign LAN discovery noise accumulated over 1d20h. It has nothing to do with Tailscale.

Two further caveats on that original measurement:

- The counters were scraped from a daemon built in a **since-deleted worktree** (`Tunnet-fix-grant-expiry`), so they cannot be mapped to any commit in this repo.

The kernel-side figures do hold: `tunnet0` shows 1,917,554 TX packets / 284 MB pushed in against 1,948 RX. That is real, and it is all multicast.

### Mechanism 3: Tailscale drops this host's own traffic to Tunnet's addresses (PROVEN, firing continuously)

This was not in the original report and is the most damaging of the three, because it needs no peers, no mesh traffic and no exit node. It is broken on every machine running both products, permanently.

Tailscale installs a source-based anti-spoof rule:

```
[398713:26504549] -A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
```

It matches on **source** address, and Tunnet's own addresses are in that range. Traffic this host sends to its own mesh IP or its own MagicDNS resolver routes via `lo` with a source inside `100.64.0.0/10`, so Tailscale drops it:

```
100.100.100.53  -> local ... dev lo  src 100.100.100.53   (src in 100.64/10, iif=lo, not tailscale0 => DROP)
100.100.100.100 -> dev tailscale0    src 100.122.80.25    (iif=tailscale0 => ACCEPT)
```

Tailscale had to add `-A ts-input -s 100.122.80.25/32 -i lo -j ACCEPT` to stop its own rule eating its own loopback traffic. Tunnet gets no such exemption.

Proven causally by measuring the rule's counter around a known burst:

| Burst | Sent | Dropped |
|---|---|---|
| `100.100.100.53:53` (Tunnet MagicDNS) | 50 | **50** |
| `100.95.248.22:9999` (Tunnet mesh IP) | 50 | **50** |
| `127.0.0.1:9999` (control) | 50 | **0** |

The observable symptom is silent DNS failure. Tunnet's resolver **is listening** on `100.100.100.53:53` and simply never receives a query, while Tailscale's `100.100.100.100` answers normally on the same host. Nothing logs anything. Confirmed live: a query to `100.100.100.53` times out, the same query to `100.100.100.100` returns.

Background rate with the mesh completely idle was 5.00 packets/s being dropped this way.

### Mechanism 2: Tailscale drops inbound mesh traffic as spoofed

Reported from the same host. Mesh traffic arrived but was never answered. Agent metrics proved delivery: the sending phone's `direction="out"` and this host's `direction="in"` matched exactly (14 packets, 1176 bytes), so the packets reached the TUN and were written to the kernel. The kernel did not reply. `sudo tailscale down` made `ping` work immediately at 0% loss.

Tailscale treats packets sourced from `100.64.0.0/10` arriving on any interface other than `tailscale0` as spoofed, because it assumes it owns that range.

**Status of the evidence:**

- **Mechanism 3 (anti-spoof kills loopback to our own addresses): PROVEN causally**, 50/50 with a clean control, and firing continuously at ~5 packets/s on an idle mesh. This is the strongest result and the likely cause of the user-visible complaint.
- **Mechanism 1 routing overlap: proven** by `ip route get`, and structurally permanent while both products share the range.
- **Mechanism 1 active leakage: not observed.** Table 52 currently covers every known peer. The hazard is latent.
- **The `no_route` counter: disproven as evidence.** It is Ableton Link multicast, per the capture above.
- **Mechanism 2 (inbound mesh packets dropped as spoofed): PROVEN.** With a phone joined as a peer, a TCP probe to the desktop's mesh service timed out with Tailscale up and returned `HTTP/1.1 200 OK` with it down, Tailscale being the only variable. Its anti-spoof counter rose by exactly the number of packets delivered to the TUN. Note the original report's "ping works after `tailscale down`" step is NOT reproducible on that host, which drops ICMP host-wide, so a TCP probe must be used instead.

The case for the fix rests on mechanisms 3 and 1, both of which are solid without the counter. The counter should not be quoted in support of anything.

### A fourth hazard, currently dormant

```
-A ts-forward -s 100.64.0.0/10 -o tailscale0 -j DROP
```

At `[0:0]` because this host does not forward. If the machine ever becomes a Tunnet exit node or subnet router while Tailscale is up, Tailscale will drop outbound mesh-sourced traffic as well. Same root cause, different chain, and it would also fail silently.

## Where the range is hardcoded

Four places, three of them independent copies of the same constant:

| Location | What |
|---|---|
| `crates/tunnet-core/src/direct/ip.rs:11-13` | `direct_cgnat()` returns `100.64.0.0/10` |
| `crates/tunnet-core/src/direct/ip.rs:39` | `derive_ipv4` re-hardcodes the `100.64.0.0` base and masks a blake3 hash into the low 22 bits |
| `crates/tunnet-agent/src/runtime.rs:161` | prefix length `10u8` hardcoded for the Direct case |
| `crates/tunnet-common/src/lib.rs:173,177` | MagicDNS defaults `100.100.100.53` and `100.100.0.1`, both inside the same `/10` |

Note `100.100.100.53` is one digit from Tailscale's own `100.100.100.100`. Both currently resolve, because Tailscale pins `100.100.100.100` as a `/32` in table 52 and Tunnet holds `100.100.100.53` in the local table, but this is luck rather than design.

## Who actually derives addresses, and from what

This is the part that decides where the CIDR belongs, and it does not match the obvious assumption. Call sites of `derive_ipv4`:

| Site | Role | Genesis available? |
|---|---|---|
| `cmds_direct.rs:254` | `tunnet create`, coordinator self-assign | Yes, being created right there |
| `cmds_direct.rs:353` | join, node's own address | **No, only the invite** |
| `cmds_direct.rs:583,592` | coordinator assigning/deconflicting joiner IPs | Yes |
| `node.rs:519,881` | local recompute of self IP from stored `collision_index` | Yes |
| `connect.rs:168` | fallback when a peer's connect response omits `ipv4` | Yes |
| `connect.rs:221` | accept-pending, derives the peer's IP | Yes |

The key observation is that **derived addresses are a proposal, not the authority**. At join, the node derives an address and puts it in the `join_request`, but the coordinator answers with an authoritative `ipv4` that overwrites it:

```rust
if let Some(ip) = resp.get("ipv4").and_then(|v| v.as_str()) {
    assigned_ipv4 = ip.parse().unwrap_or(assigned_ipv4);
}
```

And peer addresses are carried explicitly in `SignedMemberRecord.ipv4`, so `derive_ipv4` on the peer paths is only a fallback when the record or response is missing.

**Therefore the CIDR does not need to be in `InviteCode`.** Every site that needs network-wide agreement already has `Genesis` in hand by the time it runs. The one site that does not (the join-time self-proposal) is immediately corrected by the coordinator. This is a better answer than putting it in the invite, because `InviteCode` is unsigned plain base64 JSON, so a CIDR there would be attacker-mutable.

### Aside: pre-existing bug found while tracing this

`connect.rs:221` calls `derive_ipv4(&pending.endpoint_id, 0)` with `collision_index` hardcoded to `0`. If that peer was assigned a non-zero collision index, this installs a route to the wrong address. Independent of the CIDR work, but worth a separate fix.

## Proposal

### Home: `Genesis`, as an optional field

```rust
pub struct Genesis {
    // ... existing fields, unchanged order ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_cidr: Option<Ipv4Net>,
}
```

`None` means `100.64.0.0/10`, so every existing network keeps behaving exactly as today.

### Signature compatibility

`Genesis` is signed over an explicit `GenesisSignPayload` struct (`grants.rs:225-242`), which is what makes this tractable. Appending the field **last** and marking it `skip_serializing_if = "Option::is_none"` gives:

- Old genesis records deserialize to `mesh_cidr: None`, the field is skipped during signing, the payload bytes are byte-identical to today, and **existing signatures still verify**.
- New networks set `Some(cidr)`, the field is included in the payload, and the CIDR is fully authenticated by the coordinator signature.
- Tampering fails closed in both directions: stripping the field from a new genesis or adding one to an old genesis changes the payload and breaks the signature.
- An old client handed a *new* genesis computes the payload without the field, fails verification, and **rejects the network rather than silently using the wrong range**. Fail-closed on downgrade is the property we want.

This needs confirming against `serde_json`'s field ordering guarantee (declaration order), which holds for derived `Serialize` on structs.

### Renumbering: create-time only

Changing the CIDR changes every derived address in the network. That is a renumbering, not a setting: it invalidates every `SignedMemberRecord.ipv4`, every installed peer route, and every host key binding that assumes a stable address. There is no in-place migration worth building for a pre-1.0 product.

**Recommendation: `--cidr` is accepted only at `tunnet create`, and is immutable for the life of the network.** Changing it later means creating a new network. The CLI should reject the flag anywhere else with a message that says exactly this.

### MagicDNS must move with the range

`100.100.100.53` and `100.100.0.1` are inside the default `/10` and must be derived from the configured CIDR rather than remaining constants, or a custom-CIDR network will hand out DNS addresses that route nowhere. Suggest deriving them at a fixed offset from the CIDR base.

### Collision pre-check at create and join

Independent of the wire change: read the host's interfaces and routing table at `tunnet create` and `tunnet join`, and if another interface already holds an address inside the proposed mesh CIDR, refuse or warn with the offending interface named. A collision that is discovered up front costs one line of output. The same collision discovered later costs weeks of silent packet loss, as it did here.

## Phasing

**Phase 1, no wire change, landable now:** collision detection plus the drop-metric fixes below. Implemented in the accompanying commits and independently useful.

## Observability defects found while investigating (fixed in Phase 1)

The misdiagnosis above was caused by the metrics, and is worth fixing on its own merits.

**Multicast was counted as `no_route`.** Benign discovery beacons (Ableton Link here, but equally mDNS or SSDP) arrive forever at a steady rate and buried the genuine "mesh destination with no peer" signal under millions of packets. Multicast and broadcast now count as `reason="multicast"`, so `no_route` means what a reader assumes it means.

## Separate bug found, NOT fixed here: multicast leaks to the exit node

`is_mesh_or_link_local` (`routing.rs:967`) checks loopback, link-local, broadcast and unspecified, but **not** `is_multicast()`. With an exit node configured, multicast therefore passes the internet-catch-all check and is tunneled to the exit peer. Broadcast leaks too, via the `0.0.0.0/0` entry the exit node contributes to the subnet LPM table. Reproduced against the existing test harness:

```
MULTICAST 224.76.78.75 -> NoRoute? false
LEAK: multicast routed to exit peer bbbb...bbbb
```

So on any host with an exit node, LAN discovery beacons are pushed through the tunnel and out of the exit. This is left unfixed deliberately: it is a datapath behaviour change while that refactor is in flight, and it belongs to whoever owns `route_once`. The fix is an early multicast/broadcast rejection in `route_once` placed **before** the subnet LPM lookup, not merely adding `is_multicast()` to `is_mesh_or_link_local`, since the latter would not catch the broadcast-via-`0.0.0.0/0` path.

Note this also bounds the new `multicast` counter: it is incremented at the `NoRoute` site, so on a host with an exit node configured the multicast is routed away before reaching it and will not be counted.

**Phase 2, needs maintainer agreement:** the `Genesis.mesh_cidr` field, `--cidr` on `tunnet create`, threading the CIDR through `derive_ipv4` and `runtime.rs`, and MagicDNS derivation. Deferred because it touches a signed record while the datapath refactor is in flight.

## Status update

Mechanism 2 has since been proven (see above). The underlying fix is being implemented in tunnetio/Tunnet#24, which makes signed `Genesis` the allocation authority, makes signed membership the only `EndpointId -> IP` authority, replaces the connected `/10` with exact `/32` peer routes (verified: `fn mesh_cidr` is gone and the TUN is assigned a `/32`), and moves PeerDNS to a loopback address. That supersedes the proposal section above.

Two defects this investigation found are NOT addressed by that work and are tracked separately: multicast and broadcast still reach a configured exit node, and a vanished interface still disables OS DNS integration permanently.
