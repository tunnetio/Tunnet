# Tunnet Extreme Performance Audit

**Repository:** `tunnetio/Tunnet`  
**Audit baseline commit:** `2d20b0c1790634212df2e8ee738ad11474c2ca9e`  
**Initial benchmark date:** 2026-09-03  
**Primary comparison:** Tunnet vs ZeroTier, Windows client → Linux peer  
**Objective:** materially outperform ZeroTier in throughput, loaded latency, packet rate, CPU/byte, jitter, recovery, and reliability without weakening security or correctness.

> This is a living audit. Findings are classified as **Confirmed**, **Strong hypothesis**, or **Experiment**. Do not turn experiments into defaults without measurement.

---

## 1. Baseline

### Tunnet
- Idle ICMP: 93.76 ms avg
- Loaded ICMP: 221.67 ms avg
- Loaded max: 476 ms
- TCP upload: 80.4 Mbps sender / 79.4 Mbps receiver
- TCP download: 99 Mbps
- UDP 500 Mbps offered: 0.714 ms jitter, 83.11% loss

### ZeroTier
- Idle ICMP: 83.54 ms avg
- Loaded ICMP: 85.71 ms avg
- Loaded max: 111 ms
- TCP upload: 85.6 Mbps sender / 84.5 Mbps receiver
- TCP download: 136 Mbps
- UDP 500 Mbps offered: 0.556 ms jitter, 83.82% loss

### Immediate interpretation
- Tunnet's major defect is not raw throughput. It is **queueing latency under saturation**.
- Tunnet adds roughly 128 ms of latency under this load while ZeroTier adds only ~2 ms.
- The 500 Mbps UDP loss test is not a valid reliability comparison. Both products are offered several times more traffic than the measured path can sustain.
- Idle RTT is also ~10 ms worse on Tunnet, but the current benchmark does not prove whether Tunnet and ZeroTier used equivalent physical/direct paths. Path state must be captured.

---

# 2. Current data-plane map

## Outbound, Windows/Linux host → peer

`TUN`
→ `tun_io::run_outbound`
→ SSH-NAT pre-pass
→ packet parse
→ route classification / lookup
→ peer lookup
→ ACL
→ Direct firewall
→ QoS classification
→ `Bytes::copy_from_slice`
→ `OutboundScheduler`
→ per-peer class queues
→ per-peer sender task
→ `ConnPool::send_or_buffer`
→ peer-slot lookup / async mutex
→ Iroh `Connection`
→ QUIC DATAGRAM buffer
→ noq congestion control / pacing / packetization / crypto
→ noq-udp
→ OS UDP socket
→ physical network

## Inbound, peer → local host

physical network
→ OS UDP socket
→ noq-udp
→ noq QUIC
→ Iroh `Connection::read_datagram`
→ one per-connection inbound task
→ packet parse
→ route / endpoint checks
→ anti-spoof
→ ACL
→ Direct firewall
→ SSH-NAT check/rewrite
→ one `AsyncDevice::send().await`
→ TUN
→ host stack

---

# 3. Highest-priority findings

## F-001 — Stacked multi-megabyte queues create artificial bufferbloat
**Status:** Confirmed  
**Priority:** P0  
**Impact:** Extreme

Tunnet's application QoS scheduler can hold:
- latency: 64 packets
- normal: 256 packets
- bulk: 512 packets
- total: 832 packets

At the default 1280-byte virtual MTU this is approximately 1.016 MiB.

Below that, current `noq` defaults to:
- `datagram_send_buffer_size = 1 MiB`

On Windows, tun-rs/Wintun defaults to:
- ring capacity = 2 MiB

Not every buffer is necessarily full simultaneously, but the scale is enough to explain the benchmark. At ~80 Mbps, 1 MiB is about 105 ms of serialization time. Two 1 MiB queues are about 210 ms before considering other buffering.

**Evidence**
- `crates/tunnet-agent/src/qos.rs`
- `crates/tunnet-core/src/iroh_pool.rs`
- `noq-proto/src/config/transport.rs`
- tun-rs Windows device/session defaults

**Required change**
- Treat queueing budget in **time/bytes**, not packet count.
- Keep one intentionally controlled queueing point.
- Shrink Iroh/noq DATAGRAM buffering substantially for VPN traffic.
- Avoid using Wintun ring size as a latency buffer.
- Instrument sojourn time at every queue.

---

## F-002 — `send_datagram_wait` reverses low-latency DATAGRAM semantics
**Status:** Confirmed  
**Priority:** P0  
**Impact:** Extreme

Current Tunnet behavior:
1. check `datagram_send_buffer_space()`
2. when zero, call `send_datagram_wait(packet).await`

Iroh explicitly documents that `send_datagram_wait` waits during congestion and **effectively prioritizes old datagrams over new datagrams**.

That is a poor default for an IP tunnel:
- stale TCP packets amplify inner TCP queueing
- interactive packets arriving later cannot replace stale bulk
- one sender can await a bulk packet while latency traffic is already queued

This produces application-level HOL blocking over an intentionally unreliable/unordered QUIC DATAGRAM primitive.

**Required change**
- Never block the class scheduler on one stale packet.
- Make freshness/drop policy explicit in Tunnet.
- Prefer bounded `send_datagram()` semantics with Tunnet-owned scheduling.
- Use current send-buffer-space information to decide whether to dequeue, not to turn a packet into a long-lived awaited future.
- Preserve per-flow ordering in Tunnet's queue design.

---

## F-003 — Per-peer sender has priority inversion under transport pressure
**Status:** Confirmed  
**Priority:** P0  
**Impact:** Extreme

Three priority classes ultimately feed **one sender future per peer**. DRR priority helps only before the sender starts awaiting transport capacity.

If a bulk packet reaches `send_datagram_wait`, later latency packets cannot preempt it.

**Required change**
Build a non-blocking scheduler/pump:
- queue packet
- classify
- dequeue only while transport can accept useful work
- on congestion, drop/replace stale packets according to sojourn/AQM policy
- wake/retry without holding a particular bulk packet as the scheduler's awaited future

Do not immediately solve this with separate QUIC connections per class; independent congestion controllers can create fairness and path behavior problems.

---

## F-004 — Tunnet parses normal outbound packets twice
**Status:** Confirmed  
**Priority:** P1  
**Impact:** High at high PPS

`run_outbound`:
1. calls `ssh_nat::rewrite_outbound`
2. that function parses the packet
3. `run_outbound` then parses the packet again

Inbound normal packets are also parsed for the main path and again for SSH-NAT detection; rewritten SSH packets can parse yet again.

**Required change**
- Parse exactly once.
- Pass parsed metadata to SSH-NAT.
- Use a very cheap precondition before any SSH rewrite work.
- Reparse only if a rewrite changes fields required by later stages.

---

## F-005 — Every outbound packet is copied into a new `Bytes`
**Status:** Confirmed  
**Priority:** P1  
**Impact:** High

Current path reads into a reusable `Vec<u8>`, then creates:
`Bytes::copy_from_slice(packet)`.

That performs an allocation/copy before every outgoing QUIC DATAGRAM.

**Phase 1 solution**
- pooled owned packet buffers
- receive TUN data directly into an owned buffer
- turn ownership into `Bytes` without the second copy
- recycle on Drop

`Bytes::from_owner` is particularly interesting for a custom pooled owner.

**Phase 3 experiment**
Raw Wintun receive-ring ownership via RAII + `Bytes::from_owner`, releasing the Wintun packet on final Drop. This can be true zero-copy from Wintun shared memory into the QUIC application buffer, but it must not pin receive-ring entries for long under congestion.

---

## F-006 — Linux ignores tun-rs's high-performance API
**Status:** Confirmed  
**Priority:** P0  
**Impact:** Potentially extreme

tun-rs currently supports on Linux:
- `offload(true)`
- async `recv_multiple`
- async `send_multiple`
- reusable `GROTable`
- `IDEAL_BATCH_SIZE` = 128
- multi-queue
- additional queue creation

Tunnet currently uses one-packet `recv()` / `send()` and does not enable those features.

**Required Linux fast path**
- enable TUN offload
- use `recv_multiple` and `send_multiple`
- preallocate batch storage
- reuse `GROTable`
- evaluate multi-queue after single-queue batching is correct
- shard flows deterministically if multiple queues are used
- preserve ordering per flow

---

## F-007 — Windows uses Wintun as one-packet async I/O instead of a burst ring
**Status:** Confirmed  
**Priority:** P0  
**Impact:** High

tun-rs exposes `try_recv` and `try_send` on Windows.
Wintun itself is a shared-memory ring and recommends spinning briefly / draining under heavy load before falling back to the read-wait event.

tun-rs's Windows async fallback can involve a blocking worker; its send fallback copies the source to a `Vec`.

**Required Windows fast path**
- after readiness/wakeup, repeatedly `try_recv` until `WouldBlock` or batch budget
- process a bounded burst
- repeatedly `try_send` inbound packets before falling back to waiting
- benchmark spin budget vs CPU consumption
- tune Wintun ring capacity based on measured BDP/queueing, not “bigger is faster”
- do not allow ring buffering to mask queue management

---

## F-008 — Fragment mutex is paid on every packet, even non-fragments
**Status:** Confirmed  
**Priority:** P1  
**Impact:** High under PPS/concurrency

Both ACL and Direct firewall have fragment tracking guarded by a `parking_lot::Mutex<FragmentTable>`.
The normal packet path calls fragment resolution unconditionally.

**Required change**
- branch on packet fragmentation first
- non-fragment path must not acquire fragment state lock
- keep fragment tracking as a slow path
- optionally shard fragment state by flow hash

---

## F-009 — Conntrack does redundant hash-table operations
**Status:** Confirmed  
**Priority:** P1

Established-flow lookup can do:
- `contains_key(fwd)`
- `contains_key(reverse)`
- `get_mut(key)`

in both ACL and Direct firewall state.

**Required change**
- one `get_mut(fwd)`, then one reverse lookup only on miss
- consider canonical bidirectional flow keys
- separate hot “established” state from policy metadata
- replace global periodic retain behavior if it damages p99; evaluate expiry wheel/sharded GC

---

## F-010 — Direct packet policy is structurally duplicated
**Status:** Confirmed semantic overlap; consolidation design pending  
**Priority:** P1

Direct boot converts local firewall config into a `PolicyBundle` consumed by `AclEngine`, while `FirewallEngine` is also built from the firewall config and evaluated for every packet.
Suggested policies are later synchronized into `FirewallEngine`.

It is not safe to simply delete one path because the engines also serve different lifecycle/admission roles, but packet-level work can be unified.

**Required architecture**
- connection admission/auth policy at Iroh hook
- one compiled packet-policy engine for org/network/local/suggested rules
- one conntrack
- one fragment table
- one verdict
- differential tests proving exact old/new semantics

---

## F-011 — Policy rules are filtered, allocated, and sorted during evaluation
**Status:** Confirmed  
**Priority:** P1  
**Impact:** Very high for new/stateless flows

The policy engine builds a `Vec<&PolicyRule>`, filters candidates and sorts by order/priority in `first_matching_in_phase`. This can happen for multiple phases.

Some selectors also construct strings such as `format!("user:{id}")`.

**Required change**
Compile policy at install/update time:
- pre-sort phases
- normalize selectors
- compile port ranges
- use integer IDs / enums, not formatted strings
- optional protocol/port/peer indices
- immutable `ArcSwap<CompiledPolicy>` snapshot
- allocation-free evaluation

---

## F-012 — Routing performs multiple snapshots/lookups per packet
**Status:** Confirmed  
**Priority:** P1

Outbound route work calls separate methods for:
- magic DNS destination
- advertised destination
- peer lookup

These can load route state more than once. Advertised destination checking includes a linear `iter().any(...)`.

**Required change**
One immutable snapshot + one `RouteDecision`:
- LocalMagic
- LocalAdvertised
- Peer(FastPeer)
- NoRoute

Compile advertised prefixes into a prefix index.
Return a fast peer handle keyed by binary endpoint ID / compact PeerIndex.

---

## F-013 — Established send path repeatedly hits DashMap + async Mutex
**Status:** Confirmed  
**Priority:** P1

`ConnPool::send_or_buffer` resolves the peer slot through DashMap, clones an Arc, locks a `tokio::sync::Mutex`, checks connection state, updates activity, clones the connection, unlocks, and then sends.

Per-packet counters and activity/path accounting add more map/atomic work.

**Required change**
Introduce `FastPeerTx`/`PeerFastState`:
- stable per-peer object returned by routing
- live connection via atomic/ArcSwap-style pointer
- direct atomics for counters
- coarse activity update, not every packet
- reconnect/control path may still use locked state
- no DashMap lookup on established hot send

---

## F-014 — Metrics registry lookup occurs per packet
**Status:** Confirmed from current metric call pattern  
**Priority:** P1/P2

The hot path calls metric macros/counters per packet with labels.

**Required change**
- pre-register/store metric handles
- for the hottest counters, use per-task local counters and flush periodically
- retain exact drop/error counters where needed
- never allocate labels on the data path

---

## F-015 — Virtual MTU 1280 imposes high per-packet CPU cost
**Status:** Confirmed  
**Priority:** P2  
**Impact:** Potentially large

Tunnet defaults to 1280.
ZeroTier uses a much larger virtual MTU (2800) and handles fragmentation in its overlay.

At the same useful byte rate, Tunnet's small virtual MTU forces more:
- TUN packets
- packet parses
- route lookups
- ACL/conntrack hits
- queue operations
- application DATAGRAMs
- metric increments

Tunnet cannot simply set 2800 today because one inner IP packet maps to one QUIC DATAGRAM and is rejected when larger than Iroh's current max datagram size.

**Required investigation**
- safe adaptive virtual MTU
- overlay segmentation/reassembly
- GSO/GRO-aware framing
- loss amplification of fragmented unreliable DATAGRAMs
- bounded reassembly memory/time
- path MTU changes
- inner TCP MSS behavior

Do not put generic inner TCP data on reliable QUIC streams as a simple workaround; transport-over-transport HOL is unacceptable.

---

## F-016 — Iroh/noq transport configuration is completely implicit
**Status:** Confirmed  
**Priority:** P0/P1

Tunnet builds Iroh endpoints from presets but does not provide a custom `QuicTransportConfig`.

Current noq defaults include:
- CUBIC
- 1 MiB application DATAGRAM send buffer
- datagram receive buffer tied to the default stream receive window
- initial RTT 333 ms
- initial MTU 1200
- DPLPMTUD enabled
- GSO enabled
- ACK-frequency control disabled
- multipath disabled in base transport config

Iroh 1.1 exposes knobs including:
- datagram send/receive buffers
- CUBIC / NewReno / experimental BBRv3
- ACK frequency
- initial RTT
- MTU discovery
- initial/min MTU
- GSO
- multipath
- path idle/keepalive
- connection stats/congestion state

**Required plan**
Create an explicit `TunnetTransportProfile`, versioned and benchmarked. No “magic defaults.”

Initial experiment matrix:
- DATAGRAM send buffer: 16 / 32 / 64 / 128 / 256 KiB
- CUBIC vs experimental BBRv3; NewReno as control
- ACK-frequency threshold variants
- initial RTT based on known path estimate vs default
- initial MTU 1200 vs 1300/1400 only with robust DPLPMTUD
- direct and relay paths separately

Do not disable GSO; it is already enabled by default.

---

## F-017 — noq already optimizes UDP I/O; do not duplicate it above Iroh
**Status:** Confirmed

Current noq/noq-udp already has:
- Linux UDP GSO
- Linux batched receive (`recvmmsg`)
- Windows GSO/GRO support
- `WSASendMsg`
- `WSARecvMsg`
- bounded endpoint receive/send iterations

Therefore the major optimization opportunity is not “manual UDP batching” around Iroh. It is:
- feed Iroh efficiently
- avoid application queue stacks
- configure transport explicitly
- remove Tunnet hot-path overhead

---

## F-018 — ZeroTier CoDel exists but is currently disabled
**Status:** Confirmed correction

ZeroTier contains a CoDel/DRR AQM implementation with a 5 ms target and 100 ms interval, but current `Network::qosEnabled()` returns `false`.

Therefore it is **not valid** to attribute this benchmark's excellent ZeroTier loaded latency to active CoDel.

This strengthens the conclusion that Tunnet's load-latency defect is mostly self-inflicted queueing.

AQM/FQ-CoDel remains a useful Tunnet option after unnecessary buffering and `send_datagram_wait` are removed.

---

# 4. Benchmark defects that must be fixed

## Current PowerShell benchmark weaknesses
- 500 Mbps UDP offered rate massively exceeds path capacity.
- under-load iperf result is discarded
- only upload load is tested
- no bidirectional load
- no load-rate sweep
- no path-state capture
- no CPU/alloc/context-switch measurements
- averages dominate; no p95/p99/p99.9
- no repeated randomized runs

## Benchmark v2 requirements

### Path validation
For every run record:
- Tunnet direct / relay / selected address
- Iroh path state
- ZeroTier direct / relay
- native underlay RTT/path to the same physical peer when possible

### Throughput
- TCP 1 / 4 / 8 streams
- upload
- download
- bidirectional
- JSON output
- actual achieved throughput
- retransmits and congestion stats

### Loaded latency
For upload, download and bidirectional:
- 25%
- 50%
- 75%
- 90%
- 100%
- 110% of measured capacity

Record:
- p50
- p95
- p99
- p99.9
- max
- actual throughput during latency sampling

A product must not “win latency” by starving throughput.

### UDP
Sweep useful offered rates instead of only 500 Mbps:
- 25/50/75/90/100/110% of path capacity
- packet sizes 64/128/256/512/~1200/max-safe
- loss
- jitter
- delivered Mbps
- delivered PPS

### Resource efficiency
Both peers:
- total CPU
- hottest core CPU
- cycles/byte if tooling allows
- cycles/packet
- context switches
- allocations/sec
- bytes allocated/sec
- working set
- scheduler wakeups

### Reliability / adverse network
- 0.1%, 1%, 3%, 5% loss
- reordering
- 10/50/100 ms jitter
- sudden bandwidth reduction
- NAT rebinding
- direct→relay transition
- relay→direct upgrade
- temporary network outage
- MTU black hole scenario

---

# 5. Instrumentation required before aggressive tuning

Add low-overhead histograms/counters for:

1. TUN receive timestamp
2. parse/policy completion
3. scheduler enqueue
4. scheduler dequeue
5. scheduler sojourn time
6. transport submit
7. transport blocked/full event
8. Iroh datagram send buffer free bytes
9. remote datagram receive
10. remote policy completion
11. remote TUN write
12. queue lengths in bytes and packets
13. drops by reason/class
14. reconnect-buffer depth
15. per-peer active path
16. QUIC RTT
17. congestion window / bytes in flight if exposed
18. path MTU
19. direct vs relay status

Use sampled or per-task accumulation where necessary; instrumentation itself must not become the bottleneck.

---

# 6. Proposed architecture

## 6.1 Packet object

Create a `PacketBuf` / `OwnedPacket` abstraction:
- pooled storage
- immutable after classification except explicit NAT rewrite
- parsed metadata stored alongside bytes
- `Bytes` view without copying
- reusable on drop if practical

Conceptually:

```
PacketBuf {
    bytes,
    parsed: PacketMeta,
    flow_key,
    class,
    enqueue_ts,
    peer_fast_handle,
}
```

Do not keep a borrowed `etherparse::SlicedPacket` across mutations. Store compact metadata.

---

## 6.2 One-pass outbound pipeline

```
TUN batch/burst
  -> minimal parse once
  -> optional NAT rewrite using parsed metadata
  -> one route snapshot / RouteDecision
  -> one unified policy verdict
  -> classify flow/class
  -> enqueue into bounded freshness-aware peer scheduler
  -> nonblocking transport pump
```

No strings, formatting, map lookups, allocations or blocking locks in the established hot path unless unavoidable.

---

## 6.3 Scheduler design

First implementation:
- per-peer
- per-flow sparse queues inside three service classes
- byte/time bounds
- DRR across active flows
- latency class strict low sojourn budget
- normal/bulk AQM (CoDel or equivalent)
- preserve order within each flow
- never await a bulk packet while a higher-priority packet exists

Alternative simpler P0:
- retain 3 classes
- reduce queues drastically
- add enqueue timestamps
- drop stale bulk/normal
- remove `send_datagram_wait`
- pump only while transport has room

Ship simple P0 first to prove the bufferbloat diagnosis, then FQ/AQM.

---

## 6.4 OS-specific TUN engines

### Linux
Dedicated optimized engine:
- offload
- async recv_multiple/send_multiple
- GROTable reuse
- preallocated 128-packet batch
- optional multi-queue
- flow-preserving sharding
- benchmark queue count against CPU topology

### Windows
Dedicated Wintun engine:
- `try_recv` burst drain
- bounded spin under load
- event wait when idle
- `try_send` burst fill
- pooled packet storage
- tuned ring capacity
- later: raw-ring zero-copy experiment

Avoid forcing a single generic abstraction to hide every performance capability if it costs throughput. Share policy/scheduler semantics, not necessarily I/O mechanics.

---

# 7. Optimization phases

## Phase 0 — prove and remove the latency catastrophe
1. Benchmark v2 minimum: capture loaded throughput and path state.
2. Add queue-sojourn and transport-buffer telemetry.
3. Replace `send_datagram_wait` in packet tunnel path.
4. Reduce app queue limits from ~1 MiB to a time/byte budget.
5. Explicitly reduce noq DATAGRAM send buffer.
6. Windows burst `try_recv` / `try_send`.
7. Linux offload + async batching.
8. Compare CUBIC vs BBRv3 experimentally.
9. Repeat exact Windows→Linux baseline.

**Exit target**
- loaded RTT inflation < 10 ms at 90% capacity
- < 25 ms at saturation, ideally much lower
- no material throughput regression
- loss/drop reasons understood

## Phase 1 — remove per-packet taxes
1. Parse once.
2. Remove unconditional fragment locks.
3. Consolidate packet policy/conntrack.
4. Compile policy rules at update time.
5. Single routing snapshot/decision.
6. Fast peer handle; eliminate established-path DashMap + async mutex.
7. Pre-register/cache metrics handles or batch counters.
8. pooled packet buffers; remove `Bytes::copy_from_slice`.
9. coarse activity accounting.

**Exit target**
- substantial PPS increase
- lower CPU/byte
- download catches/exceeds ZeroTier
- p99 remains bounded

## Phase 2 — packetization/MTU
1. Measure path MTU distribution.
2. Evaluate virtual MTU > 1280.
3. Design safe segmentation/reassembly if needed.
4. Integrate GSO/GRO semantics with overlay framing.
5. tune MSS/PMTUD behavior.
6. measure loss amplification.

**Exit target**
- reduce inner packets per GiB materially
- throughput/CPU gains without reliability regression

## Phase 3 — extreme platform-specific work
1. raw Wintun packet ownership / true zero-copy experiment
2. custom tun-rs upstream API if required
3. multi-core Linux queue sharding
4. CPU affinity only if profiling proves scheduler migration cost
5. specialized packet parser only if etherparse remains hot
6. SIMD/checksum specialization only if profiles justify it
7. allocator/pool tuning based on allocation profiles

---

# 8. Transport experiment matrix

Do not select by intuition.

## Congestion control
- CUBIC baseline
- BBRv3 experimental
- NewReno control

Measure on:
- clean 90 ms path
- 1% loss
- varying bandwidth
- relay path
- asymmetric upload/download
- cross traffic

## DATAGRAM buffering
Test 16/32/64/128/256 KiB.
The correct value is likely related to pacing/BDP and Tunnet queue strategy, not a generic 1 MiB.

## ACK frequency
noq/Iroh supports the extension and Iroh's own benchmark code uses a threshold of 10 in benchmark configuration.
Treat this as an experiment:
- default
- 2
- 5
- 10
- loss-heavy cases

## Initial RTT
Default is 333 ms.
Useful mainly during startup/path changes.
Experiment with a more realistic initial RTT only if it improves first-second behavior without hurting unknown networks.

## MTU
- default initial 1200 + DPLPMTUD
- 1280/1350/1400 initial where safe
- never raise min MTU aggressively on arbitrary internet paths

---

# 9. Reliability invariants

Every optimization must preserve:

- authenticated encrypted transport
- anti-spoof semantics
- ACL/firewall semantics
- bounded memory
- bounded reconnect buffering
- fragment security
- per-flow packet order at Tunnet's own queue
- safe NAT rebinding
- direct/relay path migration
- no blocking shutdown regressions
- no packet lifetime that can pin an OS ring indefinitely

Testing:
- differential old/new policy evaluator
- property/fuzz packet parser and NAT rewrite
- scheduler model tests
- queue bound tests
- simulated transport backpressure
- packet-loss/reordering integration tests

---

# 10. Findings to investigate next

- Exact direct/relay path used by the supplied benchmark.
- Whether Iroh's current preset modifies multipath beyond base noq defaults.
- End-to-end connection/path stats available cheaply enough for adaptive scheduling.
- Incoming Iroh DATAGRAM drain batching opportunities.
- Cost of `pool.touch_peer` per packet and replacement with coarse activity sampling.
- Exact metrics cost under 100k/500k/1M PPS.
- Actual CPU profile Windows and Linux after P0.
- TUN queue/ring occupancy telemetry options.
- impact of Wintun ring capacity reductions.
- whether packet-policy consolidation can share state cleanly between Managed and Direct modes.
- relay performance path, including `tunnet-relay` configuration.
- asymmetric bottleneck explaining 99 Mbps download vs 136 Mbps ZeroTier.
- endpoint worker contention inside noq under many peers.
- multipath QUIC: enablement, scheduling, fairness, and loss behavior.
- path migration and multiple active physical interfaces.
- RSS/CPU-affinity interactions on Windows.
- Linux `busy_poll`, socket buffers, and UDP offload only if noq profiling says they matter.
- PGO/BOLT after architectural work; current `opt-level=3`, ThinLTO, codegen-units=1 are already reasonable.
- allocator choice only after allocations remain material.

---

# 11. Things explicitly not to do yet

- Do not blindly enlarge buffers.
- Do not use `send_datagram_wait` as a reliability mechanism.
- Do not move inner TCP to QUIC streams.
- Do not enable experimental BBRv3 as default without adverse-network testing.
- Do not raise virtual MTU above QUIC DATAGRAM limits without segmentation design.
- Do not optimize crypto before profiling proves it hot.
- Do not fork tun-rs before exhausting the current public high-performance API.
- Do not add CPU affinity before demonstrating scheduler migration/cache problems.
- Do not trust single-run throughput averages.
- Do not call a 500 Mbps offered UDP test “packet-loss reliability” on a ~100 Mbps path.

---

# 12. Current top ten implementation order

1. Make benchmark/path telemetry trustworthy.
2. Delete tunnel-path `send_datagram_wait` semantics.
3. Bound queueing by time/bytes and shrink stacked buffers.
4. Windows burst Wintun pump.
5. Linux offload + recv/send batching.
6. Explicit Tunnet Iroh/noq transport profile.
7. Parse once + pooled packet buffers.
8. Unified compiled policy/conntrack + fragment slow path.
9. Fast route/peer handle without per-packet maps/async mutex.
10. Larger-MTU/GSO-aware overlay design.

The first six are expected to change the supplied benchmark materially. The rest are how Tunnet moves from “competitive” to “architected for extreme PPS/throughput.”

---

# 13. Phase 1 implementation record (2026-09-04)

Phase 1 executed the full data-plane rewrite: the P0 queueing/backpressure work
**and** the P1 hot-path cleanup together. The old architecture no longer
controls the data plane. All findings below were verified against the exact
resolved dependency sources (`iroh 1.1.0`, `noq/noq-proto 1.2.0`,
`tun-rs 2.8.9`, `bytes 1.12.1`).

## 13.1 Dependency facts confirmed in source (invalidate/confirm audit assumptions)

- **noq defaults confirmed** (`noq-proto/src/config/transport.rs`): `initial_rtt`
  333 ms, `initial_mtu` 1200, `datagram_send_buffer_size` **1 MiB**,
  `datagram_receive_buffer_size` = STREAM_RWND, `ack_frequency_config: None`,
  GSO enabled. F-016's premise holds exactly.
- **tun-rs 2.8.9 Linux API is NOT `recv_multiple(bufs, sizes, gro)`**.
  Real signatures (`async_device/unix/mod.rs`):
  `recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, offset)` and
  `send_multiple(&mut gro_table, &mut bufs, offset)`, Linux-only
  (`#[cfg(target_os = "linux")]`), with `VIRTIO_NET_HDR_LEN + 65535` original
  buffer convention from `platform/linux/offload.rs`. `Vec<u8>` implements the
  (`pub`, re-exported) `ExpandBuffer` trait, so no wrapper type is needed.
  `GROTable: Default`, `IDEAL_BATCH_SIZE = 128`, `offload(true)` on
  `DeviceBuilder` — all as the audit assumed.
- **Windows `AsyncDevice`** exposes `try_recv` / `try_send` (plus async
  `recv`/`send`); there is no `recv_multiple` on Windows. Burst drain/fill
  around one async wait is the correct shape — implemented.
- **Iroh 1.1 transport knobs** (`endpoint/quic.rs`): the builder is
  constructed via `QuicTransportConfig::builder()` (there is **no**
  `QuicTransportConfigBuilder::default()`); all setters consume `self`
  (`mut self -> Self`, must reassign). `AckFrequencyConfig` is re-exported at
  `iroh::endpoint::AckFrequencyConfig` (the `quic` module itself is private)
  and `ack_eliciting_threshold` takes a `VarInt`, not `u64`.
  `max_concurrent_multipath_paths(0)` is **ignored with a warning** (minimum
  enforced), so multipath is left at the Iroh default rather than set to 0.
- **Congestion controllers** live in `noq_proto::congestion` as
  `CubicConfig` / `NewRenoConfig` / `Bbr3Config` (iroh re-exports only the
  `ControllerFactory` trait, so `noq-proto` is now a direct dependency).
- **Linux `send_multiple` framing requirement (new fact, correctness-critical).**
  With offload enabled the kernel expects a virtio-net header in front of
  every written packet: each send buffer must carry `VIRTIO_NET_HDR_LEN`
  headroom and `offset` must equal it (tun-rs's own framed writer does
  exactly this; `offset = 0` underflows `offset -= VIRTIO_NET_HDR_LEN` and
  fails). Plain `send()` of a raw IP packet misframes under offload, so
  **all** Linux TUN writes — including inbound — go through a reused
  `GROTable` + staged headroom (`LinuxTunWriter`), not just the batch
  receive path. Verified natively on Linux (WSL): `cargo check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and the
  `tunnet-common` / `tunnet-core` / `tunnet-agent` nextest suites are green
  (262 passed; the single exclusion is the loopback-dependent DNS test in
  §13.6, failed only by sandbox networking).
- **F-018 stands**: ZeroTier's CoDel is disabled upstream; Tunnet's loaded
  latency is self-inflicted. The new scheduler therefore targets Tunnet's own
  queueing first.

## 13.2 Architecture deleted (not preserved, no shims)

- `qos.rs` three-class (`latency/normal/bulk`, `Class`, `classify`, DRR
  quanta, `drr_round_drain` test helper) — **deleted**, replaced by
  flow-aware FQ-CoDel-style scheduler in the same module path.
- `iroh_pool::send_datagram` wait branch (`send_datagram_wait` when
  `datagram_send_buffer_space() == 0`) — **deleted**. The function is now
  non-blocking; `try_send_datagram`/`TrySendError::{Full,TooLarge,Closed}`
  is the only primitive. No `send_datagram_wait` remains on any IP-tunnel
  path (verified by search).
- SSH-NAT double parse (`needs_inbound_rewrite(&[u8])`,
  `rewrite_{in,out}bound(&mut [u8])`, internal `eligible`/`rewrite`) —
  **deleted**. Only `*_with_meta` entry points remain; tests migrated.
- Outbound `Bytes::copy_from_slice` per packet — **deleted**;
  `PacketBuf::into_bytes` (`Bytes::from(Vec<u8>)`) without a second copy.
- Outbound multi-lookup sequence (`is_magic_dns_destination` +
  `is_advertised_destination` + `lookup_ip` + second endpoint lookup) —
  replaced by `RoutingTable::route_once` (old methods retained only as
  non-hot-path delegators, not duplicated datapaths).
- Per-packet `AclEngine::allow_packet` + `FirewallEngine::evaluate` pair in
  `tun_io` — replaced by one `PacketPolicy::check`. The engines themselves
  remain as configuration/admission owners (connection-level auth stays
  separate by design); their fragment tables and conntracks are no longer
  touched by the established hot path.
- `tun_fast::build_fast_tun` duplicate builder and `is_would_block` helper
  removed during implementation; `tun_io::build_tun` is the single TUN
  constructor (Linux `offload(true)` inside).

## 13.3 New data plane (established-packet path)

```text
PlatformTunRx (LinuxBatchEngine recv_multiple / Windows try_recv burst)
  → PacketBuf { data: Vec<u8>, meta, flow, enqueued_at }   # parse once
  → ssh_nat::*_with_meta                                    # metadata only
  → RoutingTable::route_once → RouteDecision::Peer(handle)  # 1 snapshot
  → PacketPolicy::check → Allow                             # 1 verdict
  → PeerScheduler::enqueue (flow FIFO, byte caps)           # bounded
  → run_peer_pump → ConnPool::try_send_fast                 # non-blocking
  → Iroh QUIC DATAGRAM (64 KiB buffer, CUBIC, GSO on)
```

Inbound mirrors: `read_datagram → PacketBuf::from_slice → anti-spoof →
PacketPolicy::check → NAT-with-meta → try_send/send burst → TUN`.

Scheduler algorithm (selected): per-peer FQ-CoDel concept —
sparse/new-flow priority (16 KiB epoch budget, 25 ms sojourn target),
byte-DRR (`FLOW_QUANTUM` 1536) across backlogged flows, per-flow FIFO order,
absolute sojourn ceiling (250 ms) with head-drop AQM, peer caps
(256 KiB / 512 packets), per-flow cap (64). Chosen because it isolates
interactive/ICMP flows from bulk without any strict-priority pipe, keeps
fairness byte-based, bounds memory/time, and — critically — never awaits a
packet: the pump stops at `TransportFull` and requeues the head.

Transport profile (`tunnet-core/src/transport_profile.rs`, applied in
`direct/connectivity.rs::endpoint_builder` for every mesh endpoint):
DATAGRAM send 64 KiB (was 1 MiB: ~105 ms → ~6 ms serialization at 80 Mbps),
receive 256 KiB, initial RTT 90 ms (was 333 ms), initial/min MTU 1200,
GSO on, multipath untouched, CUBIC default, BBRv3/NewReno as explicit
experiments (`TunnetTransportProfile::bbr3_experiment`,
`endpoint_builder_with_transport`).

## 13.4 Remaining per-packet costs (honest accounting)

Outbound established: 1 TUN batch amortized syscall share, 1 etherparse
parse, 1 ArcSwap snapshot load (routing) + 1 HashMap/DashMap-free peer-handle
use (no DashMap, no endpoint-hex alloc), 1 compiled policy verdict
(0 alloc / 0 sort / 0 format; 1 DashMap `get_mut` only on conntrack miss…
actually one `get_mut` per packet for the established lookup — single
sharded read-lock, no async mutex), scheduler enqueue (2 mutexes:
flows + occasionally order; pump side same), 1 non-blocking
`send_datagram`, coarse atomics (bytes, activity ≤1/s).
Remaining copies: TUN buffer → owned `Vec<u8>` (1 copy; raw Wintun-ring
zero-copy deferred to Phase 3 as planned). Remaining allocs: owned packet
buffer (poolable — `PacketPool` exists, pump-wide adoption deferred),
scheduler `Bytes` handle (refcount, no payload copy).
Inbound established: 1 DATAGRAM read, 1 parse, anti-spoof compares,
1 policy verdict, 1 TUN send (Windows: `try_send` fast path).

## 13.5 Benchmark v2 (`scripts/bench.ps1`, `scripts/bench.sh`)

Rewritten per §13 requirements: throughput matrix (TCP 1/4 streams,
up/down/bidir, JSON, retransmits), loaded-latency sweep at 25/50/75/90/100/
110% of *measured* capacity with actual throughput + loss next to
p50/p95/p99/max (under-delivery >30% flagged invalid), UDP sweep over
rates × {64,256,1200}B with delivered Mbps/pps/loss/jitter, path-state
capture before/after (Tunnet API + `zerotier-cli peers` / `ip route get`).

## 13.6 Tests added (all passing)

- Scheduler: sparse-jumps-bulk, per-flow order, byte-DRR no-starvation,
  stale-ceiling drops, memory bounds, **ICMP-vs-TCP-bulk isolation with real
  packets**, transport-full requeue order + per-peer (no global HOL) isolation.
- Policy: differential legacy-equivalence matrix (org-deny range merge,
  order_index, disabled rules, TCP/UDP scoping, default-deny), first-fragment
  remembers → later-fragment allowed, later-without-state denied, malformed
  denied.
- Transport: profile builds, BBRv3 explicit-not-default.
- TUN: Linux batch constants, Windows burst budget relations.
- NAT: parse-once rewrite tests (migrated, old double-parse tests deleted).
- Packet: flow-key stability, zero-copy `into_bytes`.
- Validation: `cargo fmt --check` clean; `cargo check --workspace
  --all-targets` clean; `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` clean — on Windows **and** natively on
  Linux (WSL; only exclusion is the Tauri desktop system-dependency
  package). `cargo test` and `cargo nextest run` green: common 67, core lib
  150, agent 77 on Windows (294 total); 218 + 76 on Linux excluding the
  single sandbox-loopback DNS test proven environmental in Phase 1
  (identical signature reproduced in WSL localhost; raw-socket proof
  stands). Pump tasks are epoch-owned (teardown advances the epoch;
  schedulers drain and tasks exit — no cross-generation writes, no leaked
  tasks); the runtime sweeper is tied to the generation token.

## 13.7 Known bottlenecks / intentionally deferred

- Single TUN reader + per-peer pump tasks (no multi-queue sharding yet;
  flow-preserving sharding needs measurements first).
- Inbound DATAGRAM drain is one packet per `read_datagram` per connection
  (Iroh API shape); cross-connection batching not yet implemented.
- `PacketPool` exists but the outbound path still allocates one `Vec<u8>`
  per packet (pool acquire/release wired in the Linux engine sketch, full
  pump-wide recycling pending).
- No virtual-MTU/GSO-overlay work (Phase 2), no raw Wintun zero-copy
  (Phase 3), no CPU affinity, no PGO/allocator tuning.
- Policy `sync_from_engines` polls bundle pointer + firewall versions every
  256 packets (amortized); a push-based generation counter would be cleaner.
- No live-network measurements in this environment (Windows dev host, no
  Linux peer pair); benchmark v2 awaits the Windows→Linux baseline rerun.
- The old `AclEngine`/`FirewallEngine` conntrack/fragment/GC code is now
  off the hot path but not yet deleted; removal awaits a longer soak period
  proving the unified policy in production-like traffic (candidate for the
  next cleanup pass, since only the dataplane used them per-packet).

---

# 14. Phase 2 implementation record (2026-09-04) — new dataplane

Phase 2 rebuilt the packet plane around logical packets, tunnel framing, and a
shared policy runtime. All §0 verified issues were fixed first; the old
architecture was deleted, not shimmed.

## 14.1 Verified §0 fixes

- **§0.1 shared runtime**: `PolicyRuntime` (tunnet-core/src/policy_runtime.rs)
  is owned by the dataplane generation (`CoreNode::policy`, installed at
  node build) and shared by outbound + every inbound connection. Conntrack
  is one canonical bidirectional table; `sync_from_engines` polling is gone.
- **§0.2 network scoping**: firewall compiles per-`NetworkId` (`FwSet`);
  `from_engines` flattening and the global `enabled &&` are deleted. Fast
  states carry the pre-resolved set — no per-packet UUID lookup. Proven by
  `cross_network_firewall_isolation` and
  `disabled_network_does_not_disable_others` tests.
- **§0.3 event-driven**: engines hold the runtime and publish on every
  mutation (`replace_bundle`, `reload_local`, `set_suggested` — which now
  bumps the previously-missing version, `ensure_inbound_tcp_allow`,
  posture/stale changes). No packet-count polling remains.
- **§0.4 revocation**: conntrack entries carry `admitted_gen`; generation
  mismatch revalidates once against current policy. Tests: TCP allow→deny,
  UDP allow→deny, suggested-rule change, enabled/disabled flips.
- **§0.5 fast path**: `PeerFastState` (identity, ArcSwap connection,
  FQ-CoDel state, policy link, counters, relay/MPS/RTT cache, reassembly,
  pump wakeup) rides inside `PeerInfo`; `route_once` hands out the Arc with
  zero map lookups. Removed from the hot path: `fast_conns`, `fast_touch_ms`,
  `bytes_in/out`, `peer_cloud_relay` maps, scheduler peer map,
  `try_send_fast`, `record_bytes_*`.
- **§0.6 Model A**: `try_send_frame` submits only when
  `datagram_send_buffer_space() >= frame.len()` (the exact Iroh guarantee;
  plain `send_datagram` otherwise displaces oldest-first). The frame is
  returned on every error so stalls never consume bytes.
- **§0.7 adaptive backoff**: the fixed 5 ms sleep is replaced by
  notify-or-`clamp(RTT/4, 100µs, 2ms)`. Investigated upstream: the
  `datagrams_unblocked` Notify is private to noq with no public waiter;
  documented in code as the desired extension. No spin, no
  `send_datagram_wait` anywhere.

## 14.2 Iroh/noq source facts (exact versions)

- `send_datagram` → `datagrams().send(data, true)`: `true` = displace
  oldest-first when full (Model B is the default — Model A must check
  space first). `datagram_send_buffer_space()` guarantee is exactly
  "no displacement iff new datagram <= reported space".
- `ReadDatagram::poll` drains buffered datagrams synchronously before
  waiting on `datagram_received.notified()`; each `read_datagram()` mints a
  fresh notify, so single-poll `now_or_never` drain probes are safe (dropping
  a Pending probe only drops its waker). Used for the §10 bounded
  opportunistic drain (32) with no busy polling.
- `max_datagram_size()` changes with path MTU (documented); cached per
  fast state as MPS and refreshed periodically, on path events, and on
  `TooLarge`.
- `Path::id()`/`stats()` (+ `PathStats.rtt`) back the RTT cache for
  adaptive backoff; `AckFrequencyConfig`/`VarInt` quirks from Phase 1 stand.
- `Bytes::from_owner<T: AsRef<[u8]> + Send + 'static>` confirmed; the pool
  owner exposes exactly the frame bytes.

## 14.3 Tunnel framing, segmentation, reassembly

- Wire: `tunnet/tunnel/2` ALPN. The `/2` is only the negotiated
  wire-protocol version (it keeps old `/1` raw-IP binaries from speaking
  the incompatible framing protocol); no v1 implementation remains and
  there is no compatibility decoder. `Single [0x20][packet]`
  (1 B overhead); `Segment [0x21][id u32][index u16][count u16][total u16]`
  (11 B). Kinds `0x22..=0x2F` reserved (GSO extension space); version nibble
  `0x2_`. Decoder: no allocation, checked arithmetic, fail-closed bounds.
- Segmentation is incremental from the retained owner with a cursor
  (id/count/total); path shrink restarts with a fresh id (never mixed
  shapes); `TooLarge` refreshes MPS and restarts (bounded retries);
  ≤16 DATAGRAMs per packet by construction. No QUIC streams (§23).
- Reassembly bounds: total ≤9000, count ≤16, 32 entries/peer, 256 KiB/peer,
  shared global counter, 500 ms timeout, LRU eviction, conflicting-duplicate
  drop, ID-collision restart. Loss of a segment loses the packet (no overlay
  retransmit). Policy sees only reassembled logical packets (§5).
- Virtual MTU default 2800 (was 1280; direct-mode hardcode removed, clamp
  576–9000); all TUN slots MTU-derived (`slot_cap_for_mtu`), no fixed 2048.
  2800 chosen as the ZeroTier-parity point pending the §17 matrix (no live
  network in this environment; do not treat as measured optimum).

## 14.4 Scheduler, ownership, batching

- FQ-CoDel (`tunnet-core/src/scheduler.rs`, pure state machine): new/old
  lists (no scans), byte DRR with MPS-scaled quantum, per-flow CoDel
  (`first_above_time`/`dropping`/`drop_next`/`count`, target 5 ms /
  interval 100 ms, tunable via `with_params`), byte caps, 1 s emergency
  ceiling as safety only, bounded cap probes, wire-byte fairness feedback.
  Test-driven debugging during implementation caught and fixed three real
  bugs (requeue accounting, list double-ownership, spurious Empty).
- Ownership: `PooledBuffer` (headroom + classes 512–9216 B, `from_owner`
  transmit, pool recycle on Drop), `LogicalPacket::{from_pooled,
  from_shared (zero-copy inbound), from_vec}`; scheduler queues logical
  packets; segments encode from borrows into fresh pooled buffers.
- Linux: `recv_multiple` into pool-owned slots (swapped into packets),
  genuine multi-packet `send_multiple` batches (GSO coalescing) for both the
  reject path and a real inbound TUN batch; virtio headroom staging is
  mandatory with offload (plain `send` misframes — §13.1 fact retained).
- Windows: pooled burst receives; `TunWriteBatch` (shared with non-Linux
  fallback) retains its tail across waits — no silent loss.
- Inbound Iroh drain is burst-oriented (§10 probe above); TUN writes are
  batched per drain iteration (§9).
- Routing: advertised routes in a `PrefixMap` (no linear scan),
  `is_exit` computed at rebuild, fast states embedded in `PeerInfo` and
  pruned on rebuild; inbound resolves fast state once per connection and
  re-resolves on routing-generation change only.
- Telemetry (§15): aggregate (summed, never overwritten) queue gauges,
  sojourn bucket histogram with p50/p95/p99/avg export, cached drop
  handles, frame/segment/reassembly/TUN-syscall/datagram/pool counters;
  the dead `hot.drops` counter is deleted.

## 14.5 Deleted in Phase 2 (§13, §26)

`policy_fast.rs`, `qos.rs`, `PacketBuf`, `AclEngine` packet eval +
conntrack/fragments/GC + its tests, `FirewallEngine` packet eval +
conntrack/fragments/GC + `EvalResult`/`PacketDirection`/`peer_matches`/
`default_policy` + eval tests, pool fast maps + `try_send_fast` +
`record_bytes_*`, `send_datagram_wait` remnants (none remained),
`sync_from_engines`, `from_engines` flattening, fixed `SLOT_CAP`, fake
one-element batch wrappers, `NoopTunBatch`, dead metrics. `EvalResult` and
`PacketDirection` removals rippled only to `direct/mod.rs` re-exports.

## 14.6 Benchmark v3 (§16)

Shared JSONL schema (`results.jsonl`) for ps1/sh: throughput matrix (TCP
1/4, up/down/bidir with explicit bidir JSON parse — the v2 gap), per-run
path state, warmup, repeats, idle 1200-sample p99.9, loaded sweeps per
direction at 25–110% of independently measured directional capacity with
actual-Mbps/loss beside p50/p95/p99/max, migration/under-delivery flags,
UDP rate×size sweep with delivered/pps/loss/jitter, commit/MTU/OS/CPU
metadata. Fixes: ps1 bidir parse, sh capacity-regex bug (structured
functions, no reparsed human output). Not yet: adverse-network impairment
runs (§18 — no impairment harness in this environment; matrix specified in
§17/§19 with `with_send_buffer` and profile hooks ready), live results
(§17 matrix and §19 transport matrix await hardware).

## 14.7 Validation status

- `cargo fmt --check`, workspace check + clippy
  (`--all-targets --all-features -D warnings`): clean on Windows AND native
  Linux (WSL; only exclusion remains the Tauri desktop system-dep package).
- Tests: 294 green on Windows (common 67, core lib 149+24 integration?,
  agent 77 — see report), 218/218 green on Linux excluding the one
  sandbox-loopback DNS test proven environmental in Phase 1 (identical
  signature reproduced in WSL; raw-socket proof stands).
- Fuzzing: no cargo-fuzz harness in repo; decoder/reassembly covered by
  proptest suites (byte-string never-panics, header round-trip, bounded
  segment streams) instead.
- GSO preservation (§11): tun-rs `recv_multiple` splits super-packets
  (no public API exposes coalesced segments + `VirtioNetHdr`), so receive-
  side GSO metadata cannot be preserved without a tun-rs fork — documented
  blocker; the framing reserves `0x22..=0x2F` frame kinds for a future GSO-aware
  extension instead of a second wire rewrite. Send-side GSO coalescing via
  `send_multiple` is fully used.
- Multi-queue (§20): investigated, not enabled — needs flow-affinity
  measurements first (documented, unchanged from Phase 1).

# 15. Phase 2.1 implementation record (2026-09-04) — correctness/hardening

Ten correctness/security/performance defects in the Phase 2 architecture,
fixed at the architectural level. No compat shims; `PeerPolicyLink` deleted,
`PeerRegistry::relink_policy` narrowed to install-time slot assignment,
`ReassemblyTable::new` no longer takes an effectively-infinite global cap.

## 15.1 Segmentation restart tracks full geometry (pump.rs)

- `PartialPacket` now stores the complete `SegmentPlan` (count + seg_cap +
  shape), the packet id, the next index, and a wire-byte accumulator —
  never just a count. `transmit_cursor` adopts the current geometry
  wholesale for fresh cursors; resumed cursors continue their stored
  geometry even if the path changed.
- `TooLarge` refreshes MPS and calls `replan()`, which compares the FULL
  geometry: any change (count, seg_cap, or single↔segmented shape)
  restarts from byte 0 with a fresh id (`Replan::Restarted`); identical
  geometry retries the segment in place (`Replan::Retry`, transient);
  degenerate paths drop (`Replan::Impossible`). Old offsets are never
  reused with a new MPS. Restart budget (≤2) is threaded through
  `transmit_segmented_budgeted` so flapping paths terminate (boxed
  recursion for the restart cycle; the first implementation reset the
  budget and was fixed before merge).
- Tests: `replan_restarts_on_segcap_change_with_same_count` (2800 B needs
  3 segments at both MPS 1350 and 1400 — same count, different cap —
  still restarts with fresh id/offset), `replan_retries_in_place_...`,
  `replan_handles_shape_transitions`.

## 15.2 Scheduler: Empty means empty; account once (scheduler.rs, pump.rs)

- DRR deficits accumulate immediately inside `serve_old`: a head larger
  than one quantum (2800–9000 B logical vs ~1200 B MPS-scaled quantum) is
  served in the same `next()` call. Long-term byte fairness is unchanged
  (the full head length is still debited, so oversized heads borrow
  against future rounds and wait afterwards — proven by
  `oversized_head_borrows_future_rounds`).
- `next()` repeats rotation passes only after a pass dropped packets
  (each pass strictly reduces queued packets or retires list entries), so
  `Empty` is returned only with genuinely no schedulable work; a
  `packets + flows + 1` pass bound guards the pump against hangs. The
  50 ms idle sleep can no longer fire with packets queued.
- Wire accounting: the pump accumulates wire bytes in the cursor
  (preserved across TransportFull resume, reset on restart) and calls
  `account_sent(flow, logical_len, total_wire_len)` exactly once at
  completion. The old per-segment `account_sent(flow, 0, wire)` charged
  `len` at dequeue plus full wire per segment (double charge); the
  `account_sent` contract is now documented as once-per-logical.
- Tests: `large_heads_serve_without_stall` (2800/9000 B vs 512–1400
  quanta, zero Empty while queued), `wire_accounted_once_per_logical`.

## 15.3 Firewall publication via stable slots (policy_runtime.rs, peers.rs, routing.rs, node.rs)

- New architecture: `network → stable Arc<FwSlot> → ArcSwap<FwSet> →
  Arc<FwCounters>`. Slots live on `PolicyRuntime` (shared across all
  generations); `PeerFastState.policy` is now `ArcSwap<FwSlot>`.
  Publication swaps slot contents in place — live peers observe new rules
  with two atomic loads, no per-packet map lookup, no relink. Counters
  objects are never replaced, so stats survive republishes (the old
  identical-ruleset reuse hack is deleted).
- Slot assignment: install-time `relink_policy` (narrowed to slot
  assignment), every routing rebuild (`ensure_fast`), and the inbound
  resolve race (`resolve_fast`), via `RoutingTable::{set_policy_runtime,
  policy_slot_for}` wired in `install_policy_runtime`. Peers joining after
  install and peers changing networks are covered — both were gaps before.
- Tests: `live_fast_state_observes_publication` (local rule change,
  suggested rule change, enable/disable flips, established-flow allow→deny
  revocation through a live fast state with zero post-install relink);
  old tests that manually re-fetched sets after publish were rewritten to
  slot-style observation.

## 15.4 Atomic policy generation (policy_runtime.rs)

- The generation now lives INSIDE the immutable `RuntimeInner` snapshot;
  every publish compiles `prev.generation + 1` and performs ONE `ArcSwap`
  store. `check()`/`check_with_generation()` read generation and policy
  from the same snapshot load — the torn window (new policy + old
  generation trusting stale conntrack) is structurally impossible. The
  separate `version: Arc<AtomicU64>` is deleted. `invalidate()` publishes
  a fresh generation with cleared conntrack through the same path.
- Test: `publication_is_atomic_under_concurrency` (publisher alternates
  allow-all/deny-all bundles while 4 readers hammer one flow, pairing each
  verdict with the generation actually used; any Allow at a deny
  generation fails — would have caught the old race).

## 15.5 Hard global reassembly cap (reassembly.rs)

- `MAX_BYTES_GLOBAL = 4 MiB` (16 fully-loaded peers); `new()` enforces it
  (the old `u64::MAX` default made the global counter telemetry-only).
- Reservation model: per-peer check first (table lock), then a global
  `fetch_update` CAS reservation — impossible to exceed even with
  concurrent peers racing the shared counter. After a global-pressure
  eviction BOTH caps are re-checked (the old code re-checked per-peer
  only). Every reservation pairs with exactly one release in `remove()`,
  so the counter stays exact across complete/conflict/timeout/collision
  paths.
- Tests: `caps_bound_memory` rewritten to assert hard `global <= 500`
  (the old `<= 500 + 200` overshoot allowance is deleted);
  `global_cap_holds_under_concurrent_peers` (8 tables × threads on one
  counter, mid-race sampling, never exceeds).

## 15.6 Reject path through normal tunnel framing (tun_io.rs)

- Inbound `Reject` no longer sends a raw IP reply via the generic sender
  (malformed tunnel traffic — peers require `0x20`/`0x21`). `send_reject_framed`
  routes the reply through the normal machinery: `from_shared` (zero
  copy) → scheduler enqueue (+ gauges) → `ensure_pump` (segments large
  replies). Pool-less fallback (no pump possible) still frames a single
  correctly (`KIND_SINGLE` prefix, MPS check). Outbound (TUN-side)
  `send_reject_reply` is unchanged — raw IP is correct for the device.

## 15.7 Linux outbound zero-copy restored (tun_fast.rs, owned.rs, ssh_nat.rs, tun_io.rs)

- `needs_outbound_rewrite_with_meta` gates materialization:
  `handle_outbound_one` only takes the mutable path when metadata proves
  an SSH-NAT rewrite is required. Common packets stay immutable.
- `LinuxBatchEngine` slots are now `BatchSlot(PooledBuffer)`:
  `recv_multiple` writes at offset 0 of the headroomed receive area (new
  `PooledBuffer::recv_area_mut`; tun-rs `B: AsMut` bound verified against
  tun-rs 2.8.9 source), and receipt moves the slot wholesale into
  `LogicalPacket::from_pooled` — pool ownership AND 32 B headroom intact,
  pool recycling on drop (the old `into_vec` detached without recycling).
- Remaining copies, Linux outbound, common packet: ZERO (pooled TUN slot
  → headroom single-frame prepend → `from_owner` → QUIC). Copies remain
  only where inherent or rare: one copy per segment into pooled staging
  (QUIC needs contiguous frames), SSH-NAT rewrites (in-place on already-
  pooled storage, no extra copy), pool-miss allocation (amortized),
  shared-owner staging (reject replies synthesized off-pool).

## 15.8 Frame ownership on QUIC errors (peers.rs)

- `try_send_frame` clones the frame (one `Bytes` refcount bump) before
  `send_datagram`, which consumes its argument without returning it on
  error. The late-`Closed` path now returns the original frame — the
  return-on-every-path contract is real. Test asserts byte-identical
  return on `NoConnection`.

## 15.9 Membership-removal revocation (peers.rs, routing.rs, iroh_pool.rs, tun_io.rs)

- `PeerFastState::deactivate()`: epoch bump (pumps drain+exit, readers
  observe), live QUIC conn dropped AND closed (`membership_removed`),
  pump woken for prompt exit. Idempotent. `PeerRegistry::{remove, retain,
  clear}` deactivate before forgetting (rebuild pruning included).
- `ConnPool::drop_peer` now closes the slot conn explicitly (was leaked
  to idle timeout) and deactivates before removing.
- Inbound reader: tracks the fast-state epoch; a generation change that
  no longer resolves closes the connection and exits (was: kept
  forwarding through stale state); deactivation without a generation
  change also exits.
- Tests: `removal_deactivates_fast_state` (registry-level epoch/conn/
  resolve), `removed_peer_is_unroutable_and_deactivated` (routing-level:
  replace → delta-remove → version bump → `NoRoute` → resolve None →
  epoch+1).

## 15.10 Benchmark v3 fixes (bench.sh, bench.ps1)

- sh: `BENCH_*` exports moved before the first consumer (were after the
  idle block); `path_json` is product-aware (Tunnet API only for tunnet
  runs; zerotier-cli peer summary otherwise); loaded ping 200→1000
  samples for real p99.9 (null-gate retained); NEW full-duplex bidir
  loaded-latency scenario (simultaneous up + down UDP loads, both
  parsed, per-direction under-delivery flags).
- ps1: download load job now honors `-R` (was silently sending upload
  load); NEW bidir loaded-latency scenario (two jobs, both parsed);
  p99.9 null-gate retained (200 Test-Connection samples stay honest).
- Both scripts syntax-verified (`bash -n`, PowerShell parser, zero
  errors). No live runs yet — still awaiting hardware (§17–§19).

## 15.11 Validation status (Phase 2.1)

- `cargo fmt --check`, `cargo check --workspace --all-targets`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  clean on Windows AND native Linux (WSL; desktop excluded for the
  system `glib` dep). Feature-combo checks also clean
  (`tunnet --no-default-features --features managed`,
  `tunnet-core` no-default/direct-only) — the combo that caught the
  Phase-2 `HashMap` import gap.
- `cargo test --workspace` (minus desktop): all suites ok, zero
  failures. `cargo nextest run --workspace`: 391 passed, 1 skipped on
  Windows. Linux: 305 green (common 67 + core 158 + agent 79/80) minus
  the one sandbox-loopback DNS test proven environmental in Phase 1.
- Counts: 305 focused tests (was 294; +11 new, none weakened).

# 16. Phase 2.2 implementation record — multi-network isolation, atomic publication, remaining hardening

Pre-v1 breaking pass. ALPN bumped to `tunnet/tunnel/3` with new frame
kinds (`0x30`/`0x31`); no compatibility with the undisclosed `/2`
framing is maintained. `PeerFastState` is gone (renamed/split into
`PeerMembershipState` + `PeerTransportState`); `PeerPolicyLink` stays
deleted; `frame::decode` is now `decode_frame`.

## 16.1 P0 — transport vs membership state model (peers.rs, routing.rs, pump.rs, tun_io.rs, iroh_pool.rs)

- `PeerTransportState` (key `EndpointId`): live QUIC connection, MPS/RTT,
  transport counters, relay flag, endpoint-shared frame-ID counter. No
  network identity, no firewall state, no scheduler.
- `PeerMembershipState` (key `(EndpointId, NetworkId)`): network identity
  (mesh IP, hostname/tags), stable firewall slot, per-membership FQ-CoDel
  scheduler + reassembly table, pump task + wakeup, membership epoch.
- `PeerRegistry` holds both maps. `ensure_membership` refreshes identity
  in place and debug-asserts key/network agreement (no last-writer-wins);
  bare `get(endpoint)` returns a membership only when exactly one exists
  and otherwise refuses to guess. `remove_membership` deactivates one
  membership without touching the shared transport; `remove_transport` /
  `retain` (now keyed by `(EndpointId, NetworkId)` pairs) deactivate and —
  for fully departed endpoints — close the QUIC connection.
- Routing `ensure_fast` assigns slots per rebuild; `PeerInfo.fast` is the
  membership Arc, so outbound routes resolve each network's own state.
  `lookup_membership(hex, net)` is the exact inbound resolve path;
  `by_endpoint` (first-joined) remains for legacy single-membership
  consumers only. Connection pool mirrors into transports
  (`set_transport_conn`, `refresh_transport_path`); `drop_peer` closes and
  removes the whole endpoint.
- Pumps are per membership (`ensure_pump` unchanged shape); the pump
  processes DRR bursts packet by packet with a `pending` cursor queue,
  requeues unstarted remainders in order on stall (with gauge re-credit),
  requeues intact cursor packets on `Wait` (closes a pre-existing rare
  loss), and requeues in-flight packets before epoch-exit clearing so
  gauge reconciliation stays exact.

## 16.2 P0 — framing network discriminator + ALPN/3 (frame.rs, lib.rs)

- Every frame carries the full 16-byte `NetworkId`: `Single
  [0x30][net][packet]` (17 B overhead), `Segment
  [0x31][net][id][index][count][total][payload]` (27 B). Full-ID-over-
  channel-ID was deliberate: no negotiation handshake, no per-connection
  channel tables, unambiguous binding for out-of-order segments; 16
  B/frame is the documented price. Old `0x20`/`0x21` kinds decode as
  `UnknownKind` (fail fast, never misparse). `SegmentHeader` itself is
  unchanged, so reassembly keys are untouched.
- Outbound frames bind the route's membership network captured at dequeue
  (`PartialPacket.net`); `strip_single_prefix` accounts for the 17-byte
  header on requeue paths. All frame tests updated to the layout plus new
  `old_wire_kinds_rejected` and net-participates-in-encoding assertions.

## 16.3 P0 — authenticated network binding on inbound (tun_io.rs, accept.rs, dgram_pump.rs)

- The reader decodes each frame header first and resolves/switches the
  cached `(endpoint, network)` membership per packet; a frame claiming a
  network with no membership is dropped (`unknown_network`), never
  evaluated under another network's state. Mid-batch revocation drops the
  cache and re-resolves; a generation change with zero memberships left
  closes the connection and exits.
- `resolve_membership` enforces `auth.contains_network(endpoint, net)`
  whenever an `AuthCache` is present (wired through `InboundDeps.auth`
  from the accept path; the dialer-side pump passes `None`, where
  membership existence still gates). `DirectAuthHook` deliberately stays
  any-network: it admits CONNECTIONS (which may legitimately carry many
  networks), while packet authorization is per frame network in the
  reader. Admission still closes truly unknown endpoints at handshake.
- Antispoof, policy slot, and reassembly all run against the resolved
  per-packet membership (membership IP/slot/table).

## 16.4 P0 — network-scoped conntrack (policy_runtime.rs)

- `CanonKey` now starts with `NetworkId` (from the membership network
  passed to `check`; `None` maps to nil, isolating tests). Identical
  5-tuples in A and B are independent entries — proven by
  `conntrack_is_network_scoped` (len 1→2, B-deny revokes B while A keeps
  working) and by the strengthened `cross_network_firewall_isolation`,
  which now reuses the SAME endpoint and 5-tuple in both networks.

## 16.5 P0 — atomic firewall publication (policy_runtime.rs)

- `FwSlot → ArcSwap<FwSnapshot{generation, set}>`. One unified
  `publication` token is bumped per publish and stamped on the ACL
  snapshot and every touched firewall snapshot. Publish order is
  slot-swap-then-ACL-store; packets load ACL-then-firewall. By SeqCst
  ordering, observing the new ACL generation implies observing the new
  firewall snapshot — the (new ACL, old firewall) poison pair from the
  brief is structurally impossible (reversing either order would
  reintroduce it; both orders are documented at the code sites).
- `check()` takes the slot (not a bare set) so the ordered pair of loads
  lives in one place. Conntrack admission stamps exactly the deciding
  pair (`admitted_acl_gen`, `admitted_fw_gen`); ANY mismatch revalidates.
- Publisher-vs-publisher serialization: `publish_acl`,
  `publish_firewall`, and `invalidate` each run as one transaction under a
  shared `publish_lock` (load → allocate generation → compile → swap
  slots → store). Generation allocation happens inside the lock, so
  committed generations are strictly monotonic and no publish can clobber
  a concurrent one (previously a newer generation could be overwritten by
  an older one, and an ACL publish could lose a concurrent firewall
  update compiled from stale `fw_source`). The lock is control-path only;
  the packet hot path never takes it. All three publishers return the
  committed generation.
- Tests: `firewall_publication_is_atomic_under_concurrency` hammers one
  established flow while alternating local/suggested/disabled-deny
  publishes — Deny stamped at a deny fw_gen, Allow at an allow fw_gen,
  both asserted deterministically. `concurrent_publishers_lose_no_updates`
  runs 4+4 simultaneous publishers (unique content per publish): final
  generation is exactly 1+P, committed generations are exactly 2..=1+P
  with no overwrite, final snapshots contain each dimension's
  last-committed content, reader samples never regress, and post-churn
  revalidation re-admits. Mutation-checked: with the lock removed the
  test fails (observed generation 7→5 regression).

## 16.6 Multi-network test suite (§2.2-1, tests 1–10)

1+2+10 `same_endpoint_two_networks_isolated` (+ reverse-order variant):
one endpoint, two networks/IPs → distinct membership objects, shared
transport, exact per-network resolution, ambiguous bare resolve refuses,
insertion-order independent. 3+4
`same_endpoint_two_networks_route_to_distinct_memberships` (routing):
outbound routes resolve each network's own membership/IP/slot path.
5+6 `resolve_binds_exact_membership_and_auth` (agent): cross-network
frames resolve only their own membership; A-only auth rejects B claims;
unknown networks reject without any cache. 7 `conntrack_is_network_scoped`
(see 16.4). 8+9 `removing_one_membership_leaves_sibling` (epoch,
transport, resolvability of B untouched) and
`removed_peer_is_unroutable_and_deactivated` (routing-level NoRoute +
deactivate). All use the SAME EndpointId across networks.

## 16.7 HIGH — real byte-DRR fairness (scheduler.rs, pump.rs)

- Replaced the 2.1 within-visit multi-quantum grant (which degenerated to
  packet fairness: every call served every affordable-after-k-rounds head)
  with proper DRR: one quantum per flow per visit; each visit serves every
  affordable head as a `DequeueBurst`; unaffordable heads rotate; rounds
  repeat immediately (bounded by `MAX_DRR_ROUNDS = 64`, derived from the
  ~19 KB worst deficit gap at minimum quantum) with no `Empty` and no
  sleep. Burst bytes are naturally bounded (≤ quantum + one max head).
  Sparse flows still serve one packet (interactive latency).
- The pump transmits bursts packet by packet (§16.1). `Empty` still means
  genuinely empty.
- Measured ratios (continuously backlogged, 1200 quantum unless noted):
  9000-vs-100 ≈ 0.94 (packet-count fairness would give ≈ 90);
  2800-vs-100, 9000-vs-1200 (q1400), 2800-vs-1200 (q512) all within
  0.6–1.7; three mixed flows split ≈ 1/3 each (asserted 0.22–0.45).
- Debugging this caught two test-design traps (documented in test
  comments): blind refills overflow the peer byte cap so the jumbo flow
  hogs queue space, and emptied-then-recreated flows get stuck in sparse
  priority — fairness tests now top up to bounded depths that fit the
  caps together. Production sparse starvation is bounded by the 16 KB
  new-flow budget (transient by design).
- `oversized_head_borrows_future_rounds` replaced by the ratio tests
  above (it only proved eventual progress, per review item 7).

## 16.8 HIGH — reassembly Drop guard (reassembly.rs)

- `impl Drop for ReassemblyTable` releases `self.bytes` from the shared
  counter (entries cleared with it). Invariant restored: `global_bytes ==
  sum(bytes of live tables)` after operations complete. Tests:
  `drop_releases_global_reservation` (partial insert → drop → 0) plus a
  25-round create/fill/drop churn stress asserting zero every round.

## 16.9 HIGH — synthetic-route invalidation (routing.rs)

- `rebuild` now clears `dynamic_synth` first (before computing the live
  set, so stale entries can't keep peers alive through `retain`). DNS
  regenerates on demand. The old `dynamic_synth_survives_rebuild` test
  asserted the removed behavior and was replaced by:
  `dynamic_synth_cleared_on_rebuild` (unrelated rebuild clears; DNS
  re-resolves), `synth_peer_removal_revokes_and_deactivates` (NoRoute +
  epoch advance), `synth_network_removal_revokes` (route + DNS gone).

## 16.10 Benchmark v3 cleanup (bench.sh, bench.ps1)

- Separate configurable server ports (`$6`/`$7`, `-ServerPortUp`/
  `-ServerPortDown`, defaults 5201/5202) used by every directional
  invocation; bidir runs up/down loads on different ports (the
  same-listener conflict is gone).
- Failed iperf runs (JSON `error`, unparsable output, nonzero client
  exit) mark rows `valid=false` with explicit `BIDIR INVALID` / `LOAD
  FAILED` notes instead of hiding behind -1 placeholders; bidir rows
  additionally print validity.
- PowerShell loaded latency stays at 200 Test-Connection samples with
  `p999=null` BY DESIGN — documented in the header and the sweep banner
  (1000+ samples would take minutes per fraction; Bash uses 1000 fast
  pings for real p99.9). Both scripts syntax-verified; no live runs yet
  (awaiting hardware, unchanged).

## 16.11 Validation status (Phase 2.2)

- `cargo fmt --check`, `cargo check --workspace --all-targets`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  clean on Windows AND native Linux (WSL; desktop excluded for the
  system `glib` dep). Feature-combo checks clean
  (`tunnet --no-default-features --features managed`,
  `tunnet-core` direct-only).
- `cargo test --workspace` (minus desktop): all suites ok, zero
  failures. `cargo nextest run --workspace`: 406 passed, 1 skipped on
  Windows (was 405; +1 publisher-serialization test, none weakened).
  Linux: 320 green (common 68 + core 170 + agent 82, minus the
  proven-environmental DNS test).
- DRR fairness measured (see 16.7); scheduler/frame/policy proptests all
  green under the new layout.

# 17. Incident record (2026-09-04) — total connectivity loss, two Linux TUN boundary bugs

Symptom: 100% ping loss between a Windows and a Linux machine (even
32-byte ICMP, both directions), builds since `be4ffc7`. Both daemons
reported `data plane up`, control connected, peers online — the health
readout masked a dead packet plane (see 17.5).

## 17.1 Bug A — Linux TUN receive capacity contract (fixed in 3031604)

`LinuxBatchEngine` slots (`BatchSlot(PooledBuffer)`) implemented
`AsRef<[u8]>` as the live packet view (length 0 for fresh slots), but
tun-rs `recv_multiple` uses `as_ref().len()` as RECEIVE CAPACITY
(`device.rs` non-GSO overflow check, `gso_split` output-buffer check)
and writes into `as_mut()[offset..]`. Every `recv_batch` therefore
failed deterministically from boot
(`read len … overflows bufs element len 0`), `run_outbound` propagated
with `?`, `spawn_outbound` logged `outbound TUN loop exited`, and Linux
never transmitted a single packet. Diagnosis signature on the Linux box:
`outbound TUN loop exited` with the overflow error.

## 17.2 Bug B — Linux TUN write misframing (fixed here, was still in main)

`LinuxTunBatchWriter::push()` staged packets in `PooledBuffer` (32-byte
tunnel-frame headroom), producing `[32B headroom][12B virtio zeros][IP]`,
but `flush()` passed `VIRTIO_NET_HDR_LEN` (12) as the packet offset.
tun-rs reads the IP packet at `buf[offset..]` and encodes virtio into
`buf[offset-12..offset]` (`offload.rs handle_gro`, verified in source):
the kernel received 32 zero bytes instead of IPv4 (`0x45`) and dropped
every packet silently (`flush` still returned Ok). Windows→Linux
requests never reached the Linux stack; Linux→Windows replies died the
same way. Either bug alone explains 100% bidirectional loss; both were
present.

Fix: the writer now owns dedicated reusable `Vec<Vec<u8>>` staging with
exactly `[12B zeros][IP packet]` (`push` resizes + extends; `flush`
passes offset 12; buffers cleared and retained, no per-packet alloc
after warmup). Tunnel-frame buffers and TUN-offload buffers are
separated by construction — no abstraction can mix the two headrooms
again. Dead fallout removed: `release_raw`, `PooledBuffer::into_vec`,
`storage_mut` (all unused after the split).

## 17.3 Receive abstraction cleanup

`PooledBuffer::{recv_area, recv_area_mut}` now expose exactly the same
region and length; `BatchSlot::{AsRef, AsMut}` both return it (tun-rs
validates capacity against `AsRef::len()` and writes into `AsMut` —
divergent views fail or misframe). `prepare()` debug-asserts capacity
coverage. Same-round-trip coverage as before (pool ownership + headroom
intact for zero-copy single transmit).

## 17.4 Reader ownership + ingress generation (hardening)

- `ConnPool::adopt` no longer fires the dialer tunnel hook: whoever
  adopts a connection already owns reading it (accept path spawns its
  own reader; inbound readers adopt their own conn). Previously every
  accepted connection briefly had TWO readers splitting datagrams (the
  hook-spawned one ate packets before being aborted).
- Dial tie-break loss no longer refires the hook on the kept connection
  (it already has a reader — refiring spawned a persistent duplicate).
  Hook fires only for genuinely new dialed connections.
- `IngressRegistry` entries are now `(generation, handle)`; exit cleanup
  removes only its own generation (`remove_if`). Previously a normally-
  exiting old reader could unregister a live replacement, leaving the
  peer readerless in the registry and breaking the next abort. Test
  `stale_reader_exit_keeps_new_registration` fails deterministically on
  the old code.
- Known follow-up (documented, not fixed here): a membership re-added
  while its transport connection is live but readerless gets outbound
  (pump) but no inbound reader until the connection flaps. Rare,
  pre-existing, needs a reader-respawn trigger on re-add.

## 17.5 Honest health reporting

`DataPlaneStatusSnapshot` now tracks `outbound_alive`, `restarting`,
`restart_count`, `generation`, `last_error` with a `state()` of
Up/Degraded/Restarting/Down. `OutboundExited` publishes
restarting+error+count BEFORE supervision restarts (previously the crash
loop reported `data plane up` between restarts); bring-up success clears
to Up; intentional shutdown reports Down. Unit test covers all
transitions.

## 17.6 Build identity in status

`tunnet-common/build.rs` bakes `GIT_HASH`; `tunnet status` shows
`build cli <hash> · daemon <hash> · <alpn>` plus dataplane detail, and
warns loudly on CLI/daemon hash mismatch (the stale-daemon trap: fresh
`cargo run --bin tunnet` CLI against an old service binary, with `v0.9.1`
on both). `NodeSummary` carries `daemon_git`, `tunnel_alpn`,
`data_plane` (all optional for old-daemon compat).

## 17.7 v3 reject framing leftover

`send_reject_framed`'s pool-less fallback built `[0x30][reply]` without
the mandatory 16-byte network — now `[0x30][net][reply]` (stale `0x20`
doc reference fixed too).

## 17.8 Tests added

- `batch_slot_satisfies_tun_rs_contract` (all platforms): replicates
  tun-rs's exact checks + simulated kernel write + pool/headroom
  round-trip, fresh and recycled slots. Mutation-checked.
- `tun_batch_writer_stages_virtio_layout` (Linux): locks
  `[12B zeros][IP]` staging layout without a device.
- `tun_kernel_round_trip` (Linux, `#[ignore]`, needs `CAP_NET_ADMIN`):
  real writer→kernel→reply→engine round trip through a temporary
  offload TUN. Run with `sudo -E` on a Linux dev machine; the missing
  coverage class that let both boundary bugs ship green.
- `loopback_ping_round_trip` (existing, still green): same-binary core
  pipeline guard.
- Ingress generation + snapshot health unit tests (both
  mutation-checked where applicable).

Validation after fix: `fmt --check`, workspace `check`, workspace
`clippy --all-targets --all-features -D warnings` clean Windows +
Linux; `nextest --workspace`: 410 passed, 1 skipped (Windows);
Linux 325 green (minus the proven-environmental DNS test).


# 18. Under-load diagnosis pass (2026-09-04) — scheduler visibility, bench honesty, knobs

Context: after §17 the black hole was gone (ping 4/4), but benchmarks showed Linux→Windows collapsing under sustained load (86–93% UDP loss, ~2–4 Mbps delivered ceiling) while Windows→Linux did 55 Mbps at 0% loss, plus an all-ERROR TCP matrix. This pass makes every drop visible, stops the benchmark from lying, and adds diagnostic knobs — before any tuning guesses.

## 18.1 Silent scheduler eviction now reported (scheduler.rs, tun_io.rs, pump.rs, metrics.rs)

- `enqueue` returned `None` after evicting the flow's stalest head at `FLOW_PACKET_CAP=64`: a real loss mechanism invisible to gauges and telemetry (only `drops_cap` moved, consumed by tests alone).
- New `EnqueueOutcome::{Accepted, AcceptedEvicted{reason, evicted_len}, Rejected{reason}}`: every shed/evicted packet is reported with its reason, and evictions carry the victim length so gauges reconcile exactly (previously the victim's +1/+len leaked). Both agent enqueue sites reconcile gauges and report `dropped_inc` + `sched_drop_inc` for evictions/rejections.
- `drain_drops()` surfaces CoDel/emergency drops (which happen inside `next()` with no enqueue decision site): drained by the pump every iteration and after every agent enqueue; deltas partition across lock holders so the sum stays exact, never double-counted. New `sched_drops_add(codel, emergency)` counted sink.
- Tests: `eviction_reports_victim_for_gauge_reconcile`, `drain_drops_reports_codel_then_quiet` (plus exact-once semantics), `memory_bounds_enforced_without_scan` rewritten to the reporting model (packet conservation: retained + rejected + evicted == offered).

## 18.2 Diagnostic A/B knobs (env, documented, CI must leave them unset)

- TUNNET_FLOW_PACKET_CAP (default 64): per-flow cap override (64 vs 256 runs). Read in PeerScheduler::new; set_flow_packet_cap for programmatic use.
- TUNNET_TUN_OFFLOAD=0: disables tun-rs offload+GSO (plain TUN I/O). Safe both ways: the writer layout works with and without vnet, and 
ecv_multiple degrades to the single-packet path.
- TUNNET_QUIC_DATAGRAM_BUFFER_KB (default 64): QUIC DATAGRAM staging (64/128/256 runs), clamped to [4 KiB, 1 MiB].
- TUNNET_PUMP_BACKOFF_MAX_US (default 2000): transport-full backoff ceiling (OnceLock, stall path only).
- With these + the §18.1 counters (sched_flow_cap, sched_peer_bytes/packets, sched_codel, sched_emergency, 	ransport_full), a loaded run attributes every missing packet to exactly one cause instead of guessing.

## 18.3 Eager preconnect (actors/dataplane.rs)

- On bring-up with keep-alive, dial every known routed peer concurrently (semaphore 8, skip-when-full, errors ignored — the pump still dials on demand). Kills the classic first-ping-timeout: the first real packet no longer pays connection setup. Skipped entirely without keep-alive.

## 18.4 bench.ps1 honesty rework

- Invoke-IperfJson returns {ok, json, exitCode, error}: command, exit code, stdout, stderr file, and JSON parse status travel with every invocation. No more `2>$null` + bare `ERROR`.
- Warmup checks the exit code (fails loudly if no server listens).
- The 50.0 capacity fallback is deleted: TCP matrix failure now STOPS the benchmark (`exit 1`) instead of building all sweeps on an invented number.
- UDP reports offered / sent_mbps / actual_mbps(=receiver sum_received) / pps_sent / pps_received / loss / jitter with defensive field access (iperf JSON field names vary by version; a missing receiver summary invalidates the row rather than promoting the sender offer — the exact `actual=50Mbps loss=92%` misread).
- UDP sweep is now sizes (512/900/1200/1460/2700: single vs segmented separation) x directions (up + -R down).
- Loaded-latency jobs write result files + exit markers; crashes, bad exits, and parse failures mark `valid=false` with the cause in the note. Bidir rows require BOTH directions; 200-sample p999=null stays documented-by-design. Parser-verified.

## 18.5 bench.sh parity

- Warmup exit-checked; TCP capacity failure stops (same rule, no invented 50); UDP uses sum_received with sender/receiver split, pps both sides, `valid` flag, and error capture; UDP sweep is sizes x directions like ps1. `bash -n clean.

## 18.6 What the numbers say so far (unverified hypotheses, for the A/B)

- Plateau shape (~2–4 Mbps delivered regardless of offer) fits a sender-side ceiling: 64-packet flow cap with silent head-eviction + 64 KiB QUIC staging + backoff sleeps. The §18.1 counters will confirm or refute on the next loaded run — no tuning applied yet.
- TCP matrix all-ERROR is still unexplained (likely server-side: no iperf3 listener on the peer, or control-channel blocking); the new error capture will name it on the next run.

Validation: fmt/check/clippy clean both platforms; `nextest --workspace` 412 passed Windows; Linux 327 green; both bench scripts syntax-verified.
