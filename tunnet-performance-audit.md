# Tunnet dataplane

The packet path is a layer-3 IP tunnel over Iroh QUIC DATAGRAM.

ALPN: `tunnet/tunnel/4`.

There is no compatibility decoder for `/3` or earlier.

## Packet path

```text
                     OUTBOUND

Linux/Windows kernel
        |
        v
   TUN reader
        |
        | parse once
        | route
        | policy
        | NAT if needed
        v
   peer transport
        |
        v
 Iroh QUIC DATAGRAM


                     INBOUND

 Iroh QUIC DATAGRAM
        |
        | decode network binding
        | authenticate
        | policy
        | NAT if needed
        v
 bounded TUN sink
        |
        v
Linux/Windows kernel
```

Kameo is not on the packet path. `DataPlaneActor` owns generation lifecycle only: bring up, bring down, restart after a fatal local TUN failure, and publish health.

A generation owns:

- one TUN reader
- one TUN writer
- one peer transport task per remote endpoint

If an essential task dies, the generation fails and is rebuilt.

## Wire format

One TUN packet is one QUIC DATAGRAM:

```text
kind           1 byte   0x40
network_id    16 bytes
IP packet      N bytes
```

The virtual MTU defaults to 1100 so `MTU + 17` stays under the 1200-byte QUIC DATAGRAM floor. Overlay segmentation is gone. Inner TCP MSS and IP fragmentation handle size.

A tunnel packet is always bound to an explicit `NetworkId`. Membership is never inferred from insertion order, IP alone, or the connection.

## Peer transport

One task per remote `EndpointId` owns:

- a bounded FIFO byte queue (256 KiB / 512 packets, tail-drop)
- the current Iroh connection
- serialized dial
- the DATAGRAM reader for that connection

Accepted and dialed connections enter the same task. Simultaneous connections use one tie-break: the endpoint with the smaller id prefers its own dial; otherwise an accepted connection wins. Same-orientation duplicates keep the current connection.

QUIC DATAGRAM is unreliable packet transport. Connection failure drops the current packet, clears the connection, and redials on the next packet. Inner TCP retransmits. Inner UDP loss is valid. There is no replay, no in-flight cursor across connections, and no session-repair protocol.

The stream `ConnPool` (`TUNNEL_STREAM_ALPN`) is unrelated. It does not own tunnel connections.

## TUN I/O

Linux production uses tun-rs 2.8.9 offload:

- `recv_multiple()` is the GSO receive API. Caller buffers implement `AsRef<[u8]> + AsMut<[u8]>` over the same writable receive region. Capacity is the receive area, not the live packet length.
- `send_multiple()` performs GRO. With `vnet_hdr`, the caller stages `[12B virtio zeros][IP packet]` and passes offset `VIRTIO_NET_HDR_LEN`. tun-rs writes the virtio header itself. Packet storage used for overlay framing is never reused as this staging buffer.

Windows has one reader and one writer. The writer uses `try_send` only. `WouldBlock` keeps the same front packet and retries. Ingress never waits on the Wintun send ring.

The TUN writer queue is 512 packets / 1 MiB. A full queue drops a complete IP packet at this boundary.

## IPv4 fragments

Later fragments may arrive first. `frag_hold` holds complete original fragments, scoped by `NetworkId + Direction + src + dst + protocol + identification`, with a 32-key / 4-per-key / 256 KiB / 2 s cap. The first fragment's policy verdict releases or discards followers. Missing first fragments expire fail-closed. The OS still receives original fragments. This is not IP reassembly.

Policy publication remains atomic in `PolicyRuntime`.

## Health and metrics

Health is generation, TUN reader/writer liveness, connected peer count, and last fatal error.

Useful counters: TUN rx/tx packets and bytes, overlay tx/rx, queue depth, drops by reason, QUIC failures, dial attempts/failures, TUN `WouldBlock`.

## Benchmark

`scripts/bench.ps1` and `scripts/bench.sh` report idle latency, TCP P1/P4 up/down/bidir with repeats, capacity min/median/max/spread, loaded latency, delivered Mbps, loss, UDP size/direction matrix, software-drop deltas, and independent delivery ratio. A run that sends 100 Mbps and delivers 1 Mbps reports ~99% undelivered even if iperf `lost_percent` is near zero.

## Historical comparison

Windows client → Linux peer, 2026-09-03, before the performance series:

| | Idle ICMP | Loaded ICMP | TCP up | TCP down |
|---|---|---|---|---|
| Tunnet | 93.8 ms | 222 ms | ~80 Mbps | 99 Mbps |
| ZeroTier | 83.5 ms | 86 ms | ~85 Mbps | 136 Mbps |

The series after `2d20b0c` found real bugs (Linux `recv_multiple` buffer views, virtio write offset, multi-network binding, policy publication, fragment scoping) and then accumulated session-repair machinery that this rewrite deletes. Git history is the archive.

## Deleted

`EndpointTxRegistry`, `InFlightTx`, overlay segmentation/reassembly, FQ-CoDel scheduler, ingress/session records, lifecycle gates, and cross-connection replay. Those were not the packet path. They were an application reliability protocol on top of QUIC DATAGRAM.
