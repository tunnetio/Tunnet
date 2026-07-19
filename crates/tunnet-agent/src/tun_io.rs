use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tun_rs::{AsyncDevice, DeviceBuilder};
use tunnet_common::policy::Direction;
use tunnet_core::direct::{
    AuthCache, EvalResult, FirewallEngine, PacketDirection, SpoofTracker, source_matches_peer,
};
use tunnet_core::{AclEngine, ConnPool, RoutingTable, iroh_pool::send_datagram};
use uuid::Uuid;

use crate::dataplane::TunSlot;
use crate::ip;
use crate::metrics::AgentMetrics;
use crate::ssh_nat;

const OUTBOUND_QUEUE_CAP: usize = 1024;
const PRIORITY_QUEUE_CAP: usize = 256;

#[derive(Clone, Copy)]
enum OutPriority {
    /// ICMP / small latency-sensitive packets — drained first, may wait on CC.
    Latency,
    /// Bulk TCP/UDP — never blocks the worker on datagram congestion.
    Bulk,
}

pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
    #[cfg(windows)] wintun_file: Option<&str>,
) -> anyhow::Result<AsyncDevice> {
    let builder = DeviceBuilder::new()
        .name(ifname)
        .ipv4(ipv4, prefix, None)
        .mtu(mtu);
    #[cfg(windows)]
    let builder = {
        use crate::wintun_path;
        let path = wintun_path::resolve(wintun_file);
        tracing::info!(path = %path.display(), "loading wintun.dll");
        builder
            .wintun_file(path.display().to_string())
            .wintun_log(true)
    };
    let dev = builder
        .build_async()
        .with_context(|| {
            #[cfg(windows)]
            {
                let path = crate::wintun_path::resolve(wintun_file);
                format!(
                    "build_async TUN device (wintun={}). On Windows, ensure wintun.dll sits next to tunnet.exe",
                    path.display()
                )
            }
            #[cfg(not(windows))]
            {
                "build_async TUN device".to_string()
            }
        })?;
    tracing::info!(%ipv4, prefix, mtu, "TUN device up");
    Ok(dev)
}

pub struct OutboundDeps {
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub pool: ConnPool,
    pub acl: AclEngine,
    /// Per-network firewall engines (Direct). Empty/None in Managed.
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub metrics: AgentMetrics,
}

pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        routes,
        pool,
        acl,
        firewalls,
        metrics,
    } = deps;

    let (prio_tx, mut prio_rx) =
        tokio::sync::mpsc::channel::<(EndpointId, Bytes)>(PRIORITY_QUEUE_CAP);
    let (bulk_tx, mut bulk_rx) =
        tokio::sync::mpsc::channel::<(EndpointId, Bytes)>(OUTBOUND_QUEUE_CAP);

    let worker_pool = pool.clone();
    let worker_metrics = metrics.clone();
    let worker = tokio::spawn(async move {
        loop {
            // Prefer latency packets so iperf flood cannot stall ICMP.
            let (peer, payload, latency) = tokio::select! {
                biased;
                Some((peer, payload)) = prio_rx.recv() => (peer, payload, true),
                Some((peer, payload)) = bulk_rx.recv() => (peer, payload, false),
                else => break,
            };
            let n = payload.len() as u64;
            let result = if latency {
                worker_pool.send_or_buffer_priority(peer, payload).await
            } else {
                worker_pool.send_or_buffer(peer, payload).await
            };
            match result {
                Ok(()) => {
                    worker_metrics.packets_inc("out");
                    worker_metrics.bytes_add("out", n);
                    worker_pool.record_bytes_out(peer, n);
                }
                Err(e) => {
                    tracing::debug!(%peer, ?e, latency, "send/buffer failed");
                    worker_metrics.dropped_inc(if latency {
                        "send_failed_prio"
                    } else {
                        "send_failed_bulk"
                    });
                }
            }
        }
    });

    let mut buf = vec![0u8; 65_536];
    tracing::info!("outbound TUN→iroh loop started");
    let read_result: anyhow::Result<()> = async {
        loop {
            let n = tun.recv(&mut buf).await?;
            if n == 0 {
                continue;
            }
            // SSH port NAT: replies from internal listen port → external :22.
            let self_ip = acl.self_id.load().ip;
            let _ = ssh_nat::rewrite_outbound(&mut buf[..n], self_ip);
            let packet = &buf[..n];
            let Some(parsed) = ip::parse_ipv4(packet) else {
                metrics.dropped_inc("non_ipv4");
                continue;
            };

            // PeerDNS magic IP is local - never mesh-forward.
            if routes.is_magic_dns_destination(&parsed.dst) {
                metrics.dropped_inc("magic_dns_local");
                continue;
            }

            if routes.is_advertised_destination(&parsed.dst) {
                metrics.dropped_inc("local_subnet");
                continue;
            }

            let Some(peer) = routes.lookup_ip(&parsed.dst) else {
                metrics.dropped_inc("no_route");
                continue;
            };

            // Never mesh-forward to ourselves (PeerDNS injects self into the table).
            if peer.ip == self_ip {
                metrics.dropped_inc("self");
                continue;
            }

            // Connection-level ACL (Managed + Direct peer accept).
            if !acl.allow_packet(
                &peer.endpoint_hex,
                Some(parsed.dst),
                parsed.dst_port,
                parsed.protocol,
                Direction::Outbound,
            ) {
                metrics.dropped_inc("policy_deny");
                continue;
            }

            if let Some(fw) = firewalls.get(&peer.network_id) {
                match fw.evaluate(
                    PacketDirection::Outbound,
                    packet,
                    Some(&peer.endpoint_hex),
                    Some(&peer.hostname),
                    Some(peer.network_id),
                ) {
                    EvalResult::Allow => {}
                    EvalResult::Deny => {
                        metrics.dropped_inc("fw_deny_out");
                        continue;
                    }
                    EvalResult::Reject { reply } => {
                        metrics.dropped_inc("fw_reject_out");
                        if !reply.is_empty() {
                            let _ = tun.send(&reply).await;
                        }
                        continue;
                    }
                }
            }

            let priority = match parsed.protocol {
                tunnet_common::policy::Protocol::Icmp => OutPriority::Latency,
                // Very small packets are often ACKs / DNS / control — keep them responsive.
                _ if packet.len() <= 128 => OutPriority::Latency,
                _ => OutPriority::Bulk,
            };
            let payload = Bytes::copy_from_slice(packet);
            let tx = match priority {
                OutPriority::Latency => &prio_tx,
                OutPriority::Bulk => &bulk_tx,
            };
            match tx.try_send((peer.endpoint, payload)) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    metrics.dropped_inc(match priority {
                        OutPriority::Latency => "prio_queue_full",
                        OutPriority::Bulk => "outbound_queue_full",
                    });
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    anyhow::bail!("outbound send worker closed");
                }
            }
        }
    }
    .await;

    drop(prio_tx);
    drop(bulk_tx);
    let _ = worker.await;
    read_result
}

/// Handle an already-accepted connection negotiated with [`tunnet_common::TUNNEL_ALPN`].
pub struct InboundDeps {
    pub conn: Connection,
    pub tun: TunSlot,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub spoofs: HashMap<Uuid, SpoofTracker>,
    pub pool: Option<ConnPool>,
    pub metrics: AgentMetrics,
    pub direct_auth: Option<AuthCache>,
}

pub async fn serve_tunnel_connection(deps: InboundDeps) {
    let InboundDeps {
        conn,
        tun,
        routes,
        acl,
        firewalls,
        spoofs,
        pool,
        metrics,
        direct_auth,
    } = deps;
    let remote_id = conn.remote_id();
    let remote_hex = format!("{remote_id}");
    if !acl.allow_inbound_peer(&remote_hex) {
        tracing::warn!(%remote_id, "policy denied inbound peer");
        conn.close(1u32.into(), b"policy_deny");
        return;
    }
    tracing::info!(%remote_id, "peer connected");
    metrics.active_conns_inc();
    if let Some(p) = &pool {
        p.touch_peer(remote_id);
        // Canonical install usually happened in accept/dial; keep pool in sync.
        if !p.adopt(remote_id, conn.clone()).await {
            tracing::debug!(%remote_id, "ingress conn not canonical; exiting reader");
            metrics.active_conns_dec();
            return;
        }
    }
    // Prefer network from auth cache; fall back to route table peer.
    let inbound_network = direct_auth
        .as_ref()
        .and_then(|a| a.networks_for(&remote_hex).into_iter().next())
        .or_else(|| routes.lookup_endpoint(&remote_hex).map(|p| p.network_id));

    let start_gen = tun.read().await.generation;

    loop {
        // Exit cleanly if data plane went down or TUN was swapped.
        {
            let slot = tun.read().await;
            if slot.device.is_none() || slot.generation != start_gen {
                break;
            }
        }

        match conn.read_datagram().await {
            Ok(dg) => {
                if let Some(p) = &pool {
                    p.touch_peer(remote_id);
                }

                let Some(parsed) = ip::parse_ipv4(&dg) else {
                    metrics.dropped_inc("non_ipv4_in");
                    continue;
                };

                let peer_info = inbound_network
                    .and_then(|nid| routes.lookup_network_ip(nid, &parsed.src))
                    .or_else(|| routes.lookup_endpoint(&remote_hex));

                // Anti-spoof: source IP must match this peer's mesh IP.
                if let Some(peer_info) = &peer_info
                    && !source_matches_peer(parsed.src, peer_info.ip)
                {
                    metrics.dropped_inc("antispoof");
                    if let Some(nid) = inbound_network.or(Some(peer_info.network_id))
                        && let Some(tracker) = spoofs.get(&nid)
                        && tracker.record(&remote_hex)
                    {
                        let counts = tracker.drain_window_counts();
                        for (peer, n) in counts {
                            tracing::warn!(
                                peer = %peer,
                                spoofed_packets = n,
                                "ingress anti-spoof drops in last window"
                            );
                        }
                    }
                    continue;
                }

                // Connection-level ACL.
                let dst_for_acl = if routes.is_advertised_destination(&parsed.dst) {
                    Some(parsed.dst)
                } else {
                    Some(parsed.src)
                };
                if !acl.allow_packet(
                    &remote_hex,
                    dst_for_acl,
                    parsed.dst_port,
                    parsed.protocol,
                    Direction::Inbound,
                ) {
                    metrics.dropped_inc("policy_deny_in");
                    continue;
                }

                // Direct userspace firewall for the peer's network.
                let peer_net = peer_info.as_ref().map(|p| p.network_id).or(inbound_network);
                if let Some(nid) = peer_net
                    && let Some(fw) = firewalls.get(&nid)
                {
                    match fw.evaluate(
                        PacketDirection::Inbound,
                        &dg,
                        Some(&remote_hex),
                        peer_info.as_ref().map(|p| p.hostname.as_str()),
                        Some(nid),
                    ) {
                        EvalResult::Allow => {}
                        EvalResult::Deny => {
                            metrics.dropped_inc("fw_deny_in");
                            continue;
                        }
                        EvalResult::Reject { reply } => {
                            metrics.dropped_inc("fw_reject_in");
                            if !reply.is_empty() {
                                let _ = send_datagram(&conn, reply).await;
                            }
                            continue;
                        }
                    }
                }

                let n = dg.len() as u64;
                // SSH port NAT: inbound :22 → internal listen port before kernel.
                let self_ip = acl.self_id.load().ip;
                let send_result = {
                    let slot = tun.read().await;
                    let Some(device) = slot.device.as_ref() else {
                        break;
                    };
                    if slot.generation != start_gen {
                        break;
                    }
                    if ssh_nat::needs_inbound_rewrite(&dg, self_ip) {
                        let mut packet = dg.to_vec();
                        let _ = ssh_nat::rewrite_inbound(&mut packet, self_ip);
                        device.send(&packet).await
                    } else {
                        device.send(dg.as_ref()).await
                    }
                };
                if let Err(e) = send_result {
                    tracing::warn!(?e, "tun send failed");
                    metrics.dropped_inc("tun_send_failed");
                    break;
                }
                metrics.packets_inc("in");
                metrics.bytes_add("in", n);
                if let Some(p) = &pool {
                    p.record_bytes_in(remote_id, n);
                }
            }
            Err(e) => {
                tracing::debug!(?e, "read_datagram closed");
                break;
            }
        }
    }
    metrics.active_conns_dec();
    tracing::info!(%remote_id, "peer disconnected");
}
