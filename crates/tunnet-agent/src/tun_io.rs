use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use iroh::endpoint::Connection;
use tun_rs::{AsyncDevice, DeviceBuilder};
use tunnet_common::packet::{self, Packet};
use tunnet_common::policy::Direction;
use tunnet_core::direct::{
    AuthCache, EvalResult, FirewallEngine, PacketDirection, SpoofTracker, source_matches_peer,
};
use tunnet_core::{AclEngine, ConnPool, RoutingTable, iroh_pool::send_datagram};
use uuid::Uuid;

use crate::actors::dataplane::PublishedPlane;
use crate::metrics::AgentMetrics;
use crate::qos::{self, OutboundScheduler};
use crate::ssh_nat;

pub fn build_tun(
    ifname: &str,
    ipv4: std::net::Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    let builder = DeviceBuilder::new()
        .name(ifname)
        .ipv4(ipv4, prefix, None)
        .mtu(mtu);
    #[cfg(windows)]
    let builder = {
        let path = crate::wintun::materialize()?;
        builder
            .wintun_file(path.display().to_string())
            .wintun_log(true)
    };
    let dev = builder.build_async().context("build_async TUN device")?;
    tracing::info!(%ipv4, prefix, mtu, "TUN device up");
    Ok(dev)
}

pub struct OutboundDeps {
    pub tun: Arc<AsyncDevice>,
    pub routes: RoutingTable,
    pub pool: ConnPool,
    pub acl: AclEngine,
    pub firewalls: HashMap<Uuid, FirewallEngine>,
    pub metrics: AgentMetrics,
    pub mtu: u16,
}

fn drop_parse(metrics: &AgentMetrics, err: packet::ParseError) {
    metrics.dropped_inc(err.drop_reason());
}

fn require_ipv4<'a>(metrics: &AgentMetrics, pkt: Packet<'a>, inbound: bool) -> Option<Packet<'a>> {
    if pkt.ip.v4_src().is_none() {
        metrics.dropped_inc(if inbound {
            "ipv6_unsupported_in"
        } else {
            "ipv6_unsupported"
        });
        return None;
    }
    Some(pkt)
}

pub async fn run_outbound(deps: OutboundDeps) -> anyhow::Result<()> {
    let OutboundDeps {
        tun,
        routes,
        pool,
        acl,
        firewalls,
        metrics,
        mtu,
    } = deps;

    let scheduler = OutboundScheduler::new(pool.clone(), metrics.clone(), mtu);

    let mut buf = vec![0u8; 65_536];
    tracing::info!("outbound TUN→iroh Byte-DRR loop started");
    loop {
        let n = tun.recv(&mut buf).await?;
        if n == 0 {
            continue;
        }
        let self_ip = acl.self_id.load().ip;
        let _ = ssh_nat::rewrite_outbound(&mut buf[..n], self_ip);
        let packet = &buf[..n];
        let pkt = match packet::parse(packet) {
            Ok(p) => p,
            Err(e) => {
                drop_parse(&metrics, e);
                continue;
            }
        };
        let Some(pkt) = require_ipv4(&metrics, pkt, false) else {
            continue;
        };
        let dst = pkt.ip.v4_dst().unwrap();

        if routes.is_magic_dns_destination(&dst) {
            metrics.dropped_inc("magic_dns_local");
            continue;
        }

        if routes.is_advertised_destination(&dst) {
            metrics.dropped_inc("local_subnet");
            continue;
        }

        let Some(peer) = routes.lookup_ip(&dst) else {
            // Multicast/broadcast is unroutable on the mesh by design. LAN
            // discovery apps (mDNS, Ableton Link, SSDP) beacon on every
            // interface including ours, at a steady rate and forever. Counting
            // that as `no_route` buries genuine "mesh peer missing" drops under
            // millions of benign packets.
            if dst.is_multicast() || dst.is_broadcast() {
                metrics.dropped_inc("multicast");
            } else {
                metrics.dropped_inc("no_route");
            }
            continue;
        };

        if peer.ip == self_ip {
            metrics.dropped_inc("self");
            continue;
        }

        if !acl.allow_packet(&peer.endpoint_hex, Direction::Outbound, &pkt) {
            metrics.dropped_inc("policy_deny");
            continue;
        }

        if let Some(fw) = firewalls.get(&peer.network_id) {
            match fw.evaluate(
                PacketDirection::Outbound,
                &pkt,
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

        let class = qos::classify(&pkt, mtu);
        let payload = Bytes::copy_from_slice(packet);
        scheduler.enqueue(peer.endpoint, class, payload);
    }
}

pub struct InboundDeps {
    pub conn: Connection,
    pub tun: PublishedPlane,
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
        if !p.adopt(remote_id, conn.clone()).await {
            tracing::debug!(%remote_id, "ingress conn lost tie-break; exiting reader");
            metrics.active_conns_dec();
            return;
        }
        if let Some(max) = conn.max_datagram_size() {
            tracing::debug!(%remote_id, max_datagram_size = max, "quic datagram limit");
        }
    }
    let inbound_network = direct_auth
        .as_ref()
        .and_then(|a| a.networks_for(&remote_hex).into_iter().next())
        .or_else(|| routes.lookup_endpoint(&remote_hex).map(|p| p.network_id));

    // Load the published generation once. Retain the device + its exact
    // cancellation token; never reacquire a global lock per packet and never
    // observe a newer generation.
    let Some(plane) = tun.load_full() else {
        return;
    };
    let device = plane.device.clone();
    let generation_cancel = plane.cancel.clone();
    // Pinned at reader start: this task never observes a newer generation.
    tracing::debug!(generation = plane.generation, %remote_id, "ingress reader pinned");

    loop {
        if generation_cancel.is_cancelled() {
            break;
        }
        // Cancellation first so BringDown promptly stops old readers.
        let dg = tokio::select! {
            biased;
            _ = generation_cancel.cancelled() => break,
            res = conn.read_datagram() => match res {
                Ok(dg) => dg,
                Err(e) => {
                    tracing::debug!(?e, "read_datagram closed");
                    break;
                }
            },
        };
        if generation_cancel.is_cancelled() {
            break;
        }
        {
            #[allow(clippy::collapsible_if)]
            if let Some(p) = &pool {
                p.touch_peer(remote_id);
            }

            let pkt = match packet::parse(&dg) {
                Ok(p) => p,
                Err(e) => {
                    drop_parse(&metrics, e);
                    continue;
                }
            };
            let Some(pkt) = require_ipv4(&metrics, pkt, true) else {
                continue;
            };
            let src = pkt.ip.v4_src().unwrap();

            let peer_info = inbound_network
                .and_then(|nid| routes.lookup_network_ip(nid, &src))
                .or_else(|| routes.lookup_endpoint(&remote_hex));

            if let Some(peer_info) = &peer_info
                && !source_matches_peer(src, peer_info.ip)
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

            if !acl.allow_packet(&remote_hex, Direction::Inbound, &pkt) {
                metrics.dropped_inc("policy_deny_in");
                continue;
            }

            let peer_net = peer_info.as_ref().map(|p| p.network_id).or(inbound_network);
            if let Some(nid) = peer_net
                && let Some(fw) = firewalls.get(&nid)
            {
                match fw.evaluate(
                    PacketDirection::Inbound,
                    &pkt,
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
            let self_ip = acl.self_id.load().ip;
            // Generation already verified: device + token belong to the
            // generation loaded at reader start. Recheck cancellation
            // (not a lock) before the send so BringDown wins races.
            if generation_cancel.is_cancelled() {
                break;
            }
            let send_result = if ssh_nat::needs_inbound_rewrite(&dg, self_ip) {
                let mut packet = dg.to_vec();
                let _ = ssh_nat::rewrite_inbound(&mut packet, self_ip);
                device.send(&packet).await
            } else {
                device.send(dg.as_ref()).await
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
    }
    metrics.active_conns_dec();
    tracing::info!(%remote_id, "peer disconnected");
}
