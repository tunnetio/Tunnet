use bytes::Bytes;
use iroh::EndpointId;
use tunnet_common::packet::{self, Packet, Transport};
use tunnet_common::policy::Direction;
use uuid::Uuid;

use super::frame::unframe;
use super::policy::{Decision, PeerCtx, PolicyEngine};
use super::snapshot::{ForwardingSnapshot, NetworkPolicy};

pub const SSH_EXTERNAL_PORT: u16 = 22;
pub const SSH_INTERNAL_PORT: u16 = 30022;

#[derive(Debug, Clone, Copy)]
pub struct SshRewrite {
    pub ip_header_len: usize,
    pub port_offset: usize,
    pub port: u16,
}

#[derive(Debug)]
pub enum OutDecision {
    Forward { peer: EndpointId, network: Uuid },
    LocalDns,
    RewriteSsh(SshRewrite),
    Reject { reply: Bytes },
    Drop { reason: &'static str },
}

#[derive(Debug)]
pub enum InDecision<'a> {
    ToTun {
        ip: &'a [u8],
        ssh: Option<SshRewrite>,
    },
    Reject {
        reply: Bytes,
    },
    Spoof {
        network: Uuid,
    },
    Drop {
        reason: &'static str,
    },
}

pub fn outbound(snap: &ForwardingSnapshot, policy: &PolicyEngine, raw: &[u8]) -> OutDecision {
    let pkt = match packet::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            return OutDecision::Drop {
                reason: e.drop_reason(),
            };
        }
    };
    if pkt.ip.v4_src().is_none() {
        return OutDecision::Drop {
            reason: "ipv6_unsupported",
        };
    }
    if let Some(rewrite) = ssh_outbound(&pkt, snap) {
        return rewrite;
    }
    #[cfg(feature = "dns")]
    if crate::dns::targets_virtual_resolver(&pkt) {
        return OutDecision::LocalDns;
    }
    outbound_routed(snap, policy, &pkt)
}

fn outbound_routed(
    snap: &ForwardingSnapshot,
    policy: &PolicyEngine,
    pkt: &Packet<'_>,
) -> OutDecision {
    let dst = pkt.ip.v4_dst().unwrap();
    if snap.tables.advertised.iter().any(|net| net.contains(&dst)) {
        return OutDecision::Drop {
            reason: "local_subnet",
        };
    }
    if snap.conflicts.contains(&dst) || snap.conflict_cidrs.iter().any(|net| net.contains(&dst)) {
        return OutDecision::Drop {
            reason: "route_conflict",
        };
    }
    let Some(peer) = snap.route(&dst) else {
        return OutDecision::Drop { reason: "no_route" };
    };
    if dst == snap.self_id.ip {
        return OutDecision::Drop { reason: "self" };
    }
    if pkt.wire_len > snap.tun_mtu as usize {
        return OutDecision::Drop { reason: "oversize" };
    }
    let ctx = PeerCtx {
        endpoint: peer.endpoint,
        hex: &peer.endpoint_hex,
        hostname: &peer.hostname,
        tags: &peer.tags,
        network_name: &peer.network_name,
    };
    match policy.evaluate(snap, peer.network_id, &ctx, Direction::Outbound, pkt) {
        Decision::Allow => OutDecision::Forward {
            peer: peer.endpoint,
            network: peer.network_id,
        },
        Decision::Deny => OutDecision::Drop {
            reason: deny_reason(snap, peer.network_id, false),
        },
        Decision::Reject { reply } => OutDecision::Reject { reply },
    }
}

pub fn inbound_frame<'a>(
    snap: &ForwardingSnapshot,
    policy: &PolicyEngine,
    dg: &'a [u8],
    peer: EndpointId,
) -> InDecision<'a> {
    let (net, ip) = match unframe(dg) {
        Ok(f) => f,
        Err(e) => return InDecision::Drop { reason: e.reason() },
    };
    let Some(binding) = snap.binding(net, peer) else {
        return InDecision::Drop {
            reason: "unauthorized_network",
        };
    };
    let pkt = match packet::parse(ip) {
        Ok(p) => p,
        Err(e) => {
            return InDecision::Drop {
                reason: e.drop_reason(),
            };
        }
    };
    if pkt.ip.v4_src().is_none() {
        return InDecision::Drop {
            reason: "ipv6_unsupported_in",
        };
    }
    let src = pkt.ip.v4_src().unwrap();
    if src != binding.ip {
        return InDecision::Spoof { network: net };
    }
    let ctx = PeerCtx {
        endpoint: binding.endpoint,
        hex: &binding.endpoint_hex,
        hostname: &binding.hostname,
        tags: &binding.tags,
        network_name: &binding.network_name,
    };
    match policy.evaluate(snap, net, &ctx, Direction::Inbound, &pkt) {
        Decision::Allow => InDecision::ToTun {
            ip,
            ssh: ssh_inbound(&pkt, snap),
        },
        Decision::Deny => InDecision::Drop {
            reason: deny_reason(snap, net, true),
        },
        Decision::Reject { reply } => InDecision::Reject { reply },
    }
}

fn deny_reason(snap: &ForwardingSnapshot, net: Uuid, inbound: bool) -> &'static str {
    let direct = matches!(snap.policy_for(net), Some(NetworkPolicy::Direct { .. }));
    match (direct, inbound) {
        (true, true) => "fw_deny_in",
        (true, false) => "fw_deny_out",
        (false, true) => "policy_deny_in",
        (false, false) => "policy_deny",
    }
}

fn ssh_outbound(pkt: &Packet<'_>, snap: &ForwardingSnapshot) -> Option<OutDecision> {
    if pkt.fragmentation.is_later() {
        return None;
    }
    let Transport::Tcp {
        src_port,
        header_len,
        ..
    } = pkt.transport
    else {
        return None;
    };
    if header_len < 18 {
        return None;
    }
    let src = pkt.ip.v4_src()?;
    if !snap.ssh_addrs.contains(&src) || src_port != SSH_INTERNAL_PORT {
        return None;
    }
    Some(OutDecision::RewriteSsh(SshRewrite {
        ip_header_len: pkt.ip.header_len(),
        port_offset: pkt.ip.header_len(),
        port: SSH_EXTERNAL_PORT,
    }))
}

fn ssh_inbound(pkt: &Packet<'_>, snap: &ForwardingSnapshot) -> Option<SshRewrite> {
    if pkt.fragmentation.is_later() {
        return None;
    }
    let Transport::Tcp {
        dst_port,
        header_len,
        ..
    } = pkt.transport
    else {
        return None;
    };
    if header_len < 18 {
        return None;
    }
    let dst = pkt.ip.v4_dst()?;
    if !snap.ssh_addrs.contains(&dst) || dst_port != SSH_EXTERNAL_PORT {
        return None;
    }
    Some(SshRewrite {
        ip_header_len: pkt.ip.header_len(),
        port_offset: pkt.ip.header_len() + 2,
        port: SSH_INTERNAL_PORT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::snapshot::{ForwardingStore, SelfIdentity};
    use crate::routing::RoutingTable;
    use rstest::rstest;
    use tunnet_common::policy::PolicyBundle;

    fn v4_packet(src: &str, dst: &str, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(
            src.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            dst.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            64,
        )
        .udp(sport, dport);
        let mut out = Vec::new();
        b.write(&mut out, &[0u8; 32]).unwrap();
        out
    }

    fn tcp_packet(src: &str, dst: &str, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(
            src.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            dst.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            64,
        )
        .tcp(sport, dport, 1, 1000)
        .syn();
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn managed_setup() -> (ForwardingStore, PolicyEngine, RoutingTable) {
        let routes = RoutingTable::new();
        routes.replace(
            &[
                tunnet_common::PeerEntry {
                    ip: "10.7.0.2".parse().unwrap(),
                    endpoint_id: "bb".repeat(32),
                    hostname: "peer".into(),
                    tags: vec![],
                    ssh_host_key: None,
                },
                tunnet_common::PeerEntry {
                    ip: "10.7.0.1".parse().unwrap(),
                    endpoint_id: "aa".repeat(32),
                    hostname: "self".into(),
                    tags: vec![],
                    ssh_host_key: None,
                },
            ],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "office",
            Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
        let store = ForwardingStore::new();
        store.set_managed_bundle(
            &routes,
            Uuid::nil(),
            PolicyBundle::default(),
            SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: "10.7.0.1".parse().unwrap(),
                tags: vec![],
                network: "office".into(),
            },
        );
        (store, PolicyEngine::new(), routes)
    }

    #[test]
    fn outbound_forwards_routed_peer_with_explicit_network() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let raw = v4_packet("10.7.0.1", "10.7.0.2", 40000, 443);
        match outbound(&snap, &policy, &raw) {
            OutDecision::Forward { network, .. } => assert_eq!(network, Uuid::nil()),
            d => panic!("unexpected {d:?}"),
        }
    }

    #[test]
    fn removed_peer_loses_access() {
        let (store, policy, routes) = managed_setup();
        let peer_bb: EndpointId = "bb".repeat(32).parse().unwrap();
        let framed_in = |raw: &[u8]| super::super::frame::frame(Uuid::nil(), raw);
        let before = store.load();
        let out_bb = v4_packet("10.7.0.1", "10.7.0.2", 40000, 443);
        assert!(matches!(
            outbound(&before, &policy, &out_bb),
            OutDecision::Forward { .. }
        ));
        let in_bb = framed_in(&v4_packet("10.7.0.2", "10.7.0.1", 40000, 443));
        assert!(matches!(
            inbound_frame(&before, &policy, &in_bb, peer_bb),
            InDecision::ToTun { .. }
        ));
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: "10.7.0.1".parse().unwrap(),
                endpoint_id: "aa".repeat(32),
                hostname: "self".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "office",
            Uuid::nil(),
            &"aa".repeat(32),
            2,
        );
        store.republish(&routes);
        let after = store.load();
        assert!(matches!(
            outbound(&after, &policy, &out_bb),
            OutDecision::Drop { reason: "no_route" }
        ));
        assert!(matches!(
            inbound_frame(&after, &policy, &in_bb, peer_bb),
            InDecision::Drop {
                reason: "unauthorized_network"
            }
        ));
    }

    #[test]
    fn outbound_rejects_untagged_as_unroutable() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let raw = v4_packet("10.7.0.1", "192.0.2.99", 40000, 443);
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::Drop { .. }
        ));
    }

    #[test]
    fn inbound_frame_requires_explicit_authorized_network() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let peer: EndpointId = "bb".repeat(32).parse().unwrap();
        let raw = v4_packet("10.7.0.2", "10.7.0.1", 40000, 443);
        let framed = super::super::frame::frame(Uuid::nil(), &raw);
        assert!(matches!(
            inbound_frame(&snap, &policy, &framed, peer),
            InDecision::ToTun { .. }
        ));
        let wrong_net = super::super::frame::frame(Uuid::from_u128(9), &raw);
        assert!(matches!(
            inbound_frame(&snap, &policy, &wrong_net, peer),
            InDecision::Drop { .. }
        ));
        assert!(matches!(
            inbound_frame(&snap, &policy, &raw, peer),
            InDecision::Drop { .. }
        ));
    }

    #[test]
    fn inbound_spoofed_source_is_flagged_not_forwarded() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let peer: EndpointId = "bb".repeat(32).parse().unwrap();
        let raw = v4_packet("10.7.0.9", "10.7.0.1", 40000, 443);
        let framed = super::super::frame::frame(Uuid::nil(), &raw);
        assert!(matches!(
            inbound_frame(&snap, &policy, &framed, peer),
            InDecision::Spoof { .. }
        ));
    }

    #[test]
    fn outbound_conflicting_destination_is_rejected() {
        let routes = RoutingTable::new();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: "10.7.0.2".parse().unwrap(),
                endpoint_id: "bb".repeat(32),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "one",
            Uuid::from_u128(1),
            &"aa".repeat(32),
            1,
        );
        routes.replace_network(
            Uuid::from_u128(2),
            &[tunnet_common::PeerEntry {
                ip: "10.7.0.2".parse().unwrap(),
                endpoint_id: "cc".repeat(32),
                hostname: "peer2".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            &tunnet_common::DnsConfig::default(),
            "two",
            &"aa".repeat(32),
            1,
        );
        let store = ForwardingStore::new();
        store.set_managed_bundle(
            &routes,
            Uuid::from_u128(1),
            PolicyBundle::default(),
            SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: "10.7.0.1".parse().unwrap(),
                tags: vec![],
                network: "one".into(),
            },
        );
        let snap = store.load();
        let policy = PolicyEngine::new();
        let raw = v4_packet("10.7.0.1", "10.7.0.2", 40000, 443);
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::Drop {
                reason: "route_conflict"
            }
        ));
    }

    #[rstest]
    #[case("10.7.0.1", "10.7.0.1", "self")]
    #[case("10.7.0.1", "10.7.9.9", "no_route")]
    fn outbound_drop_reasons(#[case] src: &str, #[case] dst: &str, #[case] reason: &'static str) {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let raw = v4_packet(src, dst, 40000, 443);
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::Drop { reason: r } if r == reason
        ));
    }

    #[test]
    fn outbound_local_dns_is_explicit() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let raw = v4_packet(
            "10.7.0.1",
            &tunnet_common::VirtualResolverEndpoint::IP.to_string(),
            40000,
            tunnet_common::VirtualResolverEndpoint::PORT,
        );
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::LocalDns
        ));
    }

    #[test]
    fn outbound_oversize_frame_is_dropped() {
        let (store, policy, routes) = managed_setup();
        store.set_mtu(&routes, 576);
        let snap = store.load();
        let b = etherparse::PacketBuilder::ipv4([10, 7, 0, 1], [10, 7, 0, 2], 64).udp(40000, 443);
        let mut raw = Vec::new();
        b.write(&mut raw, &[0u8; 600]).unwrap();
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::Drop { reason: "oversize" }
        ));
    }

    fn udp_sized(payload: usize) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4([10, 7, 0, 1], [10, 7, 0, 2], 64).udp(40000, 443);
        let mut raw = Vec::new();
        b.write(&mut raw, &vec![0u8; payload]).unwrap();
        raw
    }

    #[rstest]
    #[case(1251, true)]
    #[case(1252, true)]
    #[case(1253, false)]
    fn outbound_mtu_bounds_raw_ip_packet(#[case] payload: usize, #[case] forward: bool) {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        assert_eq!(snap.tun_mtu, 1280);
        let raw = udp_sized(payload);
        assert_eq!(
            matches!(outbound(&snap, &policy, &raw), OutDecision::Forward { .. }),
            forward,
            "wire_len 20+8+{payload} vs tun_mtu 1280; framing overhead must not shrink the limit"
        );
    }

    #[test]
    fn ssh_interception_is_an_explicit_outcome() {
        let (store, policy, routes) = managed_setup();
        let mut addrs = std::collections::HashSet::new();
        addrs.insert("10.7.0.1".parse().unwrap());
        store.set_ssh_addrs(&routes, addrs);
        let snap = store.load();
        let raw = tcp_packet("10.7.0.1", "10.7.0.2", 30022, 45678);
        assert!(matches!(
            outbound(&snap, &policy, &raw),
            OutDecision::RewriteSsh(_)
        ));
        let plain = tcp_packet("10.7.0.1", "10.7.0.2", 45678, 443);
        assert!(matches!(
            outbound(&snap, &policy, &plain),
            OutDecision::Forward { .. }
        ));
    }

    #[test]
    fn inbound_ssh_rewrite_flag_survives_policy() {
        let (store, policy, routes) = managed_setup();
        let mut addrs = std::collections::HashSet::new();
        addrs.insert("10.7.0.1".parse().unwrap());
        store.set_ssh_addrs(&routes, addrs);
        let snap = store.load();
        let peer: EndpointId = "bb".repeat(32).parse().unwrap();
        let raw = tcp_packet("10.7.0.2", "10.7.0.1", 45678, 22);
        let framed = super::super::frame::frame(Uuid::nil(), &raw);
        assert!(matches!(
            inbound_frame(&snap, &policy, &framed, peer),
            InDecision::ToTun { ssh: Some(_), .. }
        ));
    }

    #[test]
    fn inbound_to_tun_carries_stripped_ip_packet() {
        let (store, policy, _) = managed_setup();
        let snap = store.load();
        let peer: EndpointId = "bb".repeat(32).parse().unwrap();
        let raw = v4_packet("10.7.0.2", "10.7.0.1", 40000, 443);
        let framed = super::super::frame::frame(Uuid::nil(), &raw);
        match inbound_frame(&snap, &policy, &framed, peer) {
            InDecision::ToTun { ip, ssh: None } => assert_eq!(ip, &raw[..]),
            d => panic!("unexpected {d:?}"),
        }
    }
}
