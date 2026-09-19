//! In-TUN PeerDNS transport: intercept packets to the virtual resolver.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use etherparse::PacketBuilder;
use parking_lot::Mutex;
use tunnet_common::VirtualResolverEndpoint;
use tunnet_common::packet::{self, Packet, TcpFlags, Transport};

use super::Resolver;

const MAX_TCP_FLOWS: usize = 64;
const MAX_TCP_BUF: usize = 4096;
const TCP_WINDOW: u16 = 65535;

pub struct InTun {
    resolver: Arc<Resolver>,
    tcp: Mutex<HashMap<FlowKey, TcpFlow>>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct FlowKey {
    src: Ipv4Addr,
    sport: u16,
}

struct TcpFlow {
    client_next: u32,
    server_next: u32,
    buf: Vec<u8>,
}

pub fn targets_virtual_resolver(pkt: &Packet<'_>) -> bool {
    pkt.ip.v4_dst() == Some(VirtualResolverEndpoint::IP)
        && pkt.transport.dst_port() == Some(VirtualResolverEndpoint::PORT)
        && matches!(pkt.transport, Transport::Udp { .. } | Transport::Tcp { .. })
}

impl InTun {
    pub fn new(resolver: Arc<Resolver>) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            tcp: Mutex::new(HashMap::new()),
        })
    }

    pub async fn handle(&self, raw: &[u8]) -> Vec<Vec<u8>> {
        let Ok(pkt) = packet::parse(raw) else {
            return Vec::new();
        };
        if !targets_virtual_resolver(&pkt) {
            return Vec::new();
        }
        match pkt.transport {
            Transport::Udp { src_port, .. } => self.handle_udp(&pkt, src_port).await,
            Transport::Tcp { .. } => self.handle_tcp(&pkt).await,
            _ => Vec::new(),
        }
    }

    async fn handle_udp(&self, pkt: &Packet<'_>, src_port: u16) -> Vec<Vec<u8>> {
        let Some(src) = pkt.ip.v4_src() else {
            return Vec::new();
        };
        let max = udp_max_payload(pkt);
        let body = self.resolver.answer_udp(pkt.l4_payload(), max).await;
        match udp_reply(
            VirtualResolverEndpoint::IP,
            src,
            VirtualResolverEndpoint::PORT,
            src_port,
            &body,
        ) {
            Some(p) => vec![p],
            None => Vec::new(),
        }
    }

    async fn handle_tcp(&self, pkt: &Packet<'_>) -> Vec<Vec<u8>> {
        let Some(src) = pkt.ip.v4_src() else {
            return Vec::new();
        };
        let Transport::Tcp {
            src_port,
            dst_port,
            flags,
            seq,
            ..
        } = pkt.transport
        else {
            return Vec::new();
        };
        let key = FlowKey {
            src,
            sport: src_port,
        };
        if flags.rst() {
            self.tcp.lock().remove(&key);
            return Vec::new();
        }
        if flags.syn() && !flags.ack() {
            let mut table = self.tcp.lock();
            evict_if_needed(&mut table);
            let server_iss: u32 = 1;
            table.insert(
                key,
                TcpFlow {
                    client_next: seq.wrapping_add(1),
                    server_next: server_iss.wrapping_add(1),
                    buf: Vec::new(),
                },
            );
            drop(table);
            return tcp_packet(
                src,
                src_port,
                dst_port,
                server_iss,
                seq.wrapping_add(1),
                TcpFlags::SYN | TcpFlags::ACK,
                &[],
            )
            .into_iter()
            .collect();
        }

        let payload = pkt.l4_payload().to_vec();
        let fin = flags.fin();
        let mut replies = Vec::new();
        let queries = {
            let mut table = self.tcp.lock();
            let Some(flow) = table.get_mut(&key) else {
                return tcp_rst(src, src_port, dst_port, seq).into_iter().collect();
            };
            if !payload.is_empty() && seq == flow.client_next {
                if flow.buf.len().saturating_add(payload.len()) > MAX_TCP_BUF {
                    table.remove(&key);
                    return tcp_rst(src, src_port, dst_port, seq).into_iter().collect();
                }
                flow.buf.extend_from_slice(&payload);
                flow.client_next = flow.client_next.wrapping_add(payload.len() as u32);
            }
            if fin {
                flow.client_next = flow.client_next.wrapping_add(1);
            }
            drain_tcp_messages(&mut flow.buf)
        };

        for q in queries {
            let answer = self.resolver.answer(&q).await;
            let mut framed = Vec::with_capacity(2 + answer.len());
            framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            framed.extend_from_slice(&answer);
            let mut table = self.tcp.lock();
            let Some(flow) = table.get_mut(&key) else {
                break;
            };
            if let Some(p) = tcp_packet(
                src,
                src_port,
                dst_port,
                flow.server_next,
                flow.client_next,
                TcpFlags::PSH | TcpFlags::ACK,
                &framed,
            ) {
                flow.server_next = flow.server_next.wrapping_add(framed.len() as u32);
                replies.push(p);
            }
        }

        if fin {
            let mut table = self.tcp.lock();
            if let Some(flow) = table.remove(&key)
                && let Some(p) = tcp_packet(
                    src,
                    src_port,
                    dst_port,
                    flow.server_next,
                    flow.client_next,
                    TcpFlags::FIN | TcpFlags::ACK,
                    &[],
                )
            {
                replies.push(p);
            }
        } else if replies.is_empty() && !payload.is_empty() {
            let table = self.tcp.lock();
            if let Some(flow) = table.get(&key)
                && let Some(p) = tcp_packet(
                    src,
                    src_port,
                    dst_port,
                    flow.server_next,
                    flow.client_next,
                    TcpFlags::ACK,
                    &[],
                )
            {
                replies.push(p);
            }
        }
        replies
    }
}

fn evict_if_needed(table: &mut HashMap<FlowKey, TcpFlow>) {
    if table.len() < MAX_TCP_FLOWS {
        return;
    }
    if let Some(key) = table.keys().next().copied() {
        table.remove(&key);
    }
}

fn drain_tcp_messages(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 2 {
            break;
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if len > MAX_TCP_BUF {
            buf.clear();
            break;
        }
        if buf.len() < 2 + len {
            break;
        }
        out.push(buf[2..2 + len].to_vec());
        buf.drain(..2 + len);
    }
    out
}

fn udp_max_payload(pkt: &Packet<'_>) -> usize {
    let ip_l4 = pkt.ip.header_len() + 8;
    512.max(pkt.wire_len.saturating_sub(ip_l4)).min(UDP_CAP)
}

const UDP_CAP: usize = super::UDP_BUF;

fn udp_reply(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(sport, dport);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

fn tcp_packet(
    client: Ipv4Addr,
    client_port: u16,
    server_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut builder =
        PacketBuilder::ipv4(VirtualResolverEndpoint::IP.octets(), client.octets(), 64)
            .tcp(server_port, client_port, seq, TCP_WINDOW)
            .ack(ack);
    if flags & TcpFlags::SYN != 0 {
        builder = builder.syn();
    }
    if flags & TcpFlags::FIN != 0 {
        builder = builder.fin();
    }
    if flags & TcpFlags::RST != 0 {
        builder = builder.rst();
    }
    if flags & TcpFlags::PSH != 0 {
        builder = builder.psh();
    }
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

fn tcp_rst(client: Ipv4Addr, client_port: u16, server_port: u16, seq: u32) -> Option<Vec<u8>> {
    tcp_packet(
        client,
        client_port,
        server_port,
        0,
        seq.wrapping_add(1),
        TcpFlags::RST | TcpFlags::ACK,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{ExternalLookup, HickoryLookup, process_query};
    use crate::routing::RoutingTable;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::str::FromStr;
    use tunnet_common::{DeviceProfile, DnsConfig, PeerEntry};
    use uuid::Uuid;

    fn peer(endpoint: &str, ip: &str, hostname: &str) -> PeerEntry {
        PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: endpoint.to_string(),
            hostname: hostname.to_string(),
            tags: vec![],
            ssh_host_key: None,
        }
    }

    fn table_two_networks() -> RoutingTable {
        let table = RoutingTable::new();
        let office_self = "a".repeat(64);
        let home_self = "b".repeat(64);
        table.replace(
            &[peer(&office_self, "10.21.0.2", "desktop")],
            &[],
            &[],
            &[],
            &DeviceProfile::default(),
            &DnsConfig::default(),
            "office",
            Uuid::nil(),
            &office_self,
            1,
        );
        table.replace_network(
            Uuid::from_u128(2),
            &[peer(&home_self, "10.22.0.3", "laptop")],
            &DnsConfig::default(),
            "home",
            &home_self,
            2,
        );
        table
    }

    fn query_bytes(name: &str, id: u16) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg.to_bytes().unwrap()
    }

    fn udp_query(src: Ipv4Addr, sport: u16, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ipv4(src.octets(), VirtualResolverEndpoint::IP.octets(), 64)
            .udp(sport, VirtualResolverEndpoint::PORT);
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    fn tcp_segment(
        src: Ipv4Addr,
        sport: u16,
        seq: u32,
        ack: u32,
        syn: bool,
        fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = PacketBuilder::ipv4(src.octets(), VirtualResolverEndpoint::IP.octets(), 64)
            .tcp(sport, VirtualResolverEndpoint::PORT, seq, TCP_WINDOW);
        if syn {
            b = b.syn();
        }
        if fin {
            b = b.fin();
        }
        if ack != 0 || !syn {
            b = b.ack(ack);
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    async fn engine() -> Arc<InTun> {
        let resolver = Resolver::new(table_two_networks(), &DnsConfig::default()).unwrap();
        InTun::new(resolver)
    }

    #[test]
    fn ordinary_traffic_is_not_intercepted() {
        let b = PacketBuilder::ipv4([10, 21, 0, 2], [10, 21, 0, 3], 64).udp(40000, 80);
        let mut out = Vec::new();
        b.write(&mut out, &[1, 2, 3]).unwrap();
        let pkt = packet::parse(&out).unwrap();
        assert!(!targets_virtual_resolver(&pkt));
    }

    #[test]
    fn virtual_udp_is_intercepted() {
        let raw = udp_query(Ipv4Addr::new(10, 21, 0, 2), 53000, &[0; 12]);
        let pkt = packet::parse(&raw).unwrap();
        assert!(targets_virtual_resolver(&pkt));
    }

    #[tokio::test]
    async fn udp_internal_hostname() {
        let dns = engine().await;
        let q = query_bytes("desktop.office.tunnet.", 7);
        let raw = udp_query(Ipv4Addr::new(10, 21, 0, 2), 53000, &q);
        let replies = dns.handle(&raw).await;
        assert_eq!(replies.len(), 1);
        let pkt = packet::parse(&replies[0]).unwrap();
        assert_eq!(pkt.ip.v4_src(), Some(VirtualResolverEndpoint::IP));
        let msg = Message::from_bytes(pkt.l4_payload()).unwrap();
        assert_eq!(
            msg.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(!msg.answers.is_empty());
    }

    #[tokio::test]
    async fn udp_unknown_external_is_not_authoritative() {
        let dns = engine().await;
        let q = query_bytes("example.com.", 8);
        let raw = udp_query(Ipv4Addr::new(10, 21, 0, 2), 53000, &q);
        let replies = dns.handle(&raw).await;
        let pkt = packet::parse(&replies[0]).unwrap();
        let msg = Message::from_bytes(pkt.l4_payload()).unwrap();
        assert!(!msg.metadata.authoritative);
    }

    #[tokio::test]
    async fn malformed_udp_is_formerr_or_empty() {
        let dns = engine().await;
        let raw = udp_query(Ipv4Addr::new(10, 21, 0, 2), 53000, &[0xff; 4]);
        let replies = dns.handle(&raw).await;
        if replies.is_empty() {
            return;
        }
        let pkt = packet::parse(&replies[0]).unwrap();
        let payload = pkt.l4_payload();
        if payload.is_empty() {
            return;
        }
        let msg = Message::from_bytes(payload).unwrap();
        assert_eq!(
            msg.metadata.response_code,
            hickory_proto::op::ResponseCode::FormErr
        );
    }

    #[tokio::test]
    async fn tcp_query_response() {
        let dns = engine().await;
        let client = Ipv4Addr::new(10, 21, 0, 2);
        let syn = tcp_segment(client, 41000, 100, 0, true, false, &[]);
        let synack = dns.handle(&syn).await;
        assert_eq!(synack.len(), 1);
        let q = query_bytes("laptop.home.tunnet.", 3);
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        let data = tcp_segment(client, 41000, 101, 2, false, false, &framed);
        let replies = dns.handle(&data).await;
        assert!(!replies.is_empty());
        let pkt = packet::parse(replies.last().unwrap()).unwrap();
        let payload = pkt.l4_payload();
        assert!(payload.len() >= 2);
        let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let msg = Message::from_bytes(&payload[2..2 + len]).unwrap();
        assert_eq!(
            msg.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
    }

    #[tokio::test]
    async fn empty_table_mesh_name_is_nxdomain() {
        let resolver = Resolver::new(RoutingTable::new(), &DnsConfig::default()).unwrap();
        let dns = InTun::new(resolver);
        let q = query_bytes("nobody.tunnet.", 1);
        let raw = udp_query(Ipv4Addr::new(10, 0, 0, 1), 1, &q);
        let replies = dns.handle(&raw).await;
        let pkt = packet::parse(&replies[0]).unwrap();
        let msg = Message::from_bytes(pkt.l4_payload()).unwrap();
        assert_eq!(
            msg.metadata.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
    }

    #[tokio::test]
    async fn non_dns_packet_yields_no_reply() {
        let dns = engine().await;
        let b = PacketBuilder::ipv4([10, 21, 0, 2], [10, 21, 0, 3], 64).udp(9, 9);
        let mut out = Vec::new();
        b.write(&mut out, &[1]).unwrap();
        assert!(dns.handle(&out).await.is_empty());
    }

    #[test]
    fn udp_truncation_sets_tc() {
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.truncation = false;
        for i in 0..40 {
            msg.add_answer(hickory_proto::rr::Record::from_rdata(
                Name::from_str("desktop.tunnet.").unwrap(),
                30,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(
                    10, 0, 0, i,
                ))),
            ));
        }
        let bytes = msg.to_bytes().unwrap();
        assert!(bytes.len() > 80);
        let out = crate::dns::truncate_udp(bytes, 80);
        let parsed = Message::from_bytes(&out).unwrap();
        assert!(parsed.metadata.truncation);
        assert!(out.len() <= 80);
    }

    #[tokio::test]
    async fn process_query_matches_engine() {
        let table = table_two_networks();
        let cfg = DnsConfig::default();
        let resolver = Resolver::new(table.clone(), &cfg).unwrap();
        let q = query_bytes("desktop.office.tunnet.", 4);
        let via_engine = resolver.answer(&q).await;
        struct NoLookup;
        impl ExternalLookup for NoLookup {
            fn lookup(
                &self,
                _name: Name,
                _qtype: RecordType,
            ) -> crate::dns::upstream::ExtLookupFut<'_> {
                Box::pin(async { crate::dns::upstream::ExternalAnswer::ServFail })
            }
        }
        let direct = process_query(&q, &table, "tunnet", &NoLookup).await;
        let a = Message::from_bytes(&via_engine).unwrap();
        let b = Message::from_bytes(&direct).unwrap();
        assert_eq!(a.metadata.response_code, b.metadata.response_code);
        assert_eq!(a.answers.len(), b.answers.len());
        let _ = HickoryLookup::from_dns_config(&cfg);
    }

    #[tokio::test]
    async fn membership_change_is_visible_without_restarting_transport() {
        let table = RoutingTable::new();
        let resolver = Resolver::new(table.clone(), &DnsConfig::default()).unwrap();
        let dns = InTun::new(resolver);
        let q = query_bytes("laptop.home.tunnet.", 1);
        let raw = udp_query(Ipv4Addr::new(10, 22, 0, 3), 53000, &q);
        let before = Message::from_bytes(
            packet::parse(&dns.handle(&raw).await[0])
                .unwrap()
                .l4_payload(),
        )
        .unwrap();
        assert_eq!(
            before.metadata.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );

        let home_self = "b".repeat(64);
        table.replace_network(
            Uuid::from_u128(2),
            &[peer(&home_self, "10.22.0.3", "laptop")],
            &DnsConfig::default(),
            "home",
            &home_self,
            2,
        );

        let after = Message::from_bytes(
            packet::parse(&dns.handle(&raw).await[0])
                .unwrap()
                .l4_payload(),
        )
        .unwrap();
        assert_eq!(
            after.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
    }

    #[tokio::test]
    async fn new_in_tun_instance_does_not_keep_tcp_state() {
        let dns = engine().await;
        let client = Ipv4Addr::new(10, 21, 0, 2);
        let syn = tcp_segment(client, 41001, 100, 0, true, false, &[]);
        assert_eq!(dns.handle(&syn).await.len(), 1);
        drop(dns);

        let dns = engine().await;
        let q = query_bytes("desktop.office.tunnet.", 9);
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        let data = tcp_segment(client, 41001, 101, 2, false, false, &framed);
        let replies = dns.handle(&data).await;
        assert_eq!(replies.len(), 1);
        let payload = packet::parse(&replies[0]).unwrap().l4_payload();
        assert!(
            payload.is_empty(),
            "stale TCP data after dataplane restart must RST, not answer DNS"
        );
    }
}
