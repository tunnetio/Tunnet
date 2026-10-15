use etherparse::{Ipv4Header, PacketBuilder, TcpHeader, TcpOptionElement};

use super::*;
use crate::policy::Protocol;

fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64)
        .tcp(sport, dport, 1, 64240)
        .syn();
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

#[test]
fn parses_tcp_syn() {
    let p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, &[]);
    let pkt = parse(&p).unwrap();
    assert_eq!(pkt.wire_len, p.len());
    assert_eq!(pkt.policy_protocol(), Protocol::Tcp);
    assert_eq!(pkt.transport.src_port(), Some(12345));
    assert_eq!(pkt.transport.dst_port(), Some(80));
    assert!(pkt.transport.tcp_flags().unwrap().syn());
    assert!(!pkt.fragmentation.is_later());
}

#[test]
fn parses_tcp_with_payload_and_options() {
    let mut tcp = TcpHeader::new(40000, 443, 9, 1000);
    tcp.syn = true;
    tcp.set_options(&[TcpOptionElement::MaximumSegmentSize(1460)])
        .unwrap();
    let mut ip = Ipv4Header::new(
        (tcp.header_len() + 4) as u16,
        64,
        etherparse::IpNumber::TCP,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap();
    ip.header_checksum = ip.calc_header_checksum();
    let payload = b"abcd";
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();
    let mut buf = Vec::new();
    ip.write(&mut buf).unwrap();
    tcp.write(&mut buf).unwrap();
    buf.extend_from_slice(payload);
    let pkt = parse(&buf).unwrap();
    match pkt.transport {
        Transport::Tcp {
            header_len,
            payload_len,
            ..
        } => {
            assert!(header_len > 20);
            assert_eq!(payload_len, 4);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn parses_udp_and_icmp() {
    let udp = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 53000, 53, b"dns");
    let pkt = parse(&udp).unwrap();
    assert_eq!(pkt.policy_protocol(), Protocol::Udp);
    assert_eq!(pkt.transport.dst_port(), Some(53));
    assert_eq!(pkt.transport.l4_payload_len(), 3);

    let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).icmpv4_echo_request(7, 9);
    let mut icmp = Vec::new();
    b.write(&mut icmp, b"hi").unwrap();
    let pkt = parse(&icmp).unwrap();
    match pkt.transport {
        Transport::Icmpv4 {
            echo_id, echo_seq, ..
        } => {
            assert_eq!(echo_id, Some(7));
            assert_eq!(echo_seq, Some(9));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn unknown_protocol_is_other_not_any() {
    let mut ip =
        Ipv4Header::new(0, 64, etherparse::IpNumber(47), [1, 1, 1, 1], [2, 2, 2, 2]).unwrap();
    ip.header_checksum = ip.calc_header_checksum();
    let mut buf = Vec::new();
    ip.write(&mut buf).unwrap();
    let pkt = parse(&buf).unwrap();
    assert_eq!(pkt.policy_protocol(), Protocol::Other(47));
    assert_ne!(pkt.policy_protocol(), Protocol::Any);
}

#[test]
fn trailing_bytes_ignored_for_wire_len() {
    let mut p = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"xy");
    let wire = p.len();
    p.extend_from_slice(&[0u8; 64]);
    let pkt = parse(&p).unwrap();
    assert_eq!(pkt.wire_len, wire);
    assert_eq!(pkt.transport.l4_payload_len(), 2);
}

#[test]
fn truncated_and_bad_version() {
    assert!(matches!(
        parse(&[0x45, 0, 0, 20]),
        Err(ParseError::Truncated) | Err(ParseError::InvalidTotalLength)
    ));
    assert!(matches!(
        parse(&[0x55; 20]),
        Err(ParseError::UnsupportedVersion(5))
    ));
}

#[test]
fn malformed_ihl() {
    let mut p = ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, &[]);
    p[0] = 0x44; // ihl=4
    assert!(matches!(
        parse(&p),
        Err(ParseError::InvalidIhl) | Err(ParseError::InvalidIpHeader)
    ));
}

#[test]
fn later_fragment_is_not_tcp_ports() {
    let mut p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 22, 22, &[]);
    // set MF=0, offset=8 (64 bytes) in IPv4 header bytes 6-7
    p[6] &= 0xe0;
    p[7] = 8;
    // payload after IP looks like ports 22/22 but must be LaterFragment
    let pkt = parse(&p).unwrap();
    assert!(pkt.transport.is_later_fragment());
    assert_eq!(pkt.transport.src_port(), None);
    assert_eq!(pkt.transport.dst_port(), None);
}

#[test]
fn first_fragment_keeps_tcp() {
    let mut p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, &[]);
    p[6] |= 0x20; // MF
    let pkt = parse(&p).unwrap();
    assert!(matches!(pkt.fragmentation, Fragmentation::First { .. }));
    assert_eq!(pkt.transport.dst_port(), Some(80));
}

#[test]
fn fragment_key_distinguishes_identity() {
    let mut first = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, &[]);
    first[6] |= 0x20;
    first[4..6].copy_from_slice(&1u16.to_be_bytes());
    let pkt = parse(&first).unwrap();
    let key = frag_key(&pkt).unwrap();

    let mut later = first.clone();
    later[6] = 0;
    later[7] = 8;
    let later_pkt = parse(&later).unwrap();
    assert!(later_pkt.transport.is_later_fragment());
    assert_eq!(frag_key(&later_pkt).unwrap(), key);

    let mut orphan = first.clone();
    orphan[4..6].copy_from_slice(&99u16.to_be_bytes());
    orphan[6] = 0;
    orphan[7] = 8;
    let orphan_pkt = parse(&orphan).unwrap();
    assert_ne!(frag_key(&orphan_pkt).unwrap(), key);
}

#[test]
fn mss_clamp_rewrites_syn_option() {
    let mut p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, &[]);
    p[33] |= 0x02;
    p.splice(40..40, [2, 4, 0x05, 0xb4]);
    p[20 + 12] = (p[20 + 12] & 0x0f) | 0x60;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    assert!(clamp_tcp_mss(&mut p, 1104));
    assert_eq!(&p[42..44], &1104u16.to_be_bytes());
    let parsed = parse(&p).unwrap();
    match parsed.transport {
        Transport::Tcp { dst_port, .. } => assert_eq!(dst_port, 80),
        other => panic!("{other:?}"),
    }
    assert!(tcp_ipv4_checksum_of(&p).is_some());
}

#[test]
fn mss_clamp_leaves_small_mss_and_non_syn() {
    let mut p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, &[]);
    p[33] |= 0x02;
    p.splice(40..40, [2, 4, 0x02, 0x18]);
    p[20 + 12] = (p[20 + 12] & 0x0f) | 0x60;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    assert!(!clamp_tcp_mss(&mut p, 1104));
    p[33] &= !0x02;
    assert!(!clamp_tcp_mss(&mut p, 100));
}

#[test]
fn frag_needed_quotes_header_and_mtu() {
    let p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, &[0u8; 100]);
    let reply = synthesize_frag_needed(&p, 1222).unwrap();
    let parsed = parse(&reply).unwrap();
    assert_eq!(parsed.ip.v4_src().unwrap().to_string(), "10.0.0.2");
    assert_eq!(parsed.ip.v4_dst().unwrap().to_string(), "10.0.0.1");
    match parsed.transport {
        Transport::Icmpv4 { type_u8, code, .. } => {
            assert_eq!((type_u8, code), (3, 4));
        }
        other => panic!("{other:?}"),
    }
    assert!(reply.len() > 28);
}

#[test]
fn reject_rst_checksum_valid() {
    let p = ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 9999, 22, &[]);
    let pkt = parse(&p).unwrap();
    let reply = synthesize_reject(&pkt).unwrap();
    let parsed = parse(&reply).unwrap();
    match parsed.transport {
        Transport::Tcp { flags, .. } => assert!(flags.rst() && flags.ack()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn protocol_any_is_not_unknown() {
    assert_ne!(Protocol::from_ip_number(47), Protocol::Any);
    assert!(Protocol::Tcp.matches_rule(Some(Protocol::Any)));
    assert!(!Protocol::Other(47).matches_rule(Some(Protocol::Tcp)));
}
