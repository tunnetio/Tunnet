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
    let p = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, &[0u8; 1400]);
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

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn mss_checksum_and_malformed_option_boundaries(#[case] odd: bool) {
    let mut tcp = TcpHeader::new(40000, 443, 9, 1000);
    tcp.syn = true;
    let options = if odd {
        vec![
            TcpOptionElement::Noop,
            TcpOptionElement::MaximumSegmentSize(1460),
        ]
    } else {
        vec![TcpOptionElement::MaximumSegmentSize(1460)]
    };
    tcp.set_options(&options).unwrap();
    let ip = Ipv4Header::new(
        tcp.header_len() as u16,
        64,
        etherparse::IpNumber::TCP,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap();
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, &[]).unwrap();
    let mut raw = Vec::new();
    ip.write(&mut raw).unwrap();
    tcp.write(&mut raw).unwrap();
    assert!(clamp_tcp_mss(&mut raw, 1104));
    assert_eq!(
        u16::from_be_bytes([raw[36], raw[37]]),
        tcp_ipv4_checksum_of(&raw).unwrap()
    );
    let mut malformed = raw.clone();
    let end = malformed.len();
    malformed[40..end].fill(1);
    malformed[end - 1] = 30;
    let original = malformed.clone();
    assert!(!clamp_tcp_mss(&mut malformed, 1000));
    assert_eq!(malformed, original);
    for length in 0..raw.len() {
        assert!(!clamp_tcp_mss(&mut raw[..length].to_vec(), 1000));
    }
    raw[6] |= 0x20;
    let original = raw.clone();
    assert!(!clamp_tcp_mss(&mut raw, 1000));
    assert_eq!(raw, original);
}

#[rstest::rstest]
#[case(6)]
#[case(17)]
fn first_fragment_requires_transport_header(#[case] protocol: u8) {
    let mut raw = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, &[0; 32]);
    raw[6] |= 0x20;
    raw.truncate(36);
    raw[2..4].copy_from_slice(&36u16.to_be_bytes());
    assert_eq!(parse(&raw).unwrap().transport.dst_port(), Some(53));
    raw[9] = protocol;
    raw.truncate(24);
    raw[2..4].copy_from_slice(&24u16.to_be_bytes());
    assert_eq!(
        parse(&raw).unwrap_err(),
        if protocol == 6 {
            ParseError::MalformedTcp
        } else {
            ParseError::MalformedUdp
        }
    );
}

#[rstest::rstest]
#[case(false, false, 6)]
#[case(false, true, 7)]
#[case(true, false, 777)]
fn reject_tcp_sequence_and_checksum(#[case] ack: bool, #[case] fin: bool, #[case] expected: u32) {
    let mut raw = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, b"four");
    raw[33] = if ack { TcpFlags::ACK } else { TcpFlags::SYN } | if fin { TcpFlags::FIN } else { 0 };
    raw[28..32].copy_from_slice(&777u32.to_be_bytes());
    let reply = synthesize_reject(&parse(&raw).unwrap()).unwrap();
    let packet = parse(&reply).unwrap();
    match packet.transport {
        Transport::Tcp {
            flags,
            seq,
            ack: acknowledgement,
            src_port,
            dst_port,
            ..
        } => {
            assert!(flags.rst());
            assert_eq!(flags.ack(), !ack);
            assert_eq!(if ack { seq } else { acknowledgement }, expected);
            assert_eq!((src_port, dst_port), (443, 1234));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        u16::from_be_bytes([reply[36], reply[37]]),
        tcp_ipv4_checksum_of(&reply).unwrap()
    );
    raw[33] = TcpFlags::RST;
    assert!(synthesize_reject(&parse(&raw).unwrap()).is_none());
}

#[rstest::rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
fn pmtu_error_suppression(#[case] invalid: u8) {
    let mut raw = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, &[0; 1400]);
    assert!(synthesize_frag_needed(&raw, 1200).is_some());
    match invalid {
        0 => raw[6] = 0,
        1 => raw[7] = 1,
        2 => raw[16..20].copy_from_slice(&[224, 0, 0, 1]),
        3 => {
            raw[9] = 1;
            raw[20] = 3;
        }
        _ => raw[2..4].copy_from_slice(&1500u16.to_be_bytes()),
    }
    assert!(synthesize_frag_needed(&raw, 1200).is_none());
}

#[test]
fn pmtu_quotes_ipv4_options_and_transport() {
    let mut raw = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, &[0; 1400]);
    raw.splice(20..20, [1, 1, 1, 0]);
    raw[0] = 0x46;
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_be_bytes());
    let reply = synthesize_frag_needed(&raw, 1200).unwrap();
    assert_eq!(&reply[28..], &raw[..32]);
}

#[test]
fn fragmentation_preserves_payload_offsets_options_and_tcp_checksum() {
    let mut raw = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 30022, 443, &[42; 1400]);
    raw[6] = 0;
    raw.splice(20..20, [0x82, 4, 9, 8, 0x44, 4, 7, 6]);
    raw[0] = 0x47;
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_be_bytes());
    assert!(set_tcp_ipv4_checksum(&mut raw, 28));
    let mut fragments = fragment_ipv4(&raw, 576).unwrap();
    assert_eq!(fragments.len(), 3);
    let mut payload = Vec::new();
    for (index, fragment) in fragments.iter().enumerate() {
        let (ip, bytes) = Ipv4Header::from_slice(fragment).unwrap();
        assert!(fragment.len() <= 576);
        assert_eq!(usize::from(ip.fragment_offset.value()) * 8, payload.len());
        assert_eq!(ip.more_fragments, index < 2);
        assert_eq!(ip.header_checksum, ip.calc_header_checksum());
        assert_eq!(
            ip.options.as_slice(),
            if index == 0 {
                &[0x82, 4, 9, 8, 0x44, 4, 7, 6][..]
            } else {
                &[0x82, 4, 9, 8][..]
            }
        );
        payload.extend_from_slice(bytes);
    }
    assert_eq!(payload, &raw[28..]);
    let first = fragments.remove(0);
    let mut first = first.to_vec();
    assert!(rewrite_tcp_port(&mut first, 28, 28, 22));
    raw[28..30].copy_from_slice(&22u16.to_be_bytes());
    assert!(set_tcp_ipv4_checksum(&mut raw, 28));
    assert_eq!(&first[44..46], &raw[44..46]);
    let split_again = fragment_ipv4(&fragments[0], 304).unwrap();
    assert_eq!(split_again.len(), 2);
    let (first_again, _) = Ipv4Header::from_slice(&split_again[0]).unwrap();
    let (last_again, _) = Ipv4Header::from_slice(&split_again[1]).unwrap();
    assert_eq!(first_again.fragment_offset.value(), 68);
    assert!(last_again.more_fragments);
    raw[6] = 0x40;
    assert!(fragment_ipv4(&raw, 576).is_none());
}
