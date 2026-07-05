//! Minimal packet parsing. We look at the IPv4 header for src/dst and,
//! for TCP/UDP, peek at the destination port for ACL evaluation.

use std::net::Ipv4Addr;

use tuntun_common::policy::Protocol;

pub struct ParsedIpv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: Protocol,
    pub dst_port: Option<u16>,
}

#[inline]
pub fn parse_ipv4(packet: &[u8]) -> Option<ParsedIpv4> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
    let proto_byte = packet[9];
    let (protocol, dst_port) = match proto_byte {
        6 if packet.len() >= ihl + 4 => (
            Protocol::Tcp,
            Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]])),
        ),
        17 if packet.len() >= ihl + 4 => (
            Protocol::Udp,
            Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]])),
        ),
        1 => (Protocol::Icmp, None),
        _ => (Protocol::Any, None),
    };
    Some(ParsedIpv4 {
        src,
        dst,
        protocol,
        dst_port,
    })
}
