use bytes::Bytes;
use etherparse::{Icmpv4Type, Ipv4Header, PacketBuilder, TcpHeader};

use super::{PacketMeta, TcpFlags, Transport};

/// TCP RST or ICMP Destination Unreachable for the original packet's source.
pub fn synthesize_reject(packet: &PacketMeta, raw: &[u8]) -> Option<Bytes> {
    match packet.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            flags,
            seq,
            ack,
            ..
        } => synthesize_tcp_rst(packet, src_port, dst_port, flags, seq, ack),
        Transport::Udp { .. } | Transport::Icmpv4 { .. } => synthesize_icmp_unreach(packet, raw),
        _ => None,
    }
}

fn ipv4_addrs(packet: &PacketMeta) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    Some((packet.src_v4?, packet.dst_v4?))
}

fn synthesize_tcp_rst(
    packet: &PacketMeta,
    src_port: u16,
    dst_port: u16,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
) -> Option<Bytes> {
    let (orig_src, orig_dst) = ipv4_addrs(packet)?;
    let new_seq = if flags.ack() { ack } else { 0 };
    let new_ack = seq.wrapping_add(1);
    let builder = PacketBuilder::ipv4(orig_dst.octets(), orig_src.octets(), 64)
        .tcp(dst_port, src_port, new_seq, 0)
        .rst()
        .ack(new_ack);
    let mut out = Vec::with_capacity(builder.size(0));
    builder.write(&mut out, &[]).ok()?;
    Some(Bytes::from(out))
}

fn synthesize_icmp_unreach(packet: &PacketMeta, raw: &[u8]) -> Option<Bytes> {
    let (orig_src, orig_dst) = ipv4_addrs(packet)?;
    let code = if matches!(packet.transport, Transport::Udp { .. }) {
        etherparse::icmpv4::DestUnreachableHeader::Port
    } else {
        etherparse::icmpv4::DestUnreachableHeader::HostProhibited
    };
    let copy_len = raw.len().min(packet.ip_header_len + 8);
    let quoted = &raw[..copy_len];
    let builder = PacketBuilder::ipv4(orig_dst.octets(), orig_src.octets(), 64)
        .icmpv4(Icmpv4Type::DestinationUnreachable(code));
    let mut out = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut out, quoted).ok()?;
    Some(Bytes::from(out))
}

/// Full IPv4 TCP checksum of `packet` (for tests vs incremental updates).
pub fn tcp_ipv4_checksum_of(packet: &[u8]) -> Option<u16> {
    let ip_hdr_len = usize::from(packet.first().map(|b| b & 0x0f).unwrap_or(0)) * 4;
    if packet.len() < ip_hdr_len + TcpHeader::MIN_LEN {
        return None;
    }
    let (ip, _) = Ipv4Header::from_slice(&packet[..ip_hdr_len]).ok()?;
    let (tcp, payload) = TcpHeader::from_slice(&packet[ip_hdr_len..]).ok()?;
    tcp.calc_checksum_ipv4(&ip, payload).ok()
}
