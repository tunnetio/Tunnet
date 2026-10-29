use bytes::Bytes;
use etherparse::{Icmpv4Type, Ipv4Header, PacketBuilder, TcpHeader};

use super::{Packet, TcpFlags, Transport};

/// TCP RST or ICMP Destination Unreachable for the original packet's source.
pub fn synthesize_reject(packet: &Packet<'_>) -> Option<Bytes> {
    match packet.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            flags,
            seq,
            ack,
            ..
        } => synthesize_tcp_rst(packet, src_port, dst_port, flags, seq, ack),
        Transport::Udp { .. } | Transport::Icmpv4 { .. } => synthesize_icmp_unreach(packet),
        _ => None,
    }
}

fn ipv4_addrs(packet: &Packet<'_>) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    Some((packet.ip.v4_src()?, packet.ip.v4_dst()?))
}

fn synthesize_tcp_rst(
    packet: &Packet<'_>,
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

fn synthesize_icmp_unreach(packet: &Packet<'_>) -> Option<Bytes> {
    let (orig_src, orig_dst) = ipv4_addrs(packet)?;
    let code = if matches!(packet.transport, Transport::Udp { .. }) {
        etherparse::icmpv4::DestUnreachableHeader::Port
    } else {
        etherparse::icmpv4::DestUnreachableHeader::HostProhibited
    };
    let copy_len = packet.raw.len().min(packet.ip.header_len() + 8).min(28);
    let quoted = &packet.raw[..copy_len];
    let builder = PacketBuilder::ipv4(orig_dst.octets(), orig_src.octets(), 64)
        .icmpv4(Icmpv4Type::DestinationUnreachable(code));
    let mut out = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut out, quoted).ok()?;
    Some(Bytes::from(out))
}

/// ICMPv4 "fragmentation needed" telling the sender of `packet` to fit `mtu`.
///
/// `None` unless `packet` is an IPv4 datagram with DF set that is not itself an
/// ICMP error: without DF the sender would not act on it, and RFC 1122 forbids
/// answering an ICMP error with another.
pub fn synthesize_frag_needed(packet: &[u8], mtu: u16) -> Option<Bytes> {
    let ip = etherparse::Ipv4HeaderSlice::from_slice(packet).ok()?;
    if !ip.dont_fragment() {
        return None;
    }
    let header_len = ip.slice().len();
    if ip.protocol() == etherparse::IpNumber::ICMP {
        let icmp_type = *packet.get(header_len)?;
        if !matches!(icmp_type, 0 | 8 | 13 | 14) {
            return None;
        }
    }
    // The quoted header plus 8 bytes is what the sender needs to find the socket.
    let quoted = &packet[..packet.len().min(header_len + 8)];
    let builder = PacketBuilder::ipv4(ip.destination(), ip.source(), 64).icmpv4(
        Icmpv4Type::DestinationUnreachable(
            etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu },
        ),
    );
    let mut out = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut out, quoted).ok()?;
    Some(Bytes::from(out))
}

/// Recompute IPv4 + TCP checksums after an in-place TCP port rewrite.
pub fn set_tcp_ipv4_checksum(packet: &mut [u8], ip_header_len: usize) -> bool {
    if packet.len() < ip_header_len + TcpHeader::MIN_LEN {
        return false;
    }
    let Ok(mut ip) = Ipv4Header::from_slice(&packet[..ip_header_len]).map(|(h, _)| h) else {
        return false;
    };
    let rest = &packet[ip_header_len..];
    let Ok((mut tcp, payload)) = TcpHeader::from_slice(rest) else {
        return false;
    };
    tcp.checksum = match tcp.calc_checksum_ipv4(&ip, payload) {
        Ok(c) => c,
        Err(_) => return false,
    };
    ip.header_checksum = ip.calc_header_checksum();
    let mut ip_bytes = Vec::with_capacity(ip.header_len());
    if ip.write(&mut ip_bytes).is_err() {
        return false;
    }
    packet[..ip_bytes.len()].copy_from_slice(&ip_bytes);
    let mut tcp_bytes = Vec::with_capacity(tcp.header_len());
    if tcp.write(&mut tcp_bytes).is_err() {
        return false;
    }
    packet[ip_header_len..ip_header_len + tcp_bytes.len()].copy_from_slice(&tcp_bytes);
    true
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
