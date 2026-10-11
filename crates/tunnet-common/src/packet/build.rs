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

/// ICMP Fragmentation Needed for a raw IPv4 packet that exceeds the path MTU.
/// Operates on raw bytes so the TUN loop can answer without a second parse.
pub fn synthesize_frag_needed(raw: &[u8], next_hop_mtu: u16) -> Option<Bytes> {
    let (ip, _) = Ipv4Header::from_slice(raw).ok()?;
    let src = std::net::Ipv4Addr::from(ip.source);
    let dst = std::net::Ipv4Addr::from(ip.destination);
    if src.is_unspecified() || dst.is_unspecified() {
        return None;
    }
    let header_len = usize::from(ip.ihl()) * 4;
    let copy_len = raw.len().min(header_len + 8).min(28);
    let quoted = &raw[..copy_len];
    let builder = PacketBuilder::ipv4(dst.octets(), src.octets(), 64).icmpv4(
        Icmpv4Type::DestinationUnreachable(
            etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu },
        ),
    );
    let mut out = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut out, quoted).ok()?;
    Some(Bytes::from(out))
}

/// Clamp the TCP MSS option on SYN packets to `max_mss`, in place.
/// Returns true when an MSS option was present and rewritten.
pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    let header_len = match packet.first() {
        Some(b) if b >> 4 == 4 => usize::from(b & 0x0f) * 4,
        _ => return false,
    };
    if packet.len() < header_len + TcpHeader::MIN_LEN || packet[9] != 6 {
        return false;
    }
    let tcp = &packet[header_len..];
    if tcp[13] & 0x02 == 0 {
        return false;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset <= TcpHeader::MIN_LEN || packet.len() < header_len + data_offset {
        return false;
    }
    let mut i = header_len + TcpHeader::MIN_LEN;
    let end = header_len + data_offset;
    while i < end {
        match packet[i] {
            0 => break,
            1 => i += 1,
            2 => {
                if i + 4 > end || packet[i + 1] != 4 {
                    return false;
                }
                let current = u16::from_be_bytes([packet[i + 2], packet[i + 3]]);
                if current <= max_mss {
                    return false;
                }
                packet[i + 2..i + 4].copy_from_slice(&max_mss.to_be_bytes());
                return set_tcp_ipv4_checksum(packet, header_len);
            }
            _ => {
                let len = usize::from(packet[i + 1]);
                if len < 2 || i + len > end {
                    return false;
                }
                i += len;
            }
        }
    }
    false
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
