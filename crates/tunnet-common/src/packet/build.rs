use bytes::Bytes;
use etherparse::{Icmpv4Type, Ipv4Header, PacketBuilder, TcpHeader};

use super::{Packet, Transport};

pub fn synthesize_reject(packet: &Packet<'_>) -> Option<Bytes> {
    if !matches!(packet.fragmentation, super::Fragmentation::None)
        || !reply_addresses_valid(packet.raw)
    {
        return None;
    }
    match packet.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            flags,
            seq,
            ack,
            payload_len,
            ..
        } => {
            if flags.rst() {
                return None;
            }
            let (src, dst) = ipv4_addrs(packet)?;
            let builder = PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                .tcp(dst_port, src_port, if flags.ack() { ack } else { 0 }, 0)
                .rst();
            let builder = if flags.ack() {
                builder
            } else {
                builder.ack(
                    seq.wrapping_add(payload_len as u32)
                        .wrapping_add(u32::from(flags.syn()))
                        .wrapping_add(u32::from(flags.fin())),
                )
            };
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).ok()?;
            Some(Bytes::from(out))
        }
        Transport::Udp { .. } | Transport::Icmpv4 { .. } => synthesize_icmp_unreach(packet),
        _ => None,
    }
}

fn ipv4_addrs(packet: &Packet<'_>) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    Some((packet.ip.v4_src()?, packet.ip.v4_dst()?))
}

fn valid_ipv4(raw: &[u8]) -> Option<Ipv4Header> {
    let (ip, _) = Ipv4Header::from_slice(raw).ok()?;
    if usize::from(ip.total_len) != raw.len() || raw.len() < ip.header_len() {
        return None;
    }
    Some(ip)
}

fn unicast(addr: std::net::Ipv4Addr) -> bool {
    let first = addr.octets()[0];
    first != 0 && first < 224 && !addr.is_loopback() && !addr.is_broadcast()
}

fn reply_addresses_valid(raw: &[u8]) -> bool {
    valid_ipv4(raw).is_some_and(|ip| unicast(ip.source.into()) && unicast(ip.destination.into()))
}

fn icmp_error_allowed(raw: &[u8]) -> bool {
    let Some(ip) = valid_ipv4(raw) else {
        return false;
    };
    if !reply_addresses_valid(raw) || ip.fragment_offset.value() != 0 {
        return false;
    }
    if u8::from(ip.protocol) == 1 {
        return raw
            .get(ip.header_len())
            .is_some_and(|kind| !matches!(kind, 3 | 4 | 5 | 11 | 12));
    }
    true
}

fn synthesize_icmp_unreach(packet: &Packet<'_>) -> Option<Bytes> {
    if !icmp_error_allowed(packet.raw) {
        return None;
    }
    let (src, dst) = ipv4_addrs(packet)?;
    let code = if matches!(packet.transport, Transport::Udp { .. }) {
        etherparse::icmpv4::DestUnreachableHeader::Port
    } else {
        etherparse::icmpv4::DestUnreachableHeader::HostProhibited
    };
    icmp_response(packet.raw, src, dst, code)
}

fn icmp_response(
    raw: &[u8],
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    code: etherparse::icmpv4::DestUnreachableHeader,
) -> Option<Bytes> {
    let ip = valid_ipv4(raw)?;
    let quoted = &raw[..raw.len().min(ip.header_len() + 8)];
    let builder = PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
        .icmpv4(Icmpv4Type::DestinationUnreachable(code));
    let mut out = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut out, quoted).ok()?;
    Some(Bytes::from(out))
}

pub fn synthesize_frag_needed(raw: &[u8], next_hop_mtu: u16) -> Option<Bytes> {
    let ip = valid_ipv4(raw)?;
    super::parse(raw).ok()?;
    if !icmp_error_allowed(raw)
        || !ip.dont_fragment
        || next_hop_mtu < 68
        || raw.len() <= usize::from(next_hop_mtu)
    {
        return None;
    }
    icmp_response(
        raw,
        ip.source.into(),
        ip.destination.into(),
        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu },
    )
}

pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    let Some(ip) = valid_ipv4(packet) else {
        return false;
    };
    if u8::from(ip.protocol) != 6 || ip.is_fragmenting_payload() {
        return false;
    }
    let header_len = ip.header_len();
    let Ok(tcp) = etherparse::TcpHeaderSlice::from_slice(&packet[header_len..]) else {
        return false;
    };
    if !tcp.syn() {
        return false;
    }
    let mut i = header_len + TcpHeader::MIN_LEN;
    let end = header_len + tcp.slice().len();
    let mut mss = None;
    while i < end {
        match packet[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&length) = packet.get(i + 1).filter(|_| i + 1 < end) else {
                    return false;
                };
                let length = usize::from(length);
                if length < 2 || i + length > end {
                    return false;
                }
                if kind == 2 {
                    if length != 4 || mss.is_some() {
                        return false;
                    }
                    mss = Some(i + 2);
                }
                i += length;
            }
        }
    }
    let Some(offset) = mss else {
        return false;
    };
    let current = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    if current <= max_mss {
        return false;
    }
    let checksum = u16::from_be_bytes([packet[header_len + 16], packet[header_len + 17]]);
    let (old_word, new_word) = if (offset - header_len).is_multiple_of(2) {
        (current, max_mss)
    } else {
        (current.swap_bytes(), max_mss.swap_bytes())
    };
    let checksum = replace_checksum_word(checksum, old_word, new_word);
    packet[offset..offset + 2].copy_from_slice(&max_mss.to_be_bytes());
    packet[header_len + 16..header_len + 18].copy_from_slice(&checksum.to_be_bytes());
    true
}

pub fn rewrite_tcp_port(
    packet: &mut [u8],
    ip_header_len: usize,
    port_offset: usize,
    port: u16,
) -> bool {
    let Some(ip) = valid_ipv4(packet) else {
        return false;
    };
    if ip.header_len() != ip_header_len
        || u8::from(ip.protocol) != 6
        || ip.fragment_offset.value() != 0
        || (port_offset != ip_header_len && port_offset != ip_header_len + 2)
        || etherparse::TcpHeaderSlice::from_slice(&packet[ip_header_len..]).is_err()
    {
        return false;
    }
    let old = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
    let checksum_offset = ip_header_len + 16;
    let checksum = u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
    packet[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
    packet[checksum_offset..checksum_offset + 2]
        .copy_from_slice(&replace_checksum_word(checksum, old, port).to_be_bytes());
    true
}

fn replace_checksum_word(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn fragment_ipv4(raw: &[u8], mtu: u16) -> Option<Vec<Bytes>> {
    let ip = valid_ipv4(raw)?;
    if mtu < 68 || ip.dont_fragment || !reply_addresses_valid(raw) {
        return None;
    }
    let payload = &raw[ip.header_len()..];
    if payload.is_empty()
        || (ip.more_fragments && !payload.len().is_multiple_of(8))
        || usize::from(ip.fragment_offset.value()) * 8 + payload.len() > 65535
    {
        return None;
    }
    let copied = copied_options(ip.options.as_slice())?;
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let mut header = ip.clone();
        if offset > 0 || ip.fragment_offset.value() != 0 {
            header.options = copied.as_slice().try_into().ok()?;
        }
        let room = usize::from(mtu).checked_sub(header.header_len())?;
        let remaining = payload.len() - offset;
        let take = if remaining > room {
            room / 8 * 8
        } else {
            remaining
        };
        if take == 0 {
            return None;
        }
        header.fragment_offset = etherparse::IpFragOffset::try_new(
            ip.fragment_offset
                .value()
                .checked_add((offset / 8) as u16)?,
        )
        .ok()?;
        header.more_fragments = offset + take < payload.len() || ip.more_fragments;
        header.total_len = u16::try_from(header.header_len() + take).ok()?;
        header.header_checksum = header.calc_header_checksum();
        let mut fragment = Vec::with_capacity(usize::from(header.total_len));
        header.write(&mut fragment).ok()?;
        fragment.extend_from_slice(&payload[offset..offset + take]);
        result.push(Bytes::from(fragment));
        offset += take;
    }
    Some(result)
}

fn copied_options(options: &[u8]) -> Option<Vec<u8>> {
    let mut copied = Vec::new();
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let length = usize::from(*options.get(offset + 1)?);
                if length < 2 || offset + length > options.len() {
                    return None;
                }
                if kind & 0x80 != 0 {
                    copied.extend_from_slice(&options[offset..offset + length]);
                }
                offset += length;
            }
        }
    }
    while !copied.len().is_multiple_of(4) {
        copied.push(0);
    }
    Some(copied)
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
