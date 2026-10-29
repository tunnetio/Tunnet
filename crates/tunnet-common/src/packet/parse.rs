use etherparse::{
    Icmpv4Type, IpPayloadSlice, Ipv4Slice, Ipv6ExtensionSlice, Ipv6Slice, NetSlice, SlicedPacket,
    TcpSlice, TransportSlice, UdpSlice,
    err::{Layer, ip, ipv4, ipv6, packet},
};

use super::{Fragmentation, IpMeta, Packet, TcpFlags, Transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    UnsupportedVersion(u8),
    InvalidIpHeader,
    InvalidIhl,
    InvalidTotalLength,
    MalformedTcp,
    MalformedUdp,
    MalformedTransport,
}

impl ParseError {
    pub fn drop_reason(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::UnsupportedVersion(_) => "unsupported_ip_version",
            Self::InvalidIpHeader => "malformed_ip",
            Self::InvalidIhl => "invalid_ihl",
            Self::InvalidTotalLength => "invalid_ip_len",
            Self::MalformedTcp => "malformed_tcp",
            Self::MalformedUdp => "malformed_udp",
            Self::MalformedTransport => "malformed_transport",
        }
    }
}

pub fn parse(data: &[u8]) -> Result<Packet<'_>, ParseError> {
    if data.is_empty() {
        return Err(ParseError::Truncated);
    }
    let version = data[0] >> 4;
    if version != 4 && version != 6 {
        return Err(ParseError::UnsupportedVersion(version));
    }

    let sliced = SlicedPacket::from_ip(data).map_err(map_slice_err)?;
    match sliced.net {
        Some(NetSlice::Ipv4(v4)) => parse_ipv4(data, &v4, sliced.transport),
        Some(NetSlice::Ipv6(v6)) => parse_ipv6(data, &v6, sliced.transport),
        _ => Err(ParseError::InvalidIpHeader),
    }
}

fn parse_ipv4<'a>(
    raw: &'a [u8],
    v4: &Ipv4Slice<'a>,
    transport: Option<TransportSlice<'a>>,
) -> Result<Packet<'a>, ParseError> {
    let header = v4.header();
    let payload = v4.payload();
    let wire_len = header.total_len() as usize;
    let identification = header.identification();
    let offset = header.fragments_offset().value();
    let more = header.more_fragments();
    let fragmentation = if offset == 0 && !more {
        Fragmentation::None
    } else if offset == 0 {
        Fragmentation::First {
            identification: u32::from(identification),
            more,
        }
    } else {
        Fragmentation::Later {
            identification: u32::from(identification),
            offset,
            more,
        }
    };

    let ip = IpMeta::V4 {
        src: header.source_addr(),
        dst: header.destination_addr(),
        protocol: u8::from(payload.ip_number),
        identification,
        header_len: usize::from(header.ihl()) * 4,
        ttl: header.ttl(),
    };

    let transport = if matches!(fragmentation, Fragmentation::Later { .. }) {
        Transport::LaterFragment {
            protocol: u8::from(payload.ip_number),
            identification: u32::from(identification),
            offset,
            more,
        }
    } else {
        decode_first_transport(payload, transport)?
    };

    Ok(Packet {
        raw: &raw[..wire_len],
        wire_len,
        ip,
        fragmentation,
        transport,
    })
}

fn parse_ipv6<'a>(
    raw: &'a [u8],
    v6: &Ipv6Slice<'a>,
    transport: Option<TransportSlice<'a>>,
) -> Result<Packet<'a>, ParseError> {
    let header = v6.header();
    let payload = v6.payload();
    let wire_len = usize::from(header.payload_length()) + etherparse::Ipv6Header::LEN;

    let mut frag_id = None;
    let mut frag_offset = 0u16;
    let mut frag_more = false;
    for ext in v6.extensions().clone() {
        if let Ipv6ExtensionSlice::Fragment(fh) = ext {
            frag_id = Some(fh.identification());
            frag_offset = fh.fragment_offset().value();
            frag_more = fh.more_fragments();
        }
    }

    let fragmentation = if !payload.fragmented {
        Fragmentation::None
    } else if frag_offset == 0 {
        Fragmentation::First {
            identification: frag_id.unwrap_or(0),
            more: frag_more,
        }
    } else {
        Fragmentation::Later {
            identification: frag_id.unwrap_or(0),
            offset: frag_offset,
            more: frag_more,
        }
    };

    let header_len = raw.len().saturating_sub(payload.payload.len());
    let ip = IpMeta::V6 {
        src: header.source_addr(),
        dst: header.destination_addr(),
        next_header: u8::from(payload.ip_number),
        hop_limit: header.hop_limit(),
        header_len,
        identification: frag_id,
    };

    let transport = if matches!(fragmentation, Fragmentation::Later { .. }) {
        Transport::LaterFragment {
            protocol: u8::from(payload.ip_number),
            identification: frag_id.unwrap_or(0),
            offset: frag_offset,
            more: frag_more,
        }
    } else {
        decode_first_transport(payload, transport)?
    };

    Ok(Packet {
        raw: &raw[..wire_len],
        wire_len,
        ip,
        fragmentation,
        transport,
    })
}

fn decode_first_transport(
    payload: &IpPayloadSlice<'_>,
    transport: Option<TransportSlice<'_>>,
) -> Result<Transport, ParseError> {
    use etherparse::{Icmpv4Slice, Icmpv6Slice, IpNumber, UdpHeaderSlice};
    if let Some(transport) = transport {
        return Ok(decode_transport(payload, Some(transport)));
    }
    match payload.ip_number {
        IpNumber::TCP => TcpSlice::from_slice(payload.payload)
            .map(|tcp| tcp_transport(&tcp))
            .map_err(|_| ParseError::MalformedTcp),
        IpNumber::UDP => {
            let udp = UdpHeaderSlice::from_slice(payload.payload)
                .map_err(|_| ParseError::MalformedUdp)?;
            if udp.length() < 8 || usize::from(udp.length()) < payload.payload.len() {
                return Err(ParseError::MalformedUdp);
            }
            Ok(Transport::Udp {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload_len: payload.payload.len() - 8,
            })
        }
        IpNumber::ICMP => Icmpv4Slice::from_slice(payload.payload)
            .map(|icmp| decode_transport(payload, Some(TransportSlice::Icmpv4(icmp))))
            .map_err(|_| ParseError::MalformedTransport),
        IpNumber::IPV6_ICMP => Icmpv6Slice::from_slice(payload.payload)
            .map(|icmp| decode_transport(payload, Some(TransportSlice::Icmpv6(icmp))))
            .map_err(|_| ParseError::MalformedTransport),
        _ => Ok(decode_transport(payload, None)),
    }
}

fn decode_transport(
    payload: &IpPayloadSlice<'_>,
    transport: Option<TransportSlice<'_>>,
) -> Transport {
    match transport {
        Some(TransportSlice::Tcp(tcp)) => tcp_transport(&tcp),
        Some(TransportSlice::Udp(udp)) => udp_transport(&udp),
        Some(TransportSlice::Icmpv4(icmp)) => {
            let (echo_id, echo_seq) = match icmp.icmp_type() {
                Icmpv4Type::EchoRequest(e) | Icmpv4Type::EchoReply(e) => (Some(e.id), Some(e.seq)),
                _ => (None, None),
            };
            Transport::Icmpv4 {
                type_u8: icmp.type_u8(),
                code: icmp.code_u8(),
                echo_id,
                echo_seq,
                payload_len: icmp.payload().len(),
            }
        }
        Some(TransportSlice::Icmpv6(icmp)) => Transport::Icmpv6 {
            type_u8: icmp.type_u8(),
            code: icmp.code_u8(),
            payload_len: icmp.payload().len(),
        },
        Some(TransportSlice::Igmp(igmp)) => Transport::Other {
            protocol: u8::from(payload.ip_number),
            payload_len: igmp.slice().len().saturating_sub(igmp.header_len()),
        },
        None => Transport::Other {
            protocol: u8::from(payload.ip_number),
            payload_len: payload.payload.len(),
        },
    }
}

fn tcp_transport(tcp: &TcpSlice<'_>) -> Transport {
    let mut flags = 0u8;
    if tcp.fin() {
        flags |= TcpFlags::FIN;
    }
    if tcp.syn() {
        flags |= TcpFlags::SYN;
    }
    if tcp.rst() {
        flags |= TcpFlags::RST;
    }
    if tcp.psh() {
        flags |= TcpFlags::PSH;
    }
    if tcp.ack() {
        flags |= TcpFlags::ACK;
    }
    if tcp.urg() {
        flags |= TcpFlags::URG;
    }
    Transport::Tcp {
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        flags: TcpFlags(flags),
        seq: tcp.sequence_number(),
        ack: tcp.acknowledgment_number(),
        header_len: tcp.header_len(),
        payload_len: tcp.payload().len(),
    }
}

fn udp_transport(udp: &UdpSlice<'_>) -> Transport {
    Transport::Udp {
        src_port: udp.source_port(),
        dst_port: udp.destination_port(),
        payload_len: udp.payload().len(),
    }
}

fn map_slice_err(err: packet::SliceError) -> ParseError {
    match err {
        packet::SliceError::Len(le) => match le.layer {
            Layer::TcpHeader => ParseError::MalformedTcp,
            Layer::UdpHeader => ParseError::MalformedUdp,
            Layer::Ipv4Packet | Layer::Ipv6Packet => ParseError::InvalidTotalLength,
            _ => ParseError::Truncated,
        },
        packet::SliceError::Ip(ip::HeaderError::UnsupportedIpVersion { version_number }) => {
            ParseError::UnsupportedVersion(version_number)
        }
        packet::SliceError::Ip(ip::HeaderError::Ipv4HeaderLengthSmallerThanHeader { .. })
        | packet::SliceError::Ipv4(ipv4::HeaderError::HeaderLengthSmallerThanHeader { .. }) => {
            ParseError::InvalidIhl
        }
        packet::SliceError::Ipv4(ipv4::HeaderError::UnexpectedVersion { version_number })
        | packet::SliceError::Ipv6(ipv6::HeaderError::UnexpectedVersion { version_number }) => {
            ParseError::UnsupportedVersion(version_number)
        }
        packet::SliceError::Tcp(_) => ParseError::MalformedTcp,
        _ => ParseError::InvalidIpHeader,
    }
}
