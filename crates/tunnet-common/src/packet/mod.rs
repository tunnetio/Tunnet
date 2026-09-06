//! Authoritative zero-copy IP packet view for the Tunnet data plane.
//!
//! Strict `etherparse` slicing is the only parser. Callers decide whether IPv6
//! (or an unknown transport) is forwarded; this module does not hide version
//! checks behind `None`.
//!
//! # Fragmentation
//!
//! IPv4 (and IPv6) later fragments do **not** contain a transport header. Port
//! policy must never invent ports from fragment payload bytes.
//!
//! [`FragmentTable`] remembers the first fragment's transport metadata, keyed by
//! IP fragment identity, with a bounded capacity and short TTL. Later fragments
//! reuse that metadata when present; otherwise policy is fail-closed.
//! Packets themselves are forwarded as original fragments — this is not a
//! reassembly pool (`IpDefragPool` is intentionally unused).

mod build;
mod frag;
mod frame;
mod meta;
mod owned;
mod parse;

pub use build::{set_tcp_ipv4_checksum, synthesize_reject, tcp_ipv4_checksum_of};
pub use frag::{
    CachedTransport, FRAGMENT_TTL, FragKey, FragmentTable, MAX_FRAGMENT_ENTRIES, ResolvedL4,
};
pub use frame::{
    DecodeError, Frame, KIND_SEGMENT, KIND_SINGLE, MAX_SEGMENTS, MIN_SEGMENT_PAYLOAD,
    SEGMENT_OVERHEAD, SINGLE_OVERHEAD, SegmentHeader, decode_frame, encode_segment_prefix,
    encode_single_prefix, segment_count,
};
pub use meta::{FlowKey, PacketMeta, SshNatClass};
pub use owned::{
    DEFAULT_VIRTUAL_MTU, FRAME_HEADROOM, LogicalPacket, MAX_LOGICAL_LEN, MIN_VIRTUAL_MTU,
    PacketOwner, PacketPool, PooledBuffer,
};
pub use parse::{ParseError, parse};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    #[inline]
    pub fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }
    #[inline]
    pub fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }
    #[inline]
    pub fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
    #[inline]
    pub fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMeta {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        identification: u16,
        header_len: usize,
        ttl: u8,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        header_len: usize,
        identification: Option<u32>,
    },
}

impl IpMeta {
    pub fn src(self) -> IpAddr {
        match self {
            Self::V4 { src, .. } => IpAddr::V4(src),
            Self::V6 { src, .. } => IpAddr::V6(src),
        }
    }

    pub fn dst(self) -> IpAddr {
        match self {
            Self::V4 { dst, .. } => IpAddr::V4(dst),
            Self::V6 { dst, .. } => IpAddr::V6(dst),
        }
    }

    pub fn v4_src(self) -> Option<Ipv4Addr> {
        match self {
            Self::V4 { src, .. } => Some(src),
            Self::V6 { .. } => None,
        }
    }

    pub fn v4_dst(self) -> Option<Ipv4Addr> {
        match self {
            Self::V4 { dst, .. } => Some(dst),
            Self::V6 { .. } => None,
        }
    }

    pub fn ip_protocol(self) -> u8 {
        match self {
            Self::V4 { protocol, .. } => protocol,
            Self::V6 { next_header, .. } => next_header,
        }
    }

    pub fn header_len(self) -> usize {
        match self {
            Self::V4 { header_len, .. } | Self::V6 { header_len, .. } => header_len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fragmentation {
    None,
    /// Offset 0 with MF (or IPv6 first fragment). Transport may be inspectable.
    First {
        identification: u32,
        more: bool,
    },
    /// Non-zero fragment offset. Payload is not a transport header.
    Later {
        identification: u32,
        offset: u16,
        more: bool,
    },
}

impl Fragmentation {
    pub fn is_later(self) -> bool {
        matches!(self, Self::Later { .. })
    }

    pub fn identification(self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::First { identification, .. } | Self::Later { identification, .. } => {
                Some(identification)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        header_len: usize,
        payload_len: usize,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload_len: usize,
    },
    Icmpv4 {
        type_u8: u8,
        code: u8,
        echo_id: Option<u16>,
        echo_seq: Option<u16>,
        payload_len: usize,
    },
    Icmpv6 {
        type_u8: u8,
        code: u8,
        payload_len: usize,
    },
    Other {
        protocol: u8,
        payload_len: usize,
    },
    /// Non-first fragment: do not interpret payload as ports/flags.
    LaterFragment {
        protocol: u8,
        identification: u32,
        offset: u16,
        more: bool,
    },
}

impl Transport {
    pub fn protocol(self) -> Protocol {
        match self {
            Self::Tcp { .. } => Protocol::Tcp,
            Self::Udp { .. } => Protocol::Udp,
            Self::Icmpv4 { .. } => Protocol::Icmp,
            Self::Icmpv6 { .. } => Protocol::Icmpv6,
            Self::Other { protocol, .. } | Self::LaterFragment { protocol, .. } => {
                Protocol::from_ip_number(protocol)
            }
        }
    }

    pub fn src_port(self) -> Option<u16> {
        match self {
            Self::Tcp { src_port, .. } | Self::Udp { src_port, .. } => Some(src_port),
            Self::Icmpv4 { echo_id, .. } => echo_id,
            _ => None,
        }
    }

    pub fn dst_port(self) -> Option<u16> {
        match self {
            Self::Tcp { dst_port, .. } | Self::Udp { dst_port, .. } => Some(dst_port),
            Self::Icmpv4 { echo_seq, .. } => echo_seq,
            _ => None,
        }
    }

    pub fn tcp_flags(self) -> Option<TcpFlags> {
        match self {
            Self::Tcp { flags, .. } => Some(flags),
            _ => None,
        }
    }

    pub fn l4_payload_len(self) -> usize {
        match self {
            Self::Tcp { payload_len, .. }
            | Self::Udp { payload_len, .. }
            | Self::Icmpv4 { payload_len, .. }
            | Self::Icmpv6 { payload_len, .. }
            | Self::Other { payload_len, .. } => payload_len,
            Self::LaterFragment { .. } => 0,
        }
    }

    pub fn is_later_fragment(self) -> bool {
        matches!(self, Self::LaterFragment { .. })
    }
}

/// Validated packet view borrowing the original buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub raw: &'a [u8],
    /// Length from the IP length field, not `raw.len()`.
    pub wire_len: usize,
    pub ip: IpMeta,
    pub fragmentation: Fragmentation,
    pub transport: Transport,
}

impl<'a> Packet<'a> {
    pub fn policy_protocol(&self) -> Protocol {
        self.transport.protocol()
    }
}

#[cfg(test)]
mod tests;
