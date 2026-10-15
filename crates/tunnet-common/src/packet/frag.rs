use std::net::IpAddr;

use super::{Packet, TcpFlags, Transport};
use crate::policy::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedL4 {
    pub protocol: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub icmp_type: Option<u8>,
    pub icmp_id: Option<u16>,
    pub icmp_seq: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub identification: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedTransport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    Icmpv4 {
        type_u8: u8,
        code: u8,
        echo_id: Option<u16>,
        echo_seq: Option<u16>,
    },
    Icmpv6 {
        type_u8: u8,
        code: u8,
    },
    Other {
        protocol: u8,
    },
}

impl CachedTransport {
    pub fn from_transport(t: Transport) -> Option<Self> {
        match t {
            Transport::Tcp {
                src_port,
                dst_port,
                flags,
                ..
            } => Some(Self::Tcp {
                src_port,
                dst_port,
                flags,
            }),
            Transport::Udp {
                src_port, dst_port, ..
            } => Some(Self::Udp { src_port, dst_port }),
            Transport::Icmpv4 {
                type_u8,
                code,
                echo_id,
                echo_seq,
                ..
            } => Some(Self::Icmpv4 {
                type_u8,
                code,
                echo_id,
                echo_seq,
            }),
            Transport::Icmpv6 { type_u8, code, .. } => Some(Self::Icmpv6 { type_u8, code }),
            Transport::Other { protocol, .. } => Some(Self::Other { protocol }),
            Transport::LaterFragment { .. } => None,
        }
    }

    pub fn to_resolved(self) -> ResolvedL4 {
        ResolvedL4 {
            protocol: self.protocol(),
            src_port: self.src_port(),
            dst_port: self.dst_port(),
            tcp_flags: self.tcp_flags(),
            icmp_type: match self {
                Self::Icmpv4 { type_u8, .. } | Self::Icmpv6 { type_u8, .. } => Some(type_u8),
                _ => None,
            },
            icmp_id: match self {
                Self::Icmpv4 { echo_id, .. } => echo_id,
                _ => None,
            },
            icmp_seq: match self {
                Self::Icmpv4 { echo_seq, .. } => echo_seq,
                _ => None,
            },
        }
    }

    pub fn protocol(self) -> crate::policy::Protocol {
        match self {
            Self::Tcp { .. } => Protocol::Tcp,
            Self::Udp { .. } => Protocol::Udp,
            Self::Icmpv4 { .. } => Protocol::Icmp,
            Self::Icmpv6 { .. } => Protocol::Icmpv6,
            Self::Other { protocol } => Protocol::from_ip_number(protocol),
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
}

impl ResolvedL4 {
    pub fn from_transport(t: Transport) -> Option<Self> {
        CachedTransport::from_transport(t).map(CachedTransport::to_resolved)
    }
}

pub fn frag_key(packet: &Packet<'_>) -> Option<FragKey> {
    let identification = packet.fragmentation.identification()?;
    Some(FragKey {
        src: packet.ip.src(),
        dst: packet.ip.dst(),
        protocol: packet.ip.ip_protocol(),
        identification,
    })
}
