//! Parse-once packet metadata: flow keys and compact IP/transport summary.
//!
//! These types are `Copy` and allocation-free; the data plane parses each
//! logical packet once and carries the metadata alongside the bytes.

use std::net::{IpAddr, Ipv4Addr};

use super::{Fragmentation, IpMeta, Packet, Transport};

/// Stable per-flow scheduling key.
///
/// TCP/UDP: IP 5-tuple. ICMP: src/dst/proto + echo id (cheap isolation).
/// Other protocols without ports: src/dst/proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
}

impl FlowKey {
    pub fn for_packet(pkt: &Packet<'_>) -> Self {
        let (src, dst) = match pkt.ip {
            IpMeta::V4 { src, dst, .. } => (IpAddr::V4(src), IpAddr::V4(dst)),
            IpMeta::V6 { src, dst, .. } => (IpAddr::V6(src), IpAddr::V6(dst)),
        };
        let proto = pkt.ip.ip_protocol();
        let (sport, dport) = match pkt.transport {
            Transport::Tcp {
                src_port, dst_port, ..
            }
            | Transport::Udp {
                src_port, dst_port, ..
            } => (src_port, dst_port),
            Transport::Icmpv4 { echo_id, .. } => (echo_id.unwrap_or(0), 0),
            Transport::Icmpv6 { .. } => (0, 0),
            Transport::Other { .. } => (0, 0),
            Transport::LaterFragment {
                protocol,
                identification,
                ..
            } => (
                (identification & 0xffff) as u16,
                (protocol as u16).wrapping_mul(31),
            ),
        };
        Self {
            src,
            dst,
            proto,
            sport,
            dport,
        }
    }

    /// Canonical bidirectional identity for conntrack fast-path hits.
    pub fn canonical(self) -> (Self, bool) {
        let rev = Self {
            src: self.dst,
            dst: self.src,
            proto: self.proto,
            sport: self.dport,
            dport: self.sport,
        };
        if (self.src, self.sport) <= (self.dst, self.dport) {
            (self, false)
        } else {
            (rev, true)
        }
    }
}

/// Compact parsed metadata stored alongside owned bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub src_v4: Option<Ipv4Addr>,
    pub dst_v4: Option<Ipv4Addr>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub wire_len: usize,
    pub ip_header_len: usize,
    pub transport: Transport,
    pub fragmentation: Fragmentation,
    pub tcp_flags: u8,
}

impl PacketMeta {
    pub fn from_packet(pkt: &Packet<'_>) -> Self {
        let (src, dst) = match pkt.ip {
            IpMeta::V4 { src, dst, .. } => (IpAddr::V4(src), IpAddr::V4(dst)),
            IpMeta::V6 { src, dst, .. } => (IpAddr::V6(src), IpAddr::V6(dst)),
        };
        let tcp_flags = match pkt.transport {
            Transport::Tcp { flags, .. } => flags.0,
            _ => 0,
        };
        Self {
            src_v4: pkt.ip.v4_src(),
            dst_v4: pkt.ip.v4_dst(),
            src,
            dst,
            proto: pkt.ip.ip_protocol(),
            wire_len: pkt.wire_len,
            ip_header_len: pkt.ip.header_len(),
            transport: pkt.transport,
            fragmentation: pkt.fragmentation,
            tcp_flags,
        }
    }

    pub fn is_fragment(&self) -> bool {
        !matches!(self.fragmentation, Fragmentation::None)
    }

    pub fn is_later_fragment(&self) -> bool {
        matches!(self.fragmentation, Fragmentation::Later { .. })
    }

    /// Cheap SSH-NAT precondition using stored metadata only (no reparse).
    pub fn ssh_nat_class(&self, self_ip: Ipv4Addr) -> SshNatClass {
        if self.is_later_fragment() {
            return SshNatClass::None;
        }
        let Transport::Tcp {
            src_port,
            dst_port,
            header_len,
            ..
        } = self.transport
        else {
            return SshNatClass::None;
        };
        if header_len < 18 {
            return SshNatClass::None;
        }
        if self.dst_v4 == Some(self_ip) && dst_port == 22 {
            return SshNatClass::InboundToInternal;
        }
        if self.src_v4 == Some(self_ip) && src_port == 30022 {
            return SshNatClass::OutboundToExternal;
        }
        SshNatClass::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshNatClass {
    None,
    InboundToInternal,
    OutboundToExternal,
}
