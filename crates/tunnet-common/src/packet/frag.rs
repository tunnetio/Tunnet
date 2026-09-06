use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::{Fragmentation, Packet, TcpFlags, Transport};
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

/// Short TTL: fragments of one datagram should arrive quickly.
pub const FRAGMENT_TTL: Duration = Duration::from_secs(2);
pub const MAX_FRAGMENT_ENTRIES: usize = 4096;

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

struct Entry {
    transport: CachedTransport,
    expires: Instant,
}

/// Bounded first-fragment cache. Not a reassembly buffer.
pub struct FragmentTable {
    map: HashMap<FragKey, Entry>,
    ttl: Duration,
    cap: usize,
}

impl Default for FragmentTable {
    fn default() -> Self {
        Self::new(MAX_FRAGMENT_ENTRIES, FRAGMENT_TTL)
    }
}

impl FragmentTable {
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::with_capacity(cap.min(64)),
            ttl,
            cap,
        }
    }

    pub fn key_for(packet: &Packet<'_>) -> Option<FragKey> {
        let identification = packet.fragmentation.identification()?;
        Some(FragKey {
            src: packet.ip.src(),
            dst: packet.ip.dst(),
            protocol: packet.ip.ip_protocol(),
            identification,
        })
    }

    pub fn remember(&mut self, packet: &Packet<'_>) {
        if !matches!(packet.fragmentation, Fragmentation::First { .. }) {
            return;
        }
        let Some(key) = Self::key_for(packet) else {
            return;
        };
        let Some(transport) = CachedTransport::from_transport(packet.transport) else {
            return;
        };
        self.evict_expired();
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            self.evict_oldest();
        }
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            return;
        }
        self.map.insert(
            key,
            Entry {
                transport,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    /// Later-fragment lookup. `None` means fail-closed (no trustworthy state).
    pub fn lookup(&mut self, packet: &Packet<'_>) -> Option<CachedTransport> {
        let key = Self::key_for(packet)?;
        self.evict_expired();
        let entry = self.map.get(&key)?;
        if Instant::now() >= entry.expires {
            self.map.remove(&key);
            return None;
        }
        Some(entry.transport)
    }

    /// First fragments are cached; later fragments require a cache hit (fail-closed).
    pub fn resolve(&mut self, packet: &Packet<'_>) -> Option<ResolvedL4> {
        if packet.transport.is_later_fragment() {
            return self.lookup(packet).map(CachedTransport::to_resolved);
        }
        self.remember(packet);
        ResolvedL4::from_transport(packet.transport)
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Metadata-based lookup for the unified policy fast path (no reparse).
    pub fn lookup_cached(&mut self, key: &FragKey) -> Option<ResolvedL4> {
        self.evict_expired();
        let entry = self.map.get(key)?;
        if Instant::now() >= entry.expires {
            self.map.remove(key);
            return None;
        }
        Some(entry.transport.to_resolved())
    }

    /// Metadata-based insert for first fragments (no reparse).
    pub fn insert_cached(&mut self, key: FragKey, transport: CachedTransport) {
        self.evict_expired();
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            self.evict_oldest();
        }
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            return;
        }
        self.map.insert(
            key,
            Entry {
                transport,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.map.retain(|_, e| e.expires > now);
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .map
            .iter()
            .min_by_key(|(_, e)| e.expires)
            .map(|(k, _)| *k);
        if let Some(k) = oldest {
            self.map.remove(&k);
        }
    }
}
