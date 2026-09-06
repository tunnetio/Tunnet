//! Transparent TCP port NAT for Tunnet SSH (22 ↔ internal listen port).
//!
//! Parse-once: all entry points take already-parsed [`PacketMeta`] — the data
//! plane never parses a packet twice for NAT. Only unfragmented (or
//! first-fragment) TCP packets are rewritten; checksums via etherparse.

use std::net::Ipv4Addr;

use tunnet_common::packet::{PacketMeta, SshNatClass, set_tcp_ipv4_checksum};

pub const SSH_EXTERNAL_PORT: u16 = 22;
pub const SSH_INTERNAL_PORT: u16 = 30022;

/// Parse-once outbound check using already-parsed metadata.
/// Gates materialization: only packets actually needing a rewrite take the
/// mutable path (§2.1-7); everything else stays immutable (zero copy).
pub fn needs_outbound_rewrite_with_meta(meta: &PacketMeta, self_ip: Ipv4Addr) -> bool {
    matches!(meta.ssh_nat_class(self_ip), SshNatClass::OutboundToExternal)
}

/// Parse-once outbound rewrite using already-parsed metadata.
/// Returns true when a rewrite was applied (caller must refresh metadata).
pub fn rewrite_outbound_with_meta(packet: &mut [u8], meta: &PacketMeta, self_ip: Ipv4Addr) -> bool {
    match meta.ssh_nat_class(self_ip) {
        SshNatClass::OutboundToExternal => {
            let ip_len = meta.ip_header_len;
            if packet.len() < ip_len + 2 {
                return false;
            }
            packet[ip_len] = (SSH_EXTERNAL_PORT >> 8) as u8;
            packet[ip_len + 1] = (SSH_EXTERNAL_PORT & 0xff) as u8;
            set_tcp_ipv4_checksum(packet, ip_len)
        }
        _ => false,
    }
}

/// Parse-once inbound check using already-parsed metadata.
pub fn needs_inbound_rewrite_with_meta(meta: &PacketMeta, self_ip: Ipv4Addr) -> bool {
    matches!(meta.ssh_nat_class(self_ip), SshNatClass::InboundToInternal)
}

pub fn rewrite_inbound_with_meta(packet: &mut [u8], meta: &PacketMeta, self_ip: Ipv4Addr) -> bool {
    match meta.ssh_nat_class(self_ip) {
        SshNatClass::InboundToInternal => {
            let ip_len = meta.ip_header_len;
            if packet.len() < ip_len + 4 {
                return false;
            }
            packet[ip_len + 2] = (SSH_INTERNAL_PORT >> 8) as u8;
            packet[ip_len + 3] = (SSH_INTERNAL_PORT & 0xff) as u8;
            set_tcp_ipv4_checksum(packet, ip_len)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use tunnet_common::packet::{PacketMeta, parse, tcp_ipv4_checksum_of};

    fn sample_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(sport, dport, 1, 1000);
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    fn meta_of(raw: &[u8]) -> PacketMeta {
        let pkt = parse(raw).unwrap();
        PacketMeta::from_packet(&pkt)
    }

    #[test]
    fn inbound_rewrites_22_to_internal() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 22, b"hello");
        let before_payload = p[40..].to_vec();
        let meta = meta_of(&p);
        assert!(needs_inbound_rewrite_with_meta(&meta, self_ip));
        assert!(rewrite_inbound_with_meta(&mut p, &meta, self_ip));
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.transport.dst_port(), Some(SSH_INTERNAL_PORT));
        assert_eq!(&p[40..], before_payload.as_slice());
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            tcp_ipv4_checksum_of(&p).unwrap()
        );
    }

    #[test]
    fn outbound_rewrites_internal_to_22() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(self_ip, peer, SSH_INTERNAL_PORT, 45678, &[]);
        let meta = meta_of(&p);
        assert!(rewrite_outbound_with_meta(&mut p, &meta, self_ip));
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.transport.src_port(), Some(22));
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            tcp_ipv4_checksum_of(&p).unwrap()
        );
    }

    #[test]
    fn ignores_other_ports_and_fragments() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 443, &[]);
        let meta = meta_of(&p);
        assert!(!needs_inbound_rewrite_with_meta(&meta, self_ip));
        assert!(!rewrite_inbound_with_meta(&mut p, &meta, self_ip));

        let later = sample_tcp(peer, self_ip, 45678, 22, &[]);
        let mut later = later;
        later[6] = 0;
        later[7] = 8;
        // Later fragment with nonzero offset: parse may fail or classify as
        // later fragment; either way no rewrite must happen.
        if let Ok(pkt) = parse(&later) {
            let meta = PacketMeta::from_packet(&pkt);
            assert!(!needs_inbound_rewrite_with_meta(&meta, self_ip));
            assert!(!rewrite_inbound_with_meta(&mut later, &meta, self_ip));
        }
    }
}
