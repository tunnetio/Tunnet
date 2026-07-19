//! Transparent TCP port NAT for Tunnet SSH (22 ↔ internal listen port).
//!
//! Clients dial mesh_ip:22. The agent listens on mesh_ip:30022. Inbound packets
//! destined for :22 are rewritten to :30022 before `tun.send`; outbound replies
//! from :30022 are rewritten back to :22 before mesh forward. Checksums use
//! RFC 1624 incremental updates.

use std::net::Ipv4Addr;

pub const SSH_EXTERNAL_PORT: u16 = 22;
pub const SSH_INTERNAL_PORT: u16 = 30022;

const IPPROTO_TCP: u8 = 6;

/// True when inbound SSH NAT would rewrite this packet (read-only peek).
pub fn needs_inbound_rewrite(packet: &[u8], self_ip: Ipv4Addr) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl + 4 || packet[9] != IPPROTO_TCP {
        return false;
    }
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if dst != self_ip {
        return false;
    }
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    dport == SSH_EXTERNAL_PORT
}

/// Rewrite inbound mesh packet: `dst==self && dport==22` → `dport=30022`.
/// Returns true if the packet was rewritten.
pub fn rewrite_inbound(packet: &mut [u8], self_ip: Ipv4Addr) -> bool {
    rewrite_port(packet, self_ip, true)
}

/// Rewrite outbound packet: `src==self && sport==30022` → `sport=22`.
/// Returns true if the packet was rewritten.
pub fn rewrite_outbound(packet: &mut [u8], self_ip: Ipv4Addr) -> bool {
    rewrite_port(packet, self_ip, false)
}

fn rewrite_port(packet: &mut [u8], self_ip: Ipv4Addr, inbound: bool) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl + 4 || packet[9] != IPPROTO_TCP {
        return false;
    }

    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (old_port, new_port, offset) = if inbound {
        if dst != self_ip {
            return false;
        }
        let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        if dport != SSH_EXTERNAL_PORT {
            return false;
        }
        (SSH_EXTERNAL_PORT, SSH_INTERNAL_PORT, ihl + 2)
    } else {
        if src != self_ip {
            return false;
        }
        let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        if sport != SSH_INTERNAL_PORT {
            return false;
        }
        (SSH_INTERNAL_PORT, SSH_EXTERNAL_PORT, ihl)
    };

    packet[offset] = (new_port >> 8) as u8;
    packet[offset + 1] = (new_port & 0xff) as u8;

    // TCP checksum is at ihl+16 when the header is present.
    if packet.len() >= ihl + 18 {
        let csum = u16::from_be_bytes([packet[ihl + 16], packet[ihl + 17]]);
        let updated = incremental_checksum(csum, old_port, new_port);
        packet[ihl + 16] = (updated >> 8) as u8;
        packet[ihl + 17] = (updated & 0xff) as u8;
    }
    true
}

/// RFC 1624 incremental checksum update for replacing one u16 field.
fn incremental_checksum(old_sum: u16, old_val: u16, new_val: u16) -> u16 {
    // ~HC' = ~HC + ~m + m'  (ones' complement)
    let mut sum = (!old_sum as u32)
        .wrapping_add(!old_val as u32)
        .wrapping_add(new_val as u32);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // v4, ihl=5
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ihl = 20;
        p[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
        // Leave checksum 0 for tests of rewrite presence.
        p
    }

    #[test]
    fn inbound_rewrites_22_to_internal() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 22);
        assert!(rewrite_inbound(&mut p, self_ip));
        let ihl = 20;
        let dport = u16::from_be_bytes([p[ihl + 2], p[ihl + 3]]);
        assert_eq!(dport, SSH_INTERNAL_PORT);
    }

    #[test]
    fn outbound_rewrites_internal_to_22() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(self_ip, peer, SSH_INTERNAL_PORT, 45678);
        assert!(rewrite_outbound(&mut p, self_ip));
        let ihl = 20;
        let sport = u16::from_be_bytes([p[ihl], p[ihl + 1]]);
        assert_eq!(sport, 22);
    }

    #[test]
    fn ignores_other_ports() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let mut p = sample_tcp(peer, self_ip, 45678, 443);
        assert!(!rewrite_inbound(&mut p, self_ip));
    }
}
