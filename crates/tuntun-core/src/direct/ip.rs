//! Derive Direct-mode IPv4 addresses from endpoint public keys on CGNAT.
//!
//! Range: `100.64.0.0/10` (shared address space) so Managed `10.x` and Direct
//! never collide when a user later runs both.

use std::net::Ipv4Addr;

use uuid::Uuid;

/// CGNAT shared address space used for Direct mode (`100.64.0.0/10`).
pub fn direct_cgnat() -> ipnet::Ipv4Net {
    ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).expect("static CGNAT")
}

/// Alias for callers that expect a const-like name.
pub use self::direct_cgnat as direct_cgnat_net;

/// Host bits available in /10 after the 10-bit prefix: 22 bits → ~4M addresses.
const HOST_BITS: u32 = 22;
const HOST_MASK: u32 = (1 << HOST_BITS) - 1;

/// Derive a stable IPv4 in `100.64.0.0/10` from an endpoint public key hex
/// and optional `collision_index` (bumped by the coordinator on conflict).
pub fn derive_ipv4(endpoint_id_hex: &str, collision_index: u8) -> Ipv4Addr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(endpoint_id_hex.as_bytes());
    hasher.update(&[collision_index]);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let host = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & HOST_MASK;
    // Avoid .0 and broadcast-ish all-ones host within the /10.
    let host = if host == 0 {
        1
    } else if host == HOST_MASK {
        HOST_MASK - 1
    } else {
        host
    };
    let base: u32 = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    Ipv4Addr::from(base | host)
}

/// Deterministic network UUID from a topic hash (32-byte hex or raw bytes).
pub fn network_id_from_topic(topic_hash_hex: &str) -> Uuid {
    let raw = hex::decode(topic_hash_hex).unwrap_or_else(|_| topic_hash_hex.as_bytes().to_vec());
    let hash = blake3::hash(&raw);
    let b = hash.as_bytes();
    Uuid::from_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_within_cgnat() {
        let ip = derive_ipv4(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            0,
        );
        assert!(direct_cgnat().contains(&ip));
        assert!(!ip.is_loopback());
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn stable_for_same_key() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(derive_ipv4(hex, 0), derive_ipv4(hex, 0));
    }

    #[test]
    fn collision_index_changes_ip() {
        let hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert_ne!(derive_ipv4(hex, 0), derive_ipv4(hex, 1));
    }

    #[test]
    fn not_in_rfc1918_10() {
        let ip = derive_ipv4(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            0,
        );
        let ten: ipnet::Ipv4Net = "10.0.0.0/8".parse().unwrap();
        assert!(!ten.contains(&ip));
    }

    #[test]
    fn network_id_stable() {
        let t = "aa".repeat(32);
        assert_eq!(network_id_from_topic(&t), network_id_from_topic(&t));
    }
}
