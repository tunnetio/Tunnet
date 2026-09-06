use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressPlan {
    pub peer_cidr: Ipv4Net,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressPlanError {
    #[error("invalid peer CIDR: {0}")]
    InvalidCidr(String),
    #[error("peer CIDR must be RFC1918 private space")]
    NotPrivate,
    #[error("peer CIDR prefix must be /16..=/28")]
    BadPrefix,
    #[error("peer CIDR capacity too small")]
    TooSmall,
    #[error("peer CIDR overlaps an active Direct network {0}")]
    OverlapsActivePlan(Uuid),
    #[error("peer CIDR conflicts with host network {conflict}")]
    HostConflict {
        conflict: String,
        category: ConflictCategory,
    },
    #[error("address pool exhausted")]
    PoolExhausted,
    #[error("no safe IPv4 peer range available on this host")]
    NoSafeRange,
    #[error("unsupported legacy Direct network: recreate with `tunnet create`")]
    LegacyUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictCategory {
    ActiveDirectPlan,
    LanPrefix,
    VpnRoute,
    SpecialUse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConflict {
    pub network_id: Uuid,
    pub network_name: String,
    pub peer_cidr: Ipv4Net,
    pub conflicting_prefix: Ipv4Net,
    pub interface: Option<String>,
    pub category: ConflictCategory,
}

fn rfc1918_nets() -> [Ipv4Net; 3] {
    [
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
    ]
}

fn contains(outer: &Ipv4Net, inner: &Ipv4Net) -> bool {
    outer.contains(&inner.network()) && outer.contains(&inner.broadcast())
}

fn overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network())
        || a.contains(&b.broadcast())
        || b.contains(&a.network())
        || b.contains(&a.broadcast())
}

pub fn is_rfc1918_net(cidr: &Ipv4Net) -> bool {
    rfc1918_nets().iter().any(|n| contains(n, cidr))
}

pub fn usable_host_count(cidr: &Ipv4Net) -> u64 {
    let host_bits = 32 - u64::from(cidr.prefix_len());
    if host_bits < 2 {
        return 0;
    }
    (1u64 << host_bits).saturating_sub(2)
}

pub fn is_usable_host(cidr: &Ipv4Net, ip: &Ipv4Addr) -> bool {
    if !cidr.contains(ip) {
        return false;
    }
    if *ip == cidr.network() || *ip == cidr.broadcast() {
        return false;
    }
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return false;
    }
    true
}

pub fn validate_peer_cidr(
    cidr: &Ipv4Net,
    existing_plans: &[(Uuid, Ipv4Net)],
    host_nets: &[Ipv4Net],
) -> Result<(), AddressPlanError> {
    let prefix = cidr.prefix_len();
    if !(16..=28).contains(&prefix) {
        return Err(AddressPlanError::BadPrefix);
    }
    if !is_rfc1918_net(cidr) {
        return Err(AddressPlanError::NotPrivate);
    }
    if usable_host_count(cidr) < 16 {
        return Err(AddressPlanError::TooSmall);
    }
    for (id, other) in existing_plans {
        if overlaps(cidr, other) {
            return Err(AddressPlanError::OverlapsActivePlan(*id));
        }
    }
    for h in host_nets {
        if overlaps(cidr, h) {
            let category = if is_rfc1918_net(h) {
                ConflictCategory::LanPrefix
            } else {
                ConflictCategory::SpecialUse
            };
            return Err(AddressPlanError::HostConflict {
                conflict: h.to_string(),
                category,
            });
        }
    }
    Ok(())
}

pub fn allocate_peer_ip(
    plan: &AddressPlan,
    network_id: &Uuid,
    endpoint_id_hex: &str,
    occupied: &HashSet<Ipv4Addr>,
) -> Result<Ipv4Addr, AddressPlanError> {
    let base = u32::from(plan.peer_cidr.network());
    let total = usable_host_count(&plan.peer_cidr);
    if total == 0 {
        return Err(AddressPlanError::PoolExhausted);
    }
    for attempt in 0..total.min(1 << 20) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(network_id.as_bytes());
        hasher.update(endpoint_id_hex.as_bytes());
        hasher.update(&attempt.to_le_bytes());
        let hash = hasher.finalize();
        let b = hash.as_bytes();
        let offset = (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64 % total) + 1;
        let candidate = Ipv4Addr::from(base.wrapping_add(offset as u32));
        if !is_usable_host(&plan.peer_cidr, &candidate) {
            continue;
        }
        if occupied.contains(&candidate) {
            continue;
        }
        return Ok(candidate);
    }
    Err(AddressPlanError::PoolExhausted)
}

pub fn validate_member_ip(plan: &AddressPlan, ip: &Ipv4Addr) -> Result<(), AddressPlanError> {
    if !is_usable_host(&plan.peer_cidr, ip) {
        return Err(AddressPlanError::InvalidCidr(format!(
            "{ip} not usable in {}",
            plan.peer_cidr
        )));
    }
    Ok(())
}

fn candidate_pool<R: rand::Rng>(rng: &mut R) -> Vec<Ipv4Net> {
    use rand::RngExt;
    let mut out = Vec::new();
    for _ in 0..48 {
        let pick: u8 = rng.random_range(0..3);
        let cidr: Ipv4Net = match pick {
            0 => {
                let b: u8 = rng.random();
                let c: u8 = rng.random();
                if b == 0 && c == 0 {
                    continue;
                }
                format!("10.{b}.{c}.0/24").parse().unwrap()
            }
            1 => {
                let b: u8 = rng.random_range(16..32);
                let c: u8 = rng.random();
                format!("172.{b}.{c}.0/24").parse().unwrap()
            }
            _ => {
                let b: u8 = rng.random();
                if b == 0 || b == 255 {
                    continue;
                }
                format!("192.168.{b}.0/24")
                    .parse()
                    .unwrap_or("192.168.7.0/24".parse().unwrap())
            }
        };
        out.push(cidr);
    }
    out
}

pub fn select_peer_cidr(
    existing_plans: &[(Uuid, Ipv4Net)],
    host_nets: &[Ipv4Net],
) -> Result<AddressPlan, AddressPlanError> {
    let mut rng = rand::rng();
    select_peer_cidr_with_rng(&mut rng, existing_plans, host_nets)
}

fn select_peer_cidr_with_rng<R: rand::Rng>(
    rng: &mut R,
    existing_plans: &[(Uuid, Ipv4Net)],
    host_nets: &[Ipv4Net],
) -> Result<AddressPlan, AddressPlanError> {
    for cidr in candidate_pool(rng) {
        if validate_peer_cidr(&cidr, existing_plans, host_nets).is_ok() {
            return Ok(AddressPlan { peer_cidr: cidr });
        }
    }
    Err(AddressPlanError::NoSafeRange)
}

pub fn detect_conflicts(
    network_id: Uuid,
    network_name: &str,
    plan: &AddressPlan,
    other_plans: &[(Uuid, String, Ipv4Net)],
    host_nets: &[(Ipv4Net, Option<String>)],
    owned: &[Ipv4Net],
) -> Vec<NetworkConflict> {
    let mut out = Vec::new();
    let owned_hit = |c: &Ipv4Net| owned.iter().any(|o| o == c || overlaps(o, c));
    for (id, name, other) in other_plans {
        if *id == network_id {
            continue;
        }
        if overlaps(&plan.peer_cidr, other) {
            out.push(NetworkConflict {
                network_id,
                network_name: network_name.to_string(),
                peer_cidr: plan.peer_cidr,
                conflicting_prefix: *other,
                interface: Some(format!("tunnet:{name}")),
                category: ConflictCategory::ActiveDirectPlan,
            });
        }
    }
    for (h, iface) in host_nets {
        if owned_hit(h) {
            continue;
        }
        if overlaps(&plan.peer_cidr, h) {
            out.push(NetworkConflict {
                network_id,
                network_name: network_name.to_string(),
                peer_cidr: plan.peer_cidr,
                conflicting_prefix: *h,
                interface: iface.clone(),
                category: ConflictCategory::LanPrefix,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cgnat_public_linklocal() {
        let existing = vec![];
        let host: Vec<Ipv4Net> = vec![];
        assert_eq!(
            validate_peer_cidr(&"100.64.0.0/10".parse().unwrap(), &existing, &host),
            Err(AddressPlanError::BadPrefix)
        );
        assert!(validate_peer_cidr(&"100.64.0.0/24".parse().unwrap(), &existing, &host).is_err());
        assert!(validate_peer_cidr(&"8.8.8.0/24".parse().unwrap(), &existing, &host).is_err());
        assert!(validate_peer_cidr(&"127.0.0.0/24".parse().unwrap(), &existing, &host).is_err());
        assert!(validate_peer_cidr(&"169.254.0.0/24".parse().unwrap(), &existing, &host).is_err());
    }

    #[test]
    fn accepts_private_and_rejects_overlap() {
        let host: Vec<Ipv4Net> = vec![];
        validate_peer_cidr(&"10.23.45.0/24".parse().unwrap(), &[], &host).unwrap();
        let id = Uuid::new_v4();
        let existing = vec![(id, "10.23.45.0/24".parse().unwrap())];
        assert_eq!(
            validate_peer_cidr(&"10.23.45.0/24".parse().unwrap(), &existing, &host),
            Err(AddressPlanError::OverlapsActivePlan(id))
        );
        let lan: Vec<Ipv4Net> = vec!["192.168.1.0/24".parse().unwrap()];
        assert!(matches!(
            validate_peer_cidr(&"192.168.1.0/24".parse().unwrap(), &[], &lan),
            Err(AddressPlanError::HostConflict { .. })
        ));
    }

    #[test]
    fn allocator_skips_network_broadcast_and_is_stable() {
        let plan = AddressPlan {
            peer_cidr: "10.9.8.0/24".parse().unwrap(),
        };
        let nid = Uuid::new_v4();
        let occupied = HashSet::new();
        let a = allocate_peer_ip(&plan, &nid, &"aa".repeat(32), &occupied).unwrap();
        let b = allocate_peer_ip(&plan, &nid, &"aa".repeat(32), &occupied).unwrap();
        assert_eq!(a, b);
        assert!(is_usable_host(&plan.peer_cidr, &a));
        assert_ne!(a, plan.peer_cidr.network());
        assert_ne!(a, plan.peer_cidr.broadcast());
        let mut occ = HashSet::new();
        occ.insert(a);
        let c = allocate_peer_ip(&plan, &nid, &"aa".repeat(32), &occ).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn allocator_probes_collisions() {
        let plan = AddressPlan {
            peer_cidr: "192.168.200.0/28".parse().unwrap(),
        };
        let nid = Uuid::new_v4();
        let mut occupied = HashSet::new();
        let first = allocate_peer_ip(&plan, &nid, &"bb".repeat(32), &occupied).unwrap();
        occupied.insert(first);
        let second = allocate_peer_ip(&plan, &nid, &"bb".repeat(32), &occupied).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn selection_avoids_host_and_existing() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let existing = vec![];
        let host: Vec<Ipv4Net> = vec!["10.0.0.0/8".parse().unwrap()];
        let plan = select_peer_cidr_with_rng(&mut rng, &existing, &host).unwrap();
        assert!(!overlaps(&plan.peer_cidr, &"10.0.0.0/8".parse().unwrap()));
        assert!(is_rfc1918_net(&plan.peer_cidr));
    }

    #[test]
    fn own_routes_are_not_conflicts() {
        let nid = Uuid::new_v4();
        let plan = AddressPlan {
            peer_cidr: "10.44.0.0/24".parse().unwrap(),
        };
        let host = vec![("10.44.0.5/32".parse().unwrap(), Some("tunnet0".to_string()))];
        let owned: Vec<Ipv4Net> = vec!["10.44.0.5/32".parse().unwrap()];
        let conflicts = detect_conflicts(nid, "home", &plan, &[], &host, &owned);
        assert!(
            conflicts.is_empty()
                || !conflicts
                    .iter()
                    .any(|c| c.conflicting_prefix == "10.44.0.5/32".parse().unwrap())
        );
    }
}
