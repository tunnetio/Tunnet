//! Detect other interfaces that already claim the mesh CIDR.
//!
//! Direct mode puts a connected route for the whole mesh range on `tunnet0`.
//! When another overlay (most often Tailscale, which also uses
//! `100.64.0.0/10`) holds an address in that range, the two fight in the
//! kernel routing table and both degrade silently: our connected route
//! swallows their unpinned destinations, and their anti-spoof filter drops
//! our inbound mesh traffic.
//!
//! The failure is invisible today. `no_route` drops climb into the millions
//! with nothing saying why. This module turns that into a named, reported
//! condition. It only observes: nothing here changes routing.

use std::fmt;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Minimal view of a host interface.
///
/// Detection is expressed against this rather than `netdev::Interface` so the
/// logic is a pure function over plain data and testable without a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInterface {
    pub name: String,
    pub ipv4: Vec<Ipv4Net>,
}

impl HostInterface {
    pub fn new(name: impl Into<String>, ipv4: Vec<Ipv4Net>) -> Self {
        Self {
            name: name.into(),
            ipv4,
        }
    }
}

/// A foreign interface holding an address that overlaps the mesh CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCidrCollision {
    /// Interface claiming the overlapping address.
    pub interface: String,
    /// The specific overlapping address on that interface.
    pub addr: Ipv4Addr,
    /// Prefix length that address was configured with.
    pub prefix_len: u8,
    /// Well-known product that owns this interface, when recognisable.
    pub known_owner: Option<&'static str>,
}

impl fmt::Display for MeshCidrCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} holds {}/{}",
            self.interface, self.addr, self.prefix_len
        )?;
        if let Some(owner) = self.known_owner {
            write!(f, " (looks like {owner})")?;
        }
        Ok(())
    }
}

/// Recognise well-known overlays so the operator message can name the culprit
/// instead of just an interface string.
fn known_owner(ifname: &str) -> Option<&'static str> {
    let lower = ifname.to_ascii_lowercase();
    if lower.contains("tailscale") || lower.starts_with("ts") {
        return Some("Tailscale");
    }
    if lower.contains("zt") || lower.contains("zerotier") {
        return Some("ZeroTier");
    }
    if lower.contains("nebula") {
        return Some("Nebula");
    }
    None
}

/// True when two v4 networks share any address.
///
/// Mirrors the containment idiom already used in `system_routes`.
fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Find interfaces other than our own TUN whose addresses fall inside `mesh`.
///
/// Loopback is ignored: the mesh address itself appears in the host's local
/// table bound to `lo`, and that is us, not a collision.
pub fn detect(mesh: Ipv4Net, our_ifname: &str, hosts: &[HostInterface]) -> Vec<MeshCidrCollision> {
    let mesh = mesh.trunc();
    let mut found = Vec::new();
    for iface in hosts {
        if iface.name.eq_ignore_ascii_case(our_ifname) || iface.name.eq_ignore_ascii_case("lo") {
            continue;
        }
        for net in &iface.ipv4 {
            let addr = net.addr();
            if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() {
                continue;
            }
            if overlaps(mesh, *net) {
                found.push(MeshCidrCollision {
                    interface: iface.name.clone(),
                    addr,
                    prefix_len: net.prefix_len(),
                    known_owner: known_owner(&iface.name),
                });
            }
        }
    }
    found
}

/// Read the host's interfaces via `netdev`.
fn host_interfaces() -> Vec<HostInterface> {
    netdev::get_interfaces()
        .into_iter()
        .map(|iface| HostInterface::new(iface.name, iface.ipv4))
        .collect()
}

/// One of our own addresses that sits inside a contested range.
///
/// These are the concrete casualties. Another overlay's anti-spoof filter
/// (Tailscale installs `-s 100.64.0.0/10 ! -i tailscale0 -j DROP`) matches on
/// SOURCE address, so it drops this host's own loopback traffic to our
/// addresses too, not just peer traffic. Measured: 50 of 50 packets sent to
/// both our mesh IP and our MagicDNS resolver were dropped, while a loopback
/// control was untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtRiskLocalAddr {
    pub addr: Ipv4Addr,
    pub role: &'static str,
}

/// Our own addresses that fall inside a contested mesh range.
pub fn at_risk_local(
    mesh: Ipv4Net,
    mesh_ip: Ipv4Addr,
    magic_dns: Option<Ipv4Addr>,
) -> Vec<AtRiskLocalAddr> {
    let mesh = mesh.trunc();
    let mut out = Vec::new();
    if mesh.contains(&mesh_ip) {
        out.push(AtRiskLocalAddr {
            addr: mesh_ip,
            role: "this node's mesh address",
        });
    }
    if let Some(dns) = magic_dns
        && dns != mesh_ip
        && mesh.contains(&dns)
    {
        out.push(AtRiskLocalAddr {
            addr: dns,
            role: "MagicDNS resolver",
        });
    }
    out
}

/// Human-readable explanation for the agent log.
///
/// Kept separate from emission so the wording is directly testable.
pub fn describe(
    mesh: Ipv4Net,
    collisions: &[MeshCidrCollision],
    at_risk: &[AtRiskLocalAddr],
) -> String {
    let list = collisions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut msg = format!(
        "mesh CIDR {mesh} is also claimed by another interface: {list}. \
         Running two overlays on one range is not supported and fails silently."
    );
    if !at_risk.is_empty() {
        let casualties = at_risk
            .iter()
            .map(|a| format!("{} ({})", a.addr, a.role))
            .collect::<Vec<_>>()
            .join(", ");
        msg.push_str(&format!(
            " The other overlay's anti-spoof filter matches on SOURCE address, \
             so it will drop this host's own traffic to {casualties}, \
             including over loopback. Expect MagicDNS to fail with no error \
             and no log line: the resolver stays listening but never receives \
             a query."
        ));
    }
    msg.push_str(&format!(
        " Mesh traffic to addresses in {mesh} with no peer is also black-holed \
         on the mesh interface (see tunnet_dropped_packets_total)."
    ));
    msg
}

/// Check the live host for collisions, log and export them.
///
/// Best effort and non-fatal: a diagnostic must never stop the agent starting.
pub fn report(
    mesh: Ipv4Net,
    our_ifname: &str,
    mesh_ip: Ipv4Addr,
    magic_dns: Option<Ipv4Addr>,
) -> Vec<MeshCidrCollision> {
    let collisions = detect(mesh, our_ifname, &host_interfaces());
    metrics::gauge!("tunnet_mesh_cidr_collisions").set(collisions.len() as f64);
    for c in &collisions {
        metrics::gauge!(
            "tunnet_mesh_cidr_collision",
            "interface" => c.interface.clone(),
            "mesh_cidr" => mesh.to_string(),
        )
        .set(1.0);
    }
    if collisions.is_empty() {
        tracing::debug!(%mesh, "no mesh CIDR collision detected");
    } else {
        let at_risk = at_risk_local(mesh, mesh_ip, magic_dns);
        tracing::warn!(
            %mesh,
            collisions = collisions.len(),
            "{}",
            describe(mesh, &collisions, &at_risk)
        );
    }
    collisions
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn net(s: &str) -> Ipv4Net {
        s.parse().expect("test net")
    }

    fn cgnat() -> Ipv4Net {
        net("100.64.0.0/10")
    }

    /// The exact situation observed on the reporter's host: Tailscale holds a
    /// /32 inside the CGNAT range while tunnet0 owns the /10.
    #[test]
    fn detects_tailscale_sharing_cgnat() {
        let hosts = vec![
            HostInterface::new("tunnet0", vec![net("100.95.248.22/10")]),
            HostInterface::new("tailscale0", vec![net("100.122.80.25/32")]),
            HostInterface::new("wlp1s0", vec![net("192.168.1.183/24")]),
        ];
        let found = detect(cgnat(), "tunnet0", &hosts);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].interface, "tailscale0");
        assert_eq!(found[0].addr, Ipv4Addr::new(100, 122, 80, 25));
        assert_eq!(found[0].known_owner, Some("Tailscale"));
    }

    #[test]
    fn our_own_interface_is_not_a_collision() {
        let hosts = vec![HostInterface::new("tunnet0", vec![net("100.95.248.22/10")])];
        assert!(detect(cgnat(), "tunnet0", &hosts).is_empty());
    }

    #[test]
    fn loopback_is_not_a_collision() {
        // The mesh address is also present on `lo` in the host's local table.
        let hosts = vec![
            HostInterface::new("lo", vec![net("127.0.0.1/8"), net("100.95.248.22/32")]),
            HostInterface::new("tunnet0", vec![net("100.95.248.22/10")]),
        ];
        assert!(detect(cgnat(), "tunnet0", &hosts).is_empty());
    }

    #[test]
    fn unrelated_private_ranges_do_not_collide() {
        let hosts = vec![
            HostInterface::new("eth0", vec![net("192.168.1.221/24")]),
            HostInterface::new("docker0", vec![net("172.17.0.1/16")]),
            HostInterface::new("wg0", vec![net("10.8.0.2/24")]),
        ];
        assert!(detect(cgnat(), "tunnet0", &hosts).is_empty());
    }

    /// A supernet on another interface still overlaps even though the mesh
    /// does not contain its network address.
    #[test]
    fn supernet_on_another_interface_overlaps() {
        let hosts = vec![HostInterface::new("eth0", vec![net("100.0.0.1/8")])];
        let found = detect(cgnat(), "tunnet0", &hosts);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].interface, "eth0");
    }

    #[test]
    fn a_custom_mesh_range_avoids_the_tailscale_collision() {
        // The Phase 2 fix: move the mesh off CGNAT and the collision clears.
        let hosts = vec![
            HostInterface::new("tunnet0", vec![net("10.99.0.5/16")]),
            HostInterface::new("tailscale0", vec![net("100.122.80.25/32")]),
        ];
        assert!(detect(net("10.99.0.0/16"), "tunnet0", &hosts).is_empty());
    }

    #[test]
    fn reports_every_overlapping_address_on_one_interface() {
        let hosts = vec![HostInterface::new(
            "tailscale0",
            vec![net("100.122.80.25/32"), net("100.64.9.9/32")],
        )];
        assert_eq!(detect(cgnat(), "tunnet0", &hosts).len(), 2);
    }

    #[rstest]
    #[case::tailscale("tailscale0", Some("Tailscale"))]
    #[case::zerotier("ztabcdef12", Some("ZeroTier"))]
    #[case::nebula("nebula1", Some("Nebula"))]
    #[case::unknown("eth0", None)]
    fn known_owner_recognises_common_overlays(
        #[case] ifname: &str,
        #[case] expect: Option<&'static str>,
    ) {
        assert_eq!(known_owner(ifname), expect);
    }

    #[test]
    fn description_names_the_interface_and_the_range() {
        let found = detect(
            cgnat(),
            "tunnet0",
            &[HostInterface::new(
                "tailscale0",
                vec![net("100.122.80.25/32")],
            )],
        );
        let msg = describe(cgnat(), &found, &[]);
        assert!(msg.contains("100.64.0.0/10"));
        assert!(msg.contains("tailscale0"));
        assert!(msg.contains("Tailscale"));
    }

    /// The observed casualties on the reporter's host.
    #[test]
    fn at_risk_lists_mesh_ip_and_magic_dns() {
        let at_risk = at_risk_local(
            cgnat(),
            "100.95.248.22".parse().unwrap(),
            Some("100.100.100.53".parse().unwrap()),
        );
        assert_eq!(at_risk.len(), 2);
        assert_eq!(at_risk[0].addr, Ipv4Addr::new(100, 95, 248, 22));
        assert_eq!(at_risk[1].addr, Ipv4Addr::new(100, 100, 100, 53));
    }

    #[test]
    fn at_risk_is_empty_when_mesh_moves_off_the_contested_range() {
        let at_risk = at_risk_local(
            net("10.99.0.0/16"),
            "10.99.0.5".parse().unwrap(),
            Some("10.99.0.53".parse().unwrap()),
        );
        assert_eq!(at_risk.len(), 2, "still inside its own mesh");
        // ...but none of them are in the CGNAT range Tailscale polices.
        assert!(at_risk.iter().all(|a| !cgnat().contains(&a.addr)));
    }

    #[test]
    fn at_risk_does_not_duplicate_when_dns_equals_mesh_ip() {
        let ip: Ipv4Addr = "100.95.248.22".parse().unwrap();
        assert_eq!(at_risk_local(cgnat(), ip, Some(ip)).len(), 1);
    }

    /// The message must name the silent-DNS symptom, since that is the one an
    /// operator will actually observe.
    #[test]
    fn description_warns_about_loopback_and_magicdns() {
        let found = detect(
            cgnat(),
            "tunnet0",
            &[HostInterface::new(
                "tailscale0",
                vec![net("100.122.80.25/32")],
            )],
        );
        let at_risk = at_risk_local(
            cgnat(),
            "100.95.248.22".parse().unwrap(),
            Some("100.100.100.53".parse().unwrap()),
        );
        let msg = describe(cgnat(), &found, &at_risk);
        assert!(msg.contains("100.100.100.53"));
        assert!(msg.contains("loopback"));
        assert!(msg.contains("MagicDNS"));
        assert!(msg.contains("SOURCE"));
    }
}
