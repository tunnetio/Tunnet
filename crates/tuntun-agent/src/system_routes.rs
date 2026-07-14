//! Install OS routes for subnet routes, exit nodes, and split tunnels.

use std::net::Ipv4Addr;
use std::process::Command;

use ipnet::Ipv4Net;
use tuntun_common::{DeviceProfile, SplitTunnelMode};

/// Apply system routes for the given profile and remote subnet CIDRs.
pub fn apply(ifname: &str, profile: &DeviceProfile, remote_subnets: &[Ipv4Net], has_exit: bool) {
    // Always route advertised remote subnets into the TUN.
    for cidr in remote_subnets {
        add_route(ifname, cidr);
    }

    match profile.split_tunnel_mode {
        SplitTunnelMode::Include => {
            for cidr in &profile.split_tunnel_cidrs {
                add_route(ifname, cidr);
            }
        }
        SplitTunnelMode::Exclude => {
            if has_exit || profile.exit_node_endpoint_id.is_some() {
                add_default_via_tun(ifname);
                if let Some(gw) = detect_default_gateway() {
                    for cidr in &profile.split_tunnel_cidrs {
                        add_route_via_gateway(cidr, gw);
                    }
                }
            }
        }
    }
}

/// Tear down system routes previously installed by [`apply`].
pub fn unapply(ifname: &str, profile: &DeviceProfile, remote_subnets: &[Ipv4Net], has_exit: bool) {
    for cidr in remote_subnets {
        del_route(ifname, cidr);
    }

    match profile.split_tunnel_mode {
        SplitTunnelMode::Include => {
            for cidr in &profile.split_tunnel_cidrs {
                del_route(ifname, cidr);
            }
        }
        SplitTunnelMode::Exclude => {
            if has_exit || profile.exit_node_endpoint_id.is_some() {
                let default: Ipv4Net = "0.0.0.0/0".parse().expect("default");
                del_route(ifname, &default);
                if let Some(gw) = detect_default_gateway() {
                    for cidr in &profile.split_tunnel_cidrs {
                        del_route_via_gateway(cidr, gw);
                    }
                }
            }
        }
    }
}

fn del_route(ifname: &str, cidr: &Ipv4Net) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "del", &cidr.to_string(), "dev", ifname])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args(["-n", "delete", "-net", &cidr.to_string()])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "delete",
                "route",
                &cidr.to_string(),
                ifname,
            ])
            .status();
    }
    tracing::debug!(%cidr, ifname, "removed route via TUN");
}

fn del_route_via_gateway(cidr: &Ipv4Net, gateway: Ipv4Addr) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args([
                "route",
                "del",
                &cidr.to_string(),
                "via",
                &gateway.to_string(),
            ])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args(["-n", "delete", "-net", &cidr.to_string()])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("route")
            .args([
                "delete",
                &cidr.network().to_string(),
                "mask",
                &cidr.netmask().to_string(),
                &gateway.to_string(),
            ])
            .status();
    }
    let _ = gateway;
    tracing::debug!(%cidr, "removed excluded CIDR route");
}

fn add_route(ifname: &str, cidr: &Ipv4Net) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "replace", &cidr.to_string(), "dev", ifname])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args(["-n", "add", "-net", &cidr.to_string(), "-interface", ifname])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "add",
                "route",
                &cidr.to_string(),
                ifname,
                "metric=1",
            ])
            .status();
    }
    tracing::debug!(%cidr, ifname, "installed route via TUN");
}

fn add_default_via_tun(ifname: &str) {
    let default: Ipv4Net = "0.0.0.0/0".parse().expect("default");
    add_route(ifname, &default);
}

fn add_route_via_gateway(cidr: &Ipv4Net, gateway: Ipv4Addr) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args([
                "route",
                "replace",
                &cidr.to_string(),
                "via",
                &gateway.to_string(),
            ])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args(["-n", "add", "-net", &cidr.to_string(), &gateway.to_string()])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("route")
            .args([
                "add",
                &cidr.network().to_string(),
                "mask",
                &cidr.netmask().to_string(),
                &gateway.to_string(),
            ])
            .status();
    }
    tracing::debug!(%cidr, %gateway, "excluded CIDR via original gateway");
}

fn detect_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // default via 192.168.1.1 dev eth0
        for part in text.split_whitespace() {
            if let Ok(ip) = part.parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("gateway:") {
                if let Ok(ip) = rest.trim().parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let cols: Vec<_> = line.split_whitespace().collect();
            if cols.len() >= 3
                && cols[0] == "0.0.0.0"
                && let Ok(ip) = cols[2].parse::<Ipv4Addr>()
            {
                return Some(ip);
            }
        }
    }
    None
}
