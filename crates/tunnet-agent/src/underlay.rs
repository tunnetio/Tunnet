use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Default)]
pub struct UnderlayInfo {
    pub interface_index: u32,
    pub interface_name: String,
    pub gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}

impl UnderlayInfo {
    pub fn discover() -> Option<Self> {
        let iface = netdev::get_default_interface().ok()?;
        let gateway = iface
            .gateway
            .as_ref()
            .and_then(|gw| {
                gw.ipv4
                    .first()
                    .copied()
                    .map(IpAddr::V4)
                    .or_else(|| gw.ipv6.first().copied().map(IpAddr::V6))
            })
            .or_else(|| {
                netdev::get_default_gateway().ok().and_then(|gw| {
                    gw.ipv4
                        .first()
                        .copied()
                        .map(IpAddr::V4)
                        .or_else(|| gw.ipv6.first().copied().map(IpAddr::V6))
                })
            });

        Some(Self {
            interface_index: iface.index,
            interface_name: iface.name,
            gateway,
            dns_servers: iface.dns_servers,
        })
    }

    pub fn gateway_v4(&self) -> Option<Ipv4Addr> {
        match self.gateway {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
    }
}

/// Underlay interface name used for NAT MASQUERADE.
pub fn default_uplink_name() -> Option<String> {
    UnderlayInfo::discover().map(|u| u.interface_name)
}
