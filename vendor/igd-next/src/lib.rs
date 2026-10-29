#![deny(missing_docs)]

//! This library allows you to communicate with an IGD enabled device.
//! Use one of the `search_gateway` functions to obtain a `Gateway` object.
//! You can then communicate with the device via this object.

// data structures
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
pub use self::common::options::{IPV6_SSDP_LINK_LOCAL, IPV6_SSDP_SITE_LOCAL};
#[cfg(all(feature = "ipv6", any(feature = "io_sync", feature = "aio_tokio")))]
pub use self::common::parsing::FirewallStatus;
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
pub use self::common::parsing::PortMappingEntry;
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
pub use self::common::SearchOptions;
#[cfg(all(feature = "ipv6", any(feature = "io_sync", feature = "aio_tokio")))]
pub use self::errors::PinholeError;
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
pub use self::errors::{
    AddAnyPortError, AddPortError, GetExternalIpError, GetGenericPortMappingEntryError, RemovePortError, RequestError,
    SearchError,
};
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
pub use self::errors::{Error, Result};
#[cfg(feature = "io_sync")]
pub use self::gateway::Gateway;
#[cfg(all(feature = "io_sync", feature = "ipv6"))]
pub use self::gateway::Ipv6FirewallGateway;

// search of gateway
#[cfg(feature = "io_sync")]
pub use self::search::search_gateway;
#[cfg(all(feature = "io_sync", feature = "ipv6"))]
pub use self::search::search_ipv6_firewall_gateway;

#[cfg(feature = "aio_tokio")]
pub mod aio;
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
mod common;
#[cfg(any(feature = "io_sync", feature = "aio_tokio"))]
mod errors;
#[cfg(feature = "io_sync")]
mod gateway;
#[cfg(feature = "io_sync")]
mod search;

use std::fmt;

/// Represents the protocols available for port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortMappingProtocol {
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
}

impl fmt::Display for PortMappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                PortMappingProtocol::TCP => "TCP",
                PortMappingProtocol::UDP => "UDP",
            }
        )
    }
}

/// Which IP version of gateway to accept during discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GatewayIpVersion {
    /// Only accept gateways reachable at an IPv4 address.
    V4,
    /// Only accept gateways reachable at an IPv6 address.
    V6,
    /// Accept gateways reachable at either an IPv4 or IPv6 address.
    #[default]
    Both,
}

impl GatewayIpVersion {
    /// Whether a gateway advertising `IpAddr` matches this preference.
    pub fn accepts(self, ip: std::net::IpAddr) -> bool {
        match self {
            GatewayIpVersion::V4 => ip.is_ipv4(),
            GatewayIpVersion::V6 => ip.is_ipv6(),
            GatewayIpVersion::Both => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn gateway_ip_version_accepts() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(GatewayIpVersion::V4.accepts(v4));
        assert!(!GatewayIpVersion::V4.accepts(v6));
        assert!(GatewayIpVersion::V6.accepts(v6));
        assert!(!GatewayIpVersion::V6.accepts(v4));
        assert!(GatewayIpVersion::Both.accepts(v4));
        assert!(GatewayIpVersion::Both.accepts(v6));
        assert_eq!(GatewayIpVersion::default(), GatewayIpVersion::Both);
    }
}
