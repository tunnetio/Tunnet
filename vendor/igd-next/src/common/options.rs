use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use crate::GatewayIpVersion;

/// Default timeout for a gateway search.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for each broadcast response during a gateway search.
#[allow(dead_code)]
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for a control request to the gateway.
#[allow(dead_code)]
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Default size (in bytes) of an HTTP response body accepted from the gateway.
#[allow(dead_code)]
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// The IPv6 link-local SSDP multicast address `FF02::C`.
pub const IPV6_SSDP_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);
/// The IPv6 site-local SSDP multicast address `FF05::C`.
pub const IPV6_SSDP_SITE_LOCAL: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x000c);

/// Gateway search configuration
///
/// SearchOptions::default() should suffice for most situations.
///
/// # Example
/// To customize options, start with `SearchOptions::default()` and assign fields.
/// ```
/// # use std::time::Duration;
/// # use igd_next::SearchOptions;
/// let mut opts = SearchOptions::default();
/// opts.timeout = Some(Duration::from_secs(60));
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct SearchOptions {
    /// Bind address for UDP socket (defaults to all `0.0.0.0`)
    pub bind_addr: SocketAddr,
    /// Broadcast address for discovery packets (defaults to `239.255.255.250:1900`)
    pub broadcast_address: SocketAddr,
    /// Timeout for a search iteration (defaults to 10s)
    pub timeout: Option<Duration>,
    /// Timeout for a single search response (defaults to 5s)
    pub single_search_timeout: Option<Duration>,
    /// Which IP version(s) of gateway to accept during discovery (defaults to `Both`).
    pub gateway_ip_version: GatewayIpVersion,
    /// Extra IP addresses trusted for device and service URLs during discovery.
    /// By default, these URLs must use the SSDP responder's IP address.
    pub allowed_gateway_ips: Vec<IpAddr>,
    /// Native authority applied before binding the SSDP socket.
    pub udp: Option<netwatch::SocketConfig>,
    /// Native authority retained for every gateway HTTP connection.
    pub tcp: Option<netwatch::TcpSocketConfig>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            bind_addr: (IpAddr::from([0, 0, 0, 0]), 0).into(),
            broadcast_address: "239.255.255.250:1900".parse().unwrap(),
            timeout: Some(DEFAULT_TIMEOUT),
            single_search_timeout: Some(RESPONSE_TIMEOUT),
            gateway_ip_version: GatewayIpVersion::Both,
            allowed_gateway_ips: Vec::new(),
            udp: None,
            tcp: None,
        }
    }
}

impl SearchOptions {
    /// Build search options for IPv6 SSDP discovery over the link-local scope (`FF02::C`).
    ///
    /// Binds to `[::]:0` and sends the `M-SEARCH` to `[FF02::C]:1900` on the interface identified
    /// by `scope_id` (its zone index such as from `if_nametoindex`, or the `if-addrs` crate). A
    /// scope id is required for link-local multicast because it has no routing.
    ///
    /// A gateway that advertises a link-local `LOCATION` is reached through the interface that
    /// received its SSDP response.
    ///
    /// # Example
    /// ```
    /// # use igd_next::SearchOptions;
    /// let opts = SearchOptions::ipv6(2); // scope id of the LAN interface
    /// ```
    pub fn ipv6(scope_id: u32) -> SearchOptions {
        SearchOptions {
            bind_addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            broadcast_address: SocketAddr::V6(SocketAddrV6::new(IPV6_SSDP_LINK_LOCAL, 1900, 0, scope_id)),
            ..Default::default()
        }
    }
}
