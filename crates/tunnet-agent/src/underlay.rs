//! Underlay discovery: the physical interface, gateway and resolvers beneath
//! the tunnel. Used by desktop OS route reconciliation.
#![cfg_attr(target_os = "android", allow(dead_code))]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "linux")]
fn initialize_udp_socket(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let size: libc::c_int = 7 << 20;
    // The socket and option value remain valid for this call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            std::ptr::from_ref(&size).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(error);
        }
        tracing::warn!(%error, "UDP receive buffer remains limited by the kernel");
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub async fn discover_transport(
    tun_name: &str,
    overlay_ips: &[IpAddr],
) -> anyhow::Result<TransportUnderlay> {
    let all_interfaces = netdev::get_interfaces();
    #[cfg(not(windows))]
    let dns_observable = !all_interfaces.iter().any(|iface| {
        (iface.default
            && (iface.name == tun_name || iface.friendly_name.as_deref() == Some(tun_name)))
            || iface
                .dns_servers
                .contains(&IpAddr::V4(tunnet_common::VirtualResolverEndpoint::IP))
    });
    let interfaces: Vec<_> = all_interfaces
        .into_iter()
        .filter(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface.name != tun_name
                && iface.friendly_name.as_deref() != Some(tun_name)
                && iface.index != 0
                && !iface
                    .ipv4
                    .iter()
                    .any(|ip| overlay_ips.contains(&IpAddr::V4(ip.addr())))
                && !iface
                    .ipv6
                    .iter()
                    .any(|ip| overlay_ips.contains(&IpAddr::V6(ip.addr())))
        })
        .collect();
    let routes = route_manager::AsyncRouteManager::new()?.list().await?;
    let bindings = bindings_from_routes(&interfaces, &routes)?;
    let signature = underlay_signature(&bindings, &interfaces, &routes);
    #[cfg(not(windows))]
    let signature = if dns_observable {
        signature
    } else {
        UnderlaySignature {
            dns: None,
            ..signature
        }
    };
    Ok(TransportUnderlay {
        bindings,
        signature,
    })
}

#[cfg(not(target_os = "android"))]
fn underlay_signature(
    bindings: &[(std::net::SocketAddr, iroh::endpoint::BindOpts)],
    interfaces: &[netdev::Interface],
    routes: &[route_manager::Route],
) -> UnderlaySignature {
    let mut defaults: Vec<_> = routes
        .iter()
        .filter(|route| route.prefix() == 0)
        .filter_map(|route| {
            let iface = interfaces
                .iter()
                .find(|iface| interface_matches_route(iface, route))?;
            #[cfg(any(windows, target_os = "linux"))]
            let metric = route.metric().unwrap_or(0);
            #[cfg(not(any(windows, target_os = "linux")))]
            let metric = 0;
            Some(DefaultRouteSignature {
                destination: route.destination(),
                gateway: route.gateway(),
                interface: iface.index,
                metric,
            })
        })
        .collect();
    defaults.sort_unstable();
    let mut dns: Vec<_> = interfaces
        .iter()
        .map(|iface| {
            let mut servers = iface
                .dns_servers
                .iter()
                .copied()
                .filter(|ip| {
                    !ip.is_loopback()
                        && *ip != IpAddr::V4(tunnet_common::VirtualResolverEndpoint::IP)
                })
                .collect::<Vec<_>>();
            servers.sort_unstable();
            servers.dedup();
            (iface.index, servers)
        })
        .collect();
    dns.sort_unstable();
    UnderlaySignature {
        bindings: bindings
            .iter()
            .map(|(address, options)| BindingSignature {
                address: *address,
                prefix: options.prefix_len(),
                default_route: options.is_default_route(),
                interface: options.socket_config().interface,
            })
            .collect(),
        defaults,
        dns: Some(dns),
    }
}

#[cfg(not(target_os = "android"))]
pub struct TransportUnderlay {
    pub bindings: Vec<(std::net::SocketAddr, iroh::endpoint::BindOpts)>,
    signature: UnderlaySignature,
}

#[cfg(not(target_os = "android"))]
impl TransportUnderlay {
    pub fn same_network(&self, other: &Self) -> bool {
        self.signature.bindings == other.signature.bindings
            && self.signature.defaults == other.signature.defaults
            && match (&self.signature.dns, &other.signature.dns) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct UnderlaySignature {
    bindings: Vec<BindingSignature>,
    defaults: Vec<DefaultRouteSignature>,
    dns: Option<Vec<(u32, Vec<IpAddr>)>>,
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BindingSignature {
    address: std::net::SocketAddr,
    prefix: u8,
    default_route: bool,
    interface: Option<iroh::endpoint::InterfaceBinding>,
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DefaultRouteSignature {
    destination: IpAddr,
    gateway: Option<IpAddr>,
    interface: u32,
    metric: u32,
}

#[cfg(not(target_os = "android"))]
fn bindings_from_routes(
    interfaces: &[netdev::Interface],
    routes: &[route_manager::Route],
) -> anyhow::Result<Vec<(std::net::SocketAddr, iroh::endpoint::BindOpts)>> {
    use std::net::{SocketAddr, SocketAddrV6};
    use std::num::NonZeroU32;

    let defaults = [
        preferred_interface(interfaces, routes, true),
        preferred_interface(interfaces, routes, false),
    ];
    let mut default_assigned = [false; 2];
    let mut interfaces: Vec<_> = interfaces.iter().collect();
    interfaces.sort_by_key(|iface| iface.index);
    let mut bindings = Vec::new();
    for iface in interfaces {
        let mut addresses: Vec<_> = iface
            .ipv4
            .iter()
            .map(|net| (IpAddr::V4(net.addr()), net.prefix_len(), 0))
            .chain(
                iface
                    .ipv6
                    .iter()
                    .map(|net| (IpAddr::V6(net.addr()), net.prefix_len(), 0)),
            )
            .filter(|(ip, _, _)| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast())
            .collect();
        addresses.sort_unstable();
        for (ip, prefix, scope) in addresses {
            let family = usize::from(ip.is_ipv6());
            let is_default = defaults[family] == Some(iface.index) && !default_assigned[family];
            default_assigned[family] |= is_default;
            let address = match ip {
                IpAddr::V4(_) => SocketAddr::new(ip, 0),
                IpAddr::V6(ip) => {
                    let scope = if ip.is_unicast_link_local() {
                        iroh::endpoint::InterfaceBinding::new(
                            NonZeroU32::new(iface.index).expect("validated interface"),
                        )?
                        .index_for_family(iroh::endpoint::IpFamily::V6)?
                        .get()
                    } else {
                        scope
                    };
                    SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, scope))
                }
            };
            bindings.push((
                address,
                iroh::endpoint::BindOpts::default()
                    .set_prefix_len(prefix)
                    .set_is_default_route(is_default)
                    .set_socket_config(iroh::endpoint::SocketConfig {
                        interface: Some(iroh::endpoint::InterfaceBinding::new(
                            NonZeroU32::new(iface.index).expect("validated interface"),
                        )?),
                        initialize: {
                            #[cfg(target_os = "linux")]
                            {
                                Some(initialize_udp_socket)
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                None
                            }
                        },
                    }),
            ));
        }
    }
    anyhow::ensure!(
        !bindings.is_empty(),
        "no usable non-Tunnet underlay interface"
    );
    Ok(bindings)
}

#[cfg(not(target_os = "android"))]
pub fn relay_tcp_config(
    bindings: &[(std::net::SocketAddr, iroh::endpoint::BindOpts)],
) -> [Option<iroh::endpoint::TcpSocketConfig>; 2] {
    let mut config = [None; 2];
    for (address, options) in bindings {
        if options.is_default_route() {
            config[usize::from(address.is_ipv6())] = Some(iroh::endpoint::TcpSocketConfig {
                interface: options.socket_config().interface,
                initialize: None,
            });
        }
    }
    config
}

#[cfg(not(target_os = "android"))]
fn preferred_interface(
    interfaces: &[netdev::Interface],
    routes: &[route_manager::Route],
    v4: bool,
) -> Option<u32> {
    routes
        .iter()
        .filter(|route| route.prefix() == 0 && route.destination().is_ipv4() == v4)
        .filter_map(|route| {
            let iface = interfaces
                .iter()
                .find(|iface| interface_matches_route(iface, route))?;
            Some((route_metric(route, iface)?, iface.index))
        })
        .min()
        .map(|(_, index)| index)
}

#[cfg(not(target_os = "android"))]
fn route_metric(route: &route_manager::Route, iface: &netdev::Interface) -> Option<u64> {
    #[cfg(any(windows, target_os = "linux"))]
    let metric = u64::from(route.metric().unwrap_or(0));
    #[cfg(not(any(windows, target_os = "linux")))]
    let metric = 0;
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
        let family = if route.destination().is_ipv4() {
            iroh::endpoint::IpFamily::V4
        } else {
            iroh::endpoint::IpFamily::V6
        };
        let index = iroh::endpoint::InterfaceBinding::new(std::num::NonZeroU32::new(iface.index)?)
            .ok()?
            .index_for_family(family)
            .ok()?;
        let mut row = MIB_IPINTERFACE_ROW {
            Family: if route.destination().is_ipv4() {
                AF_INET
            } else {
                AF_INET6
            },
            InterfaceIndex: index.get(),
            ..Default::default()
        };
        if unsafe { GetIpInterfaceEntry(&mut row) } != 0 {
            return None;
        }
        Some(metric + u64::from(row.Metric))
    }
    #[cfg(not(windows))]
    {
        let _ = (iface, route);
        Some(metric)
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnderlayInfo {
    pub interface_index: u32,
    pub interface_name: String,
    pub gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}

impl UnderlayInfo {
    #[cfg(not(target_os = "android"))]
    pub fn discover(tun_name: &str) -> Option<Self> {
        let interfaces: Vec<_> = netdev::get_interfaces()
            .into_iter()
            .filter(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && iface.index != 0
                    && iface.name != tun_name
                    && iface.friendly_name.as_deref() != Some(tun_name)
            })
            .collect();
        let routes = route_manager::RouteManager::new().ok()?.list().ok()?;
        let (route, iface, _) = routes
            .iter()
            .filter(|route| route.prefix() == 0)
            .filter_map(|route| {
                let iface = interfaces
                    .iter()
                    .find(|iface| interface_matches_route(iface, route))?;
                Some((route, iface, route_metric(route, iface)?))
            })
            .min_by_key(|(route, iface, metric)| {
                (route.destination().is_ipv6(), *metric, iface.index)
            })?;
        Some(Self {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            gateway: route.gateway(),
            dns_servers: iface.dns_servers.clone(),
        })
    }

    #[cfg(target_os = "android")]
    pub fn discover(_: &str) -> Option<Self> {
        None
    }

    pub fn gateway_v4(&self) -> Option<Ipv4Addr> {
        match self.gateway {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
    }
}

/// Underlay interface name used for NAT MASQUERADE.
pub fn default_uplink_name(tun_name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let index = UnderlayInfo::discover(tun_name)?.interface_index;
        netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.index == index)?
            .friendly_name
    }
    #[cfg(not(windows))]
    {
        UnderlayInfo::discover(tun_name).map(|u| u.interface_name)
    }
}

#[cfg(not(target_os = "android"))]
fn interface_matches_route(iface: &netdev::Interface, route: &route_manager::Route) -> bool {
    if route.if_name() == Some(&iface.name) {
        return true;
    }
    let Some(index) = std::num::NonZeroU32::new(iface.index) else {
        return false;
    };
    let family = if route.destination().is_ipv4() {
        iroh::endpoint::IpFamily::V4
    } else {
        iroh::endpoint::IpFamily::V6
    };
    iroh::endpoint::InterfaceBinding::new(index)
        .and_then(|binding| binding.index_for_family(family))
        .is_ok_and(|index| route.if_index() == Some(index.get()))
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use iroh::endpoint::{BindOpts, presets};

    #[test]
    fn underlay_signature_ignores_overlay_routes_and_dns_order() {
        use super::underlay_signature;
        use route_manager::Route;

        let mut interface = netdev::Interface::dummy();
        interface.index = 7;
        interface.name = "ethernet".into();
        interface.dns_servers = vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        let bindings = vec![("192.0.2.2:0".parse().unwrap(), BindOpts::default())];
        let default = Route::new("0.0.0.0".parse().unwrap(), 0)
            .with_if_name(interface.name.clone())
            .with_gateway("192.0.2.1".parse().unwrap());
        let baseline = underlay_signature(
            &bindings,
            &[interface.clone()],
            std::slice::from_ref(&default),
        );
        interface.dns_servers.reverse();
        interface
            .dns_servers
            .push(tunnet_common::VirtualResolverEndpoint::IP.into());
        interface.dns_servers.push("127.0.0.1".parse().unwrap());
        let routes = vec![
            Route::new("0.0.0.0".parse().unwrap(), 0).with_if_name("tunnet0".into()),
            Route::new("100.64.0.0".parse().unwrap(), 16).with_if_name("tunnet0".into()),
            default.clone(),
        ];
        assert_eq!(
            baseline,
            underlay_signature(&bindings, &[interface.clone()], &routes)
        );
        let captured = super::TransportUnderlay {
            bindings: Vec::new(),
            signature: baseline.clone(),
        };
        let mut hidden_dns = super::TransportUnderlay {
            bindings: Vec::new(),
            signature: baseline.clone(),
        };
        hidden_dns.signature.dns = None;
        assert!(captured.same_network(&hidden_dns));
        let changed_gateway = default.with_gateway("192.0.2.254".parse().unwrap());
        assert_ne!(
            baseline,
            underlay_signature(&bindings, &[interface.clone()], &[changed_gateway])
        );
        interface.dns_servers.push("9.9.9.9".parse().unwrap());
        assert_ne!(
            baseline,
            underlay_signature(&bindings, &[interface], &routes)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_defaults_ignore_the_tun_default_interface_hint() {
        use route_manager::Route;
        let mut first = netdev::Interface::dummy();
        first.index = 7;
        first.name = "ethernet".into();
        first.default = true;
        let mut second = netdev::Interface::dummy();
        second.index = 8;
        second.name = "wifi".into();
        let mut interfaces = vec![first, second];
        let mut routes = vec![
            Route::new("0.0.0.0".parse().unwrap(), 0)
                .with_if_name("ethernet".into())
                .with_metric(20),
            Route::new("0.0.0.0".parse().unwrap(), 0)
                .with_if_name("wifi".into())
                .with_metric(10),
        ];
        assert_eq!(
            super::preferred_interface(&interfaces, &routes, true),
            Some(8)
        );
        interfaces[0].default = false;
        routes.insert(
            0,
            Route::new("0.0.0.0".parse().unwrap(), 0)
                .with_if_name("tunnet0".into())
                .with_metric(1),
        );
        assert_eq!(
            super::preferred_interface(&interfaces, &routes, true),
            Some(8)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_initialization_preserves_the_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        super::initialize_udp_socket(&socket).unwrap();
        assert_eq!(socket.local_addr().unwrap(), address);
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        socket.send_to(b"ok", address).unwrap();
        let mut packet = [0; 2];
        assert_eq!(socket.recv_from(&mut packet).unwrap(), (2, address));
        assert_eq!(&packet, b"ok");
    }

    #[rstest::rstest]
    #[case("127.0.0.1:0", true)]
    #[case("127.0.0.1:0", false)]
    #[case("[::1]:0", true)]
    #[case("[::1]:0", false)]
    fn default_binding_can_precede_or_follow_other_bindings(
        #[case] address: std::net::SocketAddr,
        #[case] default_first: bool,
    ) {
        let mut builder = iroh::Endpoint::builder(presets::Minimal).clear_ip_transports();
        for is_default in [default_first, !default_first] {
            builder = builder
                .bind_addr_with_opts(
                    address,
                    BindOpts::default().set_is_default_route(is_default),
                )
                .unwrap();
        }
        assert!(
            builder
                .bind_addr_with_opts(address, BindOpts::default().set_is_default_route(true),)
                .is_err()
        );
    }
}
