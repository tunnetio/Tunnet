//! Portmapper integration.
//!
//! Wraps the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

use std::net::SocketAddrV4;

use tokio::sync::watch;

/// Configuration for the portmapper service (UPnP, PCP, NAT-PMP).
///
/// Port mapping asks the local router to open an external port so peers can
/// reach this endpoint directly, improving connectivity behind NATs. The
/// discovery step (UPnP uses SSDP multicast) can, however, trigger firewall
/// prompts on some networks — see [`PortmapperConfig::Disabled`].
///
/// Used with [`crate::endpoint::Builder::portmapper_config`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PortmapperConfig {
    /// Enable portmapping with default settings.
    ///
    /// This is the default.
    #[non_exhaustive]
    Enabled {},
    /// Disable portmapping.
    ///
    /// Skips the UPnP/PCP/NAT-PMP gateway probing. Use this to avoid the
    /// SSDP multicast discovery that can raise firewall dialogs (notably on
    /// macOS), at the cost of potentially worse direct connectivity behind
    /// some NATs.
    Disabled,
}

impl Default for PortmapperConfig {
    fn default() -> Self {
        PortmapperConfig::Enabled {}
    }
}

#[cfg(all(not(wasm_browser), feature = "portmapper"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NatAuthority {
    pub udp: Option<[Option<netwatch::SocketConfig>; 2]>,
    pub tcp: Option<[Option<netwatch::TcpSocketConfig>; 2]>,
}

#[cfg(all(not(wasm_browser), feature = "portmapper"))]
pub(crate) fn authority_from_defaults(
    defaults: impl Iterator<Item = (bool, netwatch::SocketConfig)>,
    relay_tcp: Option<[Option<netwatch::TcpSocketConfig>; 2]>,
) -> NatAuthority {
    let Some(tcp) = relay_tcp else {
        return NatAuthority {
            udp: None,
            tcp: None,
        };
    };
    let mut udp = [None, None];
    for (is_ipv6, config) in defaults {
        udp[usize::from(is_ipv6)] = Some(config);
    }
    NatAuthority {
        udp: Some(udp),
        tcp: Some(tcp),
    }
}

pub(crate) fn create_client(
    config: &PortmapperConfig,
    #[cfg(all(not(wasm_browser), feature = "portmapper"))] authority: NatAuthority,
) -> Client {
    match config {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        PortmapperConfig::Enabled {} => {
            Client::Enabled(::portmapper::Client::new(::portmapper::Config {
                enable_upnp: true,
                enable_pcp: true,
                enable_nat_pmp: true,
                protocol: ::portmapper::Protocol::Udp,
                udp: authority.udp,
                tcp: authority.tcp,
            }))
        }
        _ => {
            let (tx, rx) = watch::channel(None);
            Client::Disabled { _tx: tx, rx }
        }
    }
}

#[cfg(all(test, not(wasm_browser), feature = "portmapper"))]
mod tests {
    use super::*;

    fn protected_udp() -> netwatch::SocketConfig {
        fn allow(_: &std::net::UdpSocket) -> std::io::Result<()> {
            Ok(())
        }
        netwatch::SocketConfig {
            interface: None,
            initialize: Some(allow),
        }
    }

    #[test]
    fn system_nat_stays_unscoped_without_relay_tcp() {
        let authority = authority_from_defaults(std::iter::once((false, protected_udp())), None);
        assert!(authority.udp.is_none());
        assert!(authority.tcp.is_none());
    }

    #[test]
    fn relay_tcp_carries_only_default_family_sockets() {
        fn allow(_: &std::net::TcpStream) -> std::io::Result<()> {
            Ok(())
        }
        let tcp = [
            Some(netwatch::TcpSocketConfig {
                interface: None,
                initialize: Some(allow),
            }),
            None,
        ];
        let authority =
            authority_from_defaults(std::iter::once((false, protected_udp())), Some(tcp));
        let udp = authority.udp.unwrap();
        assert!(udp[0].unwrap().initialize.is_some());
        assert!(udp[1].is_none());
        assert!(authority.tcp.unwrap()[0].unwrap().initialize.is_some());
        assert!(authority.tcp.unwrap()[1].is_none());
    }
}

/// Portmapper client: either the real implementation or a no-op.
///
/// The disabled variant is used when the `portmapper` feature is off, on wasm,
/// or when portmapping is disabled via [`PortmapperConfig::Disabled`].
#[derive(Debug)]
pub(crate) enum Client {
    /// The real portmapper client (requires the `portmapper` feature).
    #[cfg(all(not(wasm_browser), feature = "portmapper"))]
    Enabled(::portmapper::Client),
    /// No-op: keeps the sender alive so the receiver never closes.
    Disabled {
        _tx: watch::Sender<Option<SocketAddrV4>>,
        rx: watch::Receiver<Option<SocketAddrV4>>,
    },
}

impl Client {
    pub(crate) fn procure_mapping(&self) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.procure_mapping(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn update_local_port(&self, _port: std::num::NonZeroU16) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.update_local_port(_port),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn deactivate(&self) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.deactivate(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.watch_external_address(),
            Client::Disabled { rx, .. } => rx.clone(),
        }
    }
}
