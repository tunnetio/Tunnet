//! Endpoint connectivity: resolved relay policy plus independent discovery flags.
//!
//! Relay selection is [`EffectiveRelayPolicy`] only. DHT, mDNS, and LAN discovery
//! are separate and never implied by a connectivity "profile".

use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use ipnet::Ipv4Net;
use iroh::Endpoint;
use iroh::RelayMode;
use iroh::address_lookup::AddrFilter;
use iroh::dns::{BoxIter, DNS_TIMEOUT, DnsError, DnsResolver, Resolver, TxtRecordData};
use iroh::endpoint::Builder;
use iroh::endpoint::presets;
use iroh::{EndpointAddr, RelayConfig, RelayMap, TransportAddr};
#[cfg(feature = "direct")]
use iroh_mainline_address_lookup::DhtAddressLookup;
use tunnet_common::VirtualResolverEndpoint;
use tunnet_common::{ConnectivityRelayConfig, ConnectivityRelayFallback};

#[cfg(feature = "direct")]
use super::mdns::apply_mdns;
pub use super::relay_policy::{
    DirectRelayInput, DirectRelayMode, EffectiveRelayPolicy, RelayResolveError,
    resolve_direct_relay_policy, resolve_managed_relay_policy,
};

/// Endpoint settings after relay policy has already been resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectivityOptions {
    pub relay: EffectiveRelayPolicy,
    pub enable_dht: bool,
    pub enable_mdns: bool,
    pub enable_lan_discovery: bool,
}

impl Default for ConnectivityOptions {
    fn default() -> Self {
        Self {
            relay: EffectiveRelayPolicy::N0,
            enable_dht: true,
            enable_mdns: true,
            enable_lan_discovery: true,
        }
    }
}

impl ConnectivityOptions {
    pub fn direct_from_input(
        input: &DirectRelayInput,
        enable_dht: bool,
        enable_mdns: bool,
        enable_lan_discovery: bool,
    ) -> Result<Self, RelayResolveError> {
        Ok(Self {
            relay: resolve_direct_relay_policy(input)?,
            enable_dht,
            enable_mdns,
            enable_lan_discovery,
        })
    }

    /// Shared Direct path for the daemon runtime and `tunnet join`.
    pub fn from_direct_config(
        cfg: &crate::TunnetConfig,
        credentials: std::collections::BTreeMap<String, String>,
        mode_override: Option<&str>,
        urls_override: Option<&str>,
    ) -> Result<Self, RelayResolveError> {
        let input = cfg
            .direct_relay_input(credentials)
            .overlay_process_env()?
            .overlay_mode_and_urls(mode_override, urls_override)?;
        Self::direct_from_input(
            &input,
            cfg.effective_dht_default(),
            cfg.effective_mdns_default(),
            cfg.effective_lan_discovery_default(),
        )
    }

    /// Direct defaults: `auto` with no custom relays → N0.
    pub fn direct_default(enable_mdns: bool) -> Self {
        Self {
            relay: EffectiveRelayPolicy::N0,
            enable_dht: true,
            enable_mdns,
            enable_lan_discovery: true,
        }
    }

    /// Fail-closed until the control-plane snapshot is applied.
    pub fn managed_default() -> Self {
        Self {
            relay: EffectiveRelayPolicy::Disabled,
            enable_dht: false,
            enable_mdns: false,
            enable_lan_discovery: false,
        }
    }

    /// Replace relay policy from the control-plane snapshot. Local Direct
    /// `relay-mode` is ignored.
    pub fn with_managed_snapshot(
        mut self,
        relays: Vec<ConnectivityRelayConfig>,
        fallback: ConnectivityRelayFallback,
    ) -> Result<Self, RelayResolveError> {
        self.relay = resolve_managed_relay_policy(&relays, fallback)?;
        Ok(self)
    }
}

/// Build an iroh [`RelayMap`] from resolved custom relay configs.
pub fn relay_map_from_configs(
    relays: &[ConnectivityRelayConfig],
) -> Result<RelayMap, iroh::RelayUrlParseError> {
    let map = RelayMap::empty();
    for relay in relays {
        let url: iroh::RelayUrl = relay.url.parse()?;
        let mut config = RelayConfig::from(url.clone());
        if let Some(token) = relay.auth_token.as_deref().filter(|t| !t.is_empty()) {
            config = config.with_auth_token(token.to_string());
        }
        map.insert(url, Arc::new(config));
    }
    Ok(map)
}

fn apply_relay_policy(builder: Builder, policy: &EffectiveRelayPolicy) -> Builder {
    match policy {
        EffectiveRelayPolicy::N0 => builder,
        EffectiveRelayPolicy::Custom(relays) => {
            let map =
                relay_map_from_configs(relays).expect("resolver already validated relay URLs");
            builder.relay_mode(RelayMode::Custom(map))
        }
        EffectiveRelayPolicy::Disabled => builder.relay_mode(RelayMode::Disabled),
    }
}

/// DNS that omits AAAA when A exists.
///
/// iroh picks the relay TCP family from `udp_v6` in net report (IPv6 first when
/// IPv6 STUN works). n0's IPv4 and IPv6 frontends do not share QUIC-over-relay
/// sessions, so a dual-stack coordinator never sees an IPv4-only joiner. Direct
/// UDP IPv6 is unchanged: magicsock still binds `[::]` and holepunches.
fn ipv4_preferred_dns() -> DnsResolver {
    DnsResolver::custom(Ipv4PreferredDns {
        inner: DnsResolver::new(),
    })
}

#[derive(Debug, Clone)]
struct Ipv4PreferredDns {
    inner: DnsResolver,
}

impl Ipv4PreferredDns {
    fn lookup_v4(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<Ipv4Addr>, DnsError>> + Send>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let addrs = inner.lookup_ipv4(host, DNS_TIMEOUT).await?;
            let v4: Vec<Ipv4Addr> = addrs
                .filter_map(|ip| match ip {
                    IpAddr::V4(v) => Some(v),
                    IpAddr::V6(_) => None,
                })
                .collect();
            Ok(Box::new(v4.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }
}

impl Resolver for Ipv4PreferredDns {
    fn lookup_ipv4(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<Ipv4Addr>, DnsError>> + Send>> {
        self.lookup_v4(host)
    }

    fn lookup_ipv6(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<Ipv6Addr>, DnsError>> + Send>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            if let Ok(mut v4) = inner.lookup_ipv4(host.clone(), DNS_TIMEOUT).await
                && v4.any(|ip| ip.is_ipv4())
            {
                return Ok(Box::new(std::iter::empty()) as BoxIter<Ipv6Addr>);
            }
            let addrs = inner.lookup_ipv6(host, DNS_TIMEOUT).await?;
            let v6: Vec<Ipv6Addr> = addrs
                .filter_map(|ip| match ip {
                    IpAddr::V6(v) => Some(v),
                    IpAddr::V4(_) => None,
                })
                .collect();
            Ok(Box::new(v6.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<TxtRecordData>, DnsError>> + Send>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let recs: Vec<TxtRecordData> = inner.lookup_txt(host, DNS_TIMEOUT).await?.collect();
            Ok(Box::new(recs.into_iter()) as BoxIter<TxtRecordData>)
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn Resolver> {
        self.inner.reset();
        Box::new(Self {
            inner: self.inner.clone(),
        })
    }
}

/// Start an endpoint builder from the resolved relay policy.
///
/// N0 uses the n0 preset (relays + n0 DNS lookup). Custom and Disabled use
/// [`presets::Minimal`] so n0 DNS discovery is not pulled in as a side effect.
pub fn endpoint_builder(opts: &ConnectivityOptions) -> Builder {
    let builder = match &opts.relay {
        EffectiveRelayPolicy::N0 => Endpoint::builder(presets::N0),
        EffectiveRelayPolicy::Custom(_) | EffectiveRelayPolicy::Disabled => {
            Endpoint::builder(presets::Minimal)
        }
    };
    apply_relay_policy(builder.dns_resolver(ipv4_preferred_dns()), &opts.relay)
}

/// True when an IPv4 address belongs to a Tunnet overlay or the in-TUN resolver.
pub fn is_overlay_underlay_ip(ip: std::net::Ipv4Addr, overlay_nets: &[Ipv4Net]) -> bool {
    ip == VirtualResolverEndpoint::IP || overlay_nets.iter().any(|net| net.contains(&ip))
}

/// Drop overlay/TUN IPv4 candidates. Relays, IPv6, and non-overlay IPv4 stay.
pub fn strip_overlay_addrs(mut addr: EndpointAddr, overlay_nets: &[Ipv4Net]) -> EndpointAddr {
    addr.addrs.retain(|a| match a {
        TransportAddr::Ip(sa) => match sa.ip() {
            IpAddr::V4(v4) => !is_overlay_underlay_ip(v4, overlay_nets),
            IpAddr::V6(_) => true,
        },
        _ => true,
    });
    addr
}

/// Do not publish overlay interface addresses as iroh underlay candidates.
///
/// iroh 1.2 `AddrFilter` applies to address *publish*. It does not filter
/// QNT/handshake candidates on an existing connection (n0-computer/iroh#4399).
pub fn apply_overlay_addr_filter(builder: Builder, overlay_nets: &[Ipv4Net]) -> Builder {
    if overlay_nets.is_empty() {
        return builder;
    }
    let nets = overlay_nets.to_vec();
    builder.addr_filter(AddrFilter::new(move |addrs| {
        Cow::Owned(
            addrs
                .iter()
                .filter(|a| match a {
                    TransportAddr::Ip(sa) => match sa.ip() {
                        IpAddr::V4(v4) => !is_overlay_underlay_ip(v4, &nets),
                        IpAddr::V6(_) => true,
                    },
                    _ => true,
                })
                .cloned()
                .collect(),
        )
    }))
}

/// Attach address-lookup services independently of relay policy.
pub fn apply_connectivity(builder: Builder, opts: &ConnectivityOptions) -> Builder {
    #[cfg(feature = "direct")]
    {
        let mut builder = builder;
        if opts.enable_dht {
            tracing::info!("Mainline DHT address lookup enabled");
            builder = builder.address_lookup(DhtAddressLookup::builder());
        }
        apply_mdns(builder, opts.enable_mdns)
    }
    #[cfg(not(feature = "direct"))]
    {
        let _ = opts;
        builder
    }
}

/// Whether this policy would contact n0 relay/DNS infrastructure via the preset.
pub fn relay_uses_n0_preset(policy: &EffectiveRelayPolicy) -> bool {
    policy.uses_n0_infrastructure()
}

/// Relay auth denial observed via `home_relay_status`
///
/// Returns `(relay_url, reason)` for the first home relay reporting
/// [`iroh::endpoint::RelayStatus::auth_denied_reason`]. Unlike transient
/// failures this won't resolve by retrying with the same credentials, so
/// callers should surface it rather than wait for `Endpoint::online`.
pub fn relay_auth_denied_detail(endpoint: &Endpoint) -> Option<(String, String)> {
    use iroh::Watcher;
    let mut watcher = endpoint.home_relay_status();
    watcher.get().iter().find_map(|s| {
        s.auth_denied_reason()
            .map(|reason| (s.url().to_string(), reason.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_default_is_disabled_until_snapshot() {
        let opts = ConnectivityOptions::managed_default();
        assert_eq!(opts.relay, EffectiveRelayPolicy::Disabled);
        assert!(!opts.enable_mdns);
        assert!(!opts.enable_lan_discovery);
        assert!(!opts.enable_dht);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn direct_default_is_n0_with_discovery() {
        let opts = ConnectivityOptions::direct_default(true);
        assert_eq!(opts.relay, EffectiveRelayPolicy::N0);
        assert!(opts.enable_mdns);
        assert!(opts.enable_dht);
        assert!(opts.enable_lan_discovery);
        assert!(relay_uses_n0_preset(&opts.relay));
    }

    #[cfg(feature = "direct")]
    #[test]
    fn disabled_plus_lan_discovery_is_valid() {
        let opts = ConnectivityOptions {
            relay: EffectiveRelayPolicy::Disabled,
            enable_dht: false,
            enable_mdns: true,
            enable_lan_discovery: true,
        };
        assert_eq!(opts.relay, EffectiveRelayPolicy::Disabled);
        assert!(opts.enable_lan_discovery);
        assert!(!relay_uses_n0_preset(&opts.relay));
        let _builder = apply_connectivity(endpoint_builder(&opts), &opts);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn lan_discovery_independent_of_relay_mode() {
        for relay in [
            EffectiveRelayPolicy::N0,
            EffectiveRelayPolicy::Disabled,
            EffectiveRelayPolicy::Custom(vec![ConnectivityRelayConfig {
                url: "https://relay.example.com".into(),
                region: None,
                auth_token: None,
                metering: false,
            }]),
        ] {
            let opts = ConnectivityOptions {
                relay,
                enable_dht: true,
                enable_mdns: false,
                enable_lan_discovery: true,
            };
            assert!(opts.enable_lan_discovery);
            let _builder = endpoint_builder(&opts);
        }
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn custom_relays_builder_uses_custom_map() {
        let relays = vec![ConnectivityRelayConfig {
            url: "https://relay.example.com".into(),
            region: Some("us".into()),
            auth_token: Some("tok".into()),
            metering: false,
        }];
        let opts = ConnectivityOptions::managed_default()
            .with_managed_snapshot(relays.clone(), ConnectivityRelayFallback::None)
            .expect("snapshot");
        assert!(!opts.relay.uses_n0_infrastructure());
        let _builder = endpoint_builder(&opts);
        let map = relay_map_from_configs(opts.relay.custom_relays()).expect("parse");
        assert_eq!(map.len(), 1);
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn managed_snapshot_overrides_local_direct_settings() {
        let local = ConnectivityOptions::direct_from_input(
            &DirectRelayInput {
                mode: DirectRelayMode::N0,
                relay_urls: vec![],
                credentials: Default::default(),
            },
            true,
            true,
            true,
        )
        .unwrap();
        assert_eq!(local.relay, EffectiveRelayPolicy::N0);

        let from_snapshot = local
            .with_managed_snapshot(vec![], ConnectivityRelayFallback::None)
            .unwrap();
        assert_eq!(from_snapshot.relay, EffectiveRelayPolicy::Disabled);

        let custom = ConnectivityOptions::direct_default(true)
            .with_managed_snapshot(
                vec![ConnectivityRelayConfig {
                    url: "https://org-relay.example.com".into(),
                    region: None,
                    auth_token: Some("managed-tok".into()),
                    metering: true,
                }],
                ConnectivityRelayFallback::N0,
            )
            .unwrap();
        match custom.relay {
            EffectiveRelayPolicy::Custom(ref relays) => {
                assert_eq!(relays[0].url, "https://org-relay.example.com");
            }
            other => panic!("{other:?}"),
        }
        assert!(!relay_uses_n0_preset(&custom.relay));
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn snapshot_none_does_not_upgrade_to_n0() {
        let opts = ConnectivityOptions::managed_default()
            .with_managed_snapshot(vec![], ConnectivityRelayFallback::None)
            .unwrap();
        assert_eq!(opts.relay, EffectiveRelayPolicy::Disabled);
        assert_ne!(opts.relay, EffectiveRelayPolicy::N0);
        let _builder = endpoint_builder(&opts);
    }

    #[test]
    fn auth_token_debug_is_redacted() {
        let relay = ConnectivityRelayConfig {
            url: "https://relay.example.com".into(),
            region: None,
            auth_token: Some("never-log-me".into()),
            metering: false,
        };
        let rendered = format!("{relay:?}");
        assert!(!rendered.contains("never-log-me"), "{rendered}");
        let policy = EffectiveRelayPolicy::Custom(vec![relay]);
        let rendered = format!("{policy:?}");
        assert!(!rendered.contains("never-log-me"), "{rendered}");
    }

    #[test]
    fn from_direct_config_disabled_keeps_lan_discovery() {
        let mut cfg = crate::TunnetConfig::default();
        cfg.network.relay_mode = DirectRelayMode::Disabled;
        cfg.network.lan_discovery = Some(true);
        cfg.network.mdns = Some(true);
        let opts = ConnectivityOptions::direct_from_input(
            &cfg.direct_relay_input(Default::default()),
            cfg.effective_dht_default(),
            cfg.effective_mdns_default(),
            cfg.effective_lan_discovery_default(),
        )
        .unwrap();
        assert_eq!(opts.relay, EffectiveRelayPolicy::Disabled);
        assert!(opts.enable_lan_discovery);
        assert!(opts.enable_mdns);
        assert!(!relay_uses_n0_preset(&opts.relay));
    }

    #[test]
    fn strip_overlay_keeps_relay_lan_and_v6() {
        let overlay: Ipv4Net = "10.38.0.0/16".parse().unwrap();
        let id = iroh::SecretKey::generate().public();
        let relay: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link.".parse().unwrap();
        let addr = strip_overlay_addrs(
            EndpointAddr::new(id)
                .with_relay_url(relay.clone())
                .with_ip_addr("10.38.150.60:11204".parse().unwrap())
                .with_ip_addr("192.168.1.20:11204".parse().unwrap())
                .with_ip_addr("[2001:db8::1]:11204".parse().unwrap())
                .with_ip_addr((tunnet_common::VirtualResolverEndpoint::IP, 53).into()),
            &[overlay],
        );
        assert!(addr.relay_urls().any(|u| u == &relay));
        let ips: Vec<_> = addr.ip_addrs().copied().collect();
        assert!(ips.iter().any(|a| a.ip().to_string() == "192.168.1.20"));
        assert!(ips.iter().any(|a| a.is_ipv6()));
        assert!(!ips.iter().any(|a| a.ip().to_string() == "10.38.150.60"));
        assert!(!ips
            .iter()
            .any(|a| a.ip() == std::net::IpAddr::V4(tunnet_common::VirtualResolverEndpoint::IP)));
    }
}
