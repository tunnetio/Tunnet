//! Endpoint connectivity: resolved relay policy plus independent discovery flags.
//!
//! Relay selection is [`EffectiveRelayPolicy`] only. DHT, mDNS, and LAN discovery
//! are separate and never implied by a connectivity "profile".

use std::sync::Arc;

use iroh::Endpoint;
use iroh::RelayMode;
use iroh::endpoint::Builder;
use iroh::endpoint::presets;
use iroh::{RelayConfig, RelayMap};
#[cfg(feature = "direct")]
use iroh_mainline_address_lookup::DhtAddressLookup;
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
    apply_relay_policy(builder, &opts.relay)
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
}
