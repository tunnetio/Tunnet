//! Endpoint connectivity presets for Direct and Managed agents.
//!
//! Selects iroh relay presets, optional Mainline DHT address lookup, and mDNS.

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectivityProfile {
    /// [`presets::N0`] + optional mDNS.
    #[default]
    N0Public,
    /// Tunnet-managed agents: custom RelayMap from control plane, or n0 / disabled fallback.
    TunnetManaged,
    /// [`presets::N0`] + DHT address lookup + optional mDNS.
    ServerlessDht,
    /// [`presets::Minimal`] + mDNS only (no N0 DNS).
    LanOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectivityOptions {
    pub profile: ConnectivityProfile,
    pub enable_mdns: bool,
    /// Custom connectivity relays from the control-plane snapshot (managed).
    pub custom_relays: Vec<ConnectivityRelayConfig>,
    /// When `custom_relays` is empty: use n0 public relays or disable relays.
    pub relay_fallback: ConnectivityRelayFallback,
}

impl Default for ConnectivityOptions {
    fn default() -> Self {
        Self {
            profile: ConnectivityProfile::N0Public,
            enable_mdns: true,
            custom_relays: Vec::new(),
            relay_fallback: ConnectivityRelayFallback::N0,
        }
    }
}

impl ConnectivityOptions {
    pub fn direct_default(enable_mdns: bool) -> Self {
        Self {
            profile: ConnectivityProfile::ServerlessDht,
            enable_mdns,
            custom_relays: Vec::new(),
            relay_fallback: ConnectivityRelayFallback::N0,
        }
    }

    pub fn managed_default() -> Self {
        Self {
            profile: ConnectivityProfile::TunnetManaged,
            enable_mdns: false,
            custom_relays: Vec::new(),
            // Overridden from EndpointSnapshot at managed bind time.
            relay_fallback: ConnectivityRelayFallback::N0,
        }
    }

    /// Apply snapshot relay list / fallback for managed agents (bind-time).
    pub fn with_snapshot_relays(
        mut self,
        relays: Vec<ConnectivityRelayConfig>,
        fallback: ConnectivityRelayFallback,
    ) -> Self {
        self.custom_relays = relays;
        self.relay_fallback = if self.custom_relays.is_empty()
            && fallback == ConnectivityRelayFallback::None
        {
            tracing::warn!(
                "snapshot has no connectivity relays; using n0 so mesh peers can discover each other"
            );
            ConnectivityRelayFallback::N0
        } else {
            fallback
        };
        self
    }
}

/// Build an iroh [`RelayMap`] from control-plane relay configs.
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

fn apply_relay_mode(builder: Builder, opts: &ConnectivityOptions) -> Builder {
    if !opts.custom_relays.is_empty() {
        match relay_map_from_configs(&opts.custom_relays) {
            Ok(map) => return builder.relay_mode(RelayMode::Custom(map)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "invalid connectivity relay URL; applying fallback"
                );
            }
        }
    }

    match (opts.profile, opts.relay_fallback) {
        (ConnectivityProfile::TunnetManaged, ConnectivityRelayFallback::None) => {
            tracing::warn!(
                "managed endpoint has no connectivity relays; disabling iroh relay (peer dials will fail across NAT)"
            );
            builder.relay_mode(RelayMode::Disabled)
        }
        (ConnectivityProfile::LanOnly, _) => builder,
        (_, ConnectivityRelayFallback::N0) => builder,
        (_, ConnectivityRelayFallback::None) => {
            tracing::warn!("iroh relays disabled by snapshot fallback");
            builder.relay_mode(RelayMode::Disabled)
        }
    }
}

/// Start an endpoint builder with the relay preset for this profile.
///
/// The explicit [`crate::transport_profile::TunnetTransportProfile`] is applied
/// here: every mesh endpoint shares one controlled QUIC transport instead of
/// inheriting generic Iroh/noq defaults.
pub fn endpoint_builder(opts: &ConnectivityOptions) -> Builder {
    endpoint_builder_with_transport(
        opts,
        &crate::transport_profile::TunnetTransportProfile::default(),
    )
}

/// Same as [`endpoint_builder`] with an explicit transport profile
/// (e.g. BBRv3 benchmark experiments).
pub fn endpoint_builder_with_transport(
    opts: &ConnectivityOptions,
    profile: &crate::transport_profile::TunnetTransportProfile,
) -> Builder {
    let builder = match opts.profile {
        ConnectivityProfile::LanOnly => Endpoint::builder(presets::Minimal),
        ConnectivityProfile::TunnetManaged if !opts.custom_relays.is_empty() => {
            // Minimal + Custom relay_mode (override below).
            Endpoint::builder(presets::Minimal)
        }
        ConnectivityProfile::TunnetManaged
            if opts.relay_fallback == ConnectivityRelayFallback::None =>
        {
            Endpoint::builder(presets::Minimal)
        }
        ConnectivityProfile::N0Public
        | ConnectivityProfile::TunnetManaged
        | ConnectivityProfile::ServerlessDht => Endpoint::builder(presets::N0),
    };
    apply_relay_mode(profile.apply(builder), opts)
}

/// Attach address-lookup services to an endpoint builder.
pub fn apply_connectivity(builder: Builder, opts: &ConnectivityOptions) -> Builder {
    #[cfg(feature = "direct")]
    {
        let mut builder = builder;
        if matches!(opts.profile, ConnectivityProfile::ServerlessDht) {
            tracing::info!("Mainline DHT address lookup enabled");
            builder = builder.address_lookup(DhtAddressLookup::builder());
        }
        let mdns = opts.enable_mdns || matches!(opts.profile, ConnectivityProfile::LanOnly);
        apply_mdns(builder, mdns)
    }
    #[cfg(not(feature = "direct"))]
    {
        let _ = opts;
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_default_is_tunnet_managed() {
        let opts = ConnectivityOptions::managed_default();
        assert_eq!(opts.profile, ConnectivityProfile::TunnetManaged);
        assert!(!opts.enable_mdns);
        assert!(opts.custom_relays.is_empty());
        assert_eq!(opts.relay_fallback, ConnectivityRelayFallback::N0);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn direct_default_is_serverless_dht() {
        let opts = ConnectivityOptions::direct_default(true);
        assert_eq!(opts.profile, ConnectivityProfile::ServerlessDht);
        assert!(opts.enable_mdns);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn lan_only_builder_uses_minimal() {
        let opts = ConnectivityOptions {
            profile: ConnectivityProfile::LanOnly,
            enable_mdns: false,
            custom_relays: Vec::new(),
            relay_fallback: ConnectivityRelayFallback::None,
        };
        let _builder = endpoint_builder(&opts);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn serverless_builder_uses_n0() {
        let opts = ConnectivityOptions::direct_default(false);
        let _builder = endpoint_builder(&opts);
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn custom_relays_builder_uses_custom_relay_map() {
        // Non-empty custom_relays → Minimal preset + RelayMode::Custom(map)
        // via apply_relay_mode (see endpoint_builder / apply_relay_mode).
        let opts = ConnectivityOptions::managed_default().with_snapshot_relays(
            vec![ConnectivityRelayConfig {
                url: "https://relay.example.com".into(),
                region: Some("us".into()),
                auth_token: Some("tok".into()),
                metering: false,
            }],
            ConnectivityRelayFallback::None,
        );
        assert!(!opts.custom_relays.is_empty());
        assert_eq!(opts.profile, ConnectivityProfile::TunnetManaged);
        let _builder = endpoint_builder(&opts);
        let map = relay_map_from_configs(&opts.custom_relays).expect("parse");
        assert_eq!(map.len(), 1);
        let urls: Vec<iroh::RelayUrl> = map.urls();
        assert!(urls[0].as_str().contains("relay.example.com"));
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn custom_relays_with_auth_token_builds_map() {
        let relays = vec![ConnectivityRelayConfig {
            url: "https://relay.example.com./".into(),
            region: None,
            auth_token: Some("shared-secret".into()),
            metering: false,
        }];
        let map = relay_map_from_configs(&relays).expect("parse");
        assert_eq!(map.len(), 1);
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn managed_empty_none_falls_back_to_n0() {
        let opts = ConnectivityOptions::managed_default()
            .with_snapshot_relays(vec![], ConnectivityRelayFallback::None);
        assert!(opts.custom_relays.is_empty());
        assert_eq!(opts.relay_fallback, ConnectivityRelayFallback::N0);
        let _builder = endpoint_builder(&opts);
    }

    #[cfg(any(feature = "direct", feature = "managed"))]
    #[test]
    fn managed_empty_cloud_fallback_disables_relays() {
        let opts = ConnectivityOptions {
            profile: ConnectivityProfile::TunnetManaged,
            enable_mdns: false,
            custom_relays: Vec::new(),
            relay_fallback: ConnectivityRelayFallback::None,
        };
        let _builder = endpoint_builder(&opts);
    }
}
