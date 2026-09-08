//! Direct and Managed relay policy resolution.
//!
//! User-facing Direct input (`DirectRelayMode`) and the control-plane snapshot
//! both resolve here into [`EffectiveRelayPolicy`]. Endpoint construction only
//! consumes the resolved policy.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tunnet_common::{ConnectivityRelayConfig, ConnectivityRelayFallback};

/// Direct-mode relay selection from local config / CLI / env.
///
/// `Auto` is an input only. It never appears in [`EffectiveRelayPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DirectRelayMode {
    /// Use configured custom relays if any exist; otherwise N0.
    #[default]
    Auto,
    /// Public N0 relays.
    N0,
    /// Only configured custom relays. Empty list is an error.
    Custom,
    /// `RelayMode::Disabled`. Direct paths and discovery may still run.
    Disabled,
}

impl DirectRelayMode {
    pub fn parse_str(s: &str) -> Result<Self, RelayResolveError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "n0" => Ok(Self::N0),
            "custom" => Ok(Self::Custom),
            "disabled" => Ok(Self::Disabled),
            "managed" => Err(RelayResolveError::ManagedNotSelectable),
            other => Err(RelayResolveError::UnknownMode(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::N0 => "n0",
            Self::Custom => "custom",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for DirectRelayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Runtime relay policy after resolution. No `Auto` or `Managed` variants.
#[derive(Clone, PartialEq, Eq)]
pub enum EffectiveRelayPolicy {
    N0,
    Custom(Vec<ConnectivityRelayConfig>),
    Disabled,
}

impl EffectiveRelayPolicy {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::N0 => "n0",
            Self::Custom(_) => "custom",
            Self::Disabled => "disabled",
        }
    }

    pub fn uses_n0_infrastructure(&self) -> bool {
        matches!(self, Self::N0)
    }

    pub fn custom_relays(&self) -> &[ConnectivityRelayConfig] {
        match self {
            Self::Custom(relays) => relays,
            Self::N0 | Self::Disabled => &[],
        }
    }
}

impl fmt::Debug for EffectiveRelayPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::N0 => f.write_str("N0"),
            Self::Disabled => f.write_str("Disabled"),
            Self::Custom(relays) => f
                .debug_tuple("Custom")
                .field(&relays.iter().map(public_relay_debug).collect::<Vec<_>>())
                .finish(),
        }
    }
}

fn public_relay_debug(relay: &ConnectivityRelayConfig) -> String {
    match relay.region.as_deref() {
        Some(region) => format!("{} ({region})", relay.url),
        None => relay.url.clone(),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayResolveError {
    #[error(
        "relay-mode \"managed\" is not user-selectable; Managed connectivity comes from the control plane"
    )]
    ManagedNotSelectable,
    #[error("unknown relay-mode {0:?}; want auto, n0, custom, or disabled")]
    UnknownMode(String),
    #[error("relay-mode = custom requires at least one valid relay-urls entry")]
    CustomRequiresRelays,
    #[error("invalid relay URL {url:?}: {detail}")]
    InvalidUrl { url: String, detail: String },
    #[error("TUNNET_RELAY_AUTH_JSON is not a JSON object of url -> token")]
    InvalidAuthJson,
}

/// Direct-mode resolution inputs (local config + encrypted credentials).
#[derive(Clone, Debug, Default)]
pub struct DirectRelayInput {
    pub mode: DirectRelayMode,
    pub relay_urls: Vec<String>,
    /// Auth tokens keyed by relay URL. Never log or serialize to public config.
    pub credentials: BTreeMap<String, String>,
}

impl DirectRelayInput {
    pub fn overlay_mode_and_urls(
        mut self,
        mode: Option<&str>,
        urls: Option<&str>,
    ) -> Result<Self, RelayResolveError> {
        if let Some(mode) = mode.map(str::trim).filter(|s| !s.is_empty()) {
            self.mode = DirectRelayMode::parse_str(mode)?;
        }
        if let Some(urls) = urls {
            self.relay_urls = urls
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        Ok(self)
    }

    pub fn overlay_process_env(self) -> Result<Self, RelayResolveError> {
        let mode = std::env::var("TUNNET_RELAY_MODE").ok();
        let urls = std::env::var("TUNNET_RELAY_URLS").ok();
        let mut input = self.overlay_mode_and_urls(mode.as_deref(), urls.as_deref())?;
        if let Ok(json) = std::env::var("TUNNET_RELAY_AUTH_JSON") {
            let trimmed = json.trim();
            if !trimmed.is_empty() {
                let extra: BTreeMap<String, String> = serde_json::from_str(trimmed)
                    .map_err(|_| RelayResolveError::InvalidAuthJson)?;
                input.credentials.extend(extra);
            }
        }
        Ok(input)
    }
}

pub fn resolve_direct_relay_policy(
    input: &DirectRelayInput,
) -> Result<EffectiveRelayPolicy, RelayResolveError> {
    match input.mode {
        DirectRelayMode::Disabled => Ok(EffectiveRelayPolicy::Disabled),
        DirectRelayMode::N0 => Ok(EffectiveRelayPolicy::N0),
        DirectRelayMode::Custom => {
            let relays = configured_relays(input)?;
            if relays.is_empty() {
                return Err(RelayResolveError::CustomRequiresRelays);
            }
            Ok(EffectiveRelayPolicy::Custom(relays))
        }
        DirectRelayMode::Auto => {
            let relays = configured_relays(input)?;
            if relays.is_empty() {
                Ok(EffectiveRelayPolicy::N0)
            } else {
                Ok(EffectiveRelayPolicy::Custom(relays))
            }
        }
    }
}

/// Control-plane snapshot is authoritative. Empty list + `None` stays disabled.
pub fn resolve_managed_relay_policy(
    relays: &[ConnectivityRelayConfig],
    fallback: ConnectivityRelayFallback,
) -> Result<EffectiveRelayPolicy, RelayResolveError> {
    if relays.is_empty() {
        return Ok(match fallback {
            ConnectivityRelayFallback::N0 => EffectiveRelayPolicy::N0,
            ConnectivityRelayFallback::None => EffectiveRelayPolicy::Disabled,
        });
    }
    let mut out = Vec::with_capacity(relays.len());
    for relay in relays {
        validate_relay_url(&relay.url)?;
        out.push(relay.clone());
    }
    Ok(EffectiveRelayPolicy::Custom(out))
}

fn configured_relays(
    input: &DirectRelayInput,
) -> Result<Vec<ConnectivityRelayConfig>, RelayResolveError> {
    let mut out = Vec::new();
    for url in &input.relay_urls {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        validate_relay_url(url)?;
        let auth_token = input
            .credentials
            .get(url)
            .or_else(|| input.credentials.get(url.trim_end_matches('/')))
            .cloned()
            .filter(|t| !t.is_empty());
        out.push(ConnectivityRelayConfig {
            url: url.to_string(),
            region: None,
            auth_token,
            metering: false,
        });
    }
    Ok(out)
}

fn validate_relay_url(url: &str) -> Result<(), RelayResolveError> {
    url.parse::<iroh::RelayUrl>()
        .map(|_| ())
        .map_err(|e| RelayResolveError::InvalidUrl {
            url: url.to_string(),
            detail: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn default_auto_without_urls_is_n0() {
        let policy = resolve_direct_relay_policy(&DirectRelayInput::default()).unwrap();
        assert_eq!(policy, EffectiveRelayPolicy::N0);
        assert!(policy.uses_n0_infrastructure());
    }

    #[test]
    fn auto_with_custom_relays_uses_custom() {
        let policy = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::Auto,
            relay_urls: vec!["https://relay.example.com".into()],
            credentials: BTreeMap::new(),
        })
        .unwrap();
        match policy {
            EffectiveRelayPolicy::Custom(ref relays) => {
                assert_eq!(relays.len(), 1);
                assert_eq!(relays[0].url, "https://relay.example.com");
            }
            other => panic!("expected custom, got {other:?}"),
        }
        assert!(!policy.uses_n0_infrastructure());
    }

    #[test]
    fn custom_with_no_relays_is_error() {
        let err = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::Custom,
            relay_urls: vec![],
            credentials: BTreeMap::new(),
        })
        .unwrap_err();
        assert_eq!(err, RelayResolveError::CustomRequiresRelays);
    }

    #[test]
    fn custom_never_falls_back_to_n0() {
        let err = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::Custom,
            relay_urls: vec![],
            credentials: creds(&[("https://relay.example.com", "tok")]),
        })
        .unwrap_err();
        assert_ne!(
            resolve_direct_relay_policy(&DirectRelayInput {
                mode: DirectRelayMode::Custom,
                ..Default::default()
            })
            .ok(),
            Some(EffectiveRelayPolicy::N0)
        );
        assert_eq!(err, RelayResolveError::CustomRequiresRelays);
    }

    #[test]
    fn n0_mode_is_n0_even_with_urls() {
        let policy = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::N0,
            relay_urls: vec!["https://relay.example.com".into()],
            credentials: BTreeMap::new(),
        })
        .unwrap();
        assert_eq!(policy, EffectiveRelayPolicy::N0);
    }

    #[test]
    fn disabled_is_disabled() {
        let policy = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::Disabled,
            relay_urls: vec!["https://relay.example.com".into()],
            credentials: BTreeMap::new(),
        })
        .unwrap();
        assert_eq!(policy, EffectiveRelayPolicy::Disabled);
        assert!(!policy.uses_n0_infrastructure());
    }

    #[test]
    fn custom_attaches_encrypted_credentials() {
        let url = "https://relay.example.com";
        let policy = resolve_direct_relay_policy(&DirectRelayInput {
            mode: DirectRelayMode::Custom,
            relay_urls: vec![url.into()],
            credentials: creds(&[(url, "super-secret-token")]),
        })
        .unwrap();
        let EffectiveRelayPolicy::Custom(relays) = policy else {
            panic!("custom");
        };
        assert_eq!(relays[0].auth_token.as_deref(), Some("super-secret-token"));
        let debug = format!("{:?}", EffectiveRelayPolicy::Custom(relays.clone()));
        assert!(!debug.contains("super-secret-token"), "{debug}");
    }

    #[test]
    fn managed_empty_none_stays_disabled() {
        let policy = resolve_managed_relay_policy(&[], ConnectivityRelayFallback::None).unwrap();
        assert_eq!(policy, EffectiveRelayPolicy::Disabled);
    }

    #[test]
    fn managed_empty_n0_is_n0() {
        let policy = resolve_managed_relay_policy(&[], ConnectivityRelayFallback::N0).unwrap();
        assert_eq!(policy, EffectiveRelayPolicy::N0);
    }

    #[test]
    fn managed_custom_relays_are_custom() {
        let relays = vec![ConnectivityRelayConfig {
            url: "https://relay.example.com".into(),
            region: Some("eu".into()),
            auth_token: Some("tok".into()),
            metering: true,
        }];
        let policy = resolve_managed_relay_policy(&relays, ConnectivityRelayFallback::N0).unwrap();
        match policy {
            EffectiveRelayPolicy::Custom(got) => {
                assert_eq!(got, relays);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn managed_invalid_url_is_error_not_n0() {
        let relays = vec![ConnectivityRelayConfig {
            url: "not a url".into(),
            region: None,
            auth_token: None,
            metering: false,
        }];
        let err = resolve_managed_relay_policy(&relays, ConnectivityRelayFallback::N0).unwrap_err();
        assert!(matches!(err, RelayResolveError::InvalidUrl { .. }));
    }

    #[test]
    fn parse_rejects_managed() {
        assert_eq!(
            DirectRelayMode::parse_str("managed"),
            Err(RelayResolveError::ManagedNotSelectable)
        );
    }
}
