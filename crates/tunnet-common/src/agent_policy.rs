//! Layered agent configuration: local TOML > remote org policy > defaults.

use serde::{Deserialize, Serialize};

use crate::posture::CustomScriptConfig;

/// Where an effective setting came from after merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Default,
    Remote,
    Local,
}

/// A resolved setting with provenance for dashboard display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSetting<T> {
    pub value: T,
    pub source: ConfigSource,
    /// When `source` is Local, the remote value that was overridden (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_value: Option<T>,
}

impl<T> ResolvedSetting<T> {
    pub fn new(value: T, source: ConfigSource) -> Self {
        Self {
            value,
            source,
            remote_value: None,
        }
    }

    pub fn local_override(value: T, remote_value: Option<T>) -> Self {
        Self {
            value,
            source: ConfigSource::Local,
            remote_value,
        }
    }
}

/// Org-level remote agent policy (edited in the dashboard).
///
/// Dual keys may be overridden by local `tunnet.toml`. Remote-only keys
/// are organizational; local TOML cannot change them (enforcement is via
/// compliance / access, not TOML locks).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAgentPolicy {
    /// Dual: LAN mDNS discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns: Option<bool>,
    /// Dual: LAN peer discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_discovery: Option<bool>,
    /// Dual: preferred tunnel MTU (local can override per device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_mtu: Option<u16>,

    /// Remote: auto-update defaults for the org.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<RemoteAutoUpdatePolicy>,
    /// Remote: DNS defaults pushed to agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<RemoteDnsPolicy>,
    /// Remote: connectivity relay preference (mesh DERP / hybrid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RemoteRelayPolicy>,
    /// Remote: exit-node policy defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_nodes: Option<RemoteExitNodesPolicy>,
    /// Remote: posture collector schedule / scripts (definitions stay in posture tables).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<RemotePostureCollectorPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAutoUpdatePolicy {
    pub enabled: bool,
    #[serde(default = "default_check_interval_hours")]
    pub check_interval_hours: u64,
}

fn default_check_interval_hours() -> u64 {
    6
}

impl Default for RemoteAutoUpdatePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_hours: default_check_interval_hours(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDnsPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<bool>,
}

/// How agents select deployment vs org-owned connectivity relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RelayPolicy {
    /// Use deployment (Cloud) relays only.
    #[default]
    Inherit,
    /// Prefer org relays, then fall back to deployment relays.
    Augment,
    /// Use org-owned relays only.
    Exclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRelayPolicy {
    #[serde(default)]
    pub policy: RelayPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteExitNodesPolicy {
    /// When true, devices may advertise as exit nodes.
    #[serde(default)]
    pub allow_advertise: bool,
    /// When true, devices may route via an exit node.
    #[serde(default = "default_true")]
    pub allow_use: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePostureCollectorPolicy {
    #[serde(default = "default_posture_interval")]
    pub interval_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_collectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_scripts: Vec<CustomScriptConfig>,
}

fn default_posture_interval() -> u64 {
    300
}

impl Default for RemotePostureCollectorPolicy {
    fn default() -> Self {
        Self {
            interval_secs: default_posture_interval(),
            enabled_collectors: vec![],
            custom_scripts: vec![],
        }
    }
}

/// Local dual overrides from `tunnet.toml` `[network]` / `[update]` (only set keys win).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LocalDualOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_discovery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update_check_interval_hours: Option<u64>,
}

/// Local-only operational settings (never remotely writable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalOnlySettings {
    pub logging_level: String,
    pub logging_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

impl Default for LocalOnlySettings {
    fn default() -> Self {
        Self {
            logging_level: "info".into(),
            logging_format: "text".into(),
            control_url: None,
            listen_port: None,
        }
    }
}

/// Merged config the agent runs with - reported to the control plane for the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveAgentConfig {
    pub mdns: ResolvedSetting<bool>,
    pub lan_discovery: ResolvedSetting<bool>,
    pub tunnel_mtu: ResolvedSetting<u16>,
    pub auto_update_enabled: ResolvedSetting<bool>,
    pub auto_update_check_interval_hours: ResolvedSetting<u64>,
    pub posture_interval_secs: ResolvedSetting<u64>,
    pub posture_enabled_collectors: ResolvedSetting<Vec<String>>,
    pub relay_policy: ResolvedSetting<RelayPolicy>,
    pub exit_nodes_allow_advertise: ResolvedSetting<bool>,
    pub exit_nodes_allow_use: ResolvedSetting<bool>,
    pub dns_suffix: ResolvedSetting<String>,
    pub dns_upstream: ResolvedSetting<Vec<String>>,
    pub dnssec: ResolvedSetting<bool>,
    /// Always local source.
    pub local: LocalOnlySettings,
}

const DEFAULT_MDNS: bool = true;
const DEFAULT_LAN_DISCOVERY: bool = true;
/// Default logical/virtual MTU for the dataplane. 2800 matches the
/// ZeroTier-style comparison point: far fewer packets per GiB than 1280 while
/// staying cheap to segment onto typical QUIC path MTUs. See the benchmark
/// matrix before changing this; 9000 is not an automatic default.
const DEFAULT_TUNNEL_MTU: u16 = 2800;
const DEFAULT_AUTO_UPDATE_ENABLED: bool = false;
const DEFAULT_AUTO_UPDATE_INTERVAL: u64 = 6;
const DEFAULT_POSTURE_INTERVAL: u64 = 300;
const DEFAULT_DNS_SUFFIX: &str = "tunnet";

fn resolve_dual<T: Clone>(local: Option<T>, remote: Option<T>, default: T) -> ResolvedSetting<T> {
    if let Some(v) = local {
        ResolvedSetting::local_override(v, remote)
    } else if let Some(v) = remote {
        ResolvedSetting::new(v, ConfigSource::Remote)
    } else {
        ResolvedSetting::new(default, ConfigSource::Default)
    }
}

fn resolve_remote_only<T: Clone>(remote: Option<T>, default: T) -> ResolvedSetting<T> {
    if let Some(v) = remote {
        ResolvedSetting::new(v, ConfigSource::Remote)
    } else {
        ResolvedSetting::new(default, ConfigSource::Default)
    }
}

/// Deep-merge network overrides onto org defaults (network wins when set).
pub fn inherit_remote_policy(
    org: &RemoteAgentPolicy,
    network: &RemoteAgentPolicy,
) -> RemoteAgentPolicy {
    RemoteAgentPolicy {
        mdns: network.mdns.or(org.mdns),
        lan_discovery: network.lan_discovery.or(org.lan_discovery),
        tunnel_mtu: network.tunnel_mtu.or(org.tunnel_mtu),
        auto_update: network
            .auto_update
            .clone()
            .or_else(|| org.auto_update.clone()),
        dns: match (&network.dns, &org.dns) {
            (Some(n), Some(o)) => Some(RemoteDnsPolicy {
                suffix: n.suffix.clone().or_else(|| o.suffix.clone()),
                upstream: if n.upstream.is_empty() {
                    o.upstream.clone()
                } else {
                    n.upstream.clone()
                },
                dnssec: n.dnssec.or(o.dnssec),
            }),
            (Some(n), None) => Some(n.clone()),
            (None, o) => o.clone(),
        },
        relay: network.relay.clone().or_else(|| org.relay.clone()),
        exit_nodes: network
            .exit_nodes
            .clone()
            .or_else(|| org.exit_nodes.clone()),
        posture: match (&network.posture, &org.posture) {
            (Some(n), Some(o)) => Some(RemotePostureCollectorPolicy {
                interval_secs: n.interval_secs,
                enabled_collectors: if n.enabled_collectors.is_empty() {
                    o.enabled_collectors.clone()
                } else {
                    n.enabled_collectors.clone()
                },
                custom_scripts: if n.custom_scripts.is_empty() {
                    o.custom_scripts.clone()
                } else {
                    n.custom_scripts.clone()
                },
            }),
            (Some(n), None) => Some(n.clone()),
            (None, o) => o.clone(),
        },
    }
}

/// Merge defaults ← remote ← local dual overrides.
pub fn merge_agent_config(
    remote: &RemoteAgentPolicy,
    local_dual: &LocalDualOverrides,
    local_only: LocalOnlySettings,
) -> EffectiveAgentConfig {
    let default_upstream = crate::default_dns_upstream();

    let auto_enabled_remote = remote.auto_update.as_ref().map(|a| a.enabled);
    let auto_interval_remote = remote.auto_update.as_ref().map(|a| a.check_interval_hours);

    let posture_interval_remote = remote.posture.as_ref().map(|p| p.interval_secs);
    let posture_collectors_remote = remote.posture.as_ref().and_then(|p| {
        if p.enabled_collectors.is_empty() {
            None
        } else {
            Some(p.enabled_collectors.clone())
        }
    });

    let dns_suffix_remote = remote.dns.as_ref().and_then(|d| d.suffix.clone());
    let dns_upstream_remote = remote.dns.as_ref().and_then(|d| {
        if d.upstream.is_empty() {
            None
        } else {
            Some(d.upstream.clone())
        }
    });
    let dnssec_remote = remote.dns.as_ref().and_then(|d| d.dnssec);

    let relay_policy_remote = remote.relay.as_ref().map(|r| r.policy);
    let exit_advertise_remote = remote.exit_nodes.as_ref().map(|e| e.allow_advertise);
    let exit_use_remote = remote.exit_nodes.as_ref().map(|e| e.allow_use);

    EffectiveAgentConfig {
        mdns: resolve_dual(local_dual.mdns, remote.mdns, DEFAULT_MDNS),
        lan_discovery: resolve_dual(
            local_dual.lan_discovery,
            remote.lan_discovery,
            DEFAULT_LAN_DISCOVERY,
        ),
        tunnel_mtu: resolve_dual(local_dual.tunnel_mtu, remote.tunnel_mtu, DEFAULT_TUNNEL_MTU),
        auto_update_enabled: resolve_dual(
            local_dual.auto_update_enabled,
            auto_enabled_remote,
            DEFAULT_AUTO_UPDATE_ENABLED,
        ),
        auto_update_check_interval_hours: resolve_dual(
            local_dual.auto_update_check_interval_hours,
            auto_interval_remote,
            DEFAULT_AUTO_UPDATE_INTERVAL,
        ),
        posture_interval_secs: resolve_remote_only(
            posture_interval_remote,
            DEFAULT_POSTURE_INTERVAL,
        ),
        posture_enabled_collectors: resolve_remote_only(posture_collectors_remote, Vec::new()),
        relay_policy: resolve_remote_only(relay_policy_remote, RelayPolicy::Inherit),
        exit_nodes_allow_advertise: resolve_remote_only(exit_advertise_remote, false),
        exit_nodes_allow_use: resolve_remote_only(exit_use_remote, true),
        dns_suffix: resolve_remote_only(dns_suffix_remote, DEFAULT_DNS_SUFFIX.into()),
        dns_upstream: resolve_remote_only(dns_upstream_remote, default_upstream),
        dnssec: resolve_remote_only(dnssec_remote, false),
        local: local_only,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_overrides_remote_mdns() {
        let remote = RemoteAgentPolicy {
            mdns: Some(true),
            ..Default::default()
        };
        let local = LocalDualOverrides {
            mdns: Some(false),
            ..Default::default()
        };
        let eff = merge_agent_config(&remote, &local, LocalOnlySettings::default());
        assert!(!eff.mdns.value);
        assert_eq!(eff.mdns.source, ConfigSource::Local);
        assert_eq!(eff.mdns.remote_value, Some(true));
    }

    #[test]
    fn remote_wins_when_no_local() {
        let remote = RemoteAgentPolicy {
            mdns: Some(false),
            ..Default::default()
        };
        let eff = merge_agent_config(
            &remote,
            &LocalDualOverrides::default(),
            LocalOnlySettings::default(),
        );
        assert!(!eff.mdns.value);
        assert_eq!(eff.mdns.source, ConfigSource::Remote);
    }

    #[test]
    fn network_inherits_and_overrides_org() {
        let org = RemoteAgentPolicy {
            mdns: Some(true),
            lan_discovery: Some(true),
            auto_update: Some(RemoteAutoUpdatePolicy {
                enabled: false,
                check_interval_hours: 6,
            }),
            ..Default::default()
        };
        let network = RemoteAgentPolicy {
            mdns: Some(false),
            ..Default::default()
        };
        let merged = inherit_remote_policy(&org, &network);
        assert_eq!(merged.mdns, Some(false));
        assert_eq!(merged.lan_discovery, Some(true));
        assert_eq!(merged.auto_update.as_ref().map(|a| a.enabled), Some(false));
    }

    #[test]
    fn default_when_neither() {
        let eff = merge_agent_config(
            &RemoteAgentPolicy::default(),
            &LocalDualOverrides::default(),
            LocalOnlySettings::default(),
        );
        assert!(eff.mdns.value);
        assert_eq!(eff.mdns.source, ConfigSource::Default);
        assert_eq!(eff.relay_policy.value, RelayPolicy::Inherit);
        assert_eq!(eff.relay_policy.source, ConfigSource::Default);
    }

    #[test]
    fn remote_relay_policy_resolved() {
        let remote = RemoteAgentPolicy {
            relay: Some(RemoteRelayPolicy {
                policy: RelayPolicy::Exclusive,
            }),
            ..Default::default()
        };
        let eff = merge_agent_config(
            &remote,
            &LocalDualOverrides::default(),
            LocalOnlySettings::default(),
        );
        assert_eq!(eff.relay_policy.value, RelayPolicy::Exclusive);
        assert_eq!(eff.relay_policy.source, ConfigSource::Remote);
    }
}
