//! Build the effective connectivity-relay list for an agent snapshot.

use std::sync::OnceLock;

use tunnet_common::{ConnectivityRelayConfig, ConnectivityRelayFallback, RelayPolicy};
use tunnet_license::LicenseTier;

/// Row shape used when composing effective relays (from DB / control plane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRow {
    pub url: String,
    pub region: Option<String>,
    pub auth_token: Option<String>,
    pub organization_id: Option<String>,
    pub status: String,
}

/// Deployment-wide relay mode from `TUNNET_DEPLOYMENT_RELAY_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentRelayMode {
    Custom,
    N0,
    Disabled,
}

static LICENSE_TIER: OnceLock<LicenseTier> = OnceLock::new();

/// Record the process license tier (call once after entitlements resolve).
pub fn set_license_tier(tier: LicenseTier) {
    let _ = LICENSE_TIER.set(tier);
}

pub fn license_tier() -> LicenseTier {
    *LICENSE_TIER.get().unwrap_or(&LicenseTier::Community)
}

/// Resolve deployment relay mode from env, with license-aware defaults.
///
/// Defaults: Cloud → `custom` (use n0 only while the custom list is empty);
/// Community/Enterprise → `n0`.
pub fn deployment_relay_mode() -> DeploymentRelayMode {
    match std::env::var("TUNNET_DEPLOYMENT_RELAY_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "custom" => DeploymentRelayMode::Custom,
        "n0" => DeploymentRelayMode::N0,
        "disabled" => DeploymentRelayMode::Disabled,
        _ => match license_tier() {
            LicenseTier::Cloud => DeploymentRelayMode::Custom,
            LicenseTier::Community | LicenseTier::Enterprise => DeploymentRelayMode::N0,
        },
    }
}

/// Authoritative snapshot policy when the effective relay list is empty.
pub fn connectivity_relay_fallback(
    effective: &[ConnectivityRelayConfig],
) -> ConnectivityRelayFallback {
    connectivity_relay_fallback_for(license_tier(), deployment_relay_mode(), effective)
}

pub fn connectivity_relay_fallback_for(
    _tier: LicenseTier,
    mode: DeploymentRelayMode,
    effective: &[ConnectivityRelayConfig],
) -> ConnectivityRelayFallback {
    match mode {
        DeploymentRelayMode::Disabled => ConnectivityRelayFallback::None,
        // Custom relays present: stay on that map (Cloud fail-closed vs n0).
        DeploymentRelayMode::Custom if !effective.is_empty() => ConnectivityRelayFallback::None,
        // Empty custom list: control plane chooses n0 until custom relays are healthy.
        DeploymentRelayMode::Custom | DeploymentRelayMode::N0 => ConnectivityRelayFallback::N0,
    }
}

fn is_eligible(status: &str) -> bool {
    status == "healthy"
}

fn to_config(row: &RelayRow) -> ConnectivityRelayConfig {
    ConnectivityRelayConfig {
        url: row.url.clone(),
        region: row.region.clone(),
        auth_token: row.auth_token.clone(),
        metering: row.organization_id.is_none() && license_tier() == LicenseTier::Cloud,
    }
}

/// Compose deployment + org connectivity relays according to policy.
///
/// - Only `healthy` relays are included (pending / degraded / offline / suspended excluded).
/// - `Inherit`: deployment relays only.
/// - `Augment`: org relays first, then deployment.
/// - `Exclusive`: org relays only.
pub fn build_effective_relays(
    policy: RelayPolicy,
    deployment_relays: &[RelayRow],
    org_relays: &[RelayRow],
) -> Vec<ConnectivityRelayConfig> {
    let deployment: Vec<_> = deployment_relays
        .iter()
        .filter(|r| is_eligible(&r.status))
        .map(to_config)
        .collect();
    let org: Vec<_> = org_relays
        .iter()
        .filter(|r| is_eligible(&r.status))
        .map(to_config)
        .collect();

    match policy {
        RelayPolicy::Inherit => deployment,
        RelayPolicy::Augment => {
            let mut out = org;
            out.extend(deployment);
            out
        }
        RelayPolicy::Exclusive => org,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(url: &str, status: &str, organization_id: Option<&str>) -> RelayRow {
        RelayRow {
            url: url.into(),
            region: Some("us".into()),
            auth_token: None,
            organization_id: organization_id.map(str::to_string),
            status: status.into(),
        }
    }

    #[test]
    fn inherit_uses_deployment_only() {
        let deployment = vec![
            row("https://cloud.example", "healthy", None),
            row("https://cloud-bad.example", "offline", None),
        ];
        let org = vec![row("https://org.example", "healthy", Some("org_1"))];
        let out = build_effective_relays(RelayPolicy::Inherit, &deployment, &org);
        assert_eq!(
            out,
            vec![ConnectivityRelayConfig {
                url: "https://cloud.example".into(),
                region: Some("us".into()),
                auth_token: None,
                metering: false,
            }]
        );
    }

    #[test]
    fn augment_org_then_deployment() {
        let deployment = vec![row("https://cloud.example", "healthy", None)];
        let org = vec![row("https://org.example", "healthy", Some("org_1"))];
        let out = build_effective_relays(RelayPolicy::Augment, &deployment, &org);
        assert_eq!(
            out.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
            vec!["https://org.example", "https://cloud.example"]
        );
    }

    #[test]
    fn exclusive_org_only() {
        let deployment = vec![row("https://cloud.example", "healthy", None)];
        let org = vec![row("https://org.example", "healthy", Some("org_1"))];
        let out = build_effective_relays(RelayPolicy::Exclusive, &deployment, &org);
        assert_eq!(
            out.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
            vec!["https://org.example"]
        );
    }

    #[test]
    fn suspended_and_non_healthy_excluded() {
        let deployment = vec![
            row("https://cloud.example", "healthy", None),
            row("https://cloud-pending.example", "pending", None),
            row("https://cloud-degraded.example", "degraded", None),
        ];
        let org = vec![
            row("https://org.example", "healthy", Some("org_1")),
            row("https://org-sus.example", "suspended", Some("org_1")),
            row("https://org-off.example", "offline", Some("org_1")),
        ];
        let out = build_effective_relays(RelayPolicy::Augment, &deployment, &org);
        assert_eq!(
            out.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
            vec!["https://org.example", "https://cloud.example"]
        );
    }

    #[test]
    fn disabled_is_none_even_when_list_is_empty() {
        assert_eq!(
            connectivity_relay_fallback_for(LicenseTier::Cloud, DeploymentRelayMode::Disabled, &[]),
            ConnectivityRelayFallback::None
        );
        assert_eq!(
            connectivity_relay_fallback_for(
                LicenseTier::Community,
                DeploymentRelayMode::Disabled,
                &[]
            ),
            ConnectivityRelayFallback::None
        );
    }

    #[test]
    fn empty_custom_resolves_to_n0() {
        assert_eq!(
            connectivity_relay_fallback_for(LicenseTier::Cloud, DeploymentRelayMode::Custom, &[]),
            ConnectivityRelayFallback::N0
        );
        assert_eq!(
            connectivity_relay_fallback_for(
                LicenseTier::Enterprise,
                DeploymentRelayMode::Custom,
                &[]
            ),
            ConnectivityRelayFallback::N0
        );
    }

    #[test]
    fn nonempty_custom_is_none_not_n0() {
        let relay = ConnectivityRelayConfig {
            url: "https://r.example".into(),
            region: None,
            auth_token: None,
            metering: false,
        };
        assert_eq!(
            connectivity_relay_fallback_for(
                LicenseTier::Cloud,
                DeploymentRelayMode::Custom,
                &[relay.clone()]
            ),
            ConnectivityRelayFallback::None
        );
        assert_eq!(
            connectivity_relay_fallback_for(
                LicenseTier::Enterprise,
                DeploymentRelayMode::Custom,
                &[relay]
            ),
            ConnectivityRelayFallback::None
        );
    }

    #[test]
    fn n0_mode_is_n0() {
        assert_eq!(
            connectivity_relay_fallback_for(LicenseTier::Cloud, DeploymentRelayMode::N0, &[]),
            ConnectivityRelayFallback::N0
        );
        assert_eq!(
            connectivity_relay_fallback_for(LicenseTier::Community, DeploymentRelayMode::N0, &[]),
            ConnectivityRelayFallback::N0
        );
    }
}
