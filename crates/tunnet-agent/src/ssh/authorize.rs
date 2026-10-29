//! Authorize an SSH login after Tunnet has already authenticated the source.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use tunnet_common::policy::{SshAction, SshEvalCtx, evaluate_ssh};
use tunnet_core::RoutingTable;
use tunnet_core::agent_config::DirectSshSection;
use uuid::Uuid;

use super::account::{self, LocalAccount};
use super::capabilities::SshCapabilities;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationMode {
    Direct,
    Managed,
}

#[derive(Debug, Clone)]
pub struct RecordingPolicy {
    pub record: bool,
    pub enforce_recorder: bool,
    pub recorder: Option<tunnet_common::policy::Selector>,
}

impl RecordingPolicy {
    fn none() -> Self {
        Self {
            record: false,
            enforce_recorder: false,
            recorder: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CheckState {
    None,
    Required { period_secs: u64 },
}

#[derive(Debug, Clone)]
pub struct AuthorizedSession {
    pub source_endpoint: String,
    pub source_hostname: Option<String>,
    pub source_network: Uuid,
    pub dest_network: Uuid,
    pub dest_user: String,
    pub account: LocalAccount,
    pub mode: AuthorizationMode,
    pub capabilities: SshCapabilities,
    pub recording: RecordingPolicy,
    pub check: CheckState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzFailure {
    UnknownMeshSource,
    NotCurrentMember,
    ServiceDisabled,
    UserNotAllowed { requested: String },
    AccountMissing { requested: String },
    ManagedDeny,
}

impl AuthzFailure {
    pub fn log_message(&self) -> String {
        match self {
            Self::UnknownMeshSource => "ssh source is not a known mesh IP".into(),
            Self::NotCurrentMember => {
                "ssh source is not a current member of the destination network".into()
            }
            Self::ServiceDisabled => "embedded SSH is disabled on this network".into(),
            Self::UserNotAllowed { requested } => {
                format!("destination OS account `{requested}` is not allowed")
            }
            Self::AccountMissing { requested } => {
                format!("destination OS account `{requested}` does not exist")
            }
            Self::ManagedDeny => "managed SSH policy denied the session".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BindingPolicy {
    Direct { allowed_users: BTreeSet<String> },
    Managed,
}

impl BindingPolicy {
    pub fn from_direct(ssh: &DirectSshSection) -> Option<Self> {
        if !ssh.enabled {
            return None;
        }
        Some(Self::Direct {
            allowed_users: ssh.users.iter().map(|u| u.trim().to_string()).collect(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MeshSource {
    pub endpoint: String,
    pub hostname: Option<String>,
    pub network_id: Uuid,
    pub network_name: String,
    pub tags: Vec<String>,
}

pub fn identify_source(
    peer_addr: SocketAddr,
    dest_network: Uuid,
    routes: &RoutingTable,
) -> Result<MeshSource, AuthzFailure> {
    let ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return Err(AuthzFailure::UnknownMeshSource),
    };
    let source = routes
        .lookup_ip(&ip)
        .ok_or(AuthzFailure::UnknownMeshSource)?;
    let member = routes
        .lookup_endpoint_in(dest_network, &source.endpoint_hex)
        .ok_or(AuthzFailure::NotCurrentMember)?;
    let hostname = if member.hostname.is_empty() {
        None
    } else {
        Some(member.hostname.clone())
    };
    Ok(MeshSource {
        endpoint: member.endpoint_hex.clone(),
        hostname,
        network_id: member.network_id,
        network_name: member.network_name.clone(),
        tags: member.tags.clone(),
    })
}

pub fn authorize_direct(
    source: &MeshSource,
    dest_network: Uuid,
    requested_user: &str,
    allowed_users: &BTreeSet<String>,
) -> Result<AuthorizedSession, AuthzFailure> {
    if allowed_users.is_empty() {
        return Err(AuthzFailure::ServiceDisabled);
    }
    if !allowed_users
        .iter()
        .any(|u| user_matches(u, requested_user))
    {
        return Err(AuthzFailure::UserNotAllowed {
            requested: requested_user.to_string(),
        });
    }
    finish(
        source,
        dest_network,
        requested_user,
        AuthorizationMode::Direct,
        SshCapabilities::direct(),
        RecordingPolicy::none(),
        CheckState::None,
    )
}

pub fn authorize_managed(
    source: &MeshSource,
    dest_network: Uuid,
    dest_network_name: &str,
    dest_endpoint_hex: &str,
    dest_tags: &[String],
    requested_user: &str,
    ssh_rules: &[tunnet_common::policy::SshPolicyRule],
) -> Result<AuthorizedSession, AuthzFailure> {
    let local_accounts = account::interactive_usernames();
    let ctx = SshEvalCtx {
        src_endpoint_hex: &source.endpoint,
        src_tags: &source.tags,
        src_network: &source.network_name,
        dst_endpoint_hex: dest_endpoint_hex,
        dst_tags: dest_tags,
        dst_network: dest_network_name,
        requested_user,
        local_accounts: &local_accounts,
    };
    let Some(rule) = evaluate_ssh(ssh_rules, &ctx) else {
        return Err(AuthzFailure::ManagedDeny);
    };
    if rule.action == SshAction::Deny {
        return Err(AuthzFailure::ManagedDeny);
    }
    let check = if rule.action == SshAction::Check {
        CheckState::Required {
            period_secs: rule.check_period_secs.unwrap_or(3600),
        }
    } else {
        CheckState::None
    };
    finish(
        source,
        dest_network,
        requested_user,
        AuthorizationMode::Managed,
        SshCapabilities::managed(),
        RecordingPolicy {
            record: rule.record,
            enforce_recorder: rule.enforce_recorder,
            recorder: rule.recorder.clone(),
        },
        check,
    )
}

fn finish(
    source: &MeshSource,
    dest_network: Uuid,
    requested_user: &str,
    mode: AuthorizationMode,
    capabilities: SshCapabilities,
    recording: RecordingPolicy,
    check: CheckState,
) -> Result<AuthorizedSession, AuthzFailure> {
    let account = account::resolve(requested_user).map_err(|_| AuthzFailure::AccountMissing {
        requested: requested_user.to_string(),
    })?;
    Ok(AuthorizedSession {
        source_endpoint: source.endpoint.clone(),
        source_hostname: source.hostname.clone(),
        source_network: source.network_id,
        dest_network,
        dest_user: account.username.clone(),
        account,
        mode,
        capabilities,
        recording,
        check,
    })
}

fn user_matches(allowed: &str, requested: &str) -> bool {
    #[cfg(windows)]
    {
        allowed.eq_ignore_ascii_case(requested)
    }
    #[cfg(not(windows))]
    {
        allowed == requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tunnet_common::policy::{Selector, SshPolicyRule};
    use tunnet_common::{DeviceProfile, DnsConfig, PeerEntry};

    fn net(octet: u8) -> (Uuid, Ipv4Addr) {
        (
            Uuid::from_u128(octet as u128),
            Ipv4Addr::new(100, 64, 0, octet),
        )
    }

    fn table(network: Uuid, peers: &[(&str, Ipv4Addr)]) -> RoutingTable {
        let routes = RoutingTable::new();
        let entries: Vec<PeerEntry> = peers
            .iter()
            .map(|(id, ip)| PeerEntry {
                ip: *ip,
                endpoint_id: (*id).into(),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            })
            .collect();
        routes.replace(
            &entries,
            &[],
            &[],
            &[],
            &DeviceProfile::default(),
            &DnsConfig::default(),
            "net",
            network,
            &"f".repeat(64),
            1,
        );
        routes
    }

    fn eid() -> String {
        "a".repeat(64)
    }

    fn source(routes: &RoutingTable, network: Uuid, ip: Ipv4Addr) -> MeshSource {
        identify_source(SocketAddr::new(IpAddr::V4(ip), 1234), network, routes).unwrap()
    }

    #[test]
    fn direct_missing_os_account_fails_closed() {
        let (network, ip) = net(2);
        let peer = eid();
        let routes = table(network, &[(&peer, ip)]);
        let src = source(&routes, network, ip);
        let err = authorize_direct(&src, network, "alice", &BTreeSet::from(["alice".into()]))
            .unwrap_err();
        assert_eq!(
            err,
            AuthzFailure::AccountMissing {
                requested: "alice".into()
            }
        );
    }

    #[test]
    fn direct_disallowed_user_fails() {
        let (network, ip) = net(2);
        let peer = eid();
        let routes = table(network, &[(&peer, ip)]);
        let src = source(&routes, network, ip);
        let err =
            authorize_direct(&src, network, "root", &BTreeSet::from(["alice".into()])).unwrap_err();
        assert_eq!(
            err,
            AuthzFailure::UserNotAllowed {
                requested: "root".into()
            }
        );
    }

    #[test]
    fn other_network_member_fails() {
        let (home, _ip) = net(1);
        let (other, ip) = net(2);
        let peer = eid();
        let routes = table(other, &[(&peer, ip)]);
        let err =
            identify_source(SocketAddr::new(IpAddr::V4(ip), 1234), home, &routes).unwrap_err();
        assert_eq!(err, AuthzFailure::NotCurrentMember);
    }

    #[test]
    fn empty_allowlist_is_disabled() {
        let (network, ip) = net(2);
        let peer = eid();
        let routes = table(network, &[(&peer, ip)]);
        let src = source(&routes, network, ip);
        let err = authorize_direct(&src, network, "alice", &BTreeSet::new()).unwrap_err();
        assert_eq!(err, AuthzFailure::ServiceDisabled);
    }

    #[test]
    fn unknown_ip_fails() {
        let (network, ip) = net(2);
        let peer = eid();
        let routes = table(network, &[(&peer, ip)]);
        let err = identify_source(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 22),
            network,
            &routes,
        )
        .unwrap_err();
        assert_eq!(err, AuthzFailure::UnknownMeshSource);
    }

    #[test]
    fn managed_accept_requires_account() {
        let src = MeshSource {
            endpoint: "aa".into(),
            hostname: None,
            network_id: Uuid::nil(),
            network_name: "prod".into(),
            tags: vec![],
        };
        let err = authorize_managed(
            &src,
            Uuid::nil(),
            "prod",
            "bb",
            &[],
            "missing-user-xyz",
            &[SshPolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: SshAction::Accept,
                users: vec!["missing-user-xyz".into()],
                record: false,
                recorder: None,
                enforce_recorder: false,
                check_period_secs: None,
                priority: 1,
            }],
        )
        .unwrap_err();
        assert_eq!(
            err,
            AuthzFailure::AccountMissing {
                requested: "missing-user-xyz".into()
            }
        );
    }

    #[test]
    fn managed_deny_without_rule() {
        let src = MeshSource {
            endpoint: "aa".into(),
            hostname: None,
            network_id: Uuid::nil(),
            network_name: "prod".into(),
            tags: vec![],
        };
        let err =
            authorize_managed(&src, Uuid::nil(), "prod", "bb", &[], "alice", &[]).unwrap_err();
        assert_eq!(err, AuthzFailure::ManagedDeny);
    }
}
