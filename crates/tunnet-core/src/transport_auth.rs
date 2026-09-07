//! Transport admission: authenticated membership only, never L3/L4 policy.
//!
//! Admission answers one question: is this peer currently a trusted member?
//! Flow policy ([`AclEngine::allow_packet`], [`AclEngine::allow_flow`]) runs
//! where real flow context exists, never here.

use std::fmt;

use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, Side,
};

#[cfg(feature = "direct")]
use crate::direct::AuthCache;
use crate::routing::RoutingTable;

/// Wire contract for authorization rejections, shared by the endpoint hooks
/// and the connection pool's failure classifier.
pub const CLOSE_NOT_MEMBER: u32 = 403;
pub const CLOSE_NOT_MEMBER_REASON: &[u8] = b"not_member";
pub const CLOSE_AUTH_REQUIRED: u32 = 401;
pub const CLOSE_AUTH_REQUIRED_REASON: &[u8] = b"auth_required";
/// Reason used before the contract above; still honored from older peers.
pub const CLOSE_LEGACY_POLICY_DENY_REASON: &[u8] = b"policy_deny";

/// True when an application close carries this crate's authorization rejection.
pub fn is_authorization_close(code: u32, reason: &[u8]) -> bool {
    match code {
        CLOSE_NOT_MEMBER => {
            reason == CLOSE_NOT_MEMBER_REASON || reason == CLOSE_LEGACY_POLICY_DENY_REASON
        }
        CLOSE_AUTH_REQUIRED => reason == CLOSE_AUTH_REQUIRED_REASON,
        _ => false,
    }
}

/// Membership-backed transport gate shared by endpoint hooks and [`crate::ConnPool`].
///
/// Managed: the peer is dialable while control-plane membership lists it.
/// Direct: the peer is dialable while Grant AUTH covers it.
/// Bootstrap ALPNs bypass the pool entirely (docs/gossip/auth sync membership
/// before it exists), so the gate only guards data-plane ALPNs.
#[derive(Clone)]
pub struct TransportAuth {
    inner: TransportAuthInner,
}

#[derive(Clone)]
enum TransportAuthInner {
    Managed {
        routes: RoutingTable,
    },
    #[cfg(feature = "direct")]
    Direct {
        auth: AuthCache,
    },
}

impl TransportAuth {
    pub fn managed(routes: &RoutingTable) -> Self {
        Self {
            inner: TransportAuthInner::Managed {
                routes: routes.clone(),
            },
        }
    }

    #[cfg(feature = "direct")]
    pub fn direct(auth: &AuthCache) -> Self {
        Self {
            inner: TransportAuthInner::Direct { auth: auth.clone() },
        }
    }

    pub fn allows(&self, peer_hex: &str) -> bool {
        match &self.inner {
            TransportAuthInner::Managed { routes } => routes.lookup_endpoint(peer_hex).is_some(),
            #[cfg(feature = "direct")]
            TransportAuthInner::Direct { auth } => auth.contains(peer_hex),
        }
    }

    /// Membership generation: local denials pin this value and retry only once
    /// it moves. Remote rejections additionally re-probe on a bounded cooldown
    /// since remote membership is unobservable locally.
    pub fn generation(&self) -> u64 {
        match &self.inner {
            TransportAuthInner::Managed { routes } => routes.change_seq(),
            #[cfg(feature = "direct")]
            TransportAuthInner::Direct { auth } => auth.version(),
        }
    }
}

impl fmt::Debug for TransportAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportAuth").finish_non_exhaustive()
    }
}

/// Managed endpoint hook: admit current control-plane members, reject the rest.
#[derive(Clone)]
pub struct TransportHook {
    auth: TransportAuth,
}

impl TransportHook {
    pub fn managed(routes: &RoutingTable) -> Self {
        Self {
            auth: TransportAuth::managed(routes),
        }
    }

    pub fn authorizer(&self) -> TransportAuth {
        self.auth.clone()
    }
}

impl fmt::Debug for TransportHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportHook").finish_non_exhaustive()
    }
}

impl EndpointHooks for TransportHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let peer_hex = format!("{}", remote_addr.id);
        if self.auth.allows(&peer_hex) {
            BeforeConnectOutcome::Accept
        } else {
            tracing::debug!(%peer_hex, "outbound connect blocked (not a member)");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }
        let peer_hex = format!("{}", conn.remote_id());
        if self.auth.allows(&peer_hex) {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::debug!(
                %peer_hex,
                alpn = %String::from_utf8_lossy(conn.alpn()),
                "inbound connection blocked (not a member)"
            );
            AfterHandshakeOutcome::Reject {
                error_code: CLOSE_NOT_MEMBER.into(),
                reason: CLOSE_NOT_MEMBER_REASON.to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEngine, SelfIdentity};
    use std::net::Ipv4Addr;
    use tunnet_common::policy::{DefaultAction, IcmpPolicy, PolicyBundle};

    fn deny_bundle() -> PolicyBundle {
        PolicyBundle {
            rules: vec![],
            ssh_rules: vec![],
            version: 1,
            signature: String::new(),
            default_action: DefaultAction::Deny,
            icmp_policy: IcmpPolicy::Deny,
            postures: Default::default(),
            default_src_posture: vec![],
            posture_enforcement: None,
        }
    }

    #[test]
    fn managed_admission_ignores_l3l4_default_deny() {
        let routes = RoutingTable::new();
        let peer = "bb".repeat(32);
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint_id: peer.clone(),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            uuid::Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
        // L3/L4 policy denies everything, yet the member must pass transport admission.
        let _acl = AclEngine::new(
            SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
            },
            routes.clone(),
            deny_bundle(),
        );
        let auth = TransportAuth::managed(&routes);
        assert!(auth.allows(&peer));
        assert!(!auth.allows(&"cc".repeat(32)));
    }

    #[test]
    fn authorization_close_contract() {
        assert!(is_authorization_close(403, b"not_member"));
        assert!(is_authorization_close(401, b"auth_required"));
        assert!(is_authorization_close(403, b"policy_deny"));
        assert!(!is_authorization_close(0, b"tie_break"));
        assert!(!is_authorization_close(1, b"dataplane_down"));
        assert!(!is_authorization_close(403, b"something_else"));
    }

    #[cfg(feature = "direct")]
    #[test]
    fn direct_admission_follows_auth_cache_generation() {
        let cache = AuthCache::new();
        let auth = TransportAuth::direct(&cache);
        let peer = "bb".repeat(32);
        assert!(!auth.allows(&peer));
        let first = auth.generation();
        cache.insert(peer.clone(), uuid::Uuid::nil());
        assert!(auth.allows(&peer));
        assert!(auth.generation() > first);
        cache.remove(&peer);
        assert!(!auth.allows(&peer));
    }
}
