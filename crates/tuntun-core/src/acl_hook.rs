//! Connection-level ACL via iroh [`EndpointHooks`].
//!
//! Gates peers after the QUIC/TLS handshake (and before outbound dials) so
//! disallowed remotes never reach ALPN handlers. Packet/port policy stays in
//! [`AclEngine::allow_packet`].

use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, Side,
};

use crate::acl::AclEngine;

const CLOSE_POLICY_DENY: u32 = 403;

/// Endpoint hook that enforces peer ACL at connection establishment.
#[derive(Clone)]
pub struct AclHook {
    acl: AclEngine,
}

impl AclHook {
    pub fn new(acl: AclEngine) -> Self {
        Self { acl }
    }
}

impl std::fmt::Debug for AclHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclHook").finish_non_exhaustive()
    }
}

impl EndpointHooks for AclHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let peer_hex = format!("{}", remote_addr.id);
        if self.acl.allow_outbound_peer(&peer_hex) {
            BeforeConnectOutcome::Accept
        } else {
            tracing::warn!(%peer_hex, "outbound connect blocked by ACL hook");
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        // Outgoing dials are already gated in `before_connect`.
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }

        let peer_hex = format!("{}", conn.remote_id());
        if self.acl.allow_inbound_peer(&peer_hex) {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::warn!(
                %peer_hex,
                alpn = %String::from_utf8_lossy(conn.alpn()),
                "inbound connection blocked by ACL hook"
            );
            AfterHandshakeOutcome::Reject {
                error_code: CLOSE_POLICY_DENY.into(),
                reason: b"policy_deny".to_vec(),
            }
        }
    }
}
