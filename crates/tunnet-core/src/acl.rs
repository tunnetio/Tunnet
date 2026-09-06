use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use tunnet_common::policy::{
    Action, Direction, EvalCtx, PolicyBundle, Protocol, evaluate_detailed,
};

use crate::policy_runtime::{AclDenyRecord, PolicyRuntime};
use crate::routing::RoutingTable;

#[derive(Debug, Clone)]
pub struct SelfIdentity {
    pub endpoint_hex: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network: String,
}

#[derive(Clone)]
pub struct AclEngine {
    pub self_id: Arc<ArcSwap<SelfIdentity>>,
    pub routes: RoutingTable,
    pub bundle: Arc<ArcSwap<PolicyBundle>>,
    pub stale: Arc<ArcSwap<bool>>,
    /// When false, ACL rules that require source posture do not match.
    pub src_posture_ok: Arc<ArcSwap<bool>>,
    /// Attached shared runtime. Every mutation publishes a fresh compiled
    /// snapshot + generation bump (§0.3); packet state lives there, never here.
    runtime: Arc<RwLock<Option<PolicyRuntime>>>,
}

impl AclEngine {
    pub fn new(self_id: SelfIdentity, routes: RoutingTable, bundle: PolicyBundle) -> Self {
        Self::with_posture_flag(
            self_id,
            routes,
            bundle,
            Arc::new(ArcSwap::from_pointee(true)),
        )
    }

    pub fn with_posture_flag(
        self_id: SelfIdentity,
        routes: RoutingTable,
        bundle: PolicyBundle,
        src_posture_ok: Arc<ArcSwap<bool>>,
    ) -> Self {
        Self {
            self_id: Arc::new(ArcSwap::from_pointee(self_id)),
            routes,
            bundle: Arc::new(ArcSwap::from_pointee(bundle)),
            stale: Arc::new(ArcSwap::from_pointee(false)),
            src_posture_ok,
            runtime: Arc::new(RwLock::new(None)),
        }
    }

    /// Attach the shared runtime (node build / dataplane bring-up). All
    /// subsequent mutations publish to it.
    pub fn attach_runtime(&self, runtime: PolicyRuntime) {
        *self.runtime.write() = Some(runtime);
        self.publish();
    }

    /// Compile current state and publish to the shared runtime (§0.3).
    fn publish(&self) {
        let Some(rt) = self.runtime.read().clone() else {
            return;
        };
        rt.publish_acl(
            &self.bundle.load(),
            &self.self_id.load(),
            **self.src_posture_ok.load(),
            **self.stale.load(),
        );
    }

    pub fn set_src_posture_ok(&self, ok: bool) {
        self.src_posture_ok.store(Arc::new(ok));
        self.publish();
    }

    pub fn replace_bundle(&self, b: PolicyBundle) {
        self.bundle.store(Arc::new(b));
        self.stale.store(Arc::new(false));
        self.publish();
    }

    pub fn flush_conntrack(&self) {
        if let Some(rt) = self.runtime.read().clone() {
            rt.invalidate();
        }
    }

    pub fn replace_self_tags(&self, tags: Vec<String>) {
        let current = self.self_id.load();
        if current.tags == tags {
            return;
        }
        self.self_id.store(Arc::new(SelfIdentity {
            endpoint_hex: current.endpoint_hex.clone(),
            ip: current.ip,
            tags,
            network: current.network.clone(),
        }));
        self.publish();
    }

    pub fn mark_stale(&self) {
        self.stale.store(Arc::new(true));
        self.publish();
    }

    pub fn recent_denies(&self) -> Vec<AclDenyRecord> {
        self.runtime
            .read()
            .clone()
            .map(|rt| rt.recent_denies())
            .unwrap_or_default()
    }

    pub fn allow_inbound_peer(&self, peer_endpoint_hex: &str) -> bool {
        self.allow_peer(peer_endpoint_hex, Direction::Inbound)
    }

    pub fn allow_outbound_peer(&self, peer_endpoint_hex: &str) -> bool {
        self.allow_peer(peer_endpoint_hex, Direction::Outbound)
    }

    pub fn allow_peer(&self, peer_endpoint_hex: &str, direction: Direction) -> bool {
        let peer = self.routes.lookup_endpoint(peer_endpoint_hex);
        let empty_tags: Vec<String> = Vec::new();
        let self_id = self.self_id.load();
        let bundle = self.bundle.load();
        let posture_required = !bundle.default_src_posture.is_empty()
            || bundle.rules.iter().any(|r| !r.src_posture.is_empty());
        let src_posture_ok = if posture_required {
            **self.src_posture_ok.load()
        } else {
            true
        };
        let ctx = EvalCtx {
            self_endpoint_hex: &self_id.endpoint_hex,
            self_ip: self_id.ip,
            self_tags: &self_id.tags,
            self_network: &self_id.network,
            peer_endpoint_hex,
            peer_ip: peer.as_ref().map(|p| p.ip),
            peer_tags: peer
                .as_ref()
                .map(|p| p.tags.as_slice())
                .unwrap_or(&empty_tags),
            peer_network: &self_id.network,
            dst_port: None,
            protocol: Protocol::Any,
            src_posture_ok,
        };
        evaluate_detailed(&bundle, &ctx, direction).action == Action::Allow
    }

    // Packet-level evaluation lives in PolicyRuntime (§13); this engine owns
    // connection admission (allow_peer above) and publishes configuration.
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_common::policy::PolicyBundle;

    fn test_engine(bundle: PolicyBundle) -> AclEngine {
        let self_id = SelfIdentity {
            endpoint_hex: "aa".repeat(32),
            ip: Ipv4Addr::new(100, 64, 0, 1),
            tags: vec![],
            network: "net".into(),
        };
        AclEngine::new(self_id, RoutingTable::new(), bundle)
    }

    #[test]
    fn admission_follows_bundle_default() {
        // Connection admission (not packet policy) still lives here.
        let open = test_engine(PolicyBundle::default());
        assert!(open.allow_inbound_peer(&"bb".repeat(32)));
        let restricted = test_engine(PolicyBundle {
            default_action: tunnet_common::policy::DefaultAction::Deny,
            ..PolicyBundle::default()
        });
        assert!(!restricted.allow_inbound_peer(&"bb".repeat(32)));
    }

    #[test]
    fn mutations_publish_to_attached_runtime() {
        use crate::policy_runtime::PolicyRuntime;
        use std::collections::HashMap;
        let acl = test_engine(PolicyBundle::default());
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::new(),
            &SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
            },
            true,
            false,
        );
        let policy_gen = rt.generation();
        acl.attach_runtime(rt.clone());
        // attach publishes: generation bumps.
        assert!(rt.generation() > policy_gen);
        let gen2 = rt.generation();
        acl.replace_bundle(PolicyBundle::default());
        assert!(rt.generation() > gen2);
        acl.mark_stale();
        // Stale flag propagates to the runtime snapshot.
        assert!(rt.generation() > gen2);
    }

    #[test]
    fn replace_self_tags_noop_skips_publish() {
        use crate::policy_runtime::PolicyRuntime;
        use std::collections::HashMap;
        let acl = test_engine(PolicyBundle::default());
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::new(),
            &SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
            },
            true,
            false,
        );
        acl.attach_runtime(rt.clone());
        let policy_gen = rt.generation();
        acl.replace_self_tags(vec![]);
        assert_eq!(
            rt.generation(),
            policy_gen,
            "unchanged tags must not republish"
        );
        acl.replace_self_tags(vec!["x".into()]);
        assert!(rt.generation() > policy_gen);
    }
}
