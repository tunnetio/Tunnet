//! Shared offline fixtures for actor tests (no TUN, no network, no privileges).

use std::collections::HashMap;
use std::sync::Arc;

use tunnet_core::stream::TUNNEL_STREAM_ALPN;

use crate::metrics::AgentMetrics;

/// Minimal offline `CoreNode` for actor lifecycle tests.
pub async fn test_node() -> (tunnet_core::CoreNode, tempfile::TempDir) {
    let identity = tunnet_core::AgentIdentity::generate();
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .bind()
        .await
        .expect("bind test endpoint");
    let routes = tunnet_core::RoutingTable::new();
    let revisions = Arc::new(tunnet_core::sync::ManagedRevisions::new(1, 1));
    let acl = tunnet_core::AclEngine::new(
        tunnet_core::SelfIdentity {
            endpoint_hex: identity.endpoint_id_hex(),
            ip: "10.9.0.1".parse().unwrap(),
            tags: vec![],
            network: "test".into(),
        },
        routes.clone(),
        tunnet_common::policy::PolicyBundle::default(),
    );
    let pool = tunnet_core::ConnPool::new(endpoint.clone(), TUNNEL_STREAM_ALPN);
    let tunnel = tunnet_core::TunnelMesh::new(pool.cloud_relay_meter(), true);
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = tunnet_core::StatePaths::resolve(Some(tmp.path().to_str().expect("utf8")));
    let _ = paths.ensure();
    let send = tunnet_core::SendManager::open(
        paths.blobs_dir(),
        pool.clone(),
        routes.clone(),
        acl.clone(),
        identity.endpoint_id_hex(),
    )
    .await
    .expect("open send manager");
    let node = tunnet_core::CoreNode {
        identity,
        persisted: tunnet_core::PersistedState::Direct { networks: vec![] },
        endpoint,
        pool: pool.clone(),
        tunnel,
        effective_config: tunnet_core::EffectiveConfigStore::new(),
        routes: routes.clone(),
        acl,
        revisions,
        self_ipv4: "10.9.0.1".parse().unwrap(),
        paths,
        serves: tunnet_core::ServeManager::new("10.9.0.1".parse().unwrap(), routes),
        tunnels: tunnet_core::TunnelManager::new(pool),
        send,
        signed: None,
        control_link: None,
        direct_auth: None,
        direct: HashMap::new(),
        gossip: None,
        docs_engine: None,
        presence_tables: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    (node, tmp)
}

/// Metrics handle that never touches the global recorder (parallel-safe).
pub fn test_metrics() -> AgentMetrics {
    AgentMetrics::for_tests()
}
