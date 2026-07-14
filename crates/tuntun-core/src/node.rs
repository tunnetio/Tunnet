use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tuntun_common::{SEND_ALPN, TUNNEL_ALPN};

use crate::acl::{AclEngine, SelfIdentity};
use crate::acl_hook::AclHook;
use crate::control::{SignedClient, basic_metadata};
use crate::identity::AgentIdentity;
use crate::iroh_pool::ConnPool;
use crate::routing::RoutingTable;
use crate::send::SendManager;
use crate::serve::ServeManager;
use crate::state::{PersistedState, StatePaths, load_snapshot_cache, save_snapshot_cache};
use crate::stream::TUNNEL_STREAM_ALPN;
use crate::sync::{
    apply_membership, membership_for_network, spawn_poll_fallback, spawn_ws_processor,
};
use crate::tunnel::TunnelManager;

/// Callback when CP requests killing an SSH session (`session_id`).
pub type KillSshHook = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct CoreNodeConfig {
    pub hostname: String,
    pub agent_version: &'static str,
    pub poll_secs: u64,
    pub advertise_datagram_alpn: bool,
    /// Advertise `tuntun/recording/1` (this node can receive session recordings).
    pub advertise_recording_alpn: bool,
    pub kind: &'static str, // "agent" | "sdk"
    /// Optional hook when CP requests killing an SSH session (session_id string).
    pub on_kill_ssh: Option<KillSshHook>,
}

impl Default for CoreNodeConfig {
    fn default() -> Self {
        Self {
            hostname: "tuntun-node".into(),
            agent_version: env!("CARGO_PKG_VERSION"),
            poll_secs: 30,
            advertise_datagram_alpn: false,
            advertise_recording_alpn: false,
            kind: "sdk",
            on_kill_ssh: None,
        }
    }
}

#[derive(Clone)]
pub struct CoreNode {
    pub identity: AgentIdentity,
    pub persisted: PersistedState,
    pub endpoint: Endpoint,
    pub pool: ConnPool,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub version: Arc<ArcSwap<u64>>,
    pub self_ipv4: std::net::Ipv4Addr,
    pub paths: StatePaths,
    pub serves: ServeManager,
    pub tunnels: TunnelManager,
    pub send: SendManager,
    pub signed: SignedClient,
}

impl CoreNode {
    pub async fn bootstrap(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        let mut alpns: Vec<Vec<u8>> = vec![TUNNEL_STREAM_ALPN.to_vec()];
        if cfg.advertise_datagram_alpn {
            alpns.push(TUNNEL_ALPN.to_vec());
            alpns.push(tuntun_common::SSH_ALPN.to_vec());
        }
        if cfg.advertise_recording_alpn {
            alpns.push(tuntun_common::RECORDING_ALPN.to_vec());
        }
        // File transfer (offer + iroh-blobs) available on both agent and SDK nodes.
        alpns.push(SEND_ALPN.to_vec());
        alpns.push(iroh_blobs::ALPN.to_vec());

        // Register with CP before binding so ACL policy is ready for EndpointHooks.
        let my_id_hex = identity.endpoint_id_hex();
        let signed = SignedClient::new(
            persisted.control_url.clone(),
            my_id_hex.clone(),
            identity.signing_key.clone(),
        )?;

        let meta = basic_metadata(&cfg.hostname, cfg.agent_version, cfg.kind);
        let snapshot = match signed
            .register(&cfg.hostname, cfg.agent_version, Some(meta))
            .await
        {
            Ok(s) => {
                save_snapshot_cache(&paths, &s).ok();
                s
            }
            Err(e) => {
                tracing::warn!(?e, "register failed; falling back to cache");
                load_snapshot_cache(&paths).context("no cache")?
            }
        };

        let membership = membership_for_network(&snapshot, persisted.network_id)?.clone();
        let routes = RoutingTable::new();
        let version = Arc::new(ArcSwap::from_pointee(snapshot.version));
        let acl = AclEngine::new(
            SelfIdentity {
                endpoint_hex: my_id_hex.clone(),
                ip: membership.assigned_ipv4,
                tags: membership.self_tags.clone(),
                network: persisted.network_name.clone(),
            },
            routes.clone(),
            membership.policy.clone(),
        );
        apply_membership(
            &membership,
            &routes,
            &acl,
            &version,
            snapshot.version,
            &my_id_hex,
        );

        let secret = SecretKey::from_bytes(&identity.secret_bytes);
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(AclHook::new(acl.clone()))
            .bind()
            .await
            .context("bind iroh endpoint")?;

        debug_assert_eq!(format!("{}", endpoint.id()), my_id_hex);

        match tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("endpoint online"),
            Err(_) => tracing::warn!("timed out waiting for relay; continuing"),
        }

        let serves = ServeManager::new(membership.assigned_ipv4, routes.clone());
        let pool = ConnPool::new(endpoint.clone(), TUNNEL_STREAM_ALPN);
        let tunnels = TunnelManager::new(pool.clone());
        let send = SendManager::open(
            paths.dir.join("blobs"),
            pool.clone(),
            routes.clone(),
            acl.clone(),
            my_id_hex.clone(),
        )
        .await
        .context("open send manager")?;

        // Sync loops.
        let ws = crate::ws_client::spawn(
            persisted.control_url.clone(),
            my_id_hex.clone(),
            identity.signing_key.clone(),
        );
        serves.set_client_tx(ws.tx.clone());
        send.set_client_tx(ws.tx.clone());
        spawn_ws_processor(
            ws,
            routes.clone(),
            acl.clone(),
            version.clone(),
            paths.clone_paths(),
            persisted.network_id,
            my_id_hex.clone(),
            cfg.agent_version,
            Some(serves.clone()),
            Some(tunnels.clone()),
            Some(send.clone()),
            cfg.on_kill_ssh.clone(),
        );
        spawn_poll_fallback(
            signed.clone(),
            version.clone(),
            cfg.poll_secs,
            routes.clone(),
            acl.clone(),
            persisted.network_id,
            my_id_hex.clone(),
        );

        Ok(Self {
            identity,
            persisted,
            endpoint,
            pool,
            routes,
            acl,
            version,
            self_ipv4: membership.assigned_ipv4,
            paths,
            serves,
            tunnels,
            send,
            signed,
        })
    }

    pub fn endpoint_id_hex(&self) -> String {
        self.identity.endpoint_id_hex()
    }

    pub async fn shutdown(&self) {
        self.endpoint.close().await;
    }
}

impl StatePaths {
    pub fn clone_paths(&self) -> StatePaths {
        StatePaths {
            dir: self.dir.clone(),
        }
    }
}
