use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tuntun_common::{SEND_ALPN, TUNNEL_ALPN};

use crate::acl::{AclEngine, SelfIdentity};
use crate::acl_hook::AclHook;
use crate::control::{SignedClient, basic_metadata};
use crate::direct::firewall::FirewallConfig;
use crate::direct::{
    AUTH_ALPN, AuthCache, DirectAuthHook, DocsBootstrap, DocsMembership, MembershipEntry,
    derive_ipv4, firewall_to_policy, spawn_discovery,
};
use crate::identity::AgentIdentity;
use crate::iroh_pool::ConnPool;
use crate::routing::RoutingTable;
use crate::send::SendManager;
use crate::serve::ServeManager;
use crate::state::{
    DirectState, ManagedState, PersistedState, StatePaths, load_snapshot_cache, save_snapshot_cache,
};
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
    /// Present only in Managed mode.
    pub signed: Option<SignedClient>,
    /// Direct-mode auth cache (None in Managed).
    pub direct_auth: Option<AuthCache>,
    /// Direct-mode iroh-docs membership (None in Managed).
    pub docs: Option<DocsMembership>,
}

impl CoreNode {
    /// Bootstrap based on persisted mode.
    pub async fn bootstrap(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        match &persisted {
            PersistedState::Managed(m) => {
                Self::bootstrap_managed(identity, persisted.clone(), m.clone(), paths, cfg).await
            }
            PersistedState::Direct(d) => {
                Self::bootstrap_direct(identity, persisted.clone(), d.clone(), paths, cfg).await
            }
        }
    }

    async fn bootstrap_managed(
        identity: AgentIdentity,
        persisted: PersistedState,
        managed: ManagedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        let alpns = build_alpns(&cfg, false);

        let my_id_hex = identity.endpoint_id_hex();
        let signed = SignedClient::new(
            managed.control_url.clone(),
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

        let membership = membership_for_network(&snapshot, managed.network_id)?.clone();
        let routes = RoutingTable::new();
        let version = Arc::new(ArcSwap::from_pointee(snapshot.version));
        let acl = AclEngine::new(
            SelfIdentity {
                endpoint_hex: my_id_hex.clone(),
                ip: membership.assigned_ipv4,
                tags: membership.self_tags.clone(),
                network: managed.network_name.clone(),
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

        let ws = crate::ws_client::spawn(
            managed.control_url.clone(),
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
            managed.network_id,
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
            managed.network_id,
            my_id_hex.clone(),
        );

        let _ = persisted;
        Ok(Self {
            identity,
            persisted: PersistedState::Managed(managed),
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
            signed: Some(signed),
            direct_auth: None,
            docs: None,
        })
    }

    async fn bootstrap_direct(
        identity: AgentIdentity,
        persisted: PersistedState,
        mut direct: DirectState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        let alpns = build_alpns(&cfg, true);
        let my_id_hex = identity.endpoint_id_hex();
        let self_ipv4 = if direct.assigned_ipv4.is_unspecified() {
            derive_ipv4(&my_id_hex, direct.collision_index)
        } else {
            direct.assigned_ipv4
        };

        let routes = RoutingTable::new();
        let version = Arc::new(ArcSwap::from_pointee(1u64));
        let fw = FirewallConfig::load(&paths).unwrap_or_else(|_| crate::direct::default_firewall());
        let policy = firewall_to_policy(&fw, &my_id_hex, self_ipv4);
        let acl = AclEngine::new(
            SelfIdentity {
                endpoint_hex: my_id_hex.clone(),
                ip: self_ipv4,
                tags: vec![],
                network: direct.network_name.clone(),
            },
            routes.clone(),
            policy.clone(),
        );

        let auth = AuthCache::new();
        auth.insert(my_id_hex.clone());

        let secret = SecretKey::from_bytes(&identity.secret_bytes);
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(DirectAuthHook::new(acl.clone(), auth.clone()))
            .bind()
            .await
            .context("bind iroh endpoint (direct)")?;

        match tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("direct endpoint online"),
            Err(_) => tracing::warn!("timed out waiting for relay; continuing"),
        }

        let serves = ServeManager::new(self_ipv4, routes.clone());
        let pool = ConnPool::new(endpoint.clone(), TUNNEL_STREAM_ALPN);
        let tunnels = TunnelManager::new(pool.clone());

        let blobs_dir = paths.dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;
        let blobs = iroh_blobs::store::fs::FsStore::load(&blobs_dir)
            .await
            .map_err(|e| anyhow::anyhow!("open shared FsStore: {e}"))?;

        let send = SendManager::from_store(
            blobs.clone(),
            pool.clone(),
            routes.clone(),
            acl.clone(),
            my_id_hex.clone(),
        )
        .await
        .context("open send manager")?;

        let self_entry = MembershipEntry {
            endpoint_id: my_id_hex.clone(),
            hostname: direct.hostname.clone(),
            ipv4: self_ipv4,
            collision_index: direct.collision_index,
            tags: vec![],
            joined_at: chrono::Utc::now(),
            coordinator: direct.coordinator,
            status: "online".into(),
        };

        let (docs, new_ticket, new_ns) = DocsMembership::bootstrap(DocsBootstrap {
            endpoint: endpoint.clone(),
            paths: &paths,
            direct: &direct,
            self_endpoint_id: &my_id_hex,
            self_entry,
            blobs,
            routes: routes.clone(),
            acl: acl.clone(),
            auth: auth.clone(),
            policy,
        })
        .await
        .context("bootstrap iroh-docs membership")?;

        if new_ticket.is_some() || new_ns.is_some() {
            if let Some(t) = new_ticket {
                direct.doc_ticket = Some(t);
            }
            if let Some(ns) = new_ns {
                direct.namespace_id = Some(ns);
            }
            direct.assigned_ipv4 = self_ipv4;
            PersistedState::Direct(direct.clone()).save(&paths)?;
        }

        let mut seeds = Vec::new();
        if let Some(coord) = &direct.coordinator_endpoint_id {
            seeds.push(coord.clone());
        }
        for m in docs.snapshot_members() {
            if m.endpoint_id != my_id_hex {
                seeds.push(m.endpoint_id);
            }
        }
        let _discovery = spawn_discovery(direct.topic_hash.clone(), my_id_hex.clone(), seeds);

        let _ = (cfg, persisted);
        Ok(Self {
            identity,
            persisted: PersistedState::Direct(DirectState {
                assigned_ipv4: self_ipv4,
                ..direct
            }),
            endpoint,
            pool,
            routes,
            acl,
            version,
            self_ipv4,
            paths,
            serves,
            tunnels,
            send,
            signed: None,
            direct_auth: Some(auth),
            docs: Some(docs),
        })
    }

    pub fn endpoint_id_hex(&self) -> String {
        self.identity.endpoint_id_hex()
    }

    pub fn require_signed(&self) -> anyhow::Result<&SignedClient> {
        self.signed.as_ref().context(
            "this operation requires Managed mode (control plane client unavailable in Direct)",
        )
    }

    pub async fn shutdown(&self) {
        self.endpoint.close().await;
    }
}

fn build_alpns(cfg: &CoreNodeConfig, direct: bool) -> Vec<Vec<u8>> {
    let mut alpns: Vec<Vec<u8>> = vec![TUNNEL_STREAM_ALPN.to_vec()];
    if cfg.advertise_datagram_alpn {
        alpns.push(TUNNEL_ALPN.to_vec());
        alpns.push(tuntun_common::SSH_ALPN.to_vec());
    }
    if cfg.advertise_recording_alpn {
        alpns.push(tuntun_common::RECORDING_ALPN.to_vec());
    }
    alpns.push(SEND_ALPN.to_vec());
    alpns.push(iroh_blobs::ALPN.to_vec());
    if direct {
        alpns.push(AUTH_ALPN.to_vec());
        alpns.push(iroh_gossip::ALPN.to_vec());
        alpns.push(iroh_docs::ALPN.to_vec());
    }
    alpns
}
