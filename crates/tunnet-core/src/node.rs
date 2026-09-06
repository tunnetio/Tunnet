#[cfg(any(feature = "managed", feature = "direct"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "direct")]
use std::sync::Mutex;
#[cfg(any(feature = "managed", feature = "direct"))]
use std::time::Duration;

#[cfg(any(feature = "managed", feature = "direct"))]
use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::Endpoint;
#[cfg(any(feature = "managed", feature = "direct"))]
use iroh::SecretKey;
#[cfg(any(feature = "managed", feature = "direct"))]
use tunnet_common::TUNNEL_ALPN;
#[cfg(feature = "direct")]
use uuid::Uuid;

use crate::acl::AclEngine;
#[cfg(any(feature = "managed", feature = "direct"))]
use crate::acl::SelfIdentity;
#[cfg(feature = "managed")]
use crate::acl_hook::AclHook;
#[cfg(feature = "managed")]
use crate::control::{SignedClient, basic_metadata};
#[cfg(feature = "direct")]
use crate::direct::PresenceTable;
#[cfg(feature = "direct")]
use crate::direct::{
    AUTH_ALPN, AuthCache, DirectAuthHook, DocsBootstrap, DocsMembership, MembershipEntry,
    NetworkGrant, derive_ipv4, firewall_to_policy, signing_key_from_hex, spawn_discovery,
    spawn_seed_auth,
};
#[cfg(any(feature = "managed", feature = "direct"))]
use crate::direct::{ConnectivityOptions, apply_connectivity, endpoint_builder};
use crate::identity::AgentIdentity;
use crate::iroh_pool::ConnPool;
use crate::policy_runtime::PolicyRuntime;
use crate::routing::RoutingTable;
#[cfg(feature = "send")]
use crate::send::SendManager;
#[cfg(feature = "serve")]
use crate::serve::ServeManager;
#[cfg(feature = "direct")]
use crate::state::DirectState;
#[cfg(feature = "managed")]
use crate::state::{ManagedState, load_snapshot_cache, save_snapshot_cache};
use crate::state::{PersistedState, StatePaths};
#[cfg(any(feature = "managed", feature = "direct"))]
use crate::stream::TUNNEL_STREAM_ALPN;
#[cfg(feature = "managed")]
use crate::sync::{apply_membership, membership_for_network};
#[cfg(feature = "tunnel")]
use crate::tunnel::TunnelManager;
#[cfg(feature = "direct")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "direct")]
use iroh_docs::protocol::Docs;

/// Per-Direct-network runtime (docs + firewall + state).
#[cfg(feature = "direct")]
#[derive(Clone)]
pub struct DirectNetworkRuntime {
    pub docs: DocsMembership,
    pub firewall: crate::direct::FirewallEngine,
    pub spoof_tracker: crate::direct::SpoofTracker,
    pub state: DirectState,
    pub discovery: crate::direct::DiscoveryHandle,
    pub presence: Option<Arc<PresenceTable>>,
}

#[derive(Clone)]
pub struct CoreNodeConfig {
    pub hostname: String,
    pub agent_version: &'static str,
    pub advertise_datagram_alpn: bool,
    /// Advertise `tunnet/recording/1` (this node can receive session recordings).
    pub advertise_recording_alpn: bool,
    pub kind: &'static str, // "agent" | "sdk"
    /// Shared flag updated by posture status; gates ACL rules with `srcPosture`.
    pub src_posture_ok: Option<Arc<arc_swap::ArcSwap<bool>>>,
    /// Endpoint connectivity (relay preset, DHT, mDNS).
    #[cfg(any(feature = "managed", feature = "direct"))]
    pub connectivity: ConnectivityOptions,
    /// Advertise/run shared iroh-gossip (Managed needs this for presence + service relay).
    pub enable_gossip: bool,
    /// Keep all peer connections open (Managed default: true; Direct default: false = on-demand).
    pub keep_alive: bool,
    /// Optional pre-seeded effective config store (agent shares this with policy hooks).
    pub effective_config: Option<crate::EffectiveConfigStore>,
}

impl Default for CoreNodeConfig {
    fn default() -> Self {
        Self {
            hostname: "tunnet-node".into(),
            agent_version: env!("CARGO_PKG_VERSION"),
            advertise_datagram_alpn: false,
            advertise_recording_alpn: false,
            kind: "sdk",
            src_posture_ok: None,
            #[cfg(any(feature = "managed", feature = "direct"))]
            connectivity: ConnectivityOptions::default(),
            enable_gossip: true,
            keep_alive: true,
            effective_config: None,
        }
    }
}

#[derive(Clone)]
pub struct CoreNode {
    pub identity: AgentIdentity,
    pub persisted: PersistedState,
    pub endpoint: Endpoint,
    /// Stream pool (`TUNNEL_STREAM_ALPN`).
    pub pool: ConnPool,
    /// Datagram tunnel pool (`TUNNEL_ALPN`), shares keep-alive policy with [`Self::pool`].
    pub tunnel_pool: ConnPool,
    /// Live effective agent config (local TOML + remote org policy).
    pub effective_config: crate::EffectiveConfigStore,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    /// Shared packet-policy runtime (dataplane authority, §0.1).
    pub policy: PolicyRuntime,
    pub version: Arc<ArcSwap<u64>>,
    pub self_ipv4: std::net::Ipv4Addr,
    pub paths: StatePaths,
    #[cfg(feature = "serve")]
    pub serves: ServeManager,
    #[cfg(feature = "tunnel")]
    pub tunnels: TunnelManager,
    #[cfg(feature = "send")]
    pub send: SendManager,
    /// Present only in Managed mode.
    #[cfg(feature = "managed")]
    pub signed: Option<SignedClient>,
    /// Live control-plane WebSocket status (Managed only).
    #[cfg(feature = "managed")]
    pub control_link: Option<crate::ws_client::ControlPlaneLink>,
    /// Direct-mode auth cache (None in Managed).
    #[cfg(feature = "direct")]
    pub direct_auth: Option<AuthCache>,
    /// Per-network Direct runtime (empty in Managed).
    #[cfg(feature = "direct")]
    pub direct: HashMap<Uuid, DirectNetworkRuntime>,
    /// Shared agent Gossip (Managed + Direct).
    pub gossip: Option<iroh_gossip::net::Gossip>,
    /// Unified iroh-docs engine (Direct).
    #[cfg(feature = "direct")]
    pub docs_engine: Option<Docs>,
    /// Live presence tables keyed by network id (populated by agent runtime).
    #[cfg(feature = "direct")]
    pub presence_tables: Arc<Mutex<HashMap<Uuid, Arc<PresenceTable>>>>,
}

impl CoreNode {
    #[cfg(feature = "direct")]
    pub fn firewall_for(&self, network_id: Uuid) -> Option<&crate::direct::FirewallEngine> {
        self.direct.get(&network_id).map(|r| &r.firewall)
    }

    #[cfg(feature = "direct")]
    pub fn docs_for(&self, network_id: Uuid) -> Option<&DocsMembership> {
        self.direct.get(&network_id).map(|r| &r.docs)
    }

    #[cfg(feature = "direct")]
    pub fn presence_for(&self, network_id: Uuid) -> Option<&Arc<PresenceTable>> {
        self.direct
            .get(&network_id)
            .and_then(|r| r.presence.as_ref())
    }

    #[cfg(feature = "direct")]
    pub fn peer_presence_online(&self, endpoint_hex: &str) -> Option<bool> {
        let now = jiff::Timestamp::now();
        let tables = self.presence_tables.lock().ok()?;
        if tables.is_empty() {
            return None;
        }
        let mut saw_entry = false;
        let mut any_online = false;
        for table in tables.values() {
            match table.presence_status(endpoint_hex, now) {
                Some(true) => any_online = true,
                Some(false) => saw_entry = true,
                None => {}
            }
        }
        if any_online {
            return Some(true);
        }
        // Never-seen peers stay unknown (None) so cold-start does not flood Offline.
        if saw_entry {
            return Some(false);
        }
        None
    }

    #[cfg(feature = "direct")]
    pub fn peer_presence_last_seen(&self, endpoint_hex: &str) -> Option<u64> {
        let now = jiff::Timestamp::now();
        self.presence_tables
            .lock()
            .ok()?
            .values()
            .filter_map(|table| table.last_seen(endpoint_hex, now))
            .filter_map(|duration| u64::try_from(duration.as_secs()).ok())
            .min()
    }

    #[cfg(feature = "direct")]
    pub fn register_presence_table(&self, network_id: Uuid, table: Arc<PresenceTable>) {
        if let Ok(mut tables) = self.presence_tables.lock() {
            tables.insert(network_id, table);
        }
    }

    /// Docs for the primary Direct network (explicit network_id, never arbitrary first).
    #[cfg(feature = "direct")]
    pub fn primary_docs(&self) -> Option<&DocsMembership> {
        let nid = self.persisted.primary_network_id()?;
        self.docs_for(nid)
    }

    #[cfg(feature = "direct")]
    pub fn primary_firewall(&self) -> Option<&crate::direct::FirewallEngine> {
        let nid = self.persisted.primary_network_id()?;
        self.firewall_for(nid)
    }

    /// Bootstrap based on persisted mode.
    ///
    /// Spawns no background control-plane tasks. In Managed builds the node
    /// is returned alongside its unowned transport; the caller owns control
    /// lifecycle explicitly (agent `ControlPlaneActor`, or an explicit
    /// managed driver for SDK/kube-node). Direct-only builds return the node
    /// alone so they never name the managed transport type.
    #[cfg(feature = "managed")]
    pub async fn bootstrap(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<(Self, Option<crate::ws_client::PendingControl>)> {
        match &persisted {
            PersistedState::Managed(m) => {
                Self::bootstrap_managed(identity, persisted.clone(), m.clone(), paths, cfg).await
            }
            PersistedState::Direct { networks } => {
                if networks.is_empty() {
                    anyhow::bail!("no Direct networks joined");
                }
                #[cfg(feature = "direct")]
                {
                    let node =
                        Self::bootstrap_direct(identity, persisted.clone(), paths, cfg).await?;
                    Ok((node, None))
                }
                #[cfg(not(feature = "direct"))]
                {
                    let _ = (identity, paths, cfg);
                    let _ = networks.len();
                    anyhow::bail!("direct mode requires the `direct` feature");
                }
            }
        }
    }

    /// Bootstrap based on persisted mode (Direct-only builds).
    ///
    /// Spawns no background control-plane tasks.
    #[cfg(not(feature = "managed"))]
    pub async fn bootstrap(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        match &persisted {
            PersistedState::Managed(m) => {
                let _ = (&identity, &paths, &cfg, m);
                anyhow::bail!("managed mode requires the `managed` feature");
            }
            PersistedState::Direct { networks } => {
                if networks.is_empty() {
                    anyhow::bail!("no Direct networks joined");
                }
                #[cfg(feature = "direct")]
                {
                    Self::bootstrap_direct(identity, persisted.clone(), paths, cfg).await
                }
                #[cfg(not(feature = "direct"))]
                {
                    let _ = (identity, paths, cfg);
                    let _ = networks.len();
                    anyhow::bail!("direct mode requires the `direct` feature");
                }
            }
        }
    }

    #[cfg(feature = "managed")]
    async fn bootstrap_managed(
        identity: AgentIdentity,
        persisted: PersistedState,
        managed: ManagedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<(Self, Option<crate::ws_client::PendingControl>)> {
        let alpns = build_alpns(&cfg, false, cfg.enable_gossip);

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
        let acl = if let Some(flag) = cfg.src_posture_ok.clone() {
            AclEngine::with_posture_flag(
                SelfIdentity {
                    endpoint_hex: my_id_hex.clone(),
                    ip: membership.assigned_ipv4,
                    tags: membership.self_tags.clone(),
                    network: managed.network_name.clone(),
                },
                routes.clone(),
                membership.policy.clone(),
                flag,
            )
        } else {
            AclEngine::new(
                SelfIdentity {
                    endpoint_hex: my_id_hex.clone(),
                    ip: membership.assigned_ipv4,
                    tags: membership.self_tags.clone(),
                    network: managed.network_name.clone(),
                },
                routes.clone(),
                membership.policy.clone(),
            )
        };
        apply_membership(
            &membership,
            &snapshot.org_policy,
            snapshot.policy_verifying_key.as_deref(),
            &routes,
            &acl,
            &version,
            snapshot.version,
            &my_id_hex,
            &cfg.hostname,
            Some(paths.dir.as_path()),
        );

        let secret = SecretKey::from_bytes(&identity.secret_bytes);
        let connectivity = if matches!(
            cfg.connectivity.profile,
            crate::direct::ConnectivityProfile::TunnetManaged
        ) {
            cfg.connectivity.clone().with_snapshot_relays(
                snapshot.connectivity_relays.clone(),
                snapshot.connectivity_relay_fallback,
            )
        } else {
            cfg.connectivity.clone()
        };
        let builder = endpoint_builder(&connectivity)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(AclHook::new(acl.clone()));
        let endpoint = apply_connectivity(builder, &connectivity)
            .bind()
            .await
            .context("bind iroh endpoint")?;

        debug_assert_eq!(format!("{}", endpoint.id()), my_id_hex);

        // Don't block control-plane WS / IPC readiness on relay bring-up.
        {
            let ep = endpoint.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), ep.online()).await {
                    Ok(()) => tracing::info!("endpoint online"),
                    Err(_) => tracing::warn!("timed out waiting for relay; continuing"),
                }
            });
        }

        #[cfg(feature = "serve")]
        let serves = ServeManager::new(membership.assigned_ipv4, routes.clone());
        let pool = ConnPool::new(endpoint.clone(), TUNNEL_STREAM_ALPN);
        let tunnel_pool = ConnPool::with_shared_policy(endpoint.clone(), TUNNEL_ALPN, &pool);
        pool.set_cloud_relay_urls(
            snapshot
                .connectivity_relays
                .iter()
                .filter(|r| r.metering)
                .map(|r| r.url.clone()),
        );
        let effective_config = cfg.effective_config.clone().unwrap_or_default();
        #[cfg(feature = "tunnel")]
        let tunnels = TunnelManager::new(pool.clone());
        #[cfg(feature = "send")]
        let send = SendManager::open(
            paths.dir.join("blobs"),
            pool.clone(),
            routes.clone(),
            acl.clone(),
            my_id_hex.clone(),
        )
        .await
        .context("open send manager")?;

        // Unowned transport: no task spawned. The owner runs
        // `PendingControl::transport.run(...)` explicitly.
        let pending = crate::ws_client::PendingControl::new(
            managed.control_url.clone(),
            my_id_hex.clone(),
            identity.signing_key.clone(),
        );
        let control_link = Some(pending.link());
        #[cfg(feature = "serve")]
        serves.set_client_tx(pending.client_tx.clone());
        #[cfg(feature = "send")]
        send.set_client_tx(pending.client_tx.clone());

        let _ = persisted;
        pool.set_keep_alive(cfg.keep_alive);

        let gossip = if cfg.enable_gossip {
            tracing::info!("Managed shared Gossip enabled");
            Some(iroh_gossip::net::Gossip::builder().spawn(endpoint.clone()))
        } else {
            None
        };

        // Shared packet-policy runtime: bootstrapped from live control state,
        // then wired (engine attach, peer relink, pool registries) below.
        let policy = PolicyRuntime::bootstrap(
            &acl.bundle.load(),
            &HashMap::new(),
            &acl.self_id.load(),
            **acl.src_posture_ok.load(),
            **acl.stale.load(),
        );
        let mut node = Self {
            identity,
            persisted: PersistedState::Managed(managed),
            endpoint,
            pool,
            tunnel_pool,
            effective_config,
            routes,
            acl,
            version,
            self_ipv4: membership.assigned_ipv4,
            paths,
            #[cfg(feature = "serve")]
            serves,
            #[cfg(feature = "tunnel")]
            tunnels,
            #[cfg(feature = "send")]
            send,
            signed: Some(signed),
            control_link,
            #[cfg(feature = "direct")]
            direct_auth: None,
            #[cfg(feature = "direct")]
            direct: HashMap::new(),
            gossip,
            #[cfg(feature = "direct")]
            docs_engine: None,
            #[cfg(feature = "direct")]
            presence_tables: Arc::new(Mutex::new(HashMap::new())),
            policy,
        };
        node.install_policy_runtime();
        Ok((node, Some(pending)))
    }

    #[cfg(feature = "direct")]
    async fn bootstrap_direct(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        let networks = persisted.direct_networks().to_vec();
        if networks.is_empty() {
            anyhow::bail!("no Direct networks joined");
        }

        let alpns = build_alpns(&cfg, true, true);
        let my_id_hex = identity.endpoint_id_hex();
        let primary = &networks[0];
        let self_ipv4 = if primary.assigned_ipv4.is_unspecified() {
            derive_ipv4(&my_id_hex, primary.collision_index)
        } else {
            primary.assigned_ipv4
        };

        let routes = RoutingTable::new();
        let version = Arc::new(ArcSwap::from_pointee(1u64));
        // ACL/self identity uses primary network name; per-network policy applied via docs.
        let fw0 = crate::agent_config::load_firewall_for(&paths, &primary.network_name);
        let policy0 = firewall_to_policy(&fw0, &my_id_hex, self_ipv4);
        let acl = AclEngine::new(
            SelfIdentity {
                endpoint_hex: my_id_hex.clone(),
                ip: self_ipv4,
                tags: vec![],
                network: primary.network_name.clone(),
            },
            routes.clone(),
            policy0,
        );

        let auth = AuthCache::new();
        for d in &networks {
            auth.insert(my_id_hex.clone(), d.network_id);
        }

        let secret = SecretKey::from_bytes(&identity.secret_bytes);
        let builder = endpoint_builder(&cfg.connectivity)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(DirectAuthHook::new(acl.clone(), auth.clone()));
        let endpoint = apply_connectivity(builder, &cfg.connectivity)
            .bind()
            .await
            .context("bind iroh endpoint (direct)")?;

        {
            let ep = endpoint.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), ep.online()).await {
                    Ok(()) => tracing::info!("direct endpoint online"),
                    Err(_) => tracing::warn!("timed out waiting for relay; continuing"),
                }
            });
        }

        #[cfg(feature = "serve")]
        let serves = ServeManager::new(self_ipv4, routes.clone());
        let pool = ConnPool::new(endpoint.clone(), TUNNEL_STREAM_ALPN);
        let tunnel_pool = ConnPool::with_shared_policy(endpoint.clone(), TUNNEL_ALPN, &pool);
        let effective_config = cfg.effective_config.clone().unwrap_or_default();
        pool.set_keep_alive(cfg.keep_alive);
        #[cfg(feature = "tunnel")]
        let tunnels = TunnelManager::new(pool.clone());

        let blobs_dir = paths.dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;
        let blobs = iroh_blobs::store::fs::FsStore::load(&blobs_dir)
            .await
            .map_err(|e| anyhow::anyhow!("open shared FsStore: {e}"))?;

        warn_legacy_docs_dirs(&paths, &networks);

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let docs_dir = paths.dir.join("docs");
        std::fs::create_dir_all(&docs_dir)?;
        let docs_engine = Docs::persistent(docs_dir)
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await
            .context("spawn unified Docs engine")?;

        #[cfg(feature = "send")]
        let send = {
            let mgr = SendManager::from_store(
                blobs.clone(),
                pool.clone(),
                routes.clone(),
                acl.clone(),
                my_id_hex.clone(),
            )
            .await
            .context("open send manager")?;
            if let Some(key) = primary.content_key.clone() {
                mgr.set_content_key(Some(key));
            }
            mgr
        };

        let mut direct_runtimes = HashMap::new();
        // Runtime networks that bootstrapped; persisted list keeps skipped ones so leave works.
        let mut persisted_networks = Vec::new();
        let mut any_secret_update = false;
        let mut skipped = Vec::new();

        for (join_index, mut direct) in networks.into_iter().enumerate() {
            let network_name = direct.network_name.clone();
            match bootstrap_one_direct_network(
                BootstrapOneArgs {
                    join_index,
                    identity: &identity,
                    my_id_hex: &my_id_hex,
                    paths: &paths,
                    docs_engine: &docs_engine,
                    gossip: &gossip,
                    blobs: &blobs,
                    routes: &routes,
                    acl: &acl,
                    auth: &auth,
                    endpoint: &endpoint,
                },
                &mut direct,
            )
            .await
            {
                Ok(parts) => {
                    if parts.secret_updated {
                        any_secret_update = true;
                    }
                    direct_runtimes.insert(
                        direct.network_id,
                        DirectNetworkRuntime {
                            docs: parts.docs,
                            firewall: parts.firewall,
                            spoof_tracker: parts.spoof_tracker,
                            state: direct.clone(),
                            discovery: parts.discovery,
                            presence: None,
                        },
                    );
                    persisted_networks.push(direct);
                }
                Err(e) => {
                    tracing::error!(
                        network = %network_name,
                        error = %e,
                        "skipping Direct network (leave it or re-join with a fresh invite)"
                    );
                    skipped.push(network_name);
                    persisted_networks.push(direct);
                }
            }
        }

        if direct_runtimes.is_empty() {
            let detail = if skipped.is_empty() {
                "no Direct networks joined".to_string()
            } else {
                format!(
                    "all Direct networks failed to start ({}); leave or re-join with `tunnet leave` / a fresh invite",
                    skipped.join(", ")
                )
            };
            anyhow::bail!("{detail}");
        }
        if !skipped.is_empty() {
            tracing::warn!(
                skipped = %skipped.join(","),
                active = direct_runtimes.len(),
                "started with some Direct networks skipped"
            );
        }

        if any_secret_update {
            crate::secret_store::persist_agent(
                &paths,
                &identity,
                PersistedState::Direct {
                    networks: persisted_networks.clone(),
                },
                crate::secret_store::SealPolicy::from_env_and_flag(false),
            )?;
        }

        let contact = crate::direct::contact_id_from_endpoint(&endpoint.id());
        tracing::info!(%contact, networks = direct_runtimes.len(), "direct contact id");

        let _ = cfg.agent_version;
        // Shared packet-policy runtime from live control state (per-network
        // firewall sets included), then wired below.
        let mut fw_source = HashMap::new();
        for (network_id, runtime) in &direct_runtimes {
            let fw = &runtime.firewall;
            fw_source.insert(
                *network_id,
                (
                    fw.local_rules_snapshot(),
                    fw.suggested_rules_snapshot(),
                    fw.stats().enabled,
                ),
            );
        }
        let policy = PolicyRuntime::bootstrap(
            &acl.bundle.load(),
            &fw_source,
            &acl.self_id.load(),
            **acl.src_posture_ok.load(),
            **acl.stale.load(),
        );
        let mut node = Self {
            identity,
            persisted: PersistedState::Direct {
                networks: persisted_networks,
            },
            endpoint,
            pool,
            tunnel_pool,
            effective_config,
            routes,
            acl,
            version,
            self_ipv4,
            paths,
            #[cfg(feature = "serve")]
            serves,
            #[cfg(feature = "tunnel")]
            tunnels,
            #[cfg(feature = "send")]
            send,
            #[cfg(feature = "managed")]
            signed: None,
            #[cfg(feature = "managed")]
            control_link: None,
            direct_auth: Some(auth),
            direct: direct_runtimes,
            gossip: Some(gossip),
            docs_engine: Some(docs_engine),
            presence_tables: Arc::new(Mutex::new(HashMap::new())),
            policy,
        };
        node.install_policy_runtime();
        Ok(node)
    }

    /// Shared Gossip for presence / service-relay topics.
    pub fn shared_gossip(&self) -> Option<iroh_gossip::net::Gossip> {
        self.gossip.clone()
    }

    /// Wire the shared policy runtime after construction (both modes):
    /// attach engines (future mutations publish automatically), install it
    /// on the routing table (slot assignment at every (re)resolution),
    /// relink existing peer fast states once, and hand pool slow paths the
    /// peer registry. Publication after this point needs no relink (§2.1-3).
    pub fn install_policy_runtime(&mut self) {
        self.acl.attach_runtime(self.policy.clone());
        #[cfg(feature = "direct")]
        for runtime in self.direct.values() {
            runtime.firewall.attach_runtime(self.policy.clone());
        }
        self.routes.set_policy_runtime(self.policy.clone());
        self.routes.peer_registry().relink_policy(&self.policy);
        self.pool
            .set_peer_registry(self.routes.peer_registry().clone());
        self.tunnel_pool
            .set_peer_registry(self.routes.peer_registry().clone());
    }

    pub fn endpoint_id_hex(&self) -> String {
        self.identity.endpoint_id_hex()
    }

    #[cfg(feature = "managed")]
    pub fn require_signed(&self) -> anyhow::Result<&SignedClient> {
        self.signed.as_ref().context(
            "this operation requires Managed mode (control plane client unavailable in Direct)",
        )
    }

    pub async fn shutdown(&self) {
        self.endpoint.close().await;
    }
}

#[cfg(any(feature = "managed", feature = "direct"))]
fn build_alpns(cfg: &CoreNodeConfig, direct: bool, enable_gossip: bool) -> Vec<Vec<u8>> {
    let mut alpns: Vec<Vec<u8>> = vec![TUNNEL_STREAM_ALPN.to_vec()];
    if cfg.advertise_datagram_alpn {
        alpns.push(TUNNEL_ALPN.to_vec());
    }
    if cfg.advertise_recording_alpn {
        #[cfg(feature = "recording")]
        alpns.push(tunnet_common::RECORDING_ALPN.to_vec());
        #[cfg(not(feature = "recording"))]
        tracing::warn!("advertise_recording_alpn set but `recording` feature disabled");
    }
    #[cfg(feature = "send")]
    {
        alpns.push(tunnet_common::SEND_ALPN.to_vec());
        alpns.push(iroh_blobs::ALPN.to_vec());
    }
    if direct {
        #[cfg(feature = "direct")]
        {
            alpns.push(AUTH_ALPN.to_vec());
            alpns.push(iroh_gossip::ALPN.to_vec());
            alpns.push(iroh_docs::ALPN.to_vec());
        }
    } else if enable_gossip {
        alpns.push(iroh_gossip::ALPN.to_vec());
    }
    alpns
}

#[cfg(feature = "direct")]
fn warn_legacy_docs_dirs(paths: &StatePaths, networks: &[DirectState]) {
    let unified = paths.dir.join("docs");
    let unified_nonempty = unified.exists()
        && std::fs::read_dir(&unified)
            .ok()
            .and_then(|mut d| d.next())
            .is_some();
    if unified_nonempty {
        return;
    }
    for net in networks {
        let legacy = paths.docs_dir(net.network_id);
        if legacy.exists()
            && std::fs::read_dir(&legacy)
                .ok()
                .and_then(|mut d| d.next())
                .is_some()
        {
            tracing::warn!(
                network = %net.network_name,
                legacy = %legacy.display(),
                unified = %unified.display(),
                "per-network docs store detected while unified docs/ is empty; re-join with doc ticket if import fails"
            );
        }
    }
}

#[cfg(feature = "direct")]
struct BootstrapOneArgs<'a> {
    join_index: usize,
    identity: &'a AgentIdentity,
    my_id_hex: &'a str,
    paths: &'a StatePaths,
    docs_engine: &'a Docs,
    gossip: &'a iroh_gossip::net::Gossip,
    blobs: &'a iroh_blobs::store::fs::FsStore,
    routes: &'a RoutingTable,
    acl: &'a AclEngine,
    auth: &'a AuthCache,
    endpoint: &'a Endpoint,
}

#[cfg(feature = "direct")]
struct BootstrappedNetwork {
    docs: DocsMembership,
    firewall: crate::direct::FirewallEngine,
    spoof_tracker: crate::direct::SpoofTracker,
    discovery: crate::direct::DiscoveryHandle,
    secret_updated: bool,
}

#[cfg(feature = "direct")]
async fn bootstrap_one_direct_network(
    args: BootstrapOneArgs<'_>,
    direct: &mut DirectState,
) -> anyhow::Result<BootstrappedNetwork> {
    let net_ipv4 = if direct.assigned_ipv4.is_unspecified() {
        derive_ipv4(args.my_id_hex, direct.collision_index)
    } else {
        direct.assigned_ipv4
    };

    let fw_cfg = crate::agent_config::load_firewall_for(args.paths, &direct.network_name);
    let policy = firewall_to_policy(&fw_cfg, args.my_id_hex, net_ipv4);
    let firewall = crate::direct::FirewallEngine::from_config(
        &fw_cfg,
        net_ipv4,
        args.my_id_hex.to_string(),
        direct.network_id,
    );
    let spoof_tracker = crate::direct::SpoofTracker::new();

    let self_entry = MembershipEntry {
        endpoint_id: args.my_id_hex.to_string(),
        hostname: direct.hostname.clone(),
        ipv4: net_ipv4,
        collision_index: direct.collision_index,
        tags: vec![],
        joined_at: jiff::Timestamp::now(),
        coordinator: direct.coordinator,
        status: "active".into(),
        ssh_host_key: None,
    };

    let endpoint_signing_key = SigningKey::from_bytes(&args.identity.secret_bytes);
    let coordinator_signing_key = direct
        .coordinator_signing_key
        .as_ref()
        .map(|h| signing_key_from_hex(h))
        .transpose()
        .with_context(|| {
            format!(
                "parse coordinator signing key for '{}'",
                direct.network_name
            )
        })?;
    let coordinator_verifying_key = direct.coordinator_verifying_key.clone().unwrap_or_default();
    let content_key = direct.content_key.clone().unwrap_or_default();
    let network_grant: Option<NetworkGrant> = match &direct.network_grant {
        Some(g) => match serde_json::from_str(g) {
            Ok(grant) => Some(grant),
            Err(e) => {
                if direct.coordinator {
                    tracing::error!(
                        network = %direct.network_name,
                        ?e,
                        "failed to parse network_grant; Grant AUTH disabled for this network"
                    );
                    None
                } else {
                    anyhow::bail!("corrupt network_grant ({e}); re-join with a fresh invite");
                }
            }
        },
        None => {
            if !direct.coordinator {
                anyhow::bail!("missing network_grant; re-join with a fresh invite");
            }
            tracing::warn!(
                network = %direct.network_name,
                "coordinator missing network_grant; seed AUTH will not run"
            );
            None
        }
    };

    let mut seeds = Vec::new();
    if let Some(coord) = &direct.coordinator_endpoint_id {
        seeds.push(coord.clone());
    }
    seeds.sort();
    seeds.dedup();
    let seed_peers = std::sync::Arc::new(parking_lot::Mutex::new(seeds.clone()));

    let (docs, new_ticket, new_ns) = DocsMembership::bootstrap(DocsBootstrap {
        docs: args.docs_engine.clone(),
        gossip: args.gossip.clone(),
        paths: args.paths,
        direct,
        self_endpoint_id: args.my_id_hex,
        self_entry,
        endpoint_signing_key,
        coordinator_signing_key,
        coordinator_verifying_key,
        content_key: content_key.clone(),
        network_grant: network_grant.clone(),
        blobs: args.blobs.clone(),
        routes: args.routes.clone(),
        acl: args.acl.clone(),
        auth: args.auth.clone(),
        policy,
        firewall: Some(firewall.clone()),
        dns: crate::load_dns(args.paths),
        join_index: args.join_index as u64,
        seed_peers: seed_peers.clone(),
    })
    .await
    .with_context(|| {
        format!(
            "bootstrap iroh-docs membership for '{}'",
            direct.network_name
        )
    })?;

    let mut secret_updated = false;
    if new_ticket.is_some() || new_ns.is_some() {
        secret_updated = true;
        if let Some(t) = new_ticket {
            direct.doc_ticket = Some(t);
        }
        if let Some(ns) = new_ns {
            direct.namespace_id = Some(ns);
        }
    }
    direct.assigned_ipv4 = net_ipv4;

    docs.refresh_seed_peers();
    let discovery_seeds = seed_peers.lock().clone();
    let discovery = spawn_discovery(
        direct.topic_hash.clone(),
        args.my_id_hex.to_string(),
        discovery_seeds,
    );
    spawn_seed_auth(
        args.endpoint.clone(),
        args.auth.clone(),
        direct.network_id,
        network_grant,
        args.my_id_hex.to_string(),
        seed_peers,
    );

    Ok(BootstrappedNetwork {
        docs,
        firewall,
        spoof_tracker,
        discovery,
        secret_updated,
    })
}
