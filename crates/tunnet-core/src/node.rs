#[cfg(feature = "direct")]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(feature = "managed", feature = "direct"))]
use std::time::Duration;

#[cfg(any(feature = "managed", feature = "direct"))]
use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::Endpoint;
#[cfg(any(feature = "managed", feature = "direct"))]
use iroh::{SecretKey, endpoint::presets};
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
use crate::direct::{
    AUTH_ALPN, AuthCache, DirectAuthHook, DocsBootstrap, DocsMembership, MembershipEntry,
    derive_ipv4, firewall_to_policy, spawn_discovery, spawn_seed_auth,
};
use crate::identity::AgentIdentity;
use crate::iroh_pool::ConnPool;
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
use crate::sync::{
    apply_membership, membership_for_network, spawn_poll_fallback, spawn_ws_processor,
};
#[cfg(feature = "tunnel")]
use crate::tunnel::TunnelManager;

/// Callback when CP requests killing an SSH session (`session_id`).
pub type KillSshHook = Arc<dyn Fn(&str) + Send + Sync>;

pub type PostureConfigUpdateHook =
    Arc<dyn Fn(u64, Vec<String>, Vec<tunnet_common::posture::CustomScriptConfig>) + Send + Sync>;

pub type PostureStatusHook = Arc<
    dyn Fn(Vec<tunnet_common::posture::PostureEvalResult>, String, Option<u64>, Vec<String>)
        + Send
        + Sync,
>;

/// Optional hooks for control-plane posture WebSocket messages.
#[derive(Clone, Default)]
pub struct PostureHooks {
    pub on_recheck: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_config_update: Option<PostureConfigUpdateHook>,
    pub on_status: Option<PostureStatusHook>,
}

/// Called when remote org agent policy arrives (snapshot or hot push).
/// Returns the merged effective config for reporting to the control plane.
pub type AgentPolicyHook = Arc<
    dyn Fn(tunnet_common::RemoteAgentPolicy) -> tunnet_common::EffectiveAgentConfig + Send + Sync,
>;

#[derive(Clone, Default)]
pub struct AgentConfigHooks {
    pub on_remote_policy: Option<AgentPolicyHook>,
}

/// Per-Direct-network runtime (docs + firewall + state).
#[cfg(feature = "direct")]
#[derive(Clone)]
pub struct DirectNetworkRuntime {
    pub docs: DocsMembership,
    pub firewall: crate::direct::FirewallEngine,
    pub spoof_tracker: crate::direct::SpoofTracker,
    pub state: DirectState,
}

#[derive(Clone)]
pub struct CoreNodeConfig {
    pub hostname: String,
    pub agent_version: &'static str,
    pub poll_secs: u64,
    pub advertise_datagram_alpn: bool,
    /// Advertise `tunnet/recording/1` (this node can receive session recordings).
    pub advertise_recording_alpn: bool,
    pub kind: &'static str, // "agent" | "sdk"
    /// Optional hook when CP requests killing an SSH session (session_id string).
    pub on_kill_ssh: Option<KillSshHook>,
    /// Optional hooks for posture control-plane messages.
    pub posture_hooks: Option<PostureHooks>,
    /// Optional hooks for remote agent policy merge / report.
    pub agent_config_hooks: Option<AgentConfigHooks>,
    /// Shared flag updated by posture status; gates ACL rules with `srcPosture`.
    pub src_posture_ok: Option<Arc<arc_swap::ArcSwap<bool>>>,
    /// Enable mDNS LAN address lookup (Direct default: true).
    pub enable_mdns: bool,
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
            poll_secs: 30,
            advertise_datagram_alpn: false,
            advertise_recording_alpn: false,
            kind: "sdk",
            on_kill_ssh: None,
            posture_hooks: None,
            agent_config_hooks: None,
            src_posture_ok: None,
            enable_mdns: true,
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
    /// Shared agent Gossip (Managed). Direct uses [`DocsMembership::gossip`] instead.
    pub gossip: Option<iroh_gossip::net::Gossip>,
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
    pub fn spoof_for(&self, network_id: Uuid) -> Option<&crate::direct::SpoofTracker> {
        self.direct.get(&network_id).map(|r| &r.spoof_tracker)
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
    pub async fn bootstrap(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        cfg: CoreNodeConfig,
    ) -> anyhow::Result<Self> {
        match &persisted {
            PersistedState::Managed(m) => {
                #[cfg(feature = "managed")]
                {
                    Self::bootstrap_managed(identity, persisted.clone(), m.clone(), paths, cfg)
                        .await
                }
                #[cfg(not(feature = "managed"))]
                {
                    let _ = (&identity, &paths, &cfg, m);
                    anyhow::bail!("managed mode requires the `managed` feature");
                }
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
    ) -> anyhow::Result<Self> {
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
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(AclHook::new(acl.clone()))
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

        let ws = crate::ws_client::spawn(
            managed.control_url.clone(),
            my_id_hex.clone(),
            identity.signing_key.clone(),
        );
        let control_link = Some(ws.link.clone());
        #[cfg(feature = "serve")]
        serves.set_client_tx(ws.tx.clone());
        #[cfg(feature = "send")]
        send.set_client_tx(ws.tx.clone());
        spawn_ws_processor(
            ws,
            routes.clone(),
            acl.clone(),
            version.clone(),
            paths.clone_paths(),
            managed.network_id,
            my_id_hex.clone(),
            cfg.hostname.clone(),
            cfg.agent_version,
            Some(signed.clone()),
            #[cfg(feature = "serve")]
            Some(serves.clone()),
            #[cfg(feature = "tunnel")]
            Some(tunnels.clone()),
            #[cfg(feature = "send")]
            Some(send.clone()),
            cfg.on_kill_ssh.clone(),
            cfg.posture_hooks.clone(),
            cfg.agent_config_hooks.clone(),
            Some(tunnel_pool.clone()),
        );
        spawn_poll_fallback(
            signed.clone(),
            version.clone(),
            cfg.poll_secs,
            routes.clone(),
            acl.clone(),
            managed.network_id,
            my_id_hex.clone(),
            cfg.hostname.clone(),
            Some(paths.dir.clone()),
        );

        let _ = persisted;
        pool.set_keep_alive(cfg.keep_alive);

        let gossip = if cfg.enable_gossip {
            tracing::info!("Managed shared Gossip enabled");
            Some(iroh_gossip::net::Gossip::builder().spawn(endpoint.clone()))
        } else {
            None
        };

        Ok(Self {
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
        })
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
        let builder = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(alpns)
            .hooks(DirectAuthHook::new(acl.clone(), auth.clone()));
        let builder = crate::direct::apply_mdns(builder, cfg.enable_mdns);
        let endpoint = builder
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

        #[cfg(feature = "send")]
        let send = SendManager::from_store(
            blobs.clone(),
            pool.clone(),
            routes.clone(),
            acl.clone(),
            my_id_hex.clone(),
        )
        .await
        .context("open send manager")?;

        let mut direct_runtimes = HashMap::new();
        let mut updated_networks = Vec::new();
        let mut any_secret_update = false;

        for (join_index, mut direct) in networks.into_iter().enumerate() {
            let net_ipv4 = if direct.assigned_ipv4.is_unspecified() {
                derive_ipv4(&my_id_hex, direct.collision_index)
            } else {
                direct.assigned_ipv4
            };

            let fw_cfg = crate::agent_config::load_firewall_for(&paths, &direct.network_name);
            let policy = firewall_to_policy(&fw_cfg, &my_id_hex, net_ipv4);
            let firewall =
                crate::direct::FirewallEngine::from_config(&fw_cfg, net_ipv4, my_id_hex.clone());
            let spoof_tracker = crate::direct::SpoofTracker::new();

            let self_entry = MembershipEntry {
                endpoint_id: my_id_hex.clone(),
                hostname: direct.hostname.clone(),
                ipv4: net_ipv4,
                collision_index: direct.collision_index,
                tags: vec![],
                joined_at: chrono::Utc::now(),
                coordinator: direct.coordinator,
                status: "online".into(),
                ssh_host_key: None,
            };

            let (docs, new_ticket, new_ns) = DocsMembership::bootstrap(DocsBootstrap {
                endpoint: endpoint.clone(),
                paths: &paths,
                direct: &direct,
                self_endpoint_id: &my_id_hex,
                self_entry,
                blobs: blobs.clone(),
                routes: routes.clone(),
                acl: acl.clone(),
                auth: auth.clone(),
                policy,
                firewall: Some(firewall.clone()),
                dns: crate::load_dns(&paths),
                join_index: join_index as u64,
            })
            .await
            .with_context(|| {
                format!(
                    "bootstrap iroh-docs membership for '{}'",
                    direct.network_name
                )
            })?;

            if new_ticket.is_some() || new_ns.is_some() {
                any_secret_update = true;
                if let Some(t) = new_ticket {
                    direct.doc_ticket = Some(t);
                }
                if let Some(ns) = new_ns {
                    direct.namespace_id = Some(ns);
                }
            }
            direct.assigned_ipv4 = net_ipv4;

            let mut seeds = Vec::new();
            if let Some(coord) = &direct.coordinator_endpoint_id {
                seeds.push(coord.clone());
            }
            for m in docs.snapshot_members() {
                if m.endpoint_id != my_id_hex {
                    seeds.push(m.endpoint_id);
                }
            }
            let _discovery =
                spawn_discovery(direct.topic_hash.clone(), my_id_hex.clone(), seeds.clone());
            spawn_seed_auth(
                endpoint.clone(),
                auth.clone(),
                direct.network_id,
                direct.network_secret.clone(),
                my_id_hex.clone(),
                seeds,
            );

            direct_runtimes.insert(
                direct.network_id,
                DirectNetworkRuntime {
                    docs,
                    firewall,
                    spoof_tracker,
                    state: direct.clone(),
                },
            );
            updated_networks.push(direct);
        }

        if any_secret_update {
            crate::secret_store::persist_agent(
                &paths,
                &identity,
                PersistedState::Direct {
                    networks: updated_networks.clone(),
                },
                crate::secret_store::SealPolicy::from_env_and_flag(false),
            )?;
        }

        let contact = crate::direct::contact_id_from_endpoint(&endpoint.id());
        tracing::info!(%contact, networks = direct_runtimes.len(), "direct contact id");

        let _ = cfg;
        Ok(Self {
            identity,
            persisted: PersistedState::Direct {
                networks: updated_networks,
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
            // Direct features use DocsMembership::gossip() (primary network).
            gossip: None,
        })
    }

    /// Shared Gossip for presence / service-relay topics.
    /// Direct: primary network docs gossip. Managed: agent-owned gossip.
    pub fn shared_gossip(&self) -> Option<iroh_gossip::net::Gossip> {
        if let Some(g) = &self.gossip {
            return Some(g.clone());
        }
        #[cfg(feature = "direct")]
        {
            self.primary_docs().map(|d| d.gossip())
        }
        #[cfg(not(feature = "direct"))]
        {
            None
        }
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
