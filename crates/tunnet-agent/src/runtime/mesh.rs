//! Mesh composition: identity through actors, dataplane, and outer services.
//!
//! Starts the networking runtime and returns a live session. Local API binding,
//! systemd notify, and process-signal wait belong to the daemon host.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(feature = "local-api")]
use std::time::Instant;

use anyhow::Context;
use kameo::actor::Spawn;
use tunnet_core::direct::ConnectivityOptions;
use tunnet_core::direct::build_auth_server_context;
#[cfg(feature = "local-api")]
use tunnet_core::local_api::LocalApiState;
use tunnet_core::{CoreNode, CoreNodeConfig};
use uuid::Uuid;

use crate::accept::AcceptDeps;
use crate::actors::control::{ControlPlaneActorArgs, TransportConfig};
use crate::actors::dataplane::{ActorDataPlaneControl, DataPlaneActorConfig, new_published_plane};
use crate::actors::presence::PresenceActorArgs;
use crate::actors::routes::RouteActorArgs;
#[cfg(feature = "posture")]
use crate::actors::supervisor::PostureSpawnConfig;
use crate::actors::supervisor::{
    AgentSupervisor, AgentSupervisorArgs, DataPlaneSupervisorArgs, GetAgentChildren,
    GetDataPlaneChildren,
};
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::system_dns::DnsController;

use super::AgentConfig;
use super::AgentHandle;

/// Live mesh: actor tree, node, and the pieces a host needs to observe or drain.
pub(crate) struct MeshSession {
    supervisor: kameo::actor::ActorRef<AgentSupervisor>,
    ssh_handle: Option<tokio::task::JoinHandle<()>>,
    dns_controller: Option<Arc<DnsController>>,
    /// Released when the mesh drains. iroh mDNS is bound at construction.
    _multicast: crate::multicast_demand::MulticastLease,
    pub(crate) node: CoreNode,
    pub(crate) dataplane: Arc<ActorDataPlaneControl>,
    pub(crate) peer_rtt: Arc<dashmap::DashMap<String, f64>>,
    #[cfg(feature = "local-api")]
    pub(crate) api_state: Arc<LocalApiState>,
    pub(crate) hostname: String,
    /// Must be stored: dropping iroh's Router aborts `endpoint.accept()`.
    router: iroh::protocol::Router,
}

impl MeshSession {
    pub(crate) fn is_alive(&self) -> bool {
        self.supervisor.is_alive()
    }

    pub(crate) async fn drain(self) {
        drain(
            self.supervisor,
            self.ssh_handle,
            self.dns_controller,
            self.router,
            &self.node,
        )
        .await;
    }
}

pub(crate) async fn start_mesh(
    identity: tunnet_core::AgentIdentity,
    persisted: tunnet_core::PersistedState,
    paths: tunnet_core::StatePaths,
    args: &AgentConfig,
    handle: AgentHandle,
) -> anyhow::Result<MeshSession> {
    let metrics = AgentMetrics::new().context("metrics")?;
    #[cfg(feature = "local-api")]
    let started_at = Instant::now();

    let hostname = args
        .hostname
        .clone()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-agent".into());

    let is_direct = persisted.is_direct();
    let network_id = persisted.primary_network_id().unwrap_or(Uuid::nil());

    // Shared posture flag: written by PostureActor, read by the ACL engine.
    let src_posture_ok = Arc::new(arc_swap::ArcSwap::from_pointee(true));

    let agent_cfg = tunnet_core::TunnetConfig::load(&paths).unwrap_or_default();
    let config_store = tunnet_core::EffectiveConfigStore::new();
    let _ = config_store.recompute(&agent_cfg, Default::default());

    #[cfg(not(target_os = "android"))]
    let underlay_hosts = {
        let mut hosts = Vec::new();
        if let Ok(managed) = persisted.require_managed() {
            hosts.extend(crate::dataplane::underlay_hosts_from_url(
                &managed.control_url,
            ));
        }
        if let Some(info) = crate::underlay::UnderlayInfo::discover() {
            for dns in info.dns_servers {
                if let std::net::IpAddr::V4(ip) = dns
                    && !ip.is_loopback()
                    && !hosts.contains(&ip)
                {
                    hosts.push(ip);
                }
            }
        }
        hosts
    };

    let connectivity = if is_direct {
        if let Err(errs) = agent_cfg.validate() {
            anyhow::bail!("invalid tunnet.toml: {}", errs.join("; "));
        }
        let credentials = tunnet_core::secret_store::load_relay_auth(&paths).unwrap_or_default();
        let mut opts = ConnectivityOptions::from_direct_config(
            &agent_cfg,
            credentials,
            args.relay_mode.as_deref(),
            args.relay_urls.as_deref(),
        )
        .context("resolve Direct relay policy")?;
        if args.no_mdns {
            opts.enable_mdns = false;
        }
        crate::host_constraints::constrain_lan(&mut opts);
        tracing::info!(
            relay = opts.relay.kind(),
            mdns = opts.enable_mdns,
            lan_discovery = opts.enable_lan_discovery,
            dht = opts.enable_dht,
            "direct connectivity"
        );
        opts
    } else {
        if agent_cfg.has_local_direct_relay_settings() {
            tracing::warn!(
                "ignoring [network] relay-mode / relay-urls in Managed mode; control-plane snapshot is authoritative"
            );
        }
        let mut opts = ConnectivityOptions::managed_default();
        crate::host_constraints::constrain_lan(&mut opts);
        opts
    };

    // mDNS lookup is attached during bootstrap. Service relay (mdns-sd) is
    // separate and also needs multicast reception while it runs.
    let lan = crate::host_constraints::lan_available();
    let need_multicast = connectivity.enable_mdns || (agent_cfg.effective_service_relay() && lan);
    let multicast = crate::multicast_demand::MulticastLease::request(need_multicast);

    let (node, _pending_control) = CoreNode::bootstrap(
        identity.clone(),
        persisted,
        paths.clone(),
        CoreNodeConfig {
            hostname: hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION"),
            advertise_datagram_alpn: true,
            advertise_recording_alpn: args.recorder,
            kind: "agent",
            src_posture_ok: Some(src_posture_ok.clone()),
            connectivity,
            enable_gossip: !args.disable_gossip || agent_cfg.effective_service_relay(),
            keep_alive: match std::env::var("TUNNET_KEEP_ALIVE").ok().as_deref() {
                Some("0" | "false" | "off") => false,
                Some(_) => true,
                None => true,
            } || args.keep_alive,
            effective_config: Some(config_store.clone()),
        },
    )
    .await?;
    drop(_pending_control);

    let config_store = node.effective_config.clone();

    // Seed merge from cached snapshot so TUN/DNS use remote policy before WS reconnect.
    if !is_direct && let Some(snap) = tunnet_core::state::load_snapshot_cache(&node.paths) {
        let remote = snap
            .memberships
            .iter()
            .find(|m| m.network_id == network_id)
            .map(|m| m.agent_policy.clone())
            .unwrap_or(snap.agent_policy);
        let _ = config_store.apply_remote(&agent_cfg, remote);
    }

    #[cfg(feature = "updater")]
    if let Err(e) = crate::auto_update::on_agent_start(&node.paths) {
        tracing::warn!(?e, "auto-update pending check failed");
    }

    // Request configured self tags from control plane (best-effort, one-shot).
    if !is_direct && !agent_cfg.tags.self_tags.is_empty() {
        let wanted: Vec<String> = agent_cfg
            .tags
            .self_tags
            .iter()
            .map(|t| t.trim().trim_start_matches("tag:").to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if !wanted.is_empty()
            && let Ok(managed) = node.persisted.require_managed()
        {
            match tunnet_core::control::SignedClient::new(
                managed.control_url.clone(),
                node.endpoint_id_hex(),
                node.identity.signing_key.clone(),
            ) {
                Ok(client) => {
                    if let Err(e) = client.patch_device_tags(&wanted, &[]).await {
                        tracing::warn!(?e, "failed to apply tunnet.toml self tags");
                    }
                }
                Err(e) => tracing::warn!(?e, "signed client for self tags"),
            }
        }
    }

    let (local_addrs, peer_cidrs, mtu, dns_cfg) = if is_direct {
        let _ = tunnet_core::TunnetConfig::ensure(&node.paths);
        let mut active: Vec<_> = node
            .direct
            .iter()
            .map(|(network_id, runtime)| {
                (
                    *network_id,
                    runtime.state.self_record.ipv4,
                    runtime.state.genesis.address_plan.peer_cidr,
                )
            })
            .collect();
        active.sort_by_key(|(network_id, _, _)| *network_id);
        let cidrs: Vec<_> = active.iter().map(|(_, _, cidr)| *cidr).collect();
        let addrs: Vec<_> = active.into_iter().map(|(_, address, _)| address).collect();
        let addrs = if addrs.is_empty() {
            vec![node.self_ipv4]
        } else {
            addrs
        };
        (addrs, cidrs, 1280u16, tunnet_core::load_dns(&node.paths))
    } else {
        let membership_snap = tunnet_core::state::load_snapshot_cache(&node.paths)
            .and_then(|s| {
                s.memberships
                    .into_iter()
                    .find(|m| m.network_id == network_id)
            })
            .context("cached snapshot missing enrolled network")?;
        let effective_mtu = config_store.load().effective.tunnel_mtu.value.max(576);
        // Managed enrolment has no Direct address plan; peer reachability is
        // driven by the coordinator's routes rather than a declared range.
        (
            vec![membership_snap.assigned_ipv4],
            Vec::new(),
            effective_mtu,
            {
                let mut dns = membership_snap.dns.clone();
                let eff = config_store.load();
                dns.suffix = eff.effective.dns_suffix.value.clone();
                dns.upstream = eff.effective.dns_upstream.value.clone();
                dns.dnssec = eff.effective.dnssec.value;
                dns
            },
        )
    };

    // One long-lived osdns manager for the agent lifetime. Owned by the
    // DataPlaneActor via config; created here because it needs blocking init.
    let dns_controller: Option<Arc<DnsController>> = {
        #[cfg(feature = "host-dns")]
        {
            match tokio::task::spawn_blocking(DnsController::create).await {
                Ok(Ok(controller)) => Some(controller),
                Ok(Err(e)) => {
                    if matches!(e, osdns::Error::UnsupportedPlatform { .. }) {
                        tracing::info!(
                            error = %e,
                            "host OS DNS overlay skipped (no OS DNS backend on this platform)"
                        );
                    } else {
                        tracing::error!(error = %e, "osdns DNS integration unavailable");
                    }
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, "osdns init task failed");
                    None
                }
            }
        }
        #[cfg(not(feature = "host-dns"))]
        {
            None
        }
    };

    // Shared read models. The dataplane actor is the only writer of
    // `published`/`status`; Local API GETs read them directly.
    let peer_dns_active = Arc::new(AtomicBool::new(false));
    let published = new_published_plane();
    let status_snapshot = tunnet_core::local_api::DataPlaneStatusSnapshot::new(false);

    // Child configs for the supervisor tree.
    #[cfg(any(feature = "ssh", feature = "metrics-serve"))]
    let ssh_bind = dataplane_ssh_bind(&node);
    let dataplane_cfg = DataPlaneActorConfig {
        ifname: args.ifname.clone(),
        local_addrs,
        peer_cidrs,
        mtu,
        dns_cfg: dns_cfg.clone(),
        dns: dns_controller.clone(),
        is_direct,
        #[cfg(not(target_os = "android"))]
        network_id,
        #[cfg(not(target_os = "android"))]
        underlay_hosts: underlay_hosts.clone(),
    };

    // Managed control + posture (absent in Direct mode).
    let control_args = if is_direct {
        None
    } else {
        let managed = node.persisted.require_managed().ok().cloned();
        managed.map(|m| ControlPlaneActorArgs {
            transport: TransportConfig {
                control_url: m.control_url.clone(),
                endpoint_id: node.endpoint_id_hex(),
                signing_key: node.identity.signing_key.clone(),
            },
            node: node.clone(),
            network_id,
            hostname: hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION"),
            paths: paths.clone(),
            poll_secs: args.poll_secs,
            // Late-bound by the supervisor after the dataplane tree starts.
            route_actor: None,
            dataplane_actor: None,
            #[cfg(feature = "posture")]
            posture_actor: None,
            #[cfg(feature = "ssh")]
            ssh_registry: None,
        })
    };
    #[cfg(feature = "posture")]
    let posture_cfg = if is_direct {
        None
    } else {
        Some(PostureSpawnConfig {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            src_posture_ok: src_posture_ok.clone(),
        })
    };

    // Presence args per network (Direct: one per network; Managed: one).
    let presence_args = build_presence_args(
        &node,
        is_direct,
        network_id,
        &hostname,
        &dns_cfg.suffix,
        args.disable_gossip,
    );

    // Single event bus shared by the actors, the updater, and the Local API.
    let (events_tx, _) = tokio::sync::broadcast::channel(256);
    // Ingress reader registry: shared by the dialer pump, the accept router,
    // and the DataPlaneActor (which aborts readers on BringDown).
    let ingress = IngressRegistry::new();
    // Update scheduler state (read model for status; bytes stay in CoreUpdater).
    #[cfg(feature = "updater")]
    let update_state = Arc::new(arc_swap::ArcSwap::from_pointee(
        crate::actors::update::UpdateState::Idle,
    ));
    #[cfg(feature = "updater")]
    let updater = crate::core_update::CoreUpdater::shared(paths.clone(), events_tx.clone());
    let supervisor = AgentSupervisor::spawn_with_mailbox(
        AgentSupervisorArgs {
            dataplane: DataPlaneSupervisorArgs {
                route_args: RouteActorArgs,
                dataplane_config: dataplane_cfg,
                node: node.clone(),
                metrics: metrics.clone(),
                peer_dns_active: peer_dns_active.clone(),
                events: events_tx.clone(),
                published: published.clone(),
                status: status_snapshot.clone(),
                ingress: ingress.clone(),
                initially_up: false,
                initial_generation: 0,
                // Recover service across supervised restarts; BringUp failure
                // is logged, never a crash.
                auto_up: true,
            },
            control: control_args,
            #[cfg(feature = "posture")]
            posture: posture_cfg,
            presence: presence_args,
            #[cfg(feature = "updater")]
            update: Some(crate::actors::update::UpdateActorArgs {
                paths: paths.clone(),
                store: Some(config_store.clone()),
                updater: updater.clone(),
                state: update_state.clone(),
            }),
        },
        kameo::mailbox::bounded(crate::actors::SUPERVISOR_MAILBOX),
    );
    supervisor.wait_for_startup().await;

    // Resolve the dataplane + control actors for outer wiring.
    let children: crate::actors::supervisor::AgentChildren =
        supervisor.ask(GetAgentChildren).await?;
    let (route_ref, dataplane_ref) = if let Some(dp_sup) = &children.dataplane_sup {
        let dc: crate::actors::supervisor::DataPlaneChildren =
            dp_sup.ask(GetDataPlaneChildren).await?;
        (dc.route_actor, dc.dataplane_actor)
    } else {
        (None, None)
    };
    let _ = route_ref;
    let dataplane_ref = dataplane_ref.context("dataplane actor missing")?;
    if let Some(control) = &children.control_actor {
        control.wait_for_startup().await;
    }
    #[cfg(feature = "ssh")]
    let ssh_registry = children
        .ssh_registry
        .clone()
        .context("ssh registry missing")?;

    let data_plane_control = Arc::new(ActorDataPlaneControl::new(
        status_snapshot.clone(),
        dataplane_ref.clone(),
    ));
    let peer_rtt = Arc::new(dashmap::DashMap::new());
    #[cfg(feature = "local-api")]
    let api_state = {
        let bootstrap: Arc<dyn tunnet_core::local_api::BootstrapOps> = Arc::new(
            crate::api_bootstrap::AgentBootstrapOps::new(paths.clone(), events_tx.clone())
                .with_handle(handle.clone()),
        );
        let api_state = Arc::new(LocalApiState {
            node: node.clone(),
            hostname: hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at,
            dns_upstream: dns_cfg.upstream.clone(),
            dnssec: dns_cfg.dnssec,
            resolver_endpoint: tunnet_common::LocalResolverEndpoint::default()
                .socket_addr()
                .to_string(),
            peer_dns_active: peer_dns_active.clone(),
            peer_rtt: peer_rtt.clone(),
            serves: node.serves.clone(),
            tunnels: node.tunnels.clone(),
            send: node.send.clone(),
            data_plane: data_plane_control.clone(),
            bootstrap,
            events: events_tx.clone(),
            mesh_observe: Some(Arc::new({
                let handle = handle.clone();
                move || handle.observe_mesh()
            })),
        });
        api_state.send.set_events_tx(api_state.events.clone());
        if let Some(link) = &node.control_link {
            link.set_events_tx(api_state.events.clone());
            if link.snapshot().connected {
                api_state.emit(tunnet_common::local_api::LocalEvent::ControlConnected);
            }
        }
        api_state
    };

    // Dataplane up via the owning actor (builds TUN, DNS, routes).
    // Kameo flattens `Result` replies into the `ask` error channel.
    // A Direct address conflict degrades bring-up instead of reporting healthy.
    match tokio::time::timeout(
        std::time::Duration::from_secs(60),
        dataplane_ref.ask(crate::actors::dataplane::BringUp),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "dataplane degraded at startup");
        }
        Err(e) => {
            tracing::warn!(error = %e, "dataplane bring-up timed out; degraded");
        }
    }
    {
        let dataplane_bg = dataplane_ref.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                tick.tick().await;
                if let Err(error) = dataplane_bg
                    .ask(crate::actors::dataplane::ReconcileDirectState)
                    .await
                {
                    tracing::warn!(%error, "Direct lifecycle reconciliation degraded");
                }
            }
        });
    }

    let stream_handler = tunnet_core::stream_handler(node.routes.clone(), node.acl.clone());
    let dgram_pool = node.tunnel_pool.clone();

    let firewalls: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.firewall.clone()))
        .collect();
    let spoofs: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.spoof_tracker.clone()))
        .collect();

    crate::dgram_pump::install_dialer_datagram_pump(
        &dgram_pool,
        published.clone(),
        node.routes.clone(),
        node.acl.clone(),
        firewalls.clone(),
        spoofs.clone(),
        metrics.clone(),
        node.direct_auth.clone(),
        ingress.clone(),
    );

    let docs_map: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.docs.clone()))
        .collect();

    // Direct membership sync drives pool invalidation by event, never by timer.
    for docs in docs_map.values() {
        let stream_pool = node.pool.clone();
        let dgram_pool = node.tunnel_pool.clone();
        let dataplane = dataplane_ref.clone();
        docs.set_change_hook(Arc::new(move || {
            let stream_pool = stream_pool.clone();
            let dgram_pool = dgram_pool.clone();
            let dataplane = dataplane.clone();
            tokio::spawn(async move {
                stream_pool.reconcile().await;
                dgram_pool.reconcile().await;
                if let Err(error) = dataplane
                    .ask(crate::actors::dataplane::ReconcileDirectState)
                    .await
                {
                    tracing::warn!(%error, "membership route reconciliation degraded");
                }
            });
        }));
    }

    let auth_server_ctx = if is_direct {
        Some(build_auth_server_context(&docs_map))
    } else {
        None
    };

    let join_authorities: HashMap<_, _> = node
        .direct
        .iter()
        .filter_map(|(id, rt)| {
            rt.authority
                .clone()
                .map(|auth| (*id, (auth, rt.docs.clone())))
        })
        .collect();

    if is_direct
        && let Some(key) = node
            .persisted
            .direct_networks()
            .first()
            .and_then(|d| d.content_key.clone())
    {
        node.send.set_content_key(Some(key));
    }

    #[cfg(feature = "ssh")]
    let network_name = node
        .persisted
        .primary_network_name()
        .unwrap_or("tunnet")
        .to_string();

    #[cfg(feature = "ssh")]
    for rt in node.direct.values() {
        rt.firewall
            .ensure_inbound_tcp_allow(crate::ssh_nat::SSH_EXTERNAL_PORT);
    }

    let ssh_handle = {
        #[cfg(feature = "ssh")]
        {
            let recording_store =
                match crate::recorder::RecordingStore::open(node.paths.recordings_dir()) {
                    Ok(s) => Some(Arc::new(s)),
                    Err(e) => {
                        tracing::warn!(?e, "recording store unavailable");
                        None
                    }
                };
            let ssh_deps = crate::ssh::SshServeDeps {
                routes: node.routes.clone(),
                acl: node.acl.clone(),
                sessions: ssh_registry.clone(),
                #[cfg(feature = "local-api")]
                cp_tx: node.serves.client_tx(),
                #[cfg(not(feature = "local-api"))]
                cp_tx: None,
                pool: node.pool.clone(),
                store: recording_store.clone(),
                signed: node.signed.clone(),
                hostname: hostname.clone(),
                network_name: network_name.clone(),
            };
            if ssh_deps.cp_tx.is_none() {
                tracing::warn!(
                    "SSH session reporting disabled (no control-plane WS channel yet); sessions will not appear in the dashboard"
                );
            }
            let ssh_handle =
                match crate::ssh::spawn_ssh_listener(ssh_bind, &node.paths, ssh_deps).await {
                    Ok(handle) => Some(handle),
                    Err(e) => {
                        tracing::error!(?e, "failed to start SSH listener");
                        None
                    }
                };
            if let Ok(pubkey) = crate::ssh::host_pubkey_openssh(&node.paths) {
                if let Some(signed) = node.signed.clone() {
                    let hostname = hostname.clone();
                    let pubkey = pubkey.clone();
                    tokio::spawn(async move {
                        let mut meta = tunnet_core::control::basic_metadata(
                            &hostname,
                            env!("CARGO_PKG_VERSION"),
                            "agent",
                        );
                        if let Some(obj) = meta.as_object_mut() {
                            obj.insert("sshHostKey".into(), serde_json::Value::String(pubkey));
                        }
                        match signed
                            .register(&hostname, env!("CARGO_PKG_VERSION"), Some(meta))
                            .await
                        {
                            Ok(_) => tracing::info!("published SSH host key to control plane"),
                            Err(e) => tracing::warn!(?e, "failed to publish SSH host key"),
                        }
                    });
                }
                for rt in node.direct.values() {
                    if let Err(e) = rt.docs.set_ssh_host_key(&pubkey).await {
                        tracing::warn!(?e, "failed to publish SSH host key to iroh-docs");
                    } else {
                        tracing::info!("published SSH host key to iroh-docs");
                    }
                }
            }
            let _ = recording_store;
            ssh_handle
        }
        #[cfg(not(feature = "ssh"))]
        {
            None
        }
    };

    let router = crate::accept::spawn(AcceptDeps {
        endpoint: node.endpoint.clone(),
        routes: node.routes.clone(),
        acl: node.acl.clone(),
        metrics: metrics.clone(),
        tun: published.clone(),
        stream_handler,
        #[cfg(feature = "ssh")]
        cp_tx: {
            #[cfg(feature = "local-api")]
            {
                node.serves.client_tx()
            }
            #[cfg(not(feature = "local-api"))]
            {
                None
            }
        },
        #[cfg(feature = "ssh")]
        recording_store: None,
        #[cfg(feature = "ssh")]
        signed: node.signed.clone(),
        self_endpoint_id: node.endpoint_id_hex(),
        #[cfg(feature = "ssh")]
        recorder_enabled: args.recorder,
        send: node.send.clone(),
        direct_auth: node.direct_auth.clone(),
        auth_server_ctx,
        paths: node.paths.clone(),
        join_authorities,
        firewalls,
        spoofs,
        dgram_pool: dgram_pool.clone(),
        agent_gossip: node.gossip.clone(),
        shared_docs: node.docs_engine.clone(),
        ingress: ingress.clone(),
        events: events_tx.clone(),
    });

    #[cfg(feature = "metrics-serve")]
    crate::metrics::spawn_listeners(metrics.clone(), &args.metrics_bind, ssh_bind);

    if agent_cfg.effective_service_relay() && lan {
        if let Some(gossip) = node.shared_gossip() {
            let peers: Vec<iroh::EndpointId> = node
                .routes
                .peers()
                .iter()
                .take(5)
                .filter_map(|p| p.endpoint_hex.parse().ok())
                .collect();
            let topic = tunnet_common::mdns_relay_topic_hex(&network_id);
            let _mdns_task = tunnet_core::mdns_relay::spawn(tunnet_core::mdns_relay::SpawnConfig {
                gossip,
                topic_hex: topic,
                bootstrap: peers,
                mesh_ip: node.self_ipv4,
                endpoint_id: node.endpoint_id_hex(),
                routes: node.routes.clone(),
            });
        } else {
            tracing::warn!("mDNS service relay skipped (no shared Gossip)");
        }
    } else if agent_cfg.effective_service_relay() {
        tracing::info!("mDNS service relay skipped (LAN unavailable)");
    }

    spawn_view_pump(
        handle,
        node.routes.clone(),
        events_tx.clone(),
        supervisor.clone(),
    );

    Ok(MeshSession {
        supervisor,
        ssh_handle,
        dns_controller,
        _multicast: multicast,
        node,
        dataplane: data_plane_control,
        peer_rtt,
        #[cfg(feature = "local-api")]
        api_state,
        hostname,
        router,
    })
}

fn spawn_view_pump(
    handle: AgentHandle,
    routes: tunnet_core::RoutingTable,
    events: tokio::sync::broadcast::Sender<tunnet_common::local_api::LocalEvent>,
    supervisor: kameo::actor::ActorRef<crate::actors::supervisor::AgentSupervisor>,
) {
    let shutdown = handle.shutdown_token();
    tokio::spawn(async move {
        let mut routes_rx = routes.subscribe_changes();
        let mut events_rx = events.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = supervisor.wait_for_shutdown() => {
                    handle.record_dead_mesh().await;
                    break;
                }
                r = routes_rx.changed() => {
                    if r.is_err() {
                        break;
                    }
                }
                ev = events_rx.recv() => {
                    match ev {
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                _ = shutdown.cancelled() => break,
            }
            let snap = handle.snapshot_now();
            handle.publish(snap);
        }
    });
}

/// Graceful drain with bounded waits; abort only as a final fallback.
#[cfg(any(feature = "ssh", feature = "metrics-serve"))]
fn dataplane_ssh_bind(node: &CoreNode) -> std::net::Ipv4Addr {
    node.persisted
        .direct_networks()
        .first()
        .map(|d| d.self_record.ipv4)
        .unwrap_or(node.self_ipv4)
}

async fn drain(
    supervisor: kameo::actor::ActorRef<AgentSupervisor>,
    ssh_handle: Option<tokio::task::JoinHandle<()>>,
    dns_controller: Option<Arc<DnsController>>,
    router: iroh::protocol::Router,
    node: &CoreNode,
) {
    use crate::actors::supervisor::ShutdownAgent;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let _ = supervisor.tell(ShutdownAgent).send().await;
        let _ = supervisor.stop_gracefully().await;
        supervisor.wait_for_shutdown().await;
    })
    .await;
    if let Some(handle) = ssh_handle {
        handle.abort();
    }
    if let Some(dns) = dns_controller {
        match tokio::task::spawn_blocking(move || dns.restore()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "DNS shutdown restore failed"),
            Err(e) => tracing::warn!(error = %e, "DNS shutdown task failed"),
        }
    }
    if let Err(e) = router.shutdown().await {
        tracing::warn!(error = %e, "iroh accept router shutdown failed");
    }
    node.shutdown().await;
}

/// Build presence args (no tasks spawned here; `PresenceActor` owns them).
fn build_presence_args(
    node: &CoreNode,
    is_direct: bool,
    network_id: Uuid,
    hostname: &str,
    dns_suffix: &str,
    disable_gossip: bool,
) -> Vec<PresenceActorArgs> {
    if disable_gossip {
        return Vec::new();
    }
    let Some(gossip) = node.shared_gossip() else {
        tracing::warn!("gossip presence skipped (no shared Gossip)");
        return Vec::new();
    };
    let signing_key = node.identity.signing_key.clone();
    let self_endpoint_id = node.endpoint_id_hex();
    let agent_version = env!("CARGO_PKG_VERSION").to_string();
    let known_hosts_file = node.paths.known_hosts_file();
    let mut out = Vec::new();
    if is_direct {
        for rt in node.direct.values() {
            let peers: Vec<iroh::EndpointId> = node
                .routes
                .peers()
                .iter()
                .take(5)
                .filter_map(|p| p.endpoint_hex.parse().ok())
                .collect();
            out.push(PresenceActorArgs {
                config: tunnet_core::direct::PresenceConfig {
                    gossip: gossip.clone(),
                    network_id: rt.state.network_id,
                    signing_key: signing_key.clone(),
                    self_endpoint_id: self_endpoint_id.clone(),
                    hostname: rt.state.hostname.clone(),
                    mesh_ip: Some(rt.state.self_record.ipv4.to_string()),
                    ssh_host_key: None,
                    agent_version: agent_version.clone(),
                    bootstrap: peers,
                    known_hosts_file: Some(known_hosts_file.clone()),
                    dns_suffix: Some(dns_suffix.to_string()),
                },
                tables: node.presence_tables.clone(),
            });
        }
    } else {
        let peers: Vec<iroh::EndpointId> = node
            .routes
            .peers()
            .iter()
            .take(5)
            .filter_map(|p| p.endpoint_hex.parse().ok())
            .collect();
        out.push(PresenceActorArgs {
            config: tunnet_core::direct::PresenceConfig {
                gossip,
                network_id,
                signing_key,
                self_endpoint_id,
                hostname: hostname.to_string(),
                mesh_ip: Some(node.self_ipv4.to_string()),
                ssh_host_key: None,
                agent_version,
                bootstrap: peers,
                known_hosts_file: Some(known_hosts_file),
                dns_suffix: Some(dns_suffix.to_string()),
            },
            tables: node.presence_tables.clone(),
        });
    }
    out
}
