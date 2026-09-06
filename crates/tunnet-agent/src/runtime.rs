//! Agent bootstrap/composition layer.
//!
//! This module only: loads immutable startup config, constructs core
//! resources and shared read models, spawns `AgentSupervisor`, starts the
//! Local API and required outer services, signals readiness, waits for
//! OS/service shutdown, then drains the actor tree deterministically.
//! Subsystem lifecycle lives in the owning actors.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::Context;
use kameo::actor::Spawn;
use tunnet_core::direct::ConnectivityOptions;
use tunnet_core::direct::build_auth_server_context;
use tunnet_core::local_api::{LocalApiState, spawn_local_api};
use tunnet_core::{CoreNode, CoreNodeConfig};
use uuid::Uuid;

use crate::accept::AcceptDeps;
use crate::actors::control::{ControlPlaneActorArgs, TransportConfig};
use crate::actors::dataplane::{ActorDataPlaneControl, DataPlaneActorConfig, new_published_plane};
use crate::actors::presence::PresenceActorArgs;
use crate::actors::routes::RouteActorArgs;
use crate::actors::supervisor::{
    AgentSupervisor, AgentSupervisorArgs, DataPlaneSupervisorArgs, GetAgentChildren,
    GetDataPlaneChildren, PostureSpawnConfig,
};
use crate::actors::update::{UpdateActorArgs, UpdateState};
use crate::daemon::RunArgs;
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, recordings_dir};
use crate::system_dns::DnsController;

pub async fn run(
    identity: tunnet_core::AgentIdentity,
    persisted: tunnet_core::PersistedState,
    paths: tunnet_core::StatePaths,
    args: RunArgs,
    shutdown: Option<tokio_util::sync::CancellationToken>,
    mut on_ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let metrics = AgentMetrics::new().context("metrics")?;
    let started_at = Instant::now();

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "tunnet-agent".into());

    let is_direct = persisted.is_direct();
    let network_id = persisted.primary_network_id().unwrap_or(Uuid::nil());

    // Shared posture flag: written by PostureActor, read by the ACL engine.
    let src_posture_ok = Arc::new(arc_swap::ArcSwap::from_pointee(true));

    let agent_cfg = tunnet_core::TunnetConfig::load(&paths).unwrap_or_default();
    let config_store = tunnet_core::EffectiveConfigStore::new();
    let _ = config_store.recompute(&agent_cfg, Default::default());

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
            connectivity: if is_direct {
                ConnectivityOptions::direct_default(
                    agent_cfg.effective_mdns_default() && !args.no_mdns,
                )
            } else {
                ConnectivityOptions::managed_default()
            },
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

    let (assigned_ipv4, prefix, mtu, dns_cfg) = if is_direct {
        let _ = tunnet_core::TunnetConfig::ensure(&node.paths);
        (
            node.self_ipv4,
            10u8,
            config_store
                .load()
                .effective
                .tunnel_mtu
                .value
                .clamp(576, 9000),
            tunnet_core::load_dns(&node.paths),
        )
    } else {
        let membership_snap = tunnet_core::state::load_snapshot_cache(&node.paths)
            .and_then(|s| {
                s.memberships
                    .into_iter()
                    .find(|m| m.network_id == network_id)
            })
            .context("cached snapshot missing enrolled network")?;
        let effective_mtu = config_store
            .load()
            .effective
            .tunnel_mtu
            .value
            .clamp(576, 9000);
        (
            membership_snap.assigned_ipv4,
            membership_snap.prefix,
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
        match tokio::task::spawn_blocking(DnsController::create).await {
            Ok(Ok(controller)) => Some(controller),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "osdns DNS integration unavailable");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "osdns init task failed");
                None
            }
        }
    };

    // Shared read models. The dataplane actor is the only writer of
    // `published`/`status`; Local API GETs read them directly.
    let peer_dns_active = Arc::new(AtomicBool::new(false));
    let published = new_published_plane();
    let status_snapshot = tunnet_core::local_api::DataPlaneStatusSnapshot::new(false);

    // Child configs for the supervisor tree.
    let dataplane_cfg = DataPlaneActorConfig {
        ifname: args.ifname.clone(),
        assigned_ipv4,
        prefix,
        mtu,
        dns_cfg: dns_cfg.clone(),
        dns: dns_controller.clone(),
        is_direct,
        network_id,
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
            posture_actor: None,
            ssh_registry: None,
        })
    };
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
    let update_state = Arc::new(arc_swap::ArcSwap::from_pointee(UpdateState::Idle));
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
            posture: posture_cfg,
            presence: presence_args,
            update: Some(UpdateActorArgs {
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
    let ssh_registry = children
        .ssh_registry
        .clone()
        .context("ssh registry missing")?;

    // Local API first: bind + readiness before TUN/SSH bring-up.
    let data_plane_control = Arc::new(ActorDataPlaneControl::new(
        status_snapshot.clone(),
        dataplane_ref.clone(),
    ));
    let bootstrap: Arc<dyn tunnet_core::local_api::BootstrapOps> = Arc::new(
        crate::api_bootstrap::AgentBootstrapOps::new(paths.clone(), events_tx.clone()),
    );
    let api_state = Arc::new(LocalApiState {
        node: node.clone(),
        hostname: hostname.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        dns_upstream: dns_cfg.upstream.clone(),
        dnssec: dns_cfg.dnssec,
        synthetic_base: dns_cfg.synthetic_base.to_string(),
        magic_ip: dns_cfg.magic_ip.to_string(),
        peer_dns_active: peer_dns_active.clone(),
        peer_rtt: Arc::new(dashmap::DashMap::new()),
        serves: node.serves.clone(),
        tunnels: node.tunnels.clone(),
        send: node.send.clone(),
        data_plane: data_plane_control,
        bootstrap,
        events: events_tx,
    });
    api_state.send.set_events_tx(api_state.events.clone());
    if let Some(link) = &node.control_link {
        link.set_events_tx(api_state.events.clone());
        if link.snapshot().connected {
            api_state.emit(tunnet_common::local_api::LocalEvent::ControlConnected);
        }
    }
    let _api_task = spawn_local_api(api_state.clone())
        .await
        .context("start Local Management API")?;
    if let Some(tx) = on_ready.take() {
        let _ = tx.send(());
    }

    #[cfg(unix)]
    crate::sd_notify::ready("running");

    // Dataplane up via the owning actor (builds TUN, DNS, routes).
    // Kameo flattens `Result` replies into the `ask` error channel.
    dataplane_ref
        .ask(crate::actors::dataplane::BringUp)
        .await
        .map_err(|e| anyhow::anyhow!("dataplane bring-up failed: {e}"))?;

    let recording_store = match RecordingStore::open(recordings_dir(&node.paths.dir)) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::warn!(?e, "recording store unavailable");
            None
        }
    };
    if args.recorder {
        tracing::info!("session recorder enabled (ALPN tunnet/recording/1)");
    }

    let stream_handler = tunnet_core::stream_handler(node.routes.clone());
    let dgram_pool = node.tunnel_pool.clone();

    let spoofs: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.spoof_tracker.clone()))
        .collect();
    // Shared tunnel packet resources: pooled buffers (MTU classes) for TUN
    // receives and segment staging.
    let packet_pool = tunnet_common::packet::PacketPool::new(128);

    crate::dgram_pump::install_dialer_datagram_pump(
        &dgram_pool,
        published.clone(),
        node.routes.clone(),
        node.acl.clone(),
        node.policy.clone(),
        spoofs.clone(),
        metrics.clone(),
        packet_pool.clone(),
        ingress.clone(),
    );

    let docs_map: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.docs.clone()))
        .collect();

    let auth_server_ctx = if is_direct {
        Some(build_auth_server_context(
            node.persisted.direct_networks(),
            &docs_map,
        ))
    } else {
        None
    };

    if is_direct
        && let Some(key) = node
            .persisted
            .direct_networks()
            .first()
            .and_then(|d| d.content_key.clone())
    {
        node.send.set_content_key(Some(key));
    }

    let network_name = node
        .persisted
        .primary_network_name()
        .unwrap_or("tunnet")
        .to_string();

    for rt in node.direct.values() {
        rt.firewall
            .ensure_inbound_tcp_allow(crate::ssh_nat::SSH_EXTERNAL_PORT);
    }

    let ssh_deps = crate::ssh::SshServeDeps {
        routes: node.routes.clone(),
        acl: node.acl.clone(),
        sessions: ssh_registry.clone(),
        cp_tx: node.serves.client_tx(),
        pool: node.pool.clone(),
        store: recording_store.clone(),
        signed: node.signed.clone(),
        hostname: hostname.clone(),
        network_name: network_name.clone(),
        self_endpoint_id: node.endpoint_id_hex(),
    };
    if ssh_deps.cp_tx.is_none() {
        tracing::warn!(
            "SSH session reporting disabled (no control-plane WS channel yet); sessions will not appear in the dashboard"
        );
    }
    let ssh_handle =
        match crate::ssh::spawn_ssh_listener(assigned_ipv4, &node.paths.dir, ssh_deps).await {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!(?e, "failed to start SSH listener");
                None
            }
        };

    // Publish host pubkey: control-plane metadata (managed) / iroh-docs (direct).
    let ssh_pubkey = match crate::ssh::host_pubkey_openssh(&node.paths.dir) {
        Ok(k) => Some(k),
        Err(e) => {
            tracing::warn!(?e, "SSH host pubkey unavailable for distribution");
            None
        }
    };
    if let Some(ref pubkey) = ssh_pubkey {
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
            if let Err(e) = rt.docs.set_ssh_host_key(pubkey).await {
                tracing::warn!(?e, "failed to publish SSH host key to iroh-docs");
            } else {
                tracing::info!("published SSH host key to iroh-docs");
            }
        }
    }

    let _router = crate::accept::spawn(AcceptDeps {
        endpoint: node.endpoint.clone(),
        routes: node.routes.clone(),
        acl: node.acl.clone(),
        runtime: node.policy.clone(),
        metrics: metrics.clone(),
        tun: published.clone(),
        stream_handler,
        cp_tx: node.serves.client_tx(),
        recording_store,
        signed: node.signed.clone(),
        self_endpoint_id: node.endpoint_id_hex(),
        recorder_enabled: args.recorder,
        send: node.send.clone(),
        direct_auth: node.direct_auth.clone(),
        auth_server_ctx,
        state_dir: node.paths.dir.clone(),
        docs: docs_map,
        spoofs,
        dgram_pool: dgram_pool.clone(),
        bufs: packet_pool.clone(),
        agent_gossip: node.gossip.clone(),
        shared_docs: node.docs_engine.clone(),
        ingress: ingress.clone(),
    });

    // PeerDNS first: its Hickory upstream is snapshotted from the underlay
    // resolver *before* the osdns overlay points the OS at PeerDNS.
    let dns_bind = tunnet_core::dns::bind_addr(dns_cfg.magic_ip);
    let _dns_task = tunnet_core::dns::spawn(dns_bind, node.routes.clone(), dns_cfg.clone());

    crate::metrics::spawn_listeners(metrics.clone(), &args.metrics_bind, assigned_ipv4);

    if agent_cfg.effective_service_relay() {
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
    }

    // Explicit shutdown drain: supervisor first (control → presence/posture →
    // update → dataplane → ssh registry), then outer services, then endpoint.
    #[cfg(unix)]
    {
        let _ = shutdown;
        let upgrade = crate::upgrade::UpgradeGuard::install()?;
        let reason = upgrade.wait().await;
        tracing::info!(?reason, "shutdown signal; draining");
        drain(supervisor, ssh_handle, dns_controller, &node).await;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if let Some(token) = shutdown {
            token.cancelled().await;
            tracing::info!("service stop, shutting down");
        } else {
            tokio::signal::ctrl_c().await?;
            tracing::info!("ctrl-c, shutting down");
        }
        drain(supervisor, ssh_handle, dns_controller, &node).await;
        Ok(())
    }
}

/// Graceful drain with bounded waits; abort only as a final fallback.
async fn drain(
    supervisor: kameo::actor::ActorRef<AgentSupervisor>,
    ssh_handle: Option<tokio::task::JoinHandle<()>>,
    dns_controller: Option<Arc<DnsController>>,
    node: &CoreNode,
) {
    use crate::actors::supervisor::ShutdownAgent;

    // 1. Stop accepting new lifecycle/control mutations (Local API tasks end
    //    with the process; in-flight handlers drain via timeouts).
    // 2. Actor tree: control → presence/posture/update → dataplane → ssh.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let _ = supervisor.tell(ShutdownAgent).send().await;
        let _ = supervisor.stop_gracefully().await;
        supervisor.wait_for_shutdown().await;
    })
    .await;
    // 3. Outer raw services owned by bootstrap.
    if let Some(handle) = ssh_handle {
        handle.abort();
    }
    // 4. DNS lease restore is idempotent (actor teardown already did it).
    if let Some(dns) = dns_controller {
        match tokio::task::spawn_blocking(move || dns.restore()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "DNS shutdown restore failed"),
            Err(e) => tracing::warn!(error = %e, "DNS shutdown task failed"),
        }
    }
    // 5. Close Iroh endpoint.
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
    let state_dir = node.paths.dir.clone();
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
                    mesh_ip: Some(rt.state.assigned_ipv4.to_string()),
                    ssh_host_key: None,
                    agent_version: agent_version.clone(),
                    bootstrap: peers,
                    state_dir: Some(state_dir.clone()),
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
                state_dir: Some(state_dir),
                dns_suffix: Some(dns_suffix.to_string()),
            },
            tables: node.presence_tables.clone(),
        });
    }
    out
}
