use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::Context;
use tunnet_core::direct::SecretResolver;
use tunnet_core::ipc::{AgentIpcState, DataPlaneHandle, spawn_ipc_server};
use tunnet_core::{CoreNode, CoreNodeConfig};
use uuid::Uuid;

use crate::accept::AcceptDeps;
use crate::cli::RunArgs;
use crate::dataplane::{
    ControllerSpawn, DataPlaneConfig, TunSlot, TunSlotState, build_initial_plane, spawn_controller,
    spawn_outbound,
};
use crate::ingress::IngressRegistry;
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, recordings_dir};
use crate::tun_io::build_tun;

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

    let ssh_sessions = crate::ssh::SshSessionRegistry::default();
    let on_kill_ssh = {
        let sessions = ssh_sessions.clone();
        Some(std::sync::Arc::new(move |session_id: &str| {
            if let Ok(id) = Uuid::parse_str(session_id) {
                if sessions.kill(&id) {
                    tracing::info!(%session_id, "killed SSH session by CP request");
                } else {
                    tracing::debug!(%session_id, "KillSshSession: session not found locally");
                }
            } else {
                tracing::warn!(%session_id, "KillSshSession: invalid session id");
            }
        }) as std::sync::Arc<dyn Fn(&str) + Send + Sync>)
    };

    let is_direct = persisted.is_direct();
    let network_id = persisted.primary_network_id().unwrap_or(Uuid::nil());

    let posture_runtime = if !is_direct {
        Some(crate::posture::PostureRuntime::new(env!(
            "CARGO_PKG_VERSION"
        )))
    } else {
        None
    };
    let src_posture_ok = posture_runtime.as_ref().map(|p| p.src_posture_ok());

    let secret_resolver: Option<SecretResolver> = if is_direct {
        let secrets: HashMap<Uuid, String> = persisted
            .direct_networks()
            .iter()
            .map(|d| (d.network_id, d.network_secret.clone()))
            .collect();
        Some(Arc::new(move |nid: Uuid| secrets.get(&nid).cloned()) as SecretResolver)
    } else {
        None
    };

    let agent_cfg = tunnet_core::TunnetConfig::load(&paths).unwrap_or_default();
    let config_store = tunnet_core::EffectiveConfigStore::new();
    let _ = config_store.recompute(&agent_cfg, Default::default());

    let agent_config_hooks = if !is_direct {
        Some(crate::posture::build_agent_config_hooks(
            paths.clone(),
            config_store.clone(),
            posture_runtime.as_ref().map(|p| p.engine()),
        ))
    } else {
        None
    };

    let node = CoreNode::bootstrap(
        identity,
        persisted,
        paths.clone(),
        CoreNodeConfig {
            hostname: hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION"),
            poll_secs: args.poll_secs,
            advertise_datagram_alpn: true,
            advertise_recording_alpn: args.recorder,
            kind: "agent",
            on_kill_ssh,
            posture_hooks: posture_runtime.as_ref().map(|p| p.hooks()),
            agent_config_hooks,
            src_posture_ok,
            enable_mdns: agent_cfg.effective_mdns_default() && !args.no_mdns,
            enable_gossip: !args.disable_gossip || agent_cfg.effective_service_relay(),
            keep_alive: if is_direct { args.keep_alive } else { true },
            effective_config: Some(config_store.clone()),
        },
    )
    .await?;

    let config_store = node.effective_config.clone();

    if let Some(posture) = posture_runtime {
        if let Some(tx) = node.serves.client_tx() {
            let cancel = shutdown.as_ref().cloned().unwrap_or_default();
            posture.spawn(tx, cancel);
        } else {
            tracing::warn!("posture reporter skipped (no control-plane WS channel)");
        }
    }

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
    crate::auto_update::spawn(node.paths.clone(), Some(config_store.clone()));

    // Request configured self tags from control plane (best-effort).
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

    #[cfg(windows)]
    let wintun_file = args.wintun_file.clone();

    let (assigned_ipv4, prefix, mtu, dns_cfg) = if is_direct {
        let _ = tunnet_core::TunnetConfig::ensure(&node.paths);
        (
            node.self_ipv4,
            10u8,
            1280u16,
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
        let effective_mtu = config_store.load().effective.tunnel_mtu.value.max(576);
        (
            membership_snap.assigned_ipv4,
            membership_snap.prefix,
            effective_mtu,
            {
                let mut dns = membership_snap.dns.clone();
                let eff = config_store.load();
                dns.suffix = eff.effective.dns_suffix.value.clone();
                let upstream: Vec<_> = eff
                    .effective
                    .dns_upstream
                    .value
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if !upstream.is_empty() {
                    dns.upstream = upstream;
                }
                dns
            },
        )
    };

    // Bind IPC and signal service readiness before TUN/SSH bring-up. Control-plane
    // presence can already be Online while wintun/SSH still start; `service start`
    // should not wait on that work.
    let peer_dns_active = Arc::new(AtomicBool::new(false));
    let (data_plane, cmd_rx) = DataPlaneHandle::new(8);
    let ipc_state = Arc::new(AgentIpcState {
        node: node.clone(),
        hostname: hostname.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        dns_upstream: dns_cfg.upstream.iter().map(|ip| ip.to_string()).collect(),
        synthetic_base: dns_cfg.synthetic_base.to_string(),
        magic_ip: dns_cfg.magic_ip.to_string(),
        peer_dns_active: peer_dns_active.clone(),
        peer_rtt: Arc::new(dashmap::DashMap::new()),
        serves: node.serves.clone(),
        tunnels: node.tunnels.clone(),
        send: node.send.clone(),
        data_plane: data_plane.clone(),
    });
    let _ipc_task = spawn_ipc_server(ipc_state)
        .await
        .context("start agent IPC server")?;
    if let Some(tx) = on_ready.take() {
        let _ = tx.send(());
    }

    #[cfg(unix)]
    crate::sd_notify::status("running");

    let tun = Arc::new(build_tun(
        &args.ifname,
        assigned_ipv4,
        prefix,
        mtu,
        #[cfg(windows)]
        wintun_file.as_deref(),
    )?);
    crate::system_firewall::configure(&args.ifname);
    let _ = crate::magic_dns::ensure_magic_dns_addr(&args.ifname, dns_cfg.magic_ip);
    let tun_slot: TunSlot = Arc::new(tokio::sync::RwLock::new(TunSlotState {
        device: Some(tun.clone()),
        generation: 0,
    }));
    let ingress = IngressRegistry::new();

    crate::forward::ensure_ip_forwarding(!node.routes.advertised_subnets().is_empty());

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
        tun_slot.clone(),
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

    let network_name = node
        .persisted
        .primary_network_name()
        .unwrap_or("tunnet")
        .to_string();

    // Direct mode: allow inbound TCP/22 (pre-NAT) so stock SSH clients reach us.
    for rt in node.direct.values() {
        rt.firewall
            .ensure_inbound_tcp_allow(crate::ssh_nat::SSH_EXTERNAL_PORT);
    }

    let ssh_deps = crate::ssh::SshServeDeps {
        routes: node.routes.clone(),
        acl: node.acl.clone(),
        sessions: ssh_sessions.clone(),
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
    match crate::ssh::spawn_ssh_listener(assigned_ipv4, &node.paths.dir, ssh_deps).await {
        Ok(_handle) => {}
        Err(e) => tracing::error!(?e, "failed to start SSH listener"),
    }

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
        metrics: metrics.clone(),
        tun: tun_slot.clone(),
        stream_handler,
        cp_tx: node.serves.client_tx(),
        recording_store,
        signed: node.signed.clone(),
        self_endpoint_id: node.endpoint_id_hex(),
        recorder_enabled: args.recorder,
        send: node.send.clone(),
        direct_auth: node.direct_auth.clone(),
        secret_resolver,
        state_dir: node.paths.dir.clone(),
        docs: docs_map,
        firewalls,
        spoofs,
        dgram_pool: dgram_pool.clone(),
        agent_gossip: node.gossip.clone(),
        ingress: ingress.clone(),
    });

    let dns_bind = tunnet_core::dns_stub::bind_addr(dns_cfg.magic_ip);
    let _dns_task = tunnet_core::dns_stub::spawn(dns_bind, node.routes.clone(), dns_cfg.clone());
    let dns_guard = match crate::system_dns::configure(dns_cfg.magic_ip, &dns_cfg.suffix) {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::warn!(?e, "PeerDNS system configuration skipped");
            None
        }
    };
    peer_dns_active.store(dns_guard.is_some(), std::sync::atomic::Ordering::Relaxed);

    if !is_direct
        && let Some(snap) = tunnet_core::state::load_snapshot_cache(&node.paths)
        && let Some(membership_snap) = snap.memberships.iter().find(|m| m.network_id == network_id)
    {
        let remote_subnets: Vec<ipnet::Ipv4Net> = membership_snap
            .subnet_routes
            .iter()
            .filter(|r| r.via_endpoint_id != node.identity.endpoint_id_hex())
            .map(|r| r.cidr)
            .collect();
        crate::system_routes::apply(
            &args.ifname,
            &membership_snap.device_profile,
            &remote_subnets,
            membership_snap
                .device_profile
                .exit_node_endpoint_id
                .is_some(),
        );
    }

    crate::metrics::spawn_listeners(metrics.clone(), &args.metrics_bind, assigned_ipv4);

    let outbound_firewalls: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.firewall.clone()))
        .collect();
    let outbound = spawn_outbound(
        tun.clone(),
        node.routes.clone(),
        dgram_pool,
        node.acl.clone(),
        outbound_firewalls,
        metrics.clone(),
    );

    let initial = build_initial_plane(tun, dns_guard, outbound, &node, is_direct, network_id);
    spawn_controller(ControllerSpawn {
        handle: data_plane,
        cmd_rx,
        tun_slot,
        node: node.clone(),
        metrics,
        cfg: DataPlaneConfig {
            ifname: args.ifname.clone(),
            assigned_ipv4,
            prefix,
            mtu,
            dns_cfg: dns_cfg.clone(),
            is_direct,
            network_id,
            #[cfg(windows)]
            wintun_file,
        },
        peer_dns_active: peer_dns_active.clone(),
        initial,
        ingress,
    });

    if !args.disable_gossip {
        if let Some(gossip) = node.shared_gossip() {
            let peers: Vec<iroh::EndpointId> = node
                .routes
                .peers()
                .iter()
                .take(5)
                .filter_map(|p| p.endpoint_hex.parse().ok())
                .collect();
            let topic = tunnet_common::network_topic_hex(&network_id);
            let ep = node.endpoint.clone();
            let hostname = hostname.clone();
            let state_dir = node.paths.dir.clone();
            let dns_suffix = dns_cfg.suffix.clone();
            let ssh_host_key = ssh_pubkey.clone();
            let mesh_ip = Some(assigned_ipv4.to_string());
            tokio::spawn(async move {
                if let Err(e) =
                    crate::gossip_presence::spawn(crate::gossip_presence::GossipPresenceArgs {
                        endpoint: ep,
                        gossip,
                        topic_hex: topic,
                        bootstrap: peers,
                        self_hostname: hostname,
                        mesh_ip,
                        ssh_host_key,
                        state_dir,
                        dns_suffix,
                    })
                    .await
                {
                    tracing::warn!(?e, "gossip presence disabled");
                }
            });
        } else {
            tracing::warn!("gossip presence skipped (no shared Gossip)");
        }
    }

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

    #[cfg(unix)]
    {
        let _ = shutdown;
        let upgrade = crate::upgrade::UpgradeGuard::install()?;
        let reason = upgrade.wait().await;
        tracing::info!(?reason, "shutdown signal; draining");
        node.shutdown().await;
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
        node.shutdown().await;
        Ok(())
    }
}
