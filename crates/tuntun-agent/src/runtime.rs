use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::Context;
use tuntun_common::TUNNEL_ALPN;
use tuntun_core::direct::SecretResolver;
use tuntun_core::ipc::{AgentIpcState, DataPlaneHandle, spawn_ipc_server};
use tuntun_core::{CoreNode, CoreNodeConfig};
use uuid::Uuid;

use crate::accept::AcceptDeps;
use crate::cli::RunArgs;
use crate::dataplane::{
    ControllerSpawn, DataPlaneConfig, TunSlot, build_initial_plane, spawn_controller,
    spawn_outbound,
};
use crate::metrics::AgentMetrics;
use crate::recorder::{RecordingStore, recordings_dir};
use crate::tun_io::build_tun;

pub async fn run(
    identity: tuntun_core::AgentIdentity,
    persisted: tuntun_core::PersistedState,
    paths: tuntun_core::StatePaths,
    args: RunArgs,
) -> anyhow::Result<()> {
    let metrics = AgentMetrics::new().context("metrics")?;
    let started_at = Instant::now();

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "tuntun-agent".into());

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

    let agent_cfg = tuntun_core::TunTunConfig::load(&paths).unwrap_or_default();

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
            enable_mdns: agent_cfg.mdns.enabled && !args.no_mdns,
            enable_gossip: !args.disable_gossip || agent_cfg.mdns.service_relay,
            keep_alive: if is_direct { args.keep_alive } else { true },
        },
    )
    .await?;

    if let Err(e) = crate::auto_update::on_agent_start(&node.paths) {
        tracing::warn!(?e, "auto-update pending check failed");
    }
    crate::auto_update::spawn(node.paths.clone());

    #[cfg(windows)]
    let wintun_file = args.wintun_file.clone();

    let (assigned_ipv4, prefix, mtu, dns_cfg) = if is_direct {
        let _ = tuntun_core::TunTunConfig::ensure(&node.paths);
        (
            node.self_ipv4,
            10u8,
            1280u16,
            tuntun_core::load_dns(&node.paths),
        )
    } else {
        let membership_snap = tuntun_core::state::load_snapshot_cache(&node.paths)
            .and_then(|s| {
                s.memberships
                    .into_iter()
                    .find(|m| m.network_id == network_id)
            })
            .context("cached snapshot missing enrolled network")?;
        (
            membership_snap.assigned_ipv4,
            membership_snap.prefix,
            membership_snap.mtu,
            membership_snap.dns,
        )
    };

    let tun = Arc::new(build_tun(
        &args.ifname,
        assigned_ipv4,
        prefix,
        mtu,
        #[cfg(windows)]
        wintun_file.as_deref(),
    )?);
    let _ = crate::magic_dns::ensure_magic_dns_addr(&args.ifname, dns_cfg.magic_ip);
    let tun_slot: TunSlot = Arc::new(tokio::sync::RwLock::new(Some(tun.clone())));

    crate::forward::ensure_ip_forwarding(!node.routes.advertised_subnets().is_empty());

    let recording_store = match RecordingStore::open(recordings_dir(&node.paths.dir)) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::warn!(?e, "recording store unavailable");
            None
        }
    };
    if args.recorder {
        tracing::info!("session recorder enabled (ALPN tuntun/recording/1)");
    }

    let stream_handler = crate::stream_proxy::stream_handler(node.routes.clone());
    let dgram_pool =
        tuntun_core::ConnPool::with_shared_policy(node.endpoint.clone(), TUNNEL_ALPN, &node.pool);

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
    let docs_map: HashMap<_, _> = node
        .direct
        .iter()
        .map(|(id, rt)| (*id, rt.docs.clone()))
        .collect();

    crate::accept::spawn(AcceptDeps {
        endpoint: node.endpoint.clone(),
        routes: node.routes.clone(),
        acl: node.acl.clone(),
        metrics: metrics.clone(),
        tun: tun_slot.clone(),
        stream_handler,
        ssh_sessions,
        cp_tx: node.serves.client_tx(),
        pool: node.pool.clone(),
        recording_store,
        signed: node.signed.clone(),
        hostname: hostname.clone(),
        network_name: node
            .persisted
            .primary_network_name()
            .unwrap_or("tuntun")
            .to_string(),
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
    });

    let dns_bind = tuntun_core::dns_stub::bind_addr(dns_cfg.magic_ip);
    let _dns_task = tuntun_core::dns_stub::spawn(dns_bind, node.routes.clone(), dns_cfg.clone());
    let dns_guard = match crate::system_dns::configure(dns_cfg.magic_ip, &dns_cfg.suffix) {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::warn!(?e, "PeerDNS system configuration skipped");
            None
        }
    };
    let peer_dns_active = Arc::new(AtomicBool::new(dns_guard.is_some()));

    if !is_direct
        && let Some(snap) = tuntun_core::state::load_snapshot_cache(&node.paths)
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

    let (data_plane, cmd_rx) = DataPlaneHandle::new(8);
    let initial = build_initial_plane(tun, dns_guard, outbound, &node, is_direct, network_id);
    spawn_controller(ControllerSpawn {
        handle: data_plane.clone(),
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
    });

    let ipc_state = Arc::new(AgentIpcState {
        node: node.clone(),
        hostname: hostname.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        dns_upstream: dns_cfg.upstream.iter().map(|ip| ip.to_string()).collect(),
        synthetic_base: dns_cfg.synthetic_base.to_string(),
        magic_ip: dns_cfg.magic_ip.to_string(),
        peer_dns_active,
        peer_rtt: Arc::new(dashmap::DashMap::new()),
        serves: node.serves.clone(),
        tunnels: node.tunnels.clone(),
        send: node.send.clone(),
        data_plane,
    });
    let _ipc_task = spawn_ipc_server(ipc_state);

    #[cfg(unix)]
    crate::sd_notify::status("running");

    if !args.disable_gossip {
        if let Some(gossip) = node.shared_gossip() {
            let peers: Vec<iroh::EndpointId> = node
                .routes
                .peers()
                .iter()
                .take(5)
                .filter_map(|p| p.endpoint_hex.parse().ok())
                .collect();
            let topic = tuntun_common::network_topic_hex(&network_id);
            let ep = node.endpoint.clone();
            let hostname = hostname.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::gossip_presence::spawn(ep, gossip, topic, peers, hostname).await
                {
                    tracing::warn!(?e, "gossip presence disabled");
                }
            });
        } else {
            tracing::warn!("gossip presence skipped (no shared Gossip)");
        }
    }

    if agent_cfg.mdns.service_relay {
        if let Some(gossip) = node.shared_gossip() {
            let peers: Vec<iroh::EndpointId> = node
                .routes
                .peers()
                .iter()
                .take(5)
                .filter_map(|p| p.endpoint_hex.parse().ok())
                .collect();
            let topic = tuntun_common::mdns_relay_topic_hex(&network_id);
            let _mdns_task = tuntun_core::mdns_relay::spawn(tuntun_core::mdns_relay::SpawnConfig {
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
        let upgrade = crate::upgrade::UpgradeGuard::install()?;
        let reason = upgrade.wait().await;
        tracing::info!(?reason, "shutdown signal; draining");
        node.shutdown().await;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("ctrl-c, shutting down");
        node.shutdown().await;
        Ok(())
    }
}
