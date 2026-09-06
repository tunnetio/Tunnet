//! Local Management API business logic (formerly IPC dispatch handlers).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::mpsc;
use tunnet_common::local_api::permissions::{
    DATA_PLANE_WRITE, EVENTS_READ, LIFECYCLE, SERVE, STATUS_READ, TUNNEL,
};
use tunnet_common::local_api::{
    API_VERSION, ApiError, ApiErrorCode, ControlPlaneStatusInfo, DiagInfo,
    DirectFirewallPendingResponse, DirectFirewallResponse, DirectFirewallRuleInfo,
    DirectPendingInfo, DirectPolicyResponse, DnsStatusInfo, ExitNodeRouteInfo, HostnameRouteInfo,
    LocalEvent, MetaInfo, NetcheckInfo, NetcheckItem, NetworkSummary, NodeModeApi, NodeSummary,
    OkResponse, OnDemandStatusInfo, PeerSummary, PingEvent, PingProbe, PingSummary, RoutesInfo,
    ServeInfo, SshRecordingInfo, SshSessionInfo, SubnetRouteInfo, TransferInfo, TunnelInfo,
};

use super::auth::PeerIdentity;
use super::state::LocalApiState;
use crate::node::CoreNode;

pub(crate) fn api_err(code: ApiErrorCode, message: impl Into<String>) -> ApiError {
    ApiError {
        code,
        message: message.into(),
    }
}

pub(crate) fn map_anyhow(e: impl std::fmt::Display) -> ApiError {
    let message = e.to_string();
    api_err(classify_error(&message), message)
}

pub(crate) fn classify_error(message: &str) -> ApiErrorCode {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found")
        || lower.contains("no peer")
        || lower.contains("no pending")
        || lower.contains("missing")
    {
        ApiErrorCode::NotFound
    } else if lower.contains("denied")
        || lower.contains("unauthorized")
        || lower.contains("only the coordinator")
        || lower.contains("permission")
        || lower.contains("reject")
    {
        ApiErrorCode::Denied
    } else if lower.contains("not enrolled")
        || lower.contains("requires managed")
        || lower.contains("requires direct")
        || lower.contains("no direct networks")
        || lower.contains("not connected to a network")
    {
        ApiErrorCode::NotEnrolled
    } else if lower.contains("data plane") {
        ApiErrorCode::DataPlaneDown
    } else if lower.contains("invalid")
        || lower.contains("must be")
        || lower.contains("parse")
        || lower.contains("usage:")
    {
        ApiErrorCode::InvalidRequest
    } else {
        ApiErrorCode::Internal
    }
}

pub(crate) fn result_ok(message: impl Into<String>) -> OkResponse {
    OkResponse {
        message: message.into(),
    }
}

pub(crate) async fn reload_config(state: &LocalApiState) -> anyhow::Result<String> {
    use crate::TunnetConfig;

    let paths = &state.node.paths;
    let cfg = TunnetConfig::ensure(paths)?;
    if let Err(errs) = cfg.validate() {
        anyhow::bail!("tunnet.toml invalid: {}", errs.join("; "));
    }

    let network = state
        .node
        .persisted
        .primary_network_name()
        .unwrap_or("default")
        .to_string();
    let network_id = state
        .node
        .persisted
        .primary_network_id()
        .unwrap_or(uuid::Uuid::nil());

    // Firewall from tunnet.toml
    let fw_cfg = cfg.firewall_for_network(&network);
    if let Some(engine) = state.node.primary_firewall() {
        engine.reload_local(&fw_cfg);
    }

    // DNS into membership + routes
    let dns = cfg.dns_for_network(&network);
    if let Some(docs) = state.node.primary_docs() {
        docs.set_dns(dns.clone());
        let policy = (**state.node.acl.bundle.load()).clone();
        docs.apply_to_routes(&state.node.routes, &state.node.acl, &policy);
    } else {
        let peers: Vec<_> = state
            .node
            .routes
            .peers()
            .into_iter()
            .map(|p| tunnet_common::PeerEntry {
                ip: p.ip,
                endpoint_id: p.endpoint_hex.clone(),
                hostname: p.hostname.clone(),
                tags: p.tags.clone(),
                ssh_host_key: p.ssh_host_key.clone(),
            })
            .collect();
        let version = state.node.routes.version() + 1;
        state.node.routes.replace(
            &peers,
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &dns,
            &network,
            network_id,
            &state.node.endpoint_id_hex(),
            version,
        );
    }

    if let Some(net) = cfg.direct.get(&network) {
        state.node.pool.set_keep_alive(net.keep_alive);
    }

    Ok(format!(
        "reloaded firewall, dns (suffix={}, magic={}), keep-alive from tunnet.toml; logging.level={}",
        dns.suffix, dns.magic_ip, cfg.logging.level
    ))
}

pub(crate) fn transfer_info(r: crate::send::TransferRecord) -> TransferInfo {
    use crate::send::TransferDirection;
    TransferInfo {
        transfer_id: r.transfer_id,
        direction: match r.direction {
            TransferDirection::Outbound => "outbound".into(),
            TransferDirection::Inbound => "inbound".into(),
        },
        peer_endpoint_id: r.peer_endpoint_id,
        peer_hostname: r.peer_hostname,
        file_name: r.file_name,
        size: r.size,
        hash: r.hash,
        status: r.status.as_str().into(),
        percent: r.percent,
        bytes_transferred: r.bytes_transferred,
        message: r.message,
        error: r.error,
        inbox_path: r.inbox_path,
        is_directory: r.is_directory,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_serve(
    state: &LocalApiState,
    port: u16,
    protocol: &str,
    certificate_pem: Option<&str>,
    private_key_pem: Option<&str>,
    internal_hostname: Option<&str>,
    serve_id: Option<String>,
    access_mode: Option<String>,
    allowed_tags: Vec<String>,
    allowed_endpoint_ids: Vec<String>,
) -> anyhow::Result<ServeInfo> {
    let network = state
        .node
        .persisted
        .primary_network_name()
        .unwrap_or("default")
        .to_string();
    let hostname = state.hostname.clone();
    let internal_hostname = internal_hostname
        .map(str::to_string)
        .unwrap_or_else(|| format!("{hostname}.{network}.tunnet"));
    let id = serve_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if protocol == "https" && (certificate_pem.is_none() || private_key_pem.is_none()) {
        anyhow::bail!(
            "HTTPS serve needs an internal CA leaf cert. Create the serve from the dashboard \
             (certs are pushed over WebSocket), or use --protocol tcp for a quick mesh expose."
        );
    }

    let mode = access_mode.unwrap_or_else(|| "all_peers".into());
    let acl = crate::serve::ServeAcl {
        access_mode: mode,
        allowed_tags,
        allowed_endpoint_ids,
    };

    state
        .serves
        .start(
            id,
            port,
            protocol,
            &internal_hostname,
            certificate_pem,
            private_key_pem,
            acl,
            None,
            false,
        )
        .await
}

pub(crate) async fn advertise_subnet_route(
    state: &LocalApiState,
    cidr: &str,
    description: Option<String>,
) -> anyhow::Result<String> {
    let managed = state.node.persisted.require_managed()?;
    let client = crate::control::SignedClient::new(
        managed.control_url.clone(),
        state.node.endpoint_id_hex(),
        state.node.identity.signing_key.clone(),
    )?;
    client
        .create_subnet_route(cidr, description.as_deref())
        .await
}

pub(crate) async fn start_tunnel(
    state: &LocalApiState,
    port: u16,
    protocol: &str,
    edge: Option<&str>,
    subdomain: Option<&str>,
    inspect: bool,
    inspect_addr: Option<&str>,
) -> anyhow::Result<TunnelInfo> {
    if state.node.persisted.is_direct() {
        if !inspect {
            anyhow::bail!(
                "this command requires Managed mode; this agent is in Direct mode \
                 (run `tunnet reset --yes` to switch). \
                 Or use `tunnet tunnel {port} --inspect` for a local request inspector."
            );
        }
        if protocol != "https" && protocol != "http" {
            anyhow::bail!("--inspect in Direct mode requires http/https (got {protocol})");
        }
        return state
            .tunnels
            .start_local_inspect(port, inspect_addr, state.node.self_ipv4)
            .await;
    }

    let managed = state.node.persisted.require_managed()?;
    let client = crate::control::SignedClient::new(
        managed.control_url.clone(),
        state.node.endpoint_id_hex(),
        state.node.identity.signing_key.clone(),
    )?;

    let created = client
        .create_tunnel(port, protocol, subdomain, edge)
        .await
        .context("control plane create tunnel")?;

    match state
        .tunnels
        .start(
            created.tunnel_id.clone(),
            &created.edge_endpoint_id,
            &created.subdomain,
            &created.public_hostname,
            created.local_port,
            &created.protocol,
            &created.auth_token,
            created.redirect_rules,
            None,
            inspect,
            inspect_addr,
        )
        .await
    {
        Ok(info) => {
            if let Err(e) = client.tunnel_ready(&created.tunnel_id).await {
                tracing::warn!(?e, "tunnel ready report failed");
            }
            Ok(info)
        }
        Err(e) => {
            let _ = client
                .tunnel_failed(&created.tunnel_id, &e.to_string())
                .await;
            Err(e)
        }
    }
}

pub(crate) async fn stop_tunnel(state: &LocalApiState, port: u16) -> anyhow::Result<TunnelInfo> {
    let info = state.tunnels.stop_by_port(port)?;
    if info.relay == "local" || state.node.persisted.is_direct() {
        return Ok(info);
    }
    let Ok(managed) = state.node.persisted.require_managed() else {
        return Ok(info);
    };
    let client = crate::control::SignedClient::new(
        managed.control_url.clone(),
        state.node.endpoint_id_hex(),
        state.node.identity.signing_key.clone(),
    )?;
    if let Err(e) = client.tunnel_stopped(&info.id).await {
        tracing::warn!(?e, "tunnel stopped report failed");
    }
    Ok(info)
}

pub(crate) fn parse_network_id(s: &str) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(s).map_err(|e| {
        api_err(
            ApiErrorCode::InvalidRequest,
            format!("invalid network_id: {e}"),
        )
    })
}

pub(crate) fn node_mode(state: &LocalApiState) -> NodeModeApi {
    if state.node.persisted.is_direct() {
        NodeModeApi::Direct
    } else if state.node.persisted.is_managed() {
        NodeModeApi::Managed
    } else {
        NodeModeApi::Idle
    }
}

fn control_plane_status(state: &LocalApiState) -> Option<ControlPlaneStatusInfo> {
    #[cfg(feature = "managed")]
    {
        state.node.control_link.as_ref().map(|link| {
            let s = link.snapshot();
            ControlPlaneStatusInfo {
                url: s.url,
                connected: s.connected,
                connected_for_secs: s.connected_for_secs,
                last_change_secs_ago: s.last_change_secs_ago,
                reconnects: s.reconnects,
                last_error: s.last_error,
            }
        })
    }
    #[cfg(not(feature = "managed"))]
    {
        None
    }
}

fn expiry_fields(state: &LocalApiState) -> (Option<String>, Option<u64>) {
    if let Some(snap) = crate::state::load_snapshot_cache(&state.node.paths)
        && let Some(at) = snap.expires_at
        && let Ok(expiry) = at.parse::<jiff::Timestamp>()
    {
        let remaining = expiry.duration_since(jiff::Timestamp::now()).as_secs();
        return (Some(at), Some(remaining.max(0) as u64));
    }
    (None, None)
}

fn firewall_stats_for_network(
    state: &LocalApiState,
    network_id: uuid::Uuid,
) -> (Option<u64>, Option<usize>) {
    state
        .node
        .firewall_for(network_id)
        .map(|fw| {
            let s = fw.stats();
            (
                Some(s.packets_denied + s.packets_rejected),
                Some(s.conntrack_entries),
            )
        })
        .unwrap_or((None, None))
}

fn iroh_relay_status(endpoint: &iroh::Endpoint) -> String {
    use iroh::Watcher;
    let mut watcher = endpoint.home_relay_status();
    let statuses = watcher.get();
    if statuses.iter().any(|s| s.is_connected()) {
        "connected".into()
    } else if statuses.is_empty() {
        "disabled".into()
    } else {
        "disconnected".into()
    }
}

pub(crate) fn peer_summaries(
    state: &LocalApiState,
    network_id: Option<uuid::Uuid>,
) -> Vec<PeerSummary> {
    let pool = &state.node.tunnel_pool;
    let self_id = state.node.endpoint_id_hex();
    state
        .node
        .routes
        .peers()
        .into_iter()
        .filter(|p| p.endpoint_hex != self_id)
        .filter(|p| network_id.is_none_or(|nid| p.network_id == nid))
        .map(|p| {
            let snap = pool.peer_snapshot(p.endpoint);
            let (bytes_in, bytes_out) = pool.peer_bytes(p.endpoint);
            let latency_ms = state.peer_rtt.get(&p.endpoint_hex).map(|v| *v);
            let presence_online = state.node.peer_presence_online(&p.endpoint_hex);
            let presence_last_seen = state.node.peer_presence_last_seen(&p.endpoint_hex);
            let last_seen = if snap.last_activity_secs_ago == u64::MAX {
                presence_last_seen
            } else {
                Some(snap.last_activity_secs_ago)
            };
            let pool_online = snap.live || pool.has_live(p.endpoint);
            // None = unknown (cold start / no beacon yet); do not treat as offline.
            let online = if pool_online {
                Some(true)
            } else {
                presence_online
            };
            PeerSummary {
                network_id: p.network_id.to_string(),
                ip: p.ip.to_string(),
                hostname: p.hostname.clone(),
                endpoint_id: p.endpoint_hex.clone(),
                tags: p.tags.clone(),
                online,
                latency_ms,
                os: None,
                conn_state: Some(snap.state),
                path: Some(snap.path),
                bytes_in: Some(bytes_in),
                bytes_out: Some(bytes_out),
                last_seen_secs_ago: last_seen,
                keep_alive: Some(snap.keep_alive),
                ssh_host_key: p.ssh_host_key.clone(),
            }
        })
        .collect()
}

pub(crate) fn build_network_summary(
    state: &LocalApiState,
    network_id: uuid::Uuid,
) -> Result<NetworkSummary, ApiError> {
    let peers = peer_summaries(state, Some(network_id));
    let peers_total = peers.len();
    let peers_online = peers.iter().filter(|p| p.online.unwrap_or(false)).count();
    let pool = &state.node.tunnel_pool;
    let (expires_at, expires_in_secs) = expiry_fields(state);
    let control = control_plane_status(state);

    if let Some(managed) = state.node.persisted.as_managed() {
        if managed.network_id != network_id {
            return Err(api_err(
                ApiErrorCode::NotFound,
                format!("network {network_id} not found"),
            ));
        }
        let relay_status = iroh_relay_status(&state.node.endpoint);
        let (firewall_drops, conntrack_entries) = firewall_stats_for_network(state, network_id);
        return Ok(NetworkSummary {
            network_id: network_id.to_string(),
            network_name: managed.network_name.clone(),
            mode: "managed".into(),
            ip: state.node.self_ipv4.to_string(),
            role: "managed".into(),
            peers_total,
            peers_online,
            organization_id: Some(managed.organization_id.clone()),
            control_url: Some(managed.control_url.clone()),
            management_url: managed.management_url.clone(),
            dashboard_url: managed.dashboard_url.clone(),
            firewall_drops,
            conntrack_entries,
            relay_status,
            expires_at,
            expires_in_secs,
            keep_alive: Some(pool.keep_alive_global()),
            control: control.clone(),
        });
    }

    let direct = state
        .node
        .persisted
        .require_direct_network_id(network_id)
        .map_err(|e| api_err(ApiErrorCode::NotFound, e.to_string()))?;
    let (firewall_drops, conntrack_entries) = firewall_stats_for_network(state, network_id);
    let role = if direct.coordinator {
        "coordinator"
    } else {
        "member"
    };
    Ok(NetworkSummary {
        network_id: network_id.to_string(),
        network_name: direct.network_name.clone(),
        mode: "direct".into(),
        ip: direct.assigned_ipv4.to_string(),
        role: role.into(),
        peers_total,
        peers_online,
        organization_id: None,
        control_url: None,
        management_url: None,
        dashboard_url: None,
        firewall_drops,
        conntrack_entries,
        relay_status: "n/a".into(),
        expires_at,
        expires_in_secs,
        keep_alive: Some(pool.keep_alive_global()),
        control: None,
    })
}

pub(crate) fn build_node_summary(state: &LocalApiState) -> NodeSummary {
    let pool = &state.node.tunnel_pool;
    let od = pool.on_demand_stats();
    let control = control_plane_status(state);
    let networks: Vec<NetworkSummary> = match &state.node.persisted {
        crate::state::PersistedState::Managed(m) => {
            vec![
                build_network_summary(state, m.network_id).unwrap_or_else(|_| NetworkSummary {
                    network_id: m.network_id.to_string(),
                    network_name: m.network_name.clone(),
                    mode: "managed".into(),
                    ip: state.node.self_ipv4.to_string(),
                    role: "managed".into(),
                    peers_total: 0,
                    peers_online: 0,
                    organization_id: Some(m.organization_id.clone()),
                    control_url: Some(m.control_url.clone()),
                    management_url: m.management_url.clone(),
                    dashboard_url: m.dashboard_url.clone(),
                    firewall_drops: None,
                    conntrack_entries: None,
                    relay_status: iroh_relay_status(&state.node.endpoint),
                    expires_at: None,
                    expires_in_secs: None,
                    keep_alive: None,
                    control: control.clone(),
                }),
            ]
        }
        crate::state::PersistedState::Direct { networks: dirs } => dirs
            .iter()
            .filter_map(|d| build_network_summary(state, d.network_id).ok())
            .collect(),
    };

    NodeSummary {
        endpoint_id: state.node.endpoint_id_hex(),
        hostname: state.hostname.clone(),
        mode: node_mode(state),
        daemon_version: state.agent_version.clone(),
        api_version: API_VERSION,
        data_plane_up: state.data_plane.is_up(),
        uptime_secs: state.uptime_secs(),
        snapshot_version: **state.node.version.load(),
        networks,
        on_demand: Some(OnDemandStatusInfo {
            reconnect_attempts: od.reconnect_attempts,
            reconnect_success: od.reconnect_success,
            reconnect_fail: od.reconnect_fail,
            packets_buffered: od.packets_buffered,
            packets_dropped_timeout: od.packets_dropped_timeout,
        }),
        control,
        daemon_git: Some(tunnet_common::git_hash().to_string()),
        tunnel_alpn: Some(
            std::str::from_utf8(tunnet_common::TUNNEL_ALPN)
                .unwrap_or("?")
                .to_string(),
        ),
        data_plane: Some(state.data_plane.data_plane_info()),
    }
}

pub(crate) fn build_meta(state: &LocalApiState, peer: &PeerIdentity) -> MetaInfo {
    let mut permissions: Vec<String> = peer
        .capabilities()
        .into_iter()
        .map(str::to_string)
        .collect();

    if let Some(managed) = state.node.persisted.as_managed() {
        let ui = &managed.local_ui;
        if !ui.enabled {
            permissions.retain(|p| p == STATUS_READ || p == EVENTS_READ);
        } else {
            if !ui.allow_disconnect {
                permissions.retain(|p| p != DATA_PLANE_WRITE);
            }
            if !ui.allow_serve {
                permissions.retain(|p| p != SERVE);
            }
            if !ui.allow_tunnel {
                permissions.retain(|p| p != TUNNEL);
            }
        }
    }

    MetaInfo {
        api_version: API_VERSION,
        daemon_version: state.agent_version.clone(),
        mode: node_mode(state),
        features: vec![
            "node".into(),
            "networks".into(),
            "events".into(),
            "dns".into(),
            "routes".into(),
            "diag".into(),
        ],
        permissions,
    }
}

pub(crate) fn idle_node_summary(daemon_version: &str) -> NodeSummary {
    NodeSummary {
        endpoint_id: String::new(),
        hostname: String::new(),
        mode: NodeModeApi::Idle,
        daemon_version: daemon_version.to_string(),
        api_version: API_VERSION,
        data_plane_up: false,
        uptime_secs: 0,
        snapshot_version: 0,
        networks: vec![],
        on_demand: None,
        control: None,
        daemon_git: Some(tunnet_common::git_hash().to_string()),
        tunnel_alpn: Some(
            std::str::from_utf8(tunnet_common::TUNNEL_ALPN)
                .unwrap_or("?")
                .to_string(),
        ),
        data_plane: None,
    }
}

pub(crate) fn idle_meta(daemon_version: &str, peer: &PeerIdentity) -> MetaInfo {
    MetaInfo {
        api_version: API_VERSION,
        daemon_version: daemon_version.to_string(),
        mode: NodeModeApi::Idle,
        features: vec!["node".into(), "events".into()],
        permissions: peer
            .capabilities()
            .into_iter()
            .filter(|p| *p == STATUS_READ || *p == EVENTS_READ || *p == LIFECYCLE)
            .map(str::to_string)
            .collect(),
    }
}

pub(crate) fn build_dns_status(state: &LocalApiState) -> DnsStatusInfo {
    let tables_cached = state.node.routes.cached_entry_count();
    let magic = state.magic_ip.clone();
    DnsStatusInfo {
        suffix: state.node.routes.dns_suffix(),
        upstream: state.dns_upstream.clone(),
        dnssec: state.dnssec,
        peer_dns_active: state
            .peer_dns_active
            .load(std::sync::atomic::Ordering::SeqCst),
        cached_entries: tables_cached,
        synthetic_base: state.synthetic_base.clone(),
        magic_ip: magic.clone(),
        bind: format!("{magic}:53"),
    }
}

pub(crate) fn build_routes(state: &LocalApiState, network_id: uuid::Uuid) -> RoutesInfo {
    let self_id = state.node.endpoint_id_hex();
    let snap = crate::state::load_snapshot_cache(&state.node.paths);
    let membership = snap
        .as_ref()
        .and_then(|s| s.memberships.iter().find(|m| m.network_id == network_id));

    let mut subnet_routes = Vec::new();
    let mut hostname_routes = Vec::new();
    let mut exit_node = None;
    let mut split_tunnel_mode = "exclude".to_string();
    let mut split_tunnel_cidrs = Vec::new();

    if let Some(m) = membership {
        for r in &m.subnet_routes {
            let via = state
                .node
                .routes
                .lookup_endpoint(&r.via_endpoint_id)
                .map(|p| p.hostname.clone())
                .unwrap_or_else(|| r.via_endpoint_id[..8.min(r.via_endpoint_id.len())].to_string());
            subnet_routes.push(SubnetRouteInfo {
                cidr: r.cidr.to_string(),
                via_hostname: via,
                via_ip: r.via_ip.to_string(),
                via_endpoint_id: r.via_endpoint_id.clone(),
                advertised_by_self: r.via_endpoint_id == self_id,
            });
        }
        for r in &m.hostname_routes {
            let via = state
                .node
                .routes
                .lookup_endpoint(&r.via_endpoint_id)
                .map(|p| p.hostname.clone())
                .unwrap_or_else(|| r.via_endpoint_id[..8.min(r.via_endpoint_id.len())].to_string());
            hostname_routes.push(HostnameRouteInfo {
                hostname: r.hostname.clone(),
                is_wildcard: r.is_wildcard,
                via_hostname: via,
                via_ip: r.via_ip.to_string(),
                via_endpoint_id: r.via_endpoint_id.clone(),
                target_ip: r.target_ip.map(|ip| ip.to_string()),
            });
        }
        if let Some(exit) = state.node.routes.exit_node() {
            exit_node = Some(ExitNodeRouteInfo {
                hostname: exit.hostname.clone(),
                via_ip: exit.ip.to_string(),
                endpoint_id: exit.endpoint_hex.clone(),
            });
        }
        split_tunnel_mode = format!("{:?}", m.device_profile.split_tunnel_mode).to_lowercase();
        split_tunnel_cidrs = m
            .device_profile
            .split_tunnel_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect();
    }

    RoutesInfo {
        subnet_routes,
        hostname_routes,
        exit_node,
        split_tunnel_mode,
        split_tunnel_cidrs,
    }
}

pub(crate) async fn build_diag(state: &LocalApiState) -> DiagInfo {
    let peers = state.node.routes.peers();
    let total = peers.len();
    // Without per-connection path telemetry yet, report unknowns honestly.
    DiagInfo {
        nat_type: "unknown".into(),
        endpoint_id: state.node.endpoint_id_hex(),
        endpoint_online: true,
        relay_reachable: true,
        relay_rtt_ms: None,
        direct_peers: 0,
        relayed_peers: 0,
        total_peers: total,
        notes: vec![
            "NAT classification and path telemetry land with richer peer metrics".into(),
            format!("mesh peers known: {total}"),
        ],
    }
}

pub(crate) async fn build_netcheck(state: &LocalApiState) -> NetcheckInfo {
    let mut checks = Vec::new();

    checks.push(NetcheckItem {
        name: "agent_running".into(),
        pass: true,
        detail: format!("uptime {}s", state.uptime_secs()),
    });

    checks.push(NetcheckItem {
        name: "has_mesh_ip".into(),
        pass: !state.node.self_ipv4.is_unspecified(),
        detail: state.node.self_ipv4.to_string(),
    });

    checks.push(NetcheckItem {
        name: "peer_dns".into(),
        pass: state
            .peer_dns_active
            .load(std::sync::atomic::Ordering::SeqCst),
        detail: if state
            .peer_dns_active
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            format!("suffix .{}", state.node.routes.dns_suffix())
        } else {
            "PeerDNS not active".into()
        },
    });

    checks.push(NetcheckItem {
        name: "snapshot".into(),
        pass: **state.node.version.load() > 0,
        detail: format!("version {}", **state.node.version.load()),
    });

    let ok = checks.iter().all(|c| c.pass);
    NetcheckInfo { ok, checks }
}

/// Run ping probes and send [`PingEvent`]s on `tx`. Errors are reported as channel closes / early return.
pub(crate) async fn run_ping(
    peer: String,
    count: u32,
    interval_ms: u64,
    state: Arc<LocalApiState>,
    tx: mpsc::Sender<Result<PingEvent, ApiError>>,
) {
    use crate::ping;

    let resolved = match resolve_peer(&state.node, &peer) {
        Some(p) => p,
        None => {
            let _ = tx
                .send(Err(api_err(
                    ApiErrorCode::NotFound,
                    format!("no peer matches `{peer}` (try hostname, IP, or endpoint id)"),
                )))
                .await;
            return;
        }
    };

    let self_hex = state.node.endpoint_id_hex();
    if resolved.endpoint_hex.eq_ignore_ascii_case(&self_hex) || resolved.ip == state.node.self_ipv4
    {
        let _ = tx
            .send(Err(api_err(
                ApiErrorCode::InvalidRequest,
                format!(
                    "`{peer}` is this node ({} / {}). Ping the other machine's mesh IP instead",
                    state.node.self_ipv4, resolved.hostname
                ),
            )))
            .await;
        return;
    }

    let count = count.clamp(1, 64);
    let mut latencies = Vec::new();
    let mut received = 0u32;
    let mut path = "unknown".to_string();

    for seq in 1..=count {
        match ping::ping_peer(&state.node.pool, resolved.endpoint, seq).await {
            Ok(result) => {
                received += 1;
                latencies.push(result.latency_ms);
                path = result.path.clone();
                if tx
                    .send(Ok(PingEvent::Probe(PingProbe {
                        seq,
                        peer: resolved.hostname.clone(),
                        peer_ip: resolved.ip.to_string(),
                        latency_ms: result.latency_ms,
                        path: result.path,
                    })))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(e) => {
                if tx
                    .send(Err(api_err(
                        ApiErrorCode::Internal,
                        format!("seq={seq} timeout/error: {e}"),
                    )))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if seq < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    let (min_ms, avg_ms, max_ms) = if latencies.is_empty() {
        (None, None, None)
    } else {
        let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
        state.peer_rtt.insert(resolved.endpoint_hex.clone(), avg);
        (Some(min), Some(avg), Some(max))
    };

    let loss_pct = if count == 0 {
        0.0
    } else {
        ((count - received) as f64 / count as f64) * 100.0
    };

    let _ = tx
        .send(Ok(PingEvent::Summary(PingSummary {
            peer: resolved.hostname.clone(),
            peer_ip: resolved.ip.to_string(),
            transmitted: count,
            received,
            loss_pct,
            min_ms,
            avg_ms,
            max_ms,
            path,
        })))
        .await;
}

pub(crate) fn resolve_peer(
    node: &CoreNode,
    host: &str,
) -> Option<std::sync::Arc<crate::routing::PeerInfo>> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

pub(crate) async fn list_ssh_sessions(
    state: &LocalApiState,
    limit: u32,
    status: Option<&str>,
) -> anyhow::Result<Vec<SshSessionInfo>> {
    let raw = state
        .node
        .require_signed()?
        .list_ssh_sessions(limit, status)
        .await
        .context("list ssh sessions from control plane")?;
    let sessions = raw
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        out.push(SshSessionInfo {
            id: s
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            src_endpoint_id: s
                .get("srcEndpointId")
                .or_else(|| s.get("src_endpoint_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            dst_endpoint_id: s
                .get("dstEndpointId")
                .or_else(|| s.get("dst_endpoint_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            src_hostname: s
                .get("srcHostname")
                .or_else(|| s.get("src_hostname"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            dst_hostname: s
                .get("dstHostname")
                .or_else(|| s.get("dst_hostname"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            target_user: s
                .get("targetUser")
                .or_else(|| s.get("target_user"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            status: s
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            recorded: s.get("recorded").and_then(|v| v.as_bool()).unwrap_or(false),
            started_at: s
                .get("startedAt")
                .or_else(|| s.get("started_at"))
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_default(),
            duration_ms: s
                .get("durationMs")
                .or_else(|| s.get("duration_ms"))
                .and_then(|v| v.as_u64()),
        });
    }
    Ok(out)
}

pub(crate) async fn list_ssh_recordings(
    state: &LocalApiState,
    limit: u32,
) -> anyhow::Result<Vec<SshRecordingInfo>> {
    let raw = state
        .node
        .require_signed()?
        .list_ssh_recordings(limit)
        .await
        .context("list ssh recordings from control plane")?;
    let recordings = raw
        .get("recordings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(recordings.len());
    for r in recordings {
        out.push(SshRecordingInfo {
            session_id: r
                .get("sessionId")
                .or_else(|| r.get("session_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            src_hostname: r
                .get("srcHostname")
                .or_else(|| r.get("src_hostname"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            dst_hostname: r
                .get("dstHostname")
                .or_else(|| r.get("dst_hostname"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            target_user: r
                .get("targetUser")
                .or_else(|| r.get("target_user"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            byte_size: r
                .get("byteSize")
                .or_else(|| r.get("byte_size"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            created_at: r
                .get("createdAt")
                .or_else(|| r.get("created_at"))
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_default(),
            content_sha256: r
                .get("contentSha256")
                .or_else(|| r.get("content_sha256"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }
    Ok(out)
}

pub(crate) async fn get_ssh_cast(
    state: &LocalApiState,
    session_id: &str,
) -> anyhow::Result<(String, String, String)> {
    let raw = state
        .node
        .require_signed()?
        .get_ssh_recording_cast(session_id)
        .await
        .context("fetch ssh recording cast")?;
    let cast_text = raw
        .get("castText")
        .or_else(|| raw.get("cast_text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("cast missing"))?
        .to_string();
    let content_sha256 = raw
        .get("contentSha256")
        .or_else(|| raw.get("content_sha256"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let sid = raw
        .get("sessionId")
        .or_else(|| raw.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(session_id)
        .to_string();
    Ok((sid, cast_text, content_sha256))
}

pub(crate) async fn poll_ssh_auth(
    state: &LocalApiState,
    challenge_token: &str,
) -> anyhow::Result<(String, Option<String>)> {
    let raw = state
        .node
        .require_signed()?
        .poll_ssh_auth(challenge_token)
        .await
        .context("poll ssh auth")?;
    let status = raw
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("failed")
        .to_string();
    let proof_token = raw
        .get("proofToken")
        .or_else(|| raw.get("proof_token"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok((status, proof_token))
}

pub(crate) fn require_direct_coord<'a>(
    state: &'a LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<&'a crate::state::DirectState> {
    let d = state.node.persisted.require_direct_network(network)?;
    if !d.coordinator {
        anyhow::bail!("only the coordinator can perform this action");
    }
    Ok(d)
}

pub(crate) fn direct_requests_for_network(
    state: &LocalApiState,
    network_id: uuid::Uuid,
) -> anyhow::Result<Vec<DirectPendingInfo>> {
    let direct = state.node.persisted.require_direct_network_id(network_id)?;
    let list = crate::direct::admin::load_pending(&state.node.paths, direct.network_id)?;
    Ok(list
        .into_iter()
        .map(|p| DirectPendingInfo {
            endpoint_id: p.endpoint_id,
            hostname: p.hostname,
            ipv4: p.ipv4.to_string(),
            collision_index: p.collision_index,
        })
        .collect())
}

pub(crate) fn direct_accept_for_network(
    state: &LocalApiState,
    network_id: uuid::Uuid,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network_id(network_id)?;
    direct_accept(state, Some(&direct.network_name), peer_id)
}

pub(crate) fn direct_deny_for_network(
    state: &LocalApiState,
    network_id: uuid::Uuid,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network_id(network_id)?;
    direct_deny(state, Some(&direct.network_name), peer_id)
}

pub(crate) fn direct_firewall_for_network(
    state: &LocalApiState,
    network_id: uuid::Uuid,
) -> anyhow::Result<DirectFirewallResponse> {
    let direct = state.node.persisted.require_direct_network_id(network_id)?;
    direct_firewall_show(state, Some(&direct.network_name))
}

pub(crate) fn direct_invite(
    state: &LocalApiState,
    network: Option<&str>,
    reusable: bool,
    expires: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let expires = jiff::fmt::friendly::SpanParser::new()
        .parse_span(expires)
        .context("invalid invite expiry")?;
    if !expires.is_positive() {
        anyhow::bail!("invite expiry must be positive");
    }
    let invite = crate::direct::InviteCode::new(
        direct.topic_hash.clone(),
        direct.join_secret.clone(),
        direct.network_name.clone(),
        state.node.endpoint_id_hex(),
        direct
            .coordinator_verifying_key
            .clone()
            .context("coordinator verifying key missing")?,
        expires,
        reusable,
    );
    let mut used = crate::direct::admin::load_invite_ids(&state.node.paths, direct.network_id)?;
    used.insert(invite.invite_id.clone());
    crate::direct::admin::save_invite_ids(&state.node.paths, direct.network_id, &used)?;
    crate::direct::encode_invite(&invite)
}

pub(crate) fn direct_requests(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<Vec<DirectPendingInfo>> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let list = crate::direct::admin::load_pending(&state.node.paths, direct.network_id)?;
    Ok(list
        .into_iter()
        .map(|p| DirectPendingInfo {
            endpoint_id: p.endpoint_id,
            hostname: p.hostname,
            ipv4: p.ipv4.to_string(),
            collision_index: p.collision_index,
        })
        .collect())
}

pub(crate) fn direct_accept(
    state: &LocalApiState,
    network: Option<&str>,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let network_id = direct.network_id;
    let mut list = crate::direct::admin::load_pending(&state.node.paths, network_id)?;
    let idx = list
        .iter()
        .position(|p| p.endpoint_id == peer_id || p.hostname == peer_id)
        .context("pending peer not found")?;
    let pending = list.remove(idx);
    crate::direct::admin::save_pending(&state.node.paths, network_id, &list)?;
    let mut approved = crate::direct::load_approved(&state.node.paths)?;
    if !approved.iter().any(|id| id == &pending.endpoint_id) {
        approved.push(pending.endpoint_id.clone());
        crate::direct::save_approved(&state.node.paths, &approved)?;
    }
    state.emit(LocalEvent::PeerOnline {
        network_id: network_id.to_string(),
        endpoint_id: pending.endpoint_id.clone(),
    });
    Ok(format!(
        "Approved {}. Peer should re-run join while this agent is running.",
        pending.endpoint_id
    ))
}

pub(crate) fn direct_deny(
    state: &LocalApiState,
    network: Option<&str>,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let network_id = direct.network_id;
    let mut list = crate::direct::admin::load_pending(&state.node.paths, network_id)?;
    let before = list.len();
    list.retain(|p| p.endpoint_id != peer_id && p.hostname != peer_id);
    if list.len() == before {
        anyhow::bail!("pending peer not found");
    }
    crate::direct::admin::save_pending(&state.node.paths, network_id, &list)?;
    Ok(format!("Denied {peer_id}"))
}

pub(crate) async fn direct_kick(
    state: &LocalApiState,
    network: Option<&str>,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let network_id = direct.network_id;
    let result = if let Some(rt) = state.node.direct.get(&network_id) {
        if let Some(auth) = &state.node.direct_auth {
            rt.docs.kick_peer(peer_id, auth).await?;
        } else {
            rt.docs
                .kick_peer(peer_id, &crate::direct::AuthCache::new())
                .await?;
        }
        rt.docs.rebuild_from_doc().await.ok();
        format!("Kicked {peer_id}")
    } else {
        crate::direct::admin::queue_kick(&state.node.paths, network_id, peer_id)?;
        format!("Queued kick for {peer_id} (docs not ready; will apply shortly)")
    };
    state.emit(LocalEvent::PeerOffline {
        network_id: network_id.to_string(),
        endpoint_id: peer_id.to_string(),
    });
    Ok(result)
}

pub(crate) fn direct_firewall_show(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<DirectFirewallResponse> {
    use crate::direct::firewall::{action_display, direction_display, peer_filter_display};

    let direct = state.node.persisted.require_direct_network(network)?;
    let cfg = crate::agent_config::load_firewall_for(&state.node.paths, &direct.network_name);
    let stats = state
        .node
        .firewall_for(direct.network_id)
        .map(|e| e.stats());
    let rules = cfg
        .rules
        .iter()
        .enumerate()
        .map(|(index, r)| DirectFirewallRuleInfo {
            index,
            direction: direction_display(r.direction).into(),
            action: action_display(r.action).into(),
            protocol: format!("{:?}", r.protocol).to_ascii_lowercase(),
            ports: if r.ports.is_empty() {
                None
            } else {
                Some(format!("{:?}", r.ports))
            },
            peer: peer_filter_display(&r.peer),
        })
        .collect();
    Ok(DirectFirewallResponse {
        enabled: stats.as_ref().map(|s| s.enabled).unwrap_or(cfg.enabled),
        rules,
        conntrack_entries: stats.as_ref().map(|s| s.conntrack_entries).unwrap_or(0),
        packets_allowed: stats.as_ref().map(|s| s.packets_allowed).unwrap_or(0),
        packets_denied: stats.as_ref().map(|s| s.packets_denied).unwrap_or(0),
        packets_rejected: stats.as_ref().map(|s| s.packets_rejected).unwrap_or(0),
        suggested_rules: stats.as_ref().map(|s| s.suggested_rules).unwrap_or(0),
    })
}

pub(crate) fn reload_firewall_engine(
    state: &LocalApiState,
    network_id: uuid::Uuid,
    cfg: &crate::direct::FirewallConfig,
) {
    if let Some(fw) = state.node.firewall_for(network_id) {
        fw.reload_local(cfg);
    }
}

pub(crate) fn direct_firewall_off(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let mut cfg = crate::agent_config::load_firewall_for(&state.node.paths, &direct.network_name);
    cfg.enabled = false;
    cfg.version += 1;
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok("Firewall disabled (allow all).".into())
}

pub(crate) fn direct_firewall_add(
    state: &LocalApiState,
    network: Option<&str>,
    direction: &str,
    action: &str,
    protocol: &str,
    port: Option<&str>,
    peer: Option<String>,
) -> anyhow::Result<String> {
    use crate::direct::firewall::{
        FirewallAction, FirewallDirection, FirewallRule, parse_peer_filter, parse_port_spec,
    };
    use tunnet_common::policy::Protocol;

    let direct = state.node.persisted.require_direct_network(network)?;
    let mut cfg = crate::agent_config::load_firewall_for(&state.node.paths, &direct.network_name);
    let direction = match direction {
        "in" | "inbound" => FirewallDirection::In,
        "out" | "outbound" => FirewallDirection::Out,
        _ => anyhow::bail!("direction must be 'in' or 'out'"),
    };
    let action = match action {
        "allow" => FirewallAction::Allow,
        "deny" => FirewallAction::Deny,
        "reject" => FirewallAction::Reject,
        _ => anyhow::bail!("action must be 'allow', 'deny', or 'reject'"),
    };
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "icmpv6" => Protocol::Icmpv6,
        "any" => Protocol::Any,
        _ => anyhow::bail!("protocol must be tcp|udp|icmp|any"),
    };
    let ports = parse_port_spec(port.unwrap_or(""))?;
    let peer = parse_peer_filter(peer.as_deref())?;
    cfg.enabled = true;
    cfg.add_rule(FirewallRule {
        direction,
        action,
        protocol,
        ports,
        peer,
    });
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok("Rule added.".into())
}

pub(crate) fn direct_firewall_remove(
    state: &LocalApiState,
    network: Option<&str>,
    index: usize,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let mut cfg = crate::agent_config::load_firewall_for(&state.node.paths, &direct.network_name);
    cfg.remove_at(index)?;
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok(format!("Removed rule {index}"))
}

pub(crate) fn direct_firewall_reset(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let cfg = crate::direct::default_firewall();
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok("Firewall reset to defaults.".into())
}

pub(crate) fn direct_firewall_flush(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    if let Some(fw) = state.node.firewall_for(direct.network_id) {
        fw.flush_conntrack();
    }
    Ok("Conntrack table flushed.".into())
}

pub(crate) fn direct_firewall_pending(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<DirectFirewallPendingResponse> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let path = state.node.paths.firewall_pending_file(direct.network_id);
    if !path.exists() {
        return Ok(DirectFirewallPendingResponse { pending: None });
    }
    let s = std::fs::read_to_string(&path)?;
    Ok(DirectFirewallPendingResponse { pending: Some(s) })
}

pub(crate) fn direct_firewall_accept(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let path = state.node.paths.firewall_pending_file(direct.network_id);
    if !path.exists() {
        anyhow::bail!("no pending firewall suggestion");
    }
    let pending: crate::direct::policy_docs::PendingSuggestion =
        serde_json::from_slice(&std::fs::read(&path)?)?;
    let hostname = direct.hostname.clone();
    let rules = crate::direct::policy_docs::effective_suggested(&pending.policy, &hostname);
    if let Some(fw) = state.node.firewall_for(direct.network_id) {
        fw.set_suggested(rules);
    }
    let _ = std::fs::remove_file(&path);
    Ok("Accepted pending firewall suggestion.".into())
}

pub(crate) fn direct_firewall_reject_suggestion(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let path = state.node.paths.firewall_pending_file(direct.network_id);
    let _ = std::fs::remove_file(&path);
    if let Some(fw) = state.node.firewall_for(direct.network_id) {
        fw.clear_suggested();
    }
    Ok("Rejected pending firewall suggestion.".into())
}

pub(crate) async fn direct_policy_show(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<DirectPolicyResponse> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let Some(docs) = state.node.docs_for(direct.network_id) else {
        return Ok(DirectPolicyResponse { json: None });
    };
    let policy = docs.read_suggested_policy().await?;
    Ok(DirectPolicyResponse {
        json: policy.map(|p| serde_json::to_string_pretty(&p).unwrap_or_default()),
    })
}

#[derive(serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    global: Vec<crate::direct::firewall::FirewallRule>,
    #[serde(default)]
    hostname: std::collections::HashMap<String, Vec<crate::direct::firewall::FirewallRule>>,
}

pub(crate) async fn direct_policy_set(
    state: &LocalApiState,
    network: Option<&str>,
    toml_str: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let file: PolicyFile =
        crate::agent_config::parse_toml(toml_str).context("parse policy toml")?;
    let Some(docs) = state.node.docs_for(direct.network_id) else {
        anyhow::bail!("docs membership not ready");
    };
    docs.publish_firewall_policy(file.global, file.hostname)
        .await?;
    Ok("Published firewall policy to network.".into())
}

pub(crate) async fn direct_policy_clear(
    state: &LocalApiState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let Some(docs) = state.node.docs_for(direct.network_id) else {
        anyhow::bail!("docs membership not ready");
    };
    docs.clear_firewall_policy().await?;
    Ok("Cleared published firewall policy.".into())
}

pub(crate) fn direct_keep_alive(
    state: &LocalApiState,
    hostname: &str,
    enable: bool,
) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct_network(None)?;
    if enable {
        state.node.pool.add_keep_alive_host(hostname);
        if let Some(peer) = state.node.routes.lookup_hostname(hostname) {
            state.node.pool.set_peer_keep_alive(peer.endpoint, true);
        }
        Ok(format!("Keep-alive enabled for {hostname}"))
    } else {
        state.node.pool.remove_keep_alive_host(hostname);
        if let Some(peer) = state.node.routes.lookup_hostname(hostname) {
            state.node.pool.set_peer_keep_alive(peer.endpoint, false);
        }
        Ok(format!("Keep-alive disabled for {hostname}"))
    }
}

pub(crate) fn direct_override_ip(
    state: &LocalApiState,
    network: Option<&str>,
    peer: &str,
    ip: &str,
) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let ip: std::net::Ipv4Addr = ip.parse().context("invalid IPv4 address")?;
    state
        .node
        .routes
        .set_ip_override(direct.network_id, peer, ip);
    let path = state.node.paths.ip_overrides_file();
    let mut map: std::collections::BTreeMap<String, String> = if path.exists() {
        serde_json::from_slice(&std::fs::read(&path)?).unwrap_or_default()
    } else {
        Default::default()
    };
    let key = format!("{}:{}", direct.network_id, peer.to_ascii_lowercase());
    map.insert(key, ip.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&map)?)?;
    Ok(format!(
        "Override: peer '{peer}' on network '{}' → {ip}",
        direct.network_name
    ))
}
