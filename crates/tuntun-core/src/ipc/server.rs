//! IPC server: accepts connections and dispatches [`IpcRequest`]s against agent state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use super::dataplane::DataPlaneHandle;
use super::protocol::{
    DnsStatusInfo, ExitNodeRouteInfo, HostnameRouteInfo, IpcRequest, IpcResponse, PeerLite,
    RoutesInfo, SshRecordingInfo, SshSessionInfo, StatusInfo, SubnetRouteInfo,
};
use super::transport::{IpcListener, IpcStream};
use crate::node::CoreNode;
use crate::send::SendManager;
use crate::serve::ServeManager;
use crate::tunnel::TunnelManager;

/// Live agent state shared with the IPC server.
pub struct AgentIpcState {
    pub node: CoreNode,
    pub hostname: String,
    pub agent_version: String,
    pub started_at: Instant,
    pub dns_upstream: Vec<String>,
    pub synthetic_base: String,
    pub peer_dns_active: Arc<std::sync::atomic::AtomicBool>,
    pub serves: ServeManager,
    pub tunnels: TunnelManager,
    pub send: SendManager,
    pub data_plane: DataPlaneHandle,
}

impl AgentIpcState {
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

/// Spawn the IPC listener for this agent. Returns the bound path.
pub fn spawn(network_id: Uuid, state: Arc<AgentIpcState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match IpcListener::bind(network_id).await {
            Ok((listener, path)) => {
                tracing::info!(path = %path.display(), "agent IPC ready");
                loop {
                    match listener.accept().await {
                        Ok(stream) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, state).await {
                                    tracing::debug!(?e, "IPC client session ended");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(?e, "IPC accept failed");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(?e, "failed to bind agent IPC - CLI commands will not work");
            }
        }
    })
}

async fn handle_connection(stream: IpcStream, state: Arc<AgentIpcState>) -> anyhow::Result<()> {
    let (read, mut write) = stream.split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();

    // One request per connection for most commands. OpenStream is special
    // (switches to raw splice after Ready) - handled separately.
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let req: IpcRequest = serde_json::from_str(line.trim())
        .with_context(|| format!("parse IPC request: {}", line.trim()))?;

    match req {
        IpcRequest::OpenStream { host, port } => {
            handle_open_stream(host, port, state, reader, write).await
        }
        IpcRequest::Ssh {
            target,
            user,
            local_user,
            term_type,
            width,
            height,
            env_vars,
            auth_token,
            command,
        } => {
            handle_ssh(
                target, user, local_user, term_type, width, height, env_vars, auth_token, command,
                state, reader, write,
            )
            .await
        }
        IpcRequest::Ping {
            peer,
            count,
            interval_ms,
        } => {
            handle_ping(peer, count, interval_ms, state, &mut write).await?;
            Ok(())
        }
        other => {
            let resp = dispatch(other, &state).await;
            write_response(&mut write, &resp).await
        }
    }
}

async fn write_response(
    write: &mut (impl AsyncWriteExt + Unpin),
    resp: &IpcResponse,
) -> anyhow::Result<()> {
    let mut buf = serde_json::to_vec(resp)?;
    buf.push(b'\n');
    write.write_all(&buf).await?;
    write.flush().await?;
    Ok(())
}

async fn dispatch(req: IpcRequest, state: &AgentIpcState) -> IpcResponse {
    match req {
        IpcRequest::ListPeers => {
            let peers = peer_lites(state);
            IpcResponse::Peers { peers }
        }
        IpcRequest::Status { peers } => IpcResponse::Status(build_status(state, peers)),
        IpcRequest::DnsStatus => IpcResponse::DnsStatus(build_dns_status(state)),
        IpcRequest::RouteList => IpcResponse::Routes(build_routes(state)),
        IpcRequest::RouteAdd { cidr, description } => match cidr.parse::<ipnet::Ipv4Net>() {
            Ok(net) => match advertise_subnet_route(state, &net.to_string(), description).await {
                Ok(cidr) => IpcResponse::RouteAdded { cidr },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            Err(e) => IpcResponse::Error {
                message: format!("invalid cidr: {e}"),
            },
        },
        IpcRequest::Diag => IpcResponse::Diag(build_diag(state).await),
        IpcRequest::Netcheck => IpcResponse::Netcheck(build_netcheck(state).await),
        IpcRequest::ServeStart {
            port,
            protocol,
            certificate_pem,
            private_key_pem,
            internal_hostname,
            serve_id,
        } => {
            match start_serve(
                state,
                port,
                &protocol,
                certificate_pem.as_deref(),
                private_key_pem.as_deref(),
                internal_hostname.as_deref(),
                serve_id,
            )
            .await
            {
                Ok(info) => IpcResponse::Serve(info),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::ServeStatus => IpcResponse::Serves {
            serves: state.serves.list(),
        },
        IpcRequest::ServeOff { port } => match state.serves.stop(port) {
            Ok(info) => IpcResponse::Serve(info),
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::TunnelStart {
            port,
            protocol,
            relay,
            subdomain,
        } => match start_tunnel(
            state,
            port,
            &protocol,
            relay.as_deref(),
            subdomain.as_deref(),
        )
        .await
        {
            Ok(info) => IpcResponse::Tunnel(info),
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::TunnelStatus => IpcResponse::Tunnels {
            tunnels: state.tunnels.list(),
        },
        IpcRequest::TunnelOff { port } => match stop_tunnel(state, port).await {
            Ok(info) => IpcResponse::Tunnel(info),
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::SshSessions { limit, status } => {
            match list_ssh_sessions(state, limit, status.as_deref()).await {
                Ok(sessions) => IpcResponse::SshSessions { sessions },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::SshRecordings { limit } => match list_ssh_recordings(state, limit).await {
            Ok(recordings) => IpcResponse::SshRecordings { recordings },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::SshPlay { session_id } => match get_ssh_cast(state, &session_id).await {
            Ok((session_id, cast_text, content_sha256)) => IpcResponse::SshCast {
                session_id,
                cast_text,
                content_sha256,
            },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::SshAuthPoll { challenge_token } => {
            match poll_ssh_auth(state, &challenge_token).await {
                Ok((status, proof_token)) => IpcResponse::SshAuthPoll {
                    status,
                    proof_token,
                },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::SendFile {
            path,
            target,
            message,
        } => match state
            .send
            .send_file(std::path::Path::new(&path), &target, message)
            .await
        {
            Ok(records) => IpcResponse::Transfers {
                transfers: records.into_iter().map(transfer_info).collect(),
            },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::SendAccept { transfer_id } => {
            match state.send.accept_pending(&transfer_id).await {
                Ok(r) => IpcResponse::Transfer(transfer_info(r)),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::SendReject {
            transfer_id,
            reason,
        } => match state.send.reject_pending(&transfer_id, reason).await {
            Ok(()) => IpcResponse::Ok {
                message: "rejected".into(),
            },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::SendList => {
            let mut transfers: Vec<_> = state
                .send
                .list_active()
                .into_iter()
                .chain(state.send.list_pending())
                .map(transfer_info)
                .collect();
            transfers.sort_by(|a, b| a.transfer_id.cmp(&b.transfer_id));
            transfers.dedup_by(|a, b| a.transfer_id == b.transfer_id);
            IpcResponse::Transfers { transfers }
        }
        IpcRequest::SendHistory => IpcResponse::Transfers {
            transfers: state
                .send
                .list_history()
                .into_iter()
                .map(transfer_info)
                .collect(),
        },
        IpcRequest::SendConfig => {
            let cfg = state.send.config();
            IpcResponse::SendConfig(super::protocol::SendConfigInfo {
                consent: cfg.consent.as_str().into(),
                inbox_path: cfg.inbox_path.display().to_string(),
                pin_blobs: cfg.pin_blobs,
            })
        }
        IpcRequest::SendSetConfig {
            consent,
            inbox_path,
            pin_blobs,
        } => {
            let mut cfg = state.send.config();
            if let Some(c) = consent {
                match tuntun_common::send::SendConsentMode::parse(&c) {
                    Some(m) => cfg.consent = m,
                    None => {
                        return IpcResponse::Error {
                            message: format!("invalid consent mode: {c}"),
                        };
                    }
                }
            }
            if let Some(p) = inbox_path {
                cfg.inbox_path = std::path::PathBuf::from(p);
            }
            if let Some(p) = pin_blobs {
                cfg.pin_blobs = p;
            }
            state.send.set_config(cfg.clone());
            IpcResponse::SendConfig(super::protocol::SendConfigInfo {
                consent: cfg.consent.as_str().into(),
                inbox_path: cfg.inbox_path.display().to_string(),
                pin_blobs: cfg.pin_blobs,
            })
        }
        IpcRequest::DataPlaneStatus => IpcResponse::DataPlane {
            up: state.data_plane.is_up(),
        },
        IpcRequest::DataPlaneUp => match state.data_plane.bring_up().await {
            Ok(()) => IpcResponse::Ok {
                message: "data plane up".into(),
            },
            Err(e) => IpcResponse::Error { message: e },
        },
        IpcRequest::DataPlaneDown => match state.data_plane.bring_down().await {
            Ok(()) => IpcResponse::Ok {
                message: "data plane down".into(),
            },
            Err(e) => IpcResponse::Error { message: e },
        },
        IpcRequest::DirectInvite { reusable, expires } => {
            match direct_invite(state, reusable, &expires) {
                Ok(code) => IpcResponse::DirectInvite { code },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::DirectRequests => match direct_requests(state) {
            Ok(requests) => IpcResponse::DirectPending { requests },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectAccept { peer_id } => match direct_accept(state, &peer_id) {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectDeny { peer_id } => match direct_deny(state, &peer_id) {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectKick { peer_id } => match direct_kick(state, &peer_id).await {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectFirewallShow => match direct_firewall_show(state) {
            Ok(info) => info,
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectFirewallOff => match direct_firewall_off(state) {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::DirectFirewallAdd {
            direction,
            action,
            protocol,
            port,
            peer,
        } => {
            match direct_firewall_add(state, &direction, &action, &protocol, port.as_deref(), peer)
            {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::DirectFirewallRemove { index } => match direct_firewall_remove(state, index) {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        // Handled earlier:
        IpcRequest::OpenStream { .. } | IpcRequest::Ssh { .. } | IpcRequest::Ping { .. } => {
            IpcResponse::Error {
                message: "internal: request should have been handled specially".into(),
            }
        }
    }
}

fn transfer_info(r: crate::send::TransferRecord) -> super::protocol::TransferInfo {
    use crate::send::TransferDirection;
    super::protocol::TransferInfo {
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

async fn start_serve(
    state: &AgentIpcState,
    port: u16,
    protocol: &str,
    certificate_pem: Option<&str>,
    private_key_pem: Option<&str>,
    internal_hostname: Option<&str>,
    serve_id: Option<String>,
) -> anyhow::Result<super::protocol::ServeInfo> {
    let network = state.node.persisted.network_name().to_string();
    let hostname = state.hostname.clone();
    let internal_hostname = internal_hostname
        .map(str::to_string)
        .unwrap_or_else(|| format!("{hostname}.{network}.tuntun"));
    let id = serve_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if protocol == "https" && (certificate_pem.is_none() || private_key_pem.is_none()) {
        anyhow::bail!(
            "HTTPS serve needs an internal CA leaf cert. Create the serve from the dashboard \
             (certs are pushed over WebSocket), or use --protocol tcp for a quick mesh expose."
        );
    }

    state
        .serves
        .start(
            id,
            port,
            protocol,
            &internal_hostname,
            certificate_pem,
            private_key_pem,
            crate::serve::ServeAcl::default(),
        )
        .await
}

async fn advertise_subnet_route(
    state: &AgentIpcState,
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

async fn start_tunnel(
    state: &AgentIpcState,
    port: u16,
    protocol: &str,
    relay: Option<&str>,
    subdomain: Option<&str>,
) -> anyhow::Result<super::protocol::TunnelInfo> {
    let managed = state.node.persisted.require_managed()?;
    let client = crate::control::SignedClient::new(
        managed.control_url.clone(),
        state.node.endpoint_id_hex(),
        state.node.identity.signing_key.clone(),
    )?;

    let created = client
        .create_tunnel(port, protocol, subdomain, relay)
        .await
        .context("control plane create tunnel")?;

    match state
        .tunnels
        .start(
            created.tunnel_id.clone(),
            &created.relay_endpoint_id,
            &created.subdomain,
            &created.public_hostname,
            created.local_port,
            &created.protocol,
            &created.auth_token,
            created.redirect_rules,
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

async fn stop_tunnel(
    state: &AgentIpcState,
    port: u16,
) -> anyhow::Result<super::protocol::TunnelInfo> {
    let info = state.tunnels.stop_by_port(port)?;
    let managed = state.node.persisted.require_managed()?;
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

fn peer_lites(state: &AgentIpcState) -> Vec<PeerLite> {
    state
        .node
        .routes
        .peers()
        .into_iter()
        .map(|p| PeerLite {
            ip: p.ip.to_string(),
            hostname: p.hostname.clone(),
            endpoint_id: p.endpoint_hex.clone(),
            tags: p.tags.clone(),
            online: Some(state.node.pool.has_live(p.endpoint)),
            latency_ms: None,
            os: None,
        })
        .collect()
}

fn build_status(state: &AgentIpcState, include_peers: bool) -> StatusInfo {
    let peers = peer_lites(state);
    let peers_total = peers.len();
    let peers_online = peers.iter().filter(|p| p.online.unwrap_or(false)).count();
    let relay_status = if state.tunnels.list().is_empty() {
        "disconnected"
    } else {
        "connected"
    };
    StatusInfo {
        ip: state.node.self_ipv4.to_string(),
        hostname: state.hostname.clone(),
        network_name: state.node.persisted.network_name().to_string(),
        network_id: state.node.persisted.network_id().to_string(),
        organization_id: state
            .node
            .persisted
            .as_managed()
            .map(|m| m.organization_id.clone())
            .unwrap_or_default(),
        endpoint_id: state.node.endpoint_id_hex(),
        peers_total,
        peers_online,
        relay_status: relay_status.into(),
        uptime_secs: state.uptime_secs(),
        agent_version: state.agent_version.clone(),
        snapshot_version: **state.node.version.load(),
        peers: include_peers.then_some(peers),
    }
}

fn build_dns_status(state: &AgentIpcState) -> DnsStatusInfo {
    let tables_cached = state.node.routes.cached_entry_count();
    DnsStatusInfo {
        suffix: state.node.routes.dns_suffix(),
        upstream: state.dns_upstream.clone(),
        peer_dns_active: state
            .peer_dns_active
            .load(std::sync::atomic::Ordering::SeqCst),
        cached_entries: tables_cached,
        synthetic_base: state.synthetic_base.clone(),
    }
}

fn build_routes(state: &AgentIpcState) -> RoutesInfo {
    let self_id = state.node.endpoint_id_hex();
    let snap = crate::state::load_snapshot_cache(&state.node.paths);
    let membership = snap.as_ref().and_then(|s| {
        s.memberships
            .iter()
            .find(|m| m.network_id == state.node.persisted.network_id())
    });

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

async fn build_diag(state: &AgentIpcState) -> super::protocol::DiagInfo {
    let peers = state.node.routes.peers();
    let total = peers.len();
    // Without per-connection path telemetry yet, report unknowns honestly.
    super::protocol::DiagInfo {
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

async fn build_netcheck(state: &AgentIpcState) -> super::protocol::NetcheckInfo {
    let mut checks = Vec::new();

    checks.push(super::protocol::NetcheckItem {
        name: "agent_running".into(),
        pass: true,
        detail: format!("uptime {}s", state.uptime_secs()),
    });

    checks.push(super::protocol::NetcheckItem {
        name: "has_mesh_ip".into(),
        pass: !state.node.self_ipv4.is_unspecified(),
        detail: state.node.self_ipv4.to_string(),
    });

    checks.push(super::protocol::NetcheckItem {
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

    checks.push(super::protocol::NetcheckItem {
        name: "snapshot".into(),
        pass: **state.node.version.load() > 0,
        detail: format!("version {}", **state.node.version.load()),
    });

    let ok = checks.iter().all(|c| c.pass);
    super::protocol::NetcheckInfo { ok, checks }
}

async fn handle_ping(
    peer: String,
    count: u32,
    interval_ms: u64,
    state: Arc<AgentIpcState>,
    write: &mut (impl AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    use super::protocol::{PingProbe, PingSummary};
    use crate::ping;

    let resolved = resolve_peer(&state.node, &peer).ok_or_else(|| {
        anyhow::anyhow!("no peer matches `{peer}` (try hostname, IP, or endpoint id)")
    })?;

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
                write_response(
                    write,
                    &IpcResponse::PingProbe(PingProbe {
                        seq,
                        peer: resolved.hostname.clone(),
                        peer_ip: resolved.ip.to_string(),
                        latency_ms: result.latency_ms,
                        path: result.path,
                    }),
                )
                .await?;
            }
            Err(e) => {
                write_response(
                    write,
                    &IpcResponse::Error {
                        message: format!("seq={seq} timeout/error: {e}"),
                    },
                )
                .await?;
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
        (Some(min), Some(avg), Some(max))
    };

    let loss_pct = if count == 0 {
        0.0
    } else {
        ((count - received) as f64 / count as f64) * 100.0
    };

    write_response(
        write,
        &IpcResponse::PingSummary(PingSummary {
            peer: resolved.hostname.clone(),
            peer_ip: resolved.ip.to_string(),
            transmitted: count,
            received,
            loss_pct,
            min_ms,
            avg_ms,
            max_ms,
            path,
        }),
    )
    .await
}

async fn handle_open_stream(
    host: String,
    port: u16,
    state: Arc<AgentIpcState>,
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    mut write: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
) -> anyhow::Result<()> {
    let peer = resolve_peer(&state.node, &host)
        .ok_or_else(|| anyhow::anyhow!("no peer matches host {host}"))?;
    match crate::stream::dial_stream(&state.node.pool, peer.endpoint, port, host.clone()).await {
        Ok((send, recv)) => {
            write_response(&mut write, &IpcResponse::Ready).await?;
            let local_read = reader.into_inner();
            crate::stream::splice_bidirectional(recv, send, local_read, write).await
        }
        Err(e) => {
            write_response(
                &mut write,
                &IpcResponse::Error {
                    message: e.to_string(),
                },
            )
            .await?;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ssh(
    target: String,
    user: String,
    local_user: String,
    term_type: String,
    width: u16,
    height: u16,
    env_vars: Vec<(String, String)>,
    auth_token: Option<String>,
    command: Option<String>,
    state: Arc<AgentIpcState>,
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    mut write: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
) -> anyhow::Result<()> {
    let peer = resolve_peer(&state.node, &target)
        .ok_or_else(|| anyhow::anyhow!("no peer matches target {target}"))?;
    let header = tuntun_common::ssh::SshRequestHeader {
        target_user: user,
        term_type,
        width,
        height,
        env_vars,
        auth_token,
        command,
        local_user,
    };
    match crate::ssh::dial_ssh(&state.node.pool, peer.endpoint, &header).await {
        Ok((send, recv, response)) => {
            if response.status == tuntun_common::ssh::SshStatus::ReauthRequired as u8 {
                let reauth_url = response.reauth_url.unwrap_or_default();
                let challenge_token = challenge_token_from_url(&reauth_url).unwrap_or_default();
                let message = response
                    .message
                    .unwrap_or_else(|| "Re-authentication required".into());
                write_response(
                    &mut write,
                    &IpcResponse::SshReauthRequired {
                        reauth_url,
                        challenge_token,
                        message,
                    },
                )
                .await?;
                return Ok(());
            }
            if response.status != tuntun_common::ssh::SshStatus::Ok as u8 {
                let message = response
                    .message
                    .unwrap_or_else(|| format!("ssh failed with status {}", response.status));
                write_response(&mut write, &IpcResponse::Error { message }).await?;
                return Ok(());
            }
            write_response(&mut write, &IpcResponse::Ready).await?;
            let local_read = reader.into_inner();
            crate::stream::splice_bidirectional(recv, send, local_read, write).await
        }
        Err(e) => {
            write_response(
                &mut write,
                &IpcResponse::Error {
                    message: e.to_string(),
                },
            )
            .await?;
            Err(e)
        }
    }
}

fn challenge_token_from_url(url: &str) -> Option<String> {
    let idx = url.find("token=")?;
    let rest = &url[idx + "token=".len()..];
    let end = rest.find(['&', '#']).unwrap_or(rest.len());
    let token = &rest[..end];
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn resolve_peer(node: &CoreNode, host: &str) -> Option<std::sync::Arc<crate::routing::PeerInfo>> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

async fn list_ssh_sessions(
    state: &AgentIpcState,
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

async fn list_ssh_recordings(
    state: &AgentIpcState,
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

async fn get_ssh_cast(
    state: &AgentIpcState,
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

async fn poll_ssh_auth(
    state: &AgentIpcState,
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

fn require_direct_coord(state: &AgentIpcState) -> anyhow::Result<&crate::state::DirectState> {
    let d = state.node.persisted.require_direct()?;
    if !d.coordinator {
        anyhow::bail!("only the coordinator can perform this action");
    }
    Ok(d)
}

fn direct_invite(state: &AgentIpcState, reusable: bool, expires: &str) -> anyhow::Result<String> {
    let direct = require_direct_coord(state)?;
    let expires = crate::direct::admin::parse_expires(expires)?;
    let invite = crate::direct::InviteCode::new(
        direct.topic_hash.clone(),
        direct.network_secret.clone(),
        direct.network_name.clone(),
        state.node.endpoint_id_hex(),
        expires,
        reusable,
    );
    let mut used = crate::direct::admin::load_invite_ids(&state.node.paths)?;
    used.insert(invite.invite_id.clone());
    crate::direct::admin::save_invite_ids(&state.node.paths, &used)?;
    crate::direct::encode_invite(&invite)
}

fn direct_requests(
    state: &AgentIpcState,
) -> anyhow::Result<Vec<super::protocol::DirectPendingInfo>> {
    let _ = state.node.persisted.require_direct()?;
    let list = crate::direct::admin::load_pending(&state.node.paths)?;
    Ok(list
        .into_iter()
        .map(|p| super::protocol::DirectPendingInfo {
            endpoint_id: p.endpoint_id,
            hostname: p.hostname,
            ipv4: p.ipv4.to_string(),
            collision_index: p.collision_index,
        })
        .collect())
}

fn direct_accept(state: &AgentIpcState, peer_id: &str) -> anyhow::Result<String> {
    let _ = require_direct_coord(state)?;
    let mut list = crate::direct::admin::load_pending(&state.node.paths)?;
    let idx = list
        .iter()
        .position(|p| p.endpoint_id == peer_id || p.hostname == peer_id)
        .context("pending peer not found")?;
    let pending = list.remove(idx);
    crate::direct::admin::save_pending(&state.node.paths, &list)?;
    let mut approved = crate::direct::load_approved(&state.node.paths)?;
    if !approved.iter().any(|id| id == &pending.endpoint_id) {
        approved.push(pending.endpoint_id.clone());
        crate::direct::save_approved(&state.node.paths, &approved)?;
    }
    Ok(format!(
        "Approved {}. Peer should re-run join while this agent is running.",
        pending.endpoint_id
    ))
}

fn direct_deny(state: &AgentIpcState, peer_id: &str) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct()?;
    let mut list = crate::direct::admin::load_pending(&state.node.paths)?;
    let before = list.len();
    list.retain(|p| p.endpoint_id != peer_id && p.hostname != peer_id);
    if list.len() == before {
        anyhow::bail!("pending peer not found");
    }
    crate::direct::admin::save_pending(&state.node.paths, &list)?;
    Ok(format!("Denied {peer_id}"))
}

async fn direct_kick(state: &AgentIpcState, peer_id: &str) -> anyhow::Result<String> {
    let _ = require_direct_coord(state)?;
    if let Some(docs) = &state.node.docs {
        docs.kick_peer(peer_id).await?;
        docs.rebuild_from_doc().await.ok();
        Ok(format!("Kicked {peer_id}"))
    } else {
        crate::direct::admin::queue_kick(&state.node.paths, peer_id)?;
        Ok(format!(
            "Queued kick for {peer_id} (docs not ready; will apply shortly)"
        ))
    }
}

fn direct_firewall_show(state: &AgentIpcState) -> anyhow::Result<IpcResponse> {
    let _ = state.node.persisted.require_direct()?;
    let cfg = crate::direct::FirewallConfig::load(&state.node.paths)
        .unwrap_or_else(|_| crate::direct::default_firewall());
    let rules = cfg
        .rules
        .iter()
        .enumerate()
        .map(|(index, r)| super::protocol::DirectFirewallRuleInfo {
            index,
            direction: format!("{:?}", r.direction).to_ascii_lowercase(),
            action: format!("{:?}", r.action).to_ascii_lowercase(),
            protocol: format!("{:?}", r.protocol).to_ascii_lowercase(),
            ports: if r.ports.is_empty() {
                None
            } else {
                Some(format!("{:?}", r.ports))
            },
            peer: r.peer.clone(),
        })
        .collect();
    Ok(IpcResponse::DirectFirewall {
        enabled: cfg.enabled,
        rules,
    })
}

fn direct_firewall_off(state: &AgentIpcState) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct()?;
    let mut cfg = crate::direct::FirewallConfig::load(&state.node.paths)
        .unwrap_or_else(|_| crate::direct::default_firewall());
    cfg.enabled = false;
    cfg.version += 1;
    cfg.save(&state.node.paths)?;
    Ok("Firewall disabled (allow all). Restart or re-up data plane to apply.".into())
}

fn direct_firewall_add(
    state: &AgentIpcState,
    direction: &str,
    action: &str,
    protocol: &str,
    port: Option<&str>,
    peer: Option<String>,
) -> anyhow::Result<String> {
    use crate::direct::firewall::{FirewallDirection, FirewallRule, parse_port_spec};
    use tuntun_common::policy::{Action, Protocol};

    let _ = state.node.persisted.require_direct()?;
    let mut cfg = crate::direct::FirewallConfig::load(&state.node.paths)
        .unwrap_or_else(|_| crate::direct::default_firewall());
    let direction = match direction {
        "in" | "inbound" => FirewallDirection::In,
        "out" | "outbound" => FirewallDirection::Out,
        _ => anyhow::bail!("direction must be 'in' or 'out'"),
    };
    let action = match action {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => anyhow::bail!("action must be 'allow' or 'deny'"),
    };
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "any" => Protocol::Any,
        _ => anyhow::bail!("protocol must be tcp|udp|icmp|any"),
    };
    let ports = parse_port_spec(port.unwrap_or(""))?;
    cfg.enabled = true;
    cfg.add_rule(FirewallRule {
        direction,
        action,
        protocol,
        ports,
        peer,
    });
    cfg.save(&state.node.paths)?;
    Ok("Rule added. Restart or re-up data plane to apply.".into())
}

fn direct_firewall_remove(state: &AgentIpcState, index: usize) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct()?;
    let mut cfg = crate::direct::FirewallConfig::load(&state.node.paths)?;
    cfg.remove_at(index)?;
    cfg.save(&state.node.paths)?;
    Ok(format!("Removed rule {index}"))
}
