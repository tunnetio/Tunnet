use std::sync::Arc;
use std::time::{Duration, Instant};

use super::dataplane::DataPlaneHandle;
use super::protocol::{
    DnsStatusInfo, ExitNodeRouteInfo, HostnameRouteInfo, IpcErrorCode, IpcRequest, IpcResponse,
    OnDemandStatusInfo, PeerLite, RoutesInfo, SshRecordingInfo, SshSessionInfo, StatusInfo,
    SubnetRouteInfo,
};
use super::transport::{IpcListener, IpcStream};
use crate::node::CoreNode;
use crate::send::SendManager;
use crate::serve::ServeManager;
use crate::tunnel::TunnelManager;
use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn err(code: IpcErrorCode, message: impl Into<String>) -> IpcResponse {
    IpcResponse::Error {
        code,
        message: message.into(),
    }
}

fn err_anyhow(e: impl std::fmt::Display) -> IpcResponse {
    let message = e.to_string();
    err(classify_ipc_error(&message), message)
}

fn classify_ipc_error(message: &str) -> IpcErrorCode {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found")
        || lower.contains("no peer")
        || lower.contains("no pending")
        || lower.contains("missing")
    {
        IpcErrorCode::NotFound
    } else if lower.contains("denied")
        || lower.contains("unauthorized")
        || lower.contains("only the coordinator")
        || lower.contains("permission")
        || lower.contains("reject")
    {
        IpcErrorCode::Denied
    } else if lower.contains("not enrolled")
        || lower.contains("requires managed")
        || lower.contains("requires direct")
        || lower.contains("no direct networks")
        || lower.contains("not connected to a network")
    {
        IpcErrorCode::NotEnrolled
    } else if lower.contains("data plane") {
        IpcErrorCode::DataPlaneDown
    } else if lower.contains("invalid")
        || lower.contains("must be")
        || lower.contains("parse")
        || lower.contains("usage:")
    {
        IpcErrorCode::InvalidRequest
    } else {
        IpcErrorCode::Internal
    }
}

/// Live agent state shared with the IPC server.
pub struct AgentIpcState {
    pub node: CoreNode,
    pub hostname: String,
    pub agent_version: String,
    pub started_at: Instant,
    pub dns_upstream: Vec<String>,
    pub synthetic_base: String,
    pub magic_ip: String,
    pub peer_dns_active: Arc<std::sync::atomic::AtomicBool>,
    pub peer_rtt: Arc<dashmap::DashMap<String, f64>>,
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

/// Spawn the IPC listener for this agent on the fixed path.
///
/// Binds before returning so callers can treat IPC as ready.
pub async fn spawn(state: Arc<AgentIpcState>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let (listener, path) = IpcListener::bind()
        .await
        .context("bind agent IPC listener")?;
    tracing::info!(path = %path.display(), "agent IPC ready");
    Ok(tokio::spawn(async move {
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
    }))
}

async fn handle_connection(stream: IpcStream, state: Arc<AgentIpcState>) -> anyhow::Result<()> {
    let (read, mut write) = stream.split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();

    // One request per connection for most commands. Ping streams multiple replies.
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let req: IpcRequest = serde_json::from_str(line.trim())
        .with_context(|| format!("parse IPC request: {}", line.trim()))?;

    match req {
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
        IpcRequest::Status { peers } => IpcResponse::Status(build_status(state, peers)),
        IpcRequest::DnsStatus => IpcResponse::DnsStatus(build_dns_status(state)),
        IpcRequest::RouteList => IpcResponse::Routes(build_routes(state)),
        IpcRequest::RouteAdd { cidr, description } => match cidr.parse::<ipnet::Ipv4Net>() {
            Ok(net) => match advertise_subnet_route(state, &net.to_string(), description).await {
                Ok(cidr) => IpcResponse::RouteAdded { cidr },
                Err(e) => err_anyhow(e),
            },
            Err(e) => err(IpcErrorCode::InvalidRequest, format!("invalid cidr: {e}")),
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
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::ServeStatus => IpcResponse::Serves {
            serves: state.serves.list(),
        },
        IpcRequest::ServeOff { port } => match state.serves.stop(port) {
            Ok(info) => IpcResponse::Serve(info),
            Err(e) => err_anyhow(e),
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
            Err(e) => err_anyhow(e),
        },
        IpcRequest::TunnelStatus => IpcResponse::Tunnels {
            tunnels: state.tunnels.list(),
        },
        IpcRequest::TunnelOff { port } => match stop_tunnel(state, port).await {
            Ok(info) => IpcResponse::Tunnel(info),
            Err(e) => err_anyhow(e),
        },
        IpcRequest::SshSessions { limit, status } => {
            match list_ssh_sessions(state, limit, status.as_deref()).await {
                Ok(sessions) => IpcResponse::SshSessions { sessions },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::SshRecordings { limit } => match list_ssh_recordings(state, limit).await {
            Ok(recordings) => IpcResponse::SshRecordings { recordings },
            Err(e) => err_anyhow(e),
        },
        IpcRequest::SshPlay { session_id } => match get_ssh_cast(state, &session_id).await {
            Ok((session_id, cast_text, content_sha256)) => IpcResponse::SshCast {
                session_id,
                cast_text,
                content_sha256,
            },
            Err(e) => err_anyhow(e),
        },
        IpcRequest::SshAuthPoll { challenge_token } => {
            match poll_ssh_auth(state, &challenge_token).await {
                Ok((status, proof_token)) => IpcResponse::SshAuthPoll {
                    status,
                    proof_token,
                },
                Err(e) => err_anyhow(e),
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
            Err(e) => err_anyhow(e),
        },
        IpcRequest::SendAccept { transfer_id } => {
            match state.send.accept_pending(&transfer_id).await {
                Ok(r) => IpcResponse::Transfer(transfer_info(r)),
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::SendReject {
            transfer_id,
            reason,
        } => match state.send.reject_pending(&transfer_id, reason).await {
            Ok(()) => IpcResponse::Ok {
                message: "rejected".into(),
            },
            Err(e) => err_anyhow(e),
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
                match tunnet_common::send::SendConsentMode::parse(&c) {
                    Some(m) => cfg.consent = m,
                    None => {
                        return err(
                            IpcErrorCode::InvalidRequest,
                            format!("invalid consent mode: {c}"),
                        );
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
            Err(e) => err_anyhow(e),
        },
        IpcRequest::DataPlaneDown => match state.data_plane.bring_down().await {
            Ok(()) => IpcResponse::Ok {
                message: "data plane down".into(),
            },
            Err(e) => err_anyhow(e),
        },
        IpcRequest::DirectInvite {
            network,
            reusable,
            expires,
        } => match direct_invite(state, network.as_deref(), reusable, &expires) {
            Ok(code) => IpcResponse::DirectInvite { code },
            Err(e) => err_anyhow(e),
        },
        IpcRequest::DirectRequests { network } => {
            match direct_requests(state, network.as_deref()) {
                Ok(requests) => IpcResponse::DirectPending { requests },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectAccept { network, peer_id } => {
            match direct_accept(state, network.as_deref(), &peer_id) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectDeny { network, peer_id } => {
            match direct_deny(state, network.as_deref(), &peer_id) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectKick { network, peer_id } => {
            match direct_kick(state, network.as_deref(), &peer_id).await {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallShow { network } => {
            match direct_firewall_show(state, network.as_deref()) {
                Ok(info) => info,
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallOff { network } => {
            match direct_firewall_off(state, network.as_deref()) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallAdd {
            network,
            direction,
            action,
            protocol,
            port,
            peer,
        } => match direct_firewall_add(
            state,
            network.as_deref(),
            &direction,
            &action,
            &protocol,
            port.as_deref(),
            peer,
        ) {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => err_anyhow(e),
        },
        IpcRequest::DirectFirewallRemove { network, index } => {
            match direct_firewall_remove(state, network.as_deref(), index) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallReset { network } => {
            match direct_firewall_reset(state, network.as_deref()) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallFlushConntrack { network } => {
            match direct_firewall_flush(state, network.as_deref()) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallPending { network } => {
            match direct_firewall_pending(state, network.as_deref()) {
                Ok(r) => r,
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallAcceptSuggestion { network } => {
            match direct_firewall_accept(state, network.as_deref()) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectFirewallRejectSuggestion { network } => {
            match direct_firewall_reject_suggestion(state, network.as_deref()) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectPolicyShow { network } => {
            match direct_policy_show(state, network.as_deref()).await {
                Ok(r) => r,
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectPolicySet { network, toml } => {
            match direct_policy_set(state, network.as_deref(), &toml).await {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectPolicyClear { network } => {
            match direct_policy_clear(state, network.as_deref()).await {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectOverrideIp { network, peer, ip } => {
            match direct_override_ip(state, network.as_deref(), &peer, &ip) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectKeepAlive { hostname, enable } => {
            match direct_keep_alive(state, &hostname, enable) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectConnect { contact_id } => {
            match crate::direct::connect::request_connect(state, &contact_id).await {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectConnectAllow { contact_id } => {
            match crate::direct::connect::allow_contact(state, &contact_id) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectConnectPending => match crate::direct::connect::list_pending(state) {
            Ok(r) => r,
            Err(e) => err_anyhow(e),
        },
        IpcRequest::DirectConnectAccept { contact_id } => {
            match crate::direct::connect::accept_pending(state, &contact_id).await {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectConnectDeny { contact_id } => {
            match crate::direct::connect::deny_pending(state, &contact_id) {
                Ok(msg) => IpcResponse::Ok { message: msg },
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::DirectConnectRotate => {
            match crate::direct::connect::rotate_identity(state).await {
                Ok(r) => r,
                Err(e) => err_anyhow(e),
            }
        }
        IpcRequest::Reload => match reload_config(state).await {
            Ok(msg) => IpcResponse::Ok { message: msg },
            Err(e) => err_anyhow(e),
        },
        // Handled earlier:
        IpcRequest::Ping { .. } => err(
            IpcErrorCode::Internal,
            "internal: request should have been handled specially",
        ),
    }
}

async fn reload_config(state: &AgentIpcState) -> anyhow::Result<String> {
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
        if let Some(auth) = state.node.direct_auth.as_ref() {
            let policy = (**state.node.acl.bundle.load()).clone();
            docs.apply_to_routes(&state.node.routes, &state.node.acl, auth, &policy);
        }
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
            None,
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
            None,
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
    let pool = &state.node.tunnel_pool;
    let self_id = state.node.endpoint_id_hex();
    state
        .node
        .routes
        .peers()
        .into_iter()
        .filter(|p| p.endpoint_hex != self_id)
        .map(|p| {
            let snap = pool.peer_snapshot(p.endpoint);
            let (bytes_in, bytes_out) = pool.peer_bytes(p.endpoint);
            let latency_ms = state.peer_rtt.get(&p.endpoint_hex).map(|v| *v);
            let last_seen = if snap.last_activity_secs_ago == u64::MAX {
                None
            } else {
                Some(snap.last_activity_secs_ago)
            };
            PeerLite {
                ip: p.ip.to_string(),
                hostname: p.hostname.clone(),
                endpoint_id: p.endpoint_hex.clone(),
                tags: p.tags.clone(),
                online: Some(snap.live || pool.has_live(p.endpoint)),
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

fn build_status(state: &AgentIpcState, include_peers: bool) -> StatusInfo {
    let peers = peer_lites(state);
    let peers_total = peers.len();
    let peers_online = peers.iter().filter(|p| p.online.unwrap_or(false)).count();
    let relay_status = if state.tunnels.list().is_empty() {
        "disconnected"
    } else {
        "connected"
    };
    let mode = if state.node.persisted.is_direct() {
        "direct"
    } else {
        "managed"
    };
    // Mesh datagram pool owns on-demand / keep-alive path state.
    let pool = &state.node.tunnel_pool;
    let od = pool.on_demand_stats();
    let (firewall_drops, conntrack) = state
        .node
        .primary_firewall()
        .map(|fw| {
            let s = fw.stats();
            (
                Some(s.packets_denied + s.packets_rejected),
                Some(s.conntrack_entries),
            )
        })
        .unwrap_or((None, None));
    let mut expires_at = None;
    let mut expires_in_secs = None;
    if let Some(snap) = crate::state::load_snapshot_cache(&state.node.paths)
        && let Some(at) = snap.expires_at
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&at)
    {
        let remaining = (dt.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
        expires_at = Some(at);
        expires_in_secs = Some(remaining.max(0) as u64);
    }
    StatusInfo {
        ip: state.node.self_ipv4.to_string(),
        hostname: state.hostname.clone(),
        network_name: state
            .node
            .persisted
            .primary_network_name()
            .unwrap_or("default")
            .to_string(),
        network_id: state
            .node
            .persisted
            .primary_network_id()
            .unwrap_or(uuid::Uuid::nil())
            .to_string(),
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
        mode: Some(mode.into()),
        data_plane_up: Some(state.data_plane.is_up()),
        keep_alive: Some(pool.keep_alive_global()),
        firewall_drops,
        conntrack_entries: conntrack,
        on_demand: Some(OnDemandStatusInfo {
            reconnect_attempts: od.reconnect_attempts,
            reconnect_success: od.reconnect_success,
            reconnect_fail: od.reconnect_fail,
            packets_buffered: od.packets_buffered,
            packets_dropped_timeout: od.packets_dropped_timeout,
        }),
        expires_at,
        expires_in_secs,
        control_url: state
            .node
            .persisted
            .as_managed()
            .map(|m| m.control_url.clone()),
        control: {
            #[cfg(feature = "managed")]
            {
                state.node.control_link.as_ref().map(|link| {
                    let s = link.snapshot();
                    super::protocol::ControlPlaneStatusInfo {
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
        },
    }
}

fn build_dns_status(state: &AgentIpcState) -> DnsStatusInfo {
    let tables_cached = state.node.routes.cached_entry_count();
    let magic = state.magic_ip.clone();
    DnsStatusInfo {
        suffix: state.node.routes.dns_suffix(),
        upstream: state.dns_upstream.clone(),
        peer_dns_active: state
            .peer_dns_active
            .load(std::sync::atomic::Ordering::SeqCst),
        cached_entries: tables_cached,
        synthetic_base: state.synthetic_base.clone(),
        magic_ip: magic.clone(),
        bind: format!("{magic}:53"),
    }
}

fn build_routes(state: &AgentIpcState) -> RoutesInfo {
    let self_id = state.node.endpoint_id_hex();
    let snap = crate::state::load_snapshot_cache(&state.node.paths);
    let membership = snap.as_ref().and_then(|s| {
        let nid = state.node.persisted.primary_network_id()?;
        s.memberships.iter().find(|m| m.network_id == nid)
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

    let self_hex = state.node.endpoint_id_hex();
    if resolved.endpoint_hex.eq_ignore_ascii_case(&self_hex) || resolved.ip == state.node.self_ipv4
    {
        anyhow::bail!(
            "`{peer}` is this node ({} / {}). Ping the other machine's mesh IP instead",
            state.node.self_ipv4,
            resolved.hostname
        );
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
                    &err(
                        IpcErrorCode::Internal,
                        format!("seq={seq} timeout/error: {e}"),
                    ),
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
        state.peer_rtt.insert(resolved.endpoint_hex.clone(), avg);
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

fn require_direct_coord<'a>(
    state: &'a AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<&'a crate::state::DirectState> {
    let d = state.node.persisted.require_direct_network(network)?;
    if !d.coordinator {
        anyhow::bail!("only the coordinator can perform this action");
    }
    Ok(d)
}

fn direct_invite(
    state: &AgentIpcState,
    network: Option<&str>,
    reusable: bool,
    expires: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let expires = crate::direct::admin::parse_expires(expires)?;
    let invite = crate::direct::InviteCode::new(
        direct.topic_hash.clone(),
        direct.network_secret.clone(),
        direct.network_name.clone(),
        state.node.endpoint_id_hex(),
        expires,
        reusable,
    );
    let mut used = crate::direct::admin::load_invite_ids(&state.node.paths, direct.network_id)?;
    used.insert(invite.invite_id.clone());
    crate::direct::admin::save_invite_ids(&state.node.paths, direct.network_id, &used)?;
    crate::direct::encode_invite(&invite)
}

fn direct_requests(
    state: &AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<Vec<super::protocol::DirectPendingInfo>> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let list = crate::direct::admin::load_pending(&state.node.paths, direct.network_id)?;
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

fn direct_accept(
    state: &AgentIpcState,
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
    Ok(format!(
        "Approved {}. Peer should re-run join while this agent is running.",
        pending.endpoint_id
    ))
}

fn direct_deny(
    state: &AgentIpcState,
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

async fn direct_kick(
    state: &AgentIpcState,
    network: Option<&str>,
    peer_id: &str,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    if let Some(rt) = state.node.direct.get(&direct.network_id) {
        rt.docs.kick_peer(peer_id).await?;
        rt.docs.rebuild_from_doc().await.ok();
        Ok(format!("Kicked {peer_id}"))
    } else {
        crate::direct::admin::queue_kick(&state.node.paths, direct.network_id, peer_id)?;
        Ok(format!(
            "Queued kick for {peer_id} (docs not ready; will apply shortly)"
        ))
    }
}

fn direct_firewall_show(
    state: &AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<IpcResponse> {
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
        .map(|(index, r)| super::protocol::DirectFirewallRuleInfo {
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
    Ok(IpcResponse::DirectFirewall {
        enabled: stats.as_ref().map(|s| s.enabled).unwrap_or(cfg.enabled),
        rules,
        conntrack_entries: stats.as_ref().map(|s| s.conntrack_entries).unwrap_or(0),
        packets_allowed: stats.as_ref().map(|s| s.packets_allowed).unwrap_or(0),
        packets_denied: stats.as_ref().map(|s| s.packets_denied).unwrap_or(0),
        packets_rejected: stats.as_ref().map(|s| s.packets_rejected).unwrap_or(0),
        suggested_rules: stats.as_ref().map(|s| s.suggested_rules).unwrap_or(0),
    })
}

fn reload_firewall_engine(
    state: &AgentIpcState,
    network_id: uuid::Uuid,
    cfg: &crate::direct::FirewallConfig,
) {
    if let Some(fw) = state.node.firewall_for(network_id) {
        fw.reload_local(cfg);
    }
}

fn direct_firewall_off(state: &AgentIpcState, network: Option<&str>) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let mut cfg = crate::agent_config::load_firewall_for(&state.node.paths, &direct.network_name);
    cfg.enabled = false;
    cfg.version += 1;
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok("Firewall disabled (allow all).".into())
}

fn direct_firewall_add(
    state: &AgentIpcState,
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

fn direct_firewall_remove(
    state: &AgentIpcState,
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

fn direct_firewall_reset(state: &AgentIpcState, network: Option<&str>) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let cfg = crate::direct::default_firewall();
    cfg.save(&state.node.paths, &direct.network_name)?;
    reload_firewall_engine(state, direct.network_id, &cfg);
    Ok("Firewall reset to defaults.".into())
}

fn direct_firewall_flush(state: &AgentIpcState, network: Option<&str>) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(network)?;
    if let Some(fw) = state.node.firewall_for(direct.network_id) {
        fw.flush_conntrack();
    }
    Ok("Conntrack table flushed.".into())
}

fn direct_firewall_pending(
    state: &AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<IpcResponse> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let path = state.node.paths.firewall_pending_file(direct.network_id);
    if !path.exists() {
        return Ok(IpcResponse::DirectFirewallPending { pending: None });
    }
    let s = std::fs::read_to_string(&path)?;
    Ok(IpcResponse::DirectFirewallPending { pending: Some(s) })
}

fn direct_firewall_accept(state: &AgentIpcState, network: Option<&str>) -> anyhow::Result<String> {
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

fn direct_firewall_reject_suggestion(
    state: &AgentIpcState,
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

async fn direct_policy_show(
    state: &AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<IpcResponse> {
    let direct = state.node.persisted.require_direct_network(network)?;
    let Some(docs) = state.node.docs_for(direct.network_id) else {
        return Ok(IpcResponse::DirectPolicy { json: None });
    };
    let policy = docs.read_suggested_policy().await?;
    Ok(IpcResponse::DirectPolicy {
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

async fn direct_policy_set(
    state: &AgentIpcState,
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

async fn direct_policy_clear(
    state: &AgentIpcState,
    network: Option<&str>,
) -> anyhow::Result<String> {
    let direct = require_direct_coord(state, network)?;
    let Some(docs) = state.node.docs_for(direct.network_id) else {
        anyhow::bail!("docs membership not ready");
    };
    docs.clear_firewall_policy().await?;
    Ok("Cleared published firewall policy.".into())
}

fn direct_keep_alive(
    state: &AgentIpcState,
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

fn direct_override_ip(
    state: &AgentIpcState,
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
