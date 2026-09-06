//! 2-peer Direct connect via contact IDs (`tt_…`).

use std::collections::HashSet;

use anyhow::Context;
use iroh::EndpointId;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::direct::contact::{contact_id_from_endpoint, parse_contact_id};
use crate::direct::{AUTH_ALPN, AuthClientMode, derive_ipv4, run_auth_client};
use crate::identity::AgentIdentity;
use tunnet_common::local_api::DirectConnectPendingInfo;

use crate::local_api::LocalApiState;
use crate::state::PersistedState;

const CONNECT_PENDING_FILE: &str = "connect_pending.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPending {
    pub contact_id: String,
    pub endpoint_id: String,
    pub hostname: String,
    pub received_at: Timestamp,
}

fn load_allowlist(state: &LocalApiState) -> anyhow::Result<HashSet<String>> {
    Ok(crate::agent_config::load_connect_allowlist(
        &state.node.paths,
    ))
}

fn save_allowlist(state: &LocalApiState, set: &HashSet<String>) -> anyhow::Result<()> {
    crate::agent_config::save_connect_allowlist(&state.node.paths, set.iter().cloned())
}

fn load_pending(state: &LocalApiState) -> anyhow::Result<Vec<ConnectPending>> {
    let p = state.node.paths.dir.join(CONNECT_PENDING_FILE);
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&std::fs::read(&p)?)?)
}

fn save_pending(state: &LocalApiState, list: &[ConnectPending]) -> anyhow::Result<()> {
    state.node.paths.ensure()?;
    std::fs::write(
        state.node.paths.dir.join(CONNECT_PENDING_FILE),
        serde_json::to_vec_pretty(list)?,
    )?;
    Ok(())
}

fn install_peer_route(
    state: &LocalApiState,
    endpoint: EndpointId,
    hostname: &str,
    ip: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let direct = state.node.persisted.require_direct_network(None)?;
    let network_id = direct.network_id;
    let network_name = direct.network_name.clone();
    let join_index = state
        .node
        .persisted
        .direct_networks()
        .iter()
        .position(|d| d.network_id == network_id)
        .unwrap_or(0) as u64;

    let hex = format!("{endpoint}");
    // Merge into routing table via replace with existing peers + this one.
    let mut peers: Vec<tunnet_common::PeerEntry> = state
        .node
        .routes
        .peers()
        .into_iter()
        .filter(|p| p.endpoint_hex != hex && p.network_id == network_id)
        .map(|p| tunnet_common::PeerEntry {
            ip: p.ip,
            endpoint_id: p.endpoint_hex.clone(),
            hostname: p.hostname.clone(),
            tags: p.tags.clone(),
            ssh_host_key: p.ssh_host_key.clone(),
        })
        .collect();
    peers.push(tunnet_common::PeerEntry {
        ip,
        endpoint_id: hex.clone(),
        hostname: hostname.to_string(),
        tags: vec!["connect".into()],
        ssh_host_key: None,
    });
    let version = state.node.routes.version() + 1;
    let self_id = state.node.endpoint_id_hex();
    let dns = crate::agent_config::load_dns(&state.node.paths);
    state.node.routes.replace_network(
        network_id,
        join_index,
        &peers,
        &dns,
        &network_name,
        &self_id,
        version,
    );
    if let Some(auth) = &state.node.direct_auth {
        auth.insert(hex, network_id);
    }
    Ok(())
}

/// Initiate a connect dial to a remote contact id.
pub async fn request_connect(state: &LocalApiState, contact_id: &str) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(None)?;
    let peer = parse_contact_id(contact_id).context("parse contact id")?;
    let secret = direct.join_secret.clone();
    let network_id = direct.network_id;
    let hostname = direct.hostname.clone();
    let self_hex = state.node.endpoint_id_hex();

    let conn = state
        .node
        .endpoint
        .connect(peer, AUTH_ALPN)
        .await
        .context("dial contact")?;
    run_auth_client(
        &conn,
        AuthClientMode::Invite {
            network_id,
            invite_id: "connect".into(),
            join_secret_hex: secret,
        },
        &self_hex,
    )
    .await
    .context("connect auth")?;

    // Send connect request on a bi-stream.
    let (mut send, mut recv) = conn.open_bi().await.context("open bi")?;
    let req = serde_json::json!({
        "type": "connect_request",
        "contact_id": contact_id_from_endpoint(&state.node.endpoint.id()),
        "endpoint_id": self_hex,
        "hostname": hostname,
    });
    let bytes = serde_json::to_vec(&req)?;
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.finish()?;

    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 64 * 1024 {
        anyhow::bail!("oversized connect response");
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    let resp: serde_json::Value = serde_json::from_slice(&body)?;
    match resp.get("status").and_then(|v| v.as_str()) {
        Some("accepted") => {
            let peer_ip: std::net::Ipv4Addr = resp
                .get("ipv4")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| derive_ipv4(&format!("{peer}"), 0));
            let peer_host = resp
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("peer");
            install_peer_route(state, peer, peer_host, peer_ip)?;
            Ok(format!("Connected to {contact_id} ({peer_ip})"))
        }
        Some("pending") => Ok(format!(
            "Connection request sent to {contact_id}; waiting for peer approval \
             (`tunnet connect pending` on the remote side)."
        )),
        Some("denied") => anyhow::bail!("remote denied the connection"),
        other => anyhow::bail!("unexpected connect response: {other:?}"),
    }
}

pub fn allow_contact(state: &LocalApiState, contact_id: &str) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct_network(None)?;
    let _ = parse_contact_id(contact_id)?;
    let mut set = load_allowlist(state)?;
    set.insert(contact_id.to_string());
    save_allowlist(state, &set)?;
    Ok(format!("Pre-approved {contact_id}"))
}

pub fn list_pending(state: &LocalApiState) -> anyhow::Result<Vec<DirectConnectPendingInfo>> {
    let _ = state.node.persisted.require_direct_network(None)?;
    let list = load_pending(state)?;
    Ok(list
        .into_iter()
        .map(|p| DirectConnectPendingInfo {
            contact_id: p.contact_id,
            endpoint_id: p.endpoint_id,
            hostname: p.hostname,
            received_at: p.received_at.to_string(),
        })
        .collect())
}

pub async fn accept_pending(state: &LocalApiState, contact_id: &str) -> anyhow::Result<String> {
    let direct = state.node.persisted.require_direct_network(None)?.clone();
    let mut list = load_pending(state)?;
    let Some(idx) = list.iter().position(|p| p.contact_id == contact_id) else {
        anyhow::bail!("no pending connect from {contact_id}");
    };
    let pending = list.remove(idx);
    save_pending(state, &list)?;

    let peer: EndpointId = pending
        .endpoint_id
        .parse()
        .context("parse pending endpoint")?;
    let peer_ip = derive_ipv4(&pending.endpoint_id, 0);
    install_peer_route(state, peer, &pending.hostname, peer_ip)?;

    // Best-effort: dial back to notify acceptance.
    if let Ok(conn) = state.node.endpoint.connect(peer, AUTH_ALPN).await {
        let self_hex = state.node.endpoint_id_hex();
        let _ = run_auth_client(
            &conn,
            AuthClientMode::Invite {
                network_id: direct.network_id,
                invite_id: "connect-accept".into(),
                join_secret_hex: direct.join_secret.clone(),
            },
            &self_hex,
        )
        .await;
        if let Ok((mut send, _)) = conn.open_bi().await {
            let resp = serde_json::json!({
                "type": "connect_accepted",
                "status": "accepted",
                "ipv4": state.node.self_ipv4.to_string(),
                "hostname": direct.hostname,
            });
            if let Ok(bytes) = serde_json::to_vec(&resp) {
                let _ = send.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = send.write_all(&bytes).await;
                let _ = send.finish();
            }
        }
    }

    Ok(format!(
        "Accepted {contact_id}; peer route {} installed",
        peer_ip
    ))
}

pub fn deny_pending(state: &LocalApiState, contact_id: &str) -> anyhow::Result<String> {
    let _ = state.node.persisted.require_direct_network(None)?;
    let mut list = load_pending(state)?;
    let before = list.len();
    list.retain(|p| p.contact_id != contact_id);
    if list.len() == before {
        anyhow::bail!("no pending connect from {contact_id}");
    }
    save_pending(state, &list)?;
    Ok(format!("Denied {contact_id}"))
}

pub async fn rotate_identity(state: &LocalApiState) -> anyhow::Result<String> {
    let networks = state.node.persisted.direct_networks().to_vec();
    if networks.is_empty() {
        anyhow::bail!("no Direct networks joined");
    }
    let new_id = AgentIdentity::generate();
    let persisted = PersistedState::Direct { networks };
    crate::secret_store::persist_agent(
        &state.node.paths,
        &new_id,
        persisted,
        crate::secret_store::SealPolicy::from_env_and_flag(false),
    )?;
    let contact = contact_id_from_endpoint(
        &new_id
            .endpoint_id_hex()
            .parse()
            .context("parse new endpoint")?,
    );
    Ok(contact)
}

/// Handle an inbound connect request after AUTH (called from accept path).
pub async fn handle_inbound_connect(
    state_dir: &std::path::Path,
    remote_hex: &str,
    body: &[u8],
    allowlist: &HashSet<String>,
    self_hostname: &str,
    self_ipv4: std::net::Ipv4Addr,
) -> anyhow::Result<(bool, Vec<u8>)> {
    let req: serde_json::Value = serde_json::from_slice(body)?;
    if req.get("type").and_then(|v| v.as_str()) != Some("connect_request") {
        anyhow::bail!("not a connect request");
    }
    let contact_id = req
        .get("contact_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let hostname = req
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("peer")
        .to_string();
    let endpoint_id = req
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .unwrap_or(remote_hex)
        .to_string();

    if allowlist.contains(&contact_id) {
        let resp = serde_json::json!({
            "type": "connect_response",
            "status": "accepted",
            "ipv4": self_ipv4.to_string(),
            "hostname": self_hostname,
        });
        return Ok((true, serde_json::to_vec(&resp)?));
    }

    // Queue pending.
    let paths = crate::state::StatePaths {
        dir: state_dir.to_path_buf(),
    };
    let pending_path = paths.dir.join(CONNECT_PENDING_FILE);
    let mut list: Vec<ConnectPending> = if pending_path.exists() {
        serde_json::from_slice(&std::fs::read(&pending_path)?).unwrap_or_default()
    } else {
        vec![]
    };
    list.retain(|p| p.contact_id != contact_id);
    list.push(ConnectPending {
        contact_id: contact_id.clone(),
        endpoint_id,
        hostname,
        received_at: Timestamp::now(),
    });
    let _ = std::fs::write(&pending_path, serde_json::to_vec_pretty(&list)?);

    let resp = serde_json::json!({
        "type": "connect_response",
        "status": "pending",
    });
    Ok((false, serde_json::to_vec(&resp)?))
}

/// Load allowlist from disk for accept path (no full LocalApiState).
pub fn load_allowlist_from_dir(state_dir: &std::path::Path) -> HashSet<String> {
    let paths = crate::state::StatePaths {
        dir: state_dir.to_path_buf(),
    };
    crate::agent_config::load_connect_allowlist(&paths)
}

#[allow(dead_code)]
fn _persist_mode_check(p: &PersistedState) {
    let _ = p.is_direct();
}
