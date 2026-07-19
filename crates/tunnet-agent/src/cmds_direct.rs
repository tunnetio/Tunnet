//! Direct-mode CLI: create / join / invite / firewall / coordinator / upgrade.

use std::net::Ipv4Addr;

use anyhow::Context;
use clap::{Args, Subcommand};
use tunnet_core::direct::admin::{PendingJoin, push_pending};
use tunnet_core::direct::{
    AUTH_ALPN, DocsMembership, MembershipEntry, decode_invite, derive_ipv4, load_approved,
    network_id_from_topic, run_psk_handshake_client, save_approved, topic_from_name_secret,
};
use tunnet_core::ipc::protocol::{IpcRequest, IpcResponse, format_ipc_error};
use tunnet_core::{
    AgentIdentity, DirectState, PersistedState, SealPolicy, StatePaths, load_agent, persist_agent,
};

#[derive(Args, Debug)]
pub struct CreateArgs {
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    /// Auto-admit peers with a valid invite (no manual approval queue).
    #[arg(long)]
    pub open: bool,
    /// Network name (default: direct).
    #[arg(long = "name")]
    pub network_name: Option<String>,
    /// Shared passphrase for this network.
    /// If omitted, a random secret is generated and printed.
    #[arg(long)]
    pub secret: Option<String>,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal).
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    pub invite_code: String,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    /// Automatically accept coordinator firewall policy suggestions.
    #[arg(long)]
    pub auto_accept_firewall: bool,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal).
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct InviteArgs {
    /// Network name (defaults to the local Direct network).
    pub network: Option<String>,
    #[arg(long)]
    pub reusable: bool,
    #[arg(long, default_value = "24h")]
    pub expires: String,
}

#[derive(Args, Debug)]
pub struct RequestsArgs {
    pub network: Option<String>,
}

#[derive(Args, Debug)]
pub struct AcceptArgs {
    pub network: Option<String>,
    pub peer_id: String,
}

#[derive(Args, Debug)]
pub struct DenyArgs {
    pub network: Option<String>,
    pub peer_id: String,
}

#[derive(Args, Debug)]
pub struct KickArgs {
    pub network: Option<String>,
    pub peer_id: String,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Contact id to dial, or a subcommand name when using allow/pending/…
    #[arg(required = false)]
    pub contact_id: Option<String>,
    #[command(subcommand)]
    pub cmd: Option<ConnectCommand>,
}

#[derive(Subcommand, Debug)]
pub enum ConnectCommand {
    /// Pre-approve a contact id
    Allow { contact_id: String },
    /// List pending inbound connect requests
    Pending,
    /// Accept a pending connect request
    Accept { contact_id: String },
    /// Deny a pending connect request
    Deny { contact_id: String },
    /// Rotate local identity / contact id (requires agent restart)
    Rotate,
}

#[derive(Args, Debug)]
pub struct KeepAliveArgs {
    pub hostname: String,
    #[arg(long)]
    pub off: bool,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Show published coordinator policy
    Show,
    /// Publish a policy TOML file
    Set { file: String },
    /// Clear published policy
    Clear,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    #[arg(long, env = "TUNNET_ENROLL_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct LeaveArgs {
    /// Network name to leave
    #[arg(long)]
    pub network: Option<String>,
    pub name: Option<String>,
}

#[derive(Args, Debug)]
pub struct OverrideIpArgs {
    #[arg(long)]
    pub network: Option<String>,
    #[arg(long)]
    pub peer: String,
    #[arg(long)]
    pub ip: String,
}

#[derive(Subcommand, Debug)]
pub enum FirewallCommand {
    /// Show current local firewall rules and conntrack stats
    Show,
    /// Disable the local firewall (allow all)
    Off,
    /// Add a firewall rule
    Add(FirewallAddArgs),
    /// Remove a rule by index
    Remove { index: usize },
    /// Reset to default policy
    Reset,
    /// Flush the conntrack table
    FlushConntrack,
    /// Show pending coordinator policy suggestion
    Pending,
    /// Accept pending coordinator suggestion
    Accept,
    /// Reject pending coordinator suggestion
    RejectSuggestion,
}

#[derive(Args, Debug)]
pub struct FirewallAddArgs {
    #[arg(long)]
    pub network: Option<String>,
    /// `in` or `out`
    pub direction: String,
    /// `allow`, `deny`, or `reject`
    pub action: String,
    #[arg(short = 'p', long, default_value = "tcp")]
    pub protocol: String,
    #[arg(long)]
    pub port: Option<String>,
    #[arg(long)]
    pub peer: Option<String>,
}

fn paths(state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(state_dir)
}

fn hostname_arg(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-node".into())
}

async fn write_post_auth_response(
    send: &mut iroh::endpoint::SendStream,
    resp: &[u8],
) -> anyhow::Result<()> {
    let len = (resp.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(resp).await?;
    send.finish()?;
    // Ensure the peer can finish reading before this connection is torn down.
    let _ = send.stopped().await;
    Ok(())
}

fn post_auth_deny(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "accepted": false,
        "reason": reason,
        "status": "denied",
    }))
    .unwrap_or_else(|_| b"{\"accepted\":false,\"reason\":\"internal\"}".to_vec())
}

pub async fn try_handle_post_auth(
    conn: &iroh::endpoint::Connection,
    state_dir: &std::path::Path,
    docs: Option<&DocsMembership>,
    self_endpoint_id: &str,
    network_id: uuid::Uuid,
) -> anyhow::Result<()> {
    let paths = StatePaths {
        dir: state_dir.to_path_buf(),
    };
    let policy = SealPolicy::from_env_and_flag(false);

    // Client opens a bi after PSK; wait briefly.
    let (mut send, mut recv) =
        match tokio::time::timeout(std::time::Duration::from_secs(5), conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => anyhow::bail!("accept post-auth stream: {e}"),
            Err(_) => anyhow::bail!("timed out waiting for post-auth stream from peer"),
        };

    let Ok((_identity, persisted, _)) = load_agent(&paths, policy) else {
        write_post_auth_response(&mut send, &post_auth_deny("coordinator_state_unavailable"))
            .await?;
        return Ok(());
    };
    let Some(direct) = persisted.direct_by_id(network_id) else {
        write_post_auth_response(&mut send, &post_auth_deny("unknown_network")).await?;
        return Ok(());
    };

    let mut len_buf = [0u8; 4];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        write_post_auth_response(&mut send, &post_auth_deny("bad_request"))
            .await
            .ok();
        anyhow::bail!("read post-auth length: {e}");
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 64 * 1024 {
        write_post_auth_response(&mut send, &post_auth_deny("request_too_large")).await?;
        anyhow::bail!("post-auth request too large");
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;

    let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let msg_type = req.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let resp = match msg_type {
        "join_request" if direct.coordinator => {
            handle_join_request_bytes(&paths, direct, docs, &body).await?
        }
        "join_request" => post_auth_deny("not_coordinator"),
        "connect_request" => {
            let allowlist = tunnet_core::direct::connect::load_allowlist_from_dir(state_dir);
            let (_accepted, resp_bytes) = tunnet_core::direct::connect::handle_inbound_connect(
                state_dir,
                &format!("{}", conn.remote_id()),
                &body,
                &allowlist,
                &direct.hostname,
                direct.assigned_ipv4,
            )
            .await?;
            let _ = self_endpoint_id;
            resp_bytes
        }
        "connect_accepted" => {
            // Peer notified us they accepted; install route if present.
            if let (Some(ipv4), Some(hostname)) = (
                req.get("ipv4").and_then(|v| v.as_str()),
                req.get("hostname").and_then(|v| v.as_str()),
            ) {
                tracing::info!(%hostname, %ipv4, "remote accepted connect");
            }
            return Ok(());
        }
        _ => post_auth_deny("unknown_request"),
    };

    write_post_auth_response(&mut send, &resp).await?;
    Ok(())
}

pub async fn run_create(args: CreateArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    crate::service::ensure_service_state_aligned(state_dir, &paths)?;
    paths.ensure()?;
    let existing = PersistedState::try_load(&paths)?;
    if let Some(PersistedState::Managed(m)) = &existing {
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        );
    }

    let hostname = hostname_arg(args.hostname);
    let network_name = args
        .network_name
        .unwrap_or_else(|| "direct".into())
        .to_ascii_lowercase();
    if !tunnet_common::validate_network_name(&network_name) {
        anyhow::bail!("invalid network name (3-32 lowercase alphanumeric/hyphen)");
    }

    let network_secret = match args.secret {
        Some(s) => {
            if s.len() < 8 {
                anyhow::bail!("--secret must be at least 8 characters");
            }
            s
        }
        None => {
            let secret_bytes: [u8; 32] = rand::random();
            let s = hex::encode(secret_bytes);
            println!("Generated network secret (save it): {s}");
            s
        }
    };

    let topic_hash = topic_from_name_secret(&network_name, &network_secret);
    let network_id = network_id_from_topic(&topic_hash);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);

    let (identity, mut networks) = match existing {
        Some(PersistedState::Direct { networks }) => {
            let (identity, _, _) = load_agent(&paths, policy)?;
            if networks
                .iter()
                .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
            {
                anyhow::bail!("already joined Direct network '{network_name}'");
            }
            if networks.iter().any(|d| d.network_id == network_id) {
                anyhow::bail!("network id collision with an existing Direct network");
            }
            (identity, networks)
        }
        _ => (AgentIdentity::generate(), Vec::new()),
    };
    let my_id = identity.endpoint_id_hex();
    let assigned_ipv4 = derive_ipv4(&my_id, 0);

    networks.push(DirectState {
        network_name: network_name.clone(),
        network_secret: network_secret.clone(),
        topic_hash,
        network_id,
        coordinator: true,
        open: args.open,
        assigned_ipv4,
        collision_index: 0,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(my_id.clone()),
        doc_ticket: None,
        namespace_id: None,
        auto_accept_firewall: false,
        created_at: chrono::Utc::now(),
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, args.open, false);
        cfg.save(&paths)?;
    }

    println!(
        "Created Direct network '{}'. endpoint_id={} ip={} (secrets: {})",
        network_name,
        my_id,
        assigned_ipv4,
        tier.as_str()
    );
    println!("State directory: {}", paths.dir.display());
    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = crate::cmds::wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
        println!("Once the agent is up: `tunnet invite` and share the code.");
    } else {
        println!("Agent is up. Next: `tunnet invite` and share the code.");
    }
    Ok(())
}

pub async fn run_invite(args: InviteArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectInvite {
            network: args.network.clone(),
            reusable: args.reusable,
            expires: args.expires,
        })
        .await?
    {
        IpcResponse::DirectInvite { code } => {
            println!("{code}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_join(args: JoinArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    crate::service::ensure_service_state_aligned(state_dir, &paths)?;
    paths.ensure()?;

    let invite = decode_invite(&args.invite_code)?;
    let hostname = hostname_arg(args.hostname);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let network_id = network_id_from_topic(&invite.topic);
    let network_name = invite.network_name.clone();

    let (identity, existing_networks) = match PersistedState::try_load(&paths)? {
        Some(PersistedState::Managed(m)) => anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        ),
        Some(PersistedState::Direct { networks }) => {
            if networks
                .iter()
                .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
            {
                anyhow::bail!("already joined Direct network '{network_name}'");
            }
            if networks.iter().any(|d| d.network_id == network_id) {
                anyhow::bail!("already joined this Direct network id");
            }
            let (id, _, _) = load_agent(&paths, policy)?;
            (id, networks)
        }
        None => (AgentIdentity::generate(), Vec::new()),
    };

    let my_id = identity.endpoint_id_hex();
    let mut collision_index = 0u8;
    let mut assigned_ipv4 = derive_ipv4(&my_id, collision_index);

    // Dial coordinator and prove PSK.
    let secret = iroh::SecretKey::from_bytes(&identity.secret_bytes);
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret)
        .alpns(vec![AUTH_ALPN.to_vec()])
        .bind()
        .await
        .context("bind join endpoint")?;

    let join_result = async {
        match tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("join endpoint online"),
            Err(_) => tracing::warn!("relay not ready yet; attempting join connect anyway"),
        }

        let coord: iroh::EndpointId = invite
            .coordinator
            .parse()
            .context("invalid coordinator endpoint id in invite")?;
        let conn = endpoint
            .connect(coord, AUTH_ALPN)
            .await
            .context("connect to coordinator")?;
        run_psk_handshake_client(&conn, network_id, &invite.secret, &my_id)
            .await
            .context("PSK auth with coordinator")?;

        // Send join request over the same connection.
        let (mut send, mut recv) = conn.open_bi().await.context("open join stream")?;
        let req = serde_json::json!({
            "type": "join_request",
            "endpoint_id": my_id,
            "hostname": hostname,
            "ipv4": assigned_ipv4.to_string(),
            "collision_index": collision_index,
            "invite_id": invite.invite_id,
            "reusable": invite.reusable,
        });
        let bytes = serde_json::to_vec(&req)?;
        let len = (bytes.len() as u32).to_be_bytes();
        send.write_all(&len).await.context("write join request")?;
        send.write_all(&bytes).await.context("write join request")?;
        send.finish().context("finish join request")?;

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .context("read join response (is the coordinator agent running `tunnet run`?)")?;
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        recv.read_exact(&mut body)
            .await
            .context("read join response body")?;
        let resp: serde_json::Value = serde_json::from_slice(&body)?;
        if resp.get("accepted").and_then(|v| v.as_bool()) != Some(true) {
            let reason = resp
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("denied");
            anyhow::bail!("join denied: {reason}");
        }
        if let Some(ip) = resp.get("ipv4").and_then(|v| v.as_str()) {
            assigned_ipv4 = ip.parse().unwrap_or(assigned_ipv4);
        }
        if let Some(ci) = resp.get("collision_index").and_then(|v| v.as_u64()) {
            collision_index = ci as u8;
        }
        let doc_ticket = resp
            .get("doc_ticket")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .context(
                "coordinator did not return a doc_ticket (is `tunnet run` up on the coordinator?)",
            )?;
        Ok::<_, anyhow::Error>(doc_ticket)
    }
    .await;

    endpoint.close().await;
    let doc_ticket = join_result?;

    let mut networks = existing_networks;
    networks.push(DirectState {
        network_name: network_name.clone(),
        network_secret: invite.secret,
        topic_hash: invite.topic,
        network_id,
        coordinator: false,
        open: false,
        assigned_ipv4,
        collision_index,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(invite.coordinator),
        doc_ticket: Some(doc_ticket),
        namespace_id: None,
        auto_accept_firewall: args.auto_accept_firewall,
        created_at: chrono::Utc::now(),
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, false, false);
        cfg.save(&paths)?;
    }

    println!(
        "Joined Direct network '{}'. endpoint_id={} ip={} (secrets: {})",
        network_name,
        my_id,
        assigned_ipv4,
        tier.as_str()
    );
    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = crate::cmds::wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
    } else {
        println!("Agent is up. Bring the data plane online with `tunnet up` if needed.");
    }
    Ok(())
}

/// Coordinator-side: handle join over AUTH connection (called from accept loop).
/// Requires a live [`DocsMembership`] to issue a write ticket.
pub async fn handle_join_request_bytes(
    paths: &StatePaths,
    direct: &DirectState,
    docs: Option<&DocsMembership>,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let req: serde_json::Value = serde_json::from_slice(body)?;
    let endpoint_id = req
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .context("endpoint_id")?
        .to_string();
    let hostname = req
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("peer")
        .to_string();
    let ipv4: Ipv4Addr = req
        .get("ipv4")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0.0")
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let collision_index = req
        .get("collision_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let invite_id = req
        .get("invite_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let reusable = req
        .get("reusable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let approved = load_approved(paths).unwrap_or_default();
    let pre_approved = approved.iter().any(|id| id == &endpoint_id);

    let issued =
        tunnet_core::direct::admin::load_invite_ids(paths, direct.network_id).unwrap_or_default();
    let invite_ok = invite_id.as_ref().is_some_and(|id| issued.contains(id));

    if !direct.open && !pre_approved && !invite_ok {
        if invite_id.is_some() {
            return Ok(serde_json::to_vec(&serde_json::json!({
                "accepted": false,
                "reason": "invalid_or_used_invite",
            }))?);
        }
        push_pending(
            paths,
            direct.network_id,
            &PendingJoin {
                endpoint_id: endpoint_id.clone(),
                hostname: hostname.clone(),
                ipv4,
                collision_index,
            },
        )?;
        return Ok(serde_json::to_vec(&serde_json::json!({
            "accepted": false,
            "reason": "pending_approval",
        }))?);
    }

    let Some(docs) = docs else {
        return Ok(serde_json::to_vec(&serde_json::json!({
            "accepted": false,
            "reason": "coordinator_docs_not_ready",
        }))?);
    };

    let members = docs.snapshot_members();
    let mut ci = collision_index;
    let mut ip = if ipv4.is_unspecified() {
        derive_ipv4(&endpoint_id, ci)
    } else {
        ipv4
    };
    while members
        .iter()
        .any(|m| m.ipv4 == ip && m.endpoint_id != endpoint_id)
    {
        ci = ci.saturating_add(1);
        ip = derive_ipv4(&endpoint_id, ci);
    }

    // Ensure joiner is in auth cache via a status write from coordinator (optional).
    // Joiner will write its own peer keys after import; we only issue the ticket.
    let ticket = docs.share_write_ticket().await?;

    // Drop from approved list once ticket issued.
    if pre_approved {
        let mut ids = approved;
        ids.retain(|id| id != &endpoint_id);
        let _ = save_approved(paths, &ids);
    }

    // Consume one-time invites after a successful ticket issue.
    if !reusable && let Some(id) = invite_id.as_ref() {
        let mut ids = issued;
        ids.remove(id);
        let _ = tunnet_core::direct::admin::save_invite_ids(paths, direct.network_id, &ids);
    }

    let _ = (hostname,); // joiner publishes hostname itself via docs
    Ok(serde_json::to_vec(&serde_json::json!({
        "accepted": true,
        "ipv4": ip.to_string(),
        "collision_index": ci,
        "doc_ticket": ticket,
    }))?)
}

pub async fn run_requests(args: RequestsArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectRequests {
            network: args.network.clone(),
        })
        .await?
    {
        IpcResponse::DirectPending { requests } => {
            if requests.is_empty() {
                println!("No pending join requests.");
                return Ok(());
            }
            for (i, p) in requests.iter().enumerate() {
                println!("{i}: {} {} {}", p.endpoint_id, p.hostname, p.ipv4);
            }
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_accept(args: AcceptArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectAccept {
            network: args.network,
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_deny(args: DenyArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectDeny {
            network: args.network,
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_kick(args: KickArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectKick {
            network: args.network,
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_connect(args: ConnectArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    let req = if let Some(cmd) = args.cmd {
        match cmd {
            ConnectCommand::Allow { contact_id } => IpcRequest::DirectConnectAllow { contact_id },
            ConnectCommand::Pending => IpcRequest::DirectConnectPending,
            ConnectCommand::Accept { contact_id } => IpcRequest::DirectConnectAccept { contact_id },
            ConnectCommand::Deny { contact_id } => IpcRequest::DirectConnectDeny { contact_id },
            ConnectCommand::Rotate => IpcRequest::DirectConnectRotate,
        }
    } else if let Some(contact_id) = args.contact_id {
        IpcRequest::DirectConnect { contact_id }
    } else {
        anyhow::bail!("usage: tunnet connect <tt_…> | allow|pending|accept|deny|rotate");
    };
    match ipc.request(req).await? {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::DirectConnectPending { requests } => {
            if requests.is_empty() {
                println!("(no pending connect requests)");
            }
            for r in requests {
                println!(
                    "{}  {}  {}  {}",
                    r.contact_id, r.hostname, r.endpoint_id, r.received_at
                );
            }
            Ok(())
        }
        IpcResponse::DirectContact { contact_id } => {
            println!("New contact id: {contact_id}");
            println!("Restart the agent (`tunnet run`) for the new identity to take effect.");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_firewall(cmd: FirewallCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    let req = match cmd {
        FirewallCommand::Show => IpcRequest::DirectFirewallShow { network: None },
        FirewallCommand::Off => IpcRequest::DirectFirewallOff { network: None },
        FirewallCommand::Add(a) => IpcRequest::DirectFirewallAdd {
            network: a.network,
            direction: a.direction,
            action: a.action,
            protocol: a.protocol,
            port: a.port,
            peer: a.peer,
        },
        FirewallCommand::Remove { index } => IpcRequest::DirectFirewallRemove {
            network: None,
            index,
        },
        FirewallCommand::Reset => IpcRequest::DirectFirewallReset { network: None },
        FirewallCommand::FlushConntrack => {
            IpcRequest::DirectFirewallFlushConntrack { network: None }
        }
        FirewallCommand::Pending => IpcRequest::DirectFirewallPending { network: None },
        FirewallCommand::Accept => IpcRequest::DirectFirewallAcceptSuggestion { network: None },
        FirewallCommand::RejectSuggestion => {
            IpcRequest::DirectFirewallRejectSuggestion { network: None }
        }
    };
    match ipc.request(req).await? {
        IpcResponse::DirectFirewall {
            enabled,
            rules,
            conntrack_entries,
            packets_allowed,
            packets_denied,
            packets_rejected,
            suggested_rules,
        } => {
            println!("enabled={enabled}");
            println!(
                "conntrack={conntrack_entries} allowed={packets_allowed} denied={packets_denied} rejected={packets_rejected} suggested={suggested_rules}"
            );
            for r in rules {
                println!(
                    "{}: {} {} {} ports={:?} peer={:?}",
                    r.index, r.direction, r.action, r.protocol, r.ports, r.peer
                );
            }
            Ok(())
        }
        IpcResponse::DirectFirewallPending { pending } => {
            match pending {
                Some(s) => println!("{s}"),
                None => println!("(no pending suggestion)"),
            }
            Ok(())
        }
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_policy(cmd: PolicyCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    let req = match cmd {
        PolicyCommand::Show => IpcRequest::DirectPolicyShow { network: None },
        PolicyCommand::Set { file } => {
            let toml = std::fs::read_to_string(&file)
                .with_context(|| format!("read policy file {file}"))?;
            IpcRequest::DirectPolicySet {
                network: None,
                toml,
            }
        }
        PolicyCommand::Clear => IpcRequest::DirectPolicyClear { network: None },
    };
    match ipc.request(req).await? {
        IpcResponse::DirectPolicy { json } => {
            match json {
                Some(s) => println!("{s}"),
                None => println!("(no published policy)"),
            }
            Ok(())
        }
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_keep_alive(args: KeepAliveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectKeepAlive {
            hostname: args.hostname,
            enable: !args.off,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(&paths, policy)?;
    let direct = persisted.require_direct_network(None)?.clone();
    if !direct.coordinator {
        anyhow::bail!("only the coordinator should run upgrade-to-managed first");
    }

    // Prefer live docs cache if present from a previous run; else empty members list.
    let members_path = paths.dir.join("direct_members_cache.json");
    let members: Vec<MembershipEntry> = if members_path.exists() {
        serde_json::from_slice(&std::fs::read(&members_path)?).unwrap_or_default()
    } else {
        vec![]
    };

    let token = args
        .token
        .context("provide --token <enrollment token> from the dashboard")?;

    let import = serde_json::json!({
        "direct_network_name": direct.network_name,
        "topic_hash": direct.topic_hash,
        "namespace_id": direct.namespace_id,
        "members": members,
        "coordinator_endpoint_id": identity.endpoint_id_hex(),
    });

    let client = tunnet_core::UnauthedClient::new(args.control_url.clone())?;
    let meta =
        crate::system_info::collect_system_metadata(&direct.hostname, env!("CARGO_PKG_VERSION"));
    let resp = client
        .enroll(tunnet_common::EnrollRequest {
            enrollment_token: Some(token.clone()),
            organization_slug: None,
            network_id: None,
            network_name: Some(direct.network_name.clone()),
            endpoint_id: identity.endpoint_id_hex(),
            hostname: direct.hostname.clone(),
            os: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: Some(serde_json::json!({
                "direct_upgrade": import,
                "system": meta,
            })),
            labels: None,
            expires_in: None,
        })
        .await
        .context("enroll into Managed during upgrade")?;

    if resp.status == "pending" {
        anyhow::bail!("upgrade enroll is pending approval; approve in the dashboard then re-run");
    }

    let managed = PersistedState::Managed(tunnet_core::ManagedState {
        control_url: args.control_url.clone(),
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: chrono::Utc::now(),
    });
    persist_agent(&paths, &identity, managed, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

    let notice = serde_json::json!({
        "type": "upgrade_to_managed",
        "control_url": args.control_url,
        "enrollment_token": token,
        "network_id": resp.network_id,
        "network_name": resp.network_name,
    });
    std::fs::write(
        paths.dir.join("upgrade_notice.json"),
        serde_json::to_vec_pretty(&notice)?,
    )?;

    println!(
        "Upgraded to Managed network '{}'. Restart with `tunnet run`. \
         Peers should pick up the upgrade notice or re-enroll with the same token.",
        resp.network_name
    );
    Ok(())
}

pub async fn run_leave(args: LeaveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, mut persisted, _) = load_agent(&paths, policy)?;
    let name = args.network.or(args.name);
    let direct = persisted.require_direct_network(name.as_deref())?.clone();
    let nid = direct.network_id;
    let nname = direct.network_name.clone();
    let Some(networks) = persisted.direct_networks_mut() else {
        anyhow::bail!("not in Direct mode");
    };
    networks.retain(|d| d.network_id != nid);
    if networks.is_empty() {
        // wipe public state + docs; keep identity only via full reset suggestion
        anyhow::bail!("leaving the last Direct network; use `tunnet reset --yes` instead");
    }
    let docs = paths.docs_dir(nid);
    if docs.exists() {
        let _ = std::fs::remove_dir_all(&docs);
    }
    persist_agent(&paths, &identity, persisted, policy)?;
    println!("Left Direct network '{nname}'. Restart the agent to apply.");
    crate::service::reload_after_config(state_dir)?;
    Ok(())
}

pub async fn run_override_ip(args: OverrideIpArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectOverrideIp {
            network: args.network,
            peer: args.peer,
            ip: args.ip,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}
