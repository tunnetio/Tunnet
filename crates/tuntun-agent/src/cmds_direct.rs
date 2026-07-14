//! Direct-mode CLI: create / join / invite / firewall / coordinator / upgrade.

use std::net::Ipv4Addr;

use anyhow::Context;
use clap::{Args, Subcommand};
use tuntun_core::direct::admin::{PendingJoin, push_pending};
use tuntun_core::direct::firewall::default_firewall;
use tuntun_core::direct::{
    AUTH_ALPN, DocsMembership, MembershipEntry, decode_invite, derive_ipv4, load_approved,
    network_id_from_topic, run_psk_handshake_client, save_approved, topic_from_name_secret,
};
use tuntun_core::ipc::protocol::{IpcRequest, IpcResponse};
use tuntun_core::{AgentIdentity, DirectState, PersistedState, StatePaths};

#[derive(Args, Debug)]
pub struct CreateArgs {
    #[arg(long, env = "TUNTUN_HOSTNAME")]
    pub hostname: Option<String>,
    /// Auto-admit peers with a valid invite (no manual approval queue).
    #[arg(long)]
    pub open: bool,
    #[arg(long)]
    pub network_name: Option<String>,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    pub invite_code: String,
    #[arg(long, env = "TUNTUN_HOSTNAME")]
    pub hostname: Option<String>,
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
    pub contact_id: String,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(long, env = "TUNTUN_CONTROL_URL")]
    pub control_url: String,
    #[arg(long, env = "TUNTUN_ENROLL_TOKEN")]
    pub token: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum FirewallCommand {
    /// Show current local firewall rules
    Show,
    /// Disable the local firewall (allow all)
    Off,
    /// Add a firewall rule
    Add(FirewallAddArgs),
    /// Remove a rule by index
    Remove { index: usize },
}

#[derive(Args, Debug)]
pub struct FirewallAddArgs {
    /// `in` or `out`
    pub direction: String,
    /// `allow` or `deny`
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
        .unwrap_or_else(|| "tuntun-node".into())
}

pub async fn try_handle_join_on_auth_conn(
    conn: &iroh::endpoint::Connection,
    state_dir: &std::path::Path,
    docs: Option<&DocsMembership>,
) -> anyhow::Result<()> {
    let paths = StatePaths {
        dir: state_dir.to_path_buf(),
    };
    let Ok(persisted) = PersistedState::load(&paths) else {
        return Ok(());
    };
    let Ok(direct) = persisted.require_direct() else {
        return Ok(());
    };
    if !direct.coordinator {
        return Ok(());
    }

    // Join client opens a second bi after PSK; wait briefly.
    let Ok(Ok((mut send, mut recv))) =
        tokio::time::timeout(std::time::Duration::from_secs(5), conn.accept_bi()).await
    else {
        return Ok(());
    };
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 64 * 1024 {
        anyhow::bail!("join request too large");
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    let resp = handle_join_request_bytes(&paths, direct, docs, &body).await?;
    let len = (resp.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&resp).await?;
    Ok(())
}

pub async fn run_create(args: CreateArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;
    if let Ok(existing) = PersistedState::load(&paths) {
        anyhow::bail!(
            "already configured in {:?} mode (network '{}'); run `tuntun reset --yes` first",
            existing.mode(),
            existing.network_name()
        );
    }

    let hostname = hostname_arg(args.hostname);
    let network_name = args
        .network_name
        .unwrap_or_else(|| "direct".into())
        .to_ascii_lowercase();
    if !tuntun_common::validate_network_name(&network_name) {
        anyhow::bail!("invalid network name (3-32 lowercase alphanumeric/hyphen)");
    }

    let identity = AgentIdentity::generate();
    let secret_bytes: [u8; 32] = rand::random();
    let network_secret = hex::encode(secret_bytes);
    let topic_hash = topic_from_name_secret(&network_name, &network_secret);
    let network_id = network_id_from_topic(&topic_hash);
    let my_id = identity.endpoint_id_hex();
    let assigned_ipv4 = derive_ipv4(&my_id, 0);

    default_firewall().save(&paths)?;

    let persisted = PersistedState::Direct(DirectState {
        network_name: network_name.clone(),
        network_secret,
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
        created_at: chrono::Utc::now(),
    });
    identity.save_to(&paths.key_file())?;
    persisted.save(&paths)?;

    println!(
        "Created Direct network '{}'. endpoint_id={} ip={}",
        network_name, my_id, assigned_ipv4
    );
    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = crate::cmds::wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
        println!("Once the agent is up: `tuntun invite` and share the code.");
    } else {
        println!("Agent is up. Next: `tuntun invite` and share the code.");
    }
    Ok(())
}

pub async fn run_invite(args: InviteArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectInvite {
            reusable: args.reusable,
            expires: args.expires,
        })
        .await?
    {
        IpcResponse::DirectInvite { code } => {
            println!("{code}");
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_join(args: JoinArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;
    if let Ok(existing) = PersistedState::load(&paths) {
        anyhow::bail!(
            "already configured in {:?} mode; run `tuntun reset --yes` first",
            existing.mode()
        );
    }

    let invite = decode_invite(&args.invite_code)?;
    let hostname = hostname_arg(args.hostname);
    let identity = AgentIdentity::generate();
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

    let coord: iroh::EndpointId = invite
        .coordinator
        .parse()
        .context("invalid coordinator endpoint id in invite")?;
    let conn = endpoint
        .connect(coord, AUTH_ALPN)
        .await
        .context("connect to coordinator")?;
    run_psk_handshake_client(&conn, &invite.secret, &my_id)
        .await
        .context("PSK auth with coordinator")?;

    // Send join request over the same connection.
    let (mut send, mut recv) = conn.open_bi().await?;
    let req = serde_json::json!({
        "type": "join_request",
        "endpoint_id": my_id,
        "hostname": hostname,
        "ipv4": assigned_ipv4.to_string(),
        "collision_index": collision_index,
        "invite_id": invite.invite_id,
    });
    let bytes = serde_json::to_vec(&req)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&bytes).await?;

    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
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
            "coordinator did not return a doc_ticket (is `tuntun run` up on the coordinator?)",
        )?;

    endpoint.close().await;

    let network_id = network_id_from_topic(&invite.topic);
    default_firewall().save(&paths)?;
    let persisted = PersistedState::Direct(DirectState {
        network_name: invite.network_name.clone(),
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
        created_at: chrono::Utc::now(),
    });
    identity.save_to(&paths.key_file())?;
    persisted.save(&paths)?;

    println!(
        "Joined Direct network '{}'. endpoint_id={} ip={}",
        invite.network_name, my_id, assigned_ipv4
    );
    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = crate::cmds::wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
    } else {
        println!("Agent is up. Bring the data plane online with `tuntun up` if needed.");
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

    let approved = load_approved(paths).unwrap_or_default();
    let pre_approved = approved.iter().any(|id| id == &endpoint_id);

    if !direct.open && !pre_approved && invite_id.is_none() {
        push_pending(
            paths,
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

    let _ = (hostname,); // joiner publishes hostname itself via docs
    Ok(serde_json::to_vec(&serde_json::json!({
        "accepted": true,
        "ipv4": ip.to_string(),
        "collision_index": ci,
        "doc_ticket": ticket,
    }))?)
}

pub async fn run_requests(_args: RequestsArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc.request(IpcRequest::DirectRequests).await? {
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
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_accept(args: AcceptArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectAccept {
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_deny(args: DenyArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectDeny {
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_kick(args: KickArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    match ipc
        .request(IpcRequest::DirectKick {
            peer_id: args.peer_id,
        })
        .await?
    {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_connect(args: ConnectArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    // Ephemeral 2-peer: store a minimal Direct state if none exists.
    if PersistedState::load(&paths).is_err() {
        anyhow::bail!(
            "connect requires an existing Direct or Managed agent; create a network first \
             (`tuntun create`) or enroll, then use mesh dial. Ephemeral contact-id mesh \
             will dial {} after `tuntun run`.",
            args.contact_id
        );
    }
    println!(
        "Contact {} - ensure both peers are running (`tuntun run`). \
         Use `tuntun ping {}` once membership includes the peer.",
        args.contact_id, args.contact_id
    );
    Ok(())
}

pub async fn run_firewall(cmd: FirewallCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = crate::cmds::ipc_or_err(state_dir).await?;
    let req = match cmd {
        FirewallCommand::Show => IpcRequest::DirectFirewallShow,
        FirewallCommand::Off => IpcRequest::DirectFirewallOff,
        FirewallCommand::Add(a) => IpcRequest::DirectFirewallAdd {
            direction: a.direction,
            action: a.action,
            protocol: a.protocol,
            port: a.port,
            peer: a.peer,
        },
        FirewallCommand::Remove { index } => IpcRequest::DirectFirewallRemove { index },
    };
    match ipc.request(req).await? {
        IpcResponse::DirectFirewall { enabled, rules } => {
            println!("enabled={enabled}");
            for r in rules {
                println!(
                    "{}: {} {} {} ports={:?} peer={:?}",
                    r.index, r.direction, r.action, r.protocol, r.ports, r.peer
                );
            }
            Ok(())
        }
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let persisted = PersistedState::load(&paths)?;
    let direct = persisted.require_direct()?.clone();
    if !direct.coordinator {
        anyhow::bail!("only the coordinator should run upgrade-to-managed first");
    }
    let identity = AgentIdentity::load_from(&paths.key_file())?;

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

    let client = tuntun_core::UnauthedClient::new(args.control_url.clone())?;
    let meta =
        crate::system_info::collect_system_metadata(&direct.hostname, env!("CARGO_PKG_VERSION"));
    let resp = client
        .enroll(tuntun_common::EnrollRequest {
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
        })
        .await
        .context("enroll into Managed during upgrade")?;

    if resp.status == "pending" {
        anyhow::bail!("upgrade enroll is pending approval; approve in the dashboard then re-run");
    }

    let managed = PersistedState::Managed(tuntun_core::ManagedState {
        control_url: args.control_url.clone(),
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: chrono::Utc::now(),
    });
    managed.save(&paths)?;
    tuntun_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

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
        "Upgraded to Managed network '{}'. Restart with `tuntun run`. \
         Peers should pick up the upgrade notice or re-enroll with the same token.",
        resp.network_name
    );
    Ok(())
}
