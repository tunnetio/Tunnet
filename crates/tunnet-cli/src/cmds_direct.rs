//! Direct-mode CLI via the Local API.

use anyhow::Context;
use clap::{Args, Subcommand};
use tunnet_common::local_api::{
    DirectFirewallAddRequest, DirectInviteRequest, DirectKeepAliveRequest, DirectPolicySetRequest,
    NetworkCreateRequest, NetworkJoinRequest, NetworkLeaveRequest, NetworkUpgradeRequest,
};

use crate::cmds::ipc_or_err;

#[derive(Args, Debug)]
pub struct CreateArgs {
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long)]
    pub open: bool,
    #[arg(long = "name")]
    pub network_name: Option<String>,
    #[arg(long)]
    pub secret: Option<String>,
    #[arg(long)]
    pub cidr: Option<String>,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    pub invite_code: String,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long)]
    pub auto_accept_firewall: bool,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct InviteArgs {
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
    #[arg(required = false)]
    pub contact_id: Option<String>,
    #[command(subcommand)]
    pub cmd: Option<ConnectCommand>,
}

#[derive(Subcommand, Debug)]
pub enum ConnectCommand {
    Allow { contact_id: String },
    Pending,
    Accept { contact_id: String },
    Deny { contact_id: String },
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
    Show,
    Set { file: String },
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
    #[arg(long)]
    pub network: Option<String>,
    pub name: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum FirewallCommand {
    Show,
    Off,
    Add(FirewallAddArgs),
    Remove { index: usize },
    Reset,
    FlushConntrack,
    Pending,
    Accept,
    RejectSuggestion,
}

#[derive(Args, Debug)]
pub struct FirewallAddArgs {
    #[arg(long)]
    pub network: Option<String>,
    pub direction: String,
    pub action: String,
    #[arg(short = 'p', long, default_value = "tcp")]
    pub protocol: String,
    #[arg(long)]
    pub port: Option<String>,
    #[arg(long)]
    pub peer: Option<String>,
}

pub async fn run_create(args: CreateArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = crate::cmds::ensure_daemon_running(state_dir, "create a network").await?;
    tunnet_service::ensure_admin()?;
    let body = NetworkCreateRequest {
        hostname: args.hostname,
        open: args.open,
        network_name: args.network_name.clone(),
        secret: args.secret,
        cidr: args.cidr,
        no_encrypt_state: args.no_encrypt_state,
    };
    match client.network_create(&body).await {
        Ok(resp) => {
            println!("{}", resp.message);
            if let Err(e) = crate::cmds::wait_until_daemon(state_dir, 60).await {
                println!("Note: {e}");
            }
            Ok(())
        }
        Err(e) if crate::cmds::is_api_connection_closed(&e) => {
            crate::cmds::recover_bootstrap_result(state_dir, "created", e).await
        }
        Err(e) => Err(e),
    }
}

pub async fn run_join(args: JoinArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = crate::cmds::ensure_daemon_running(state_dir, "join a network").await?;
    tunnet_service::ensure_admin()?;
    let body = NetworkJoinRequest {
        invite_code: args.invite_code,
        hostname: args.hostname,
        auto_accept_firewall: args.auto_accept_firewall,
        no_encrypt_state: args.no_encrypt_state,
    };
    match client.network_join(&body).await {
        Ok(resp) => {
            println!("{}", resp.message);
            if let Err(e) = crate::cmds::wait_until_daemon(state_dir, 60).await {
                println!("Note: {e}");
            }
            Ok(())
        }
        Err(e) if crate::cmds::is_api_connection_closed(&e) => {
            crate::cmds::recover_bootstrap_result(state_dir, "joined", e).await
        }
        Err(e) => Err(e),
    }
}

pub async fn run_invite(args: InviteArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let body = DirectInviteRequest {
        network: args.network.clone(),
        reusable: args.reusable,
        expires: args.expires,
    };
    let resp = client.direct_invite(&body).await?;
    println!("{}", resp.code);
    Ok(())
}

pub async fn run_requests(args: RequestsArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client.direct_requests(args.network.as_deref()).await?;
    if resp.requests.is_empty() {
        println!("No pending join requests.");
        return Ok(());
    }
    for (i, p) in resp.requests.iter().enumerate() {
        println!("{i}: {} {}", p.endpoint_id, p.hostname);
    }
    Ok(())
}

pub async fn run_accept(args: AcceptArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .direct_accept(&args.peer_id, args.network.as_deref())
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_deny(args: DenyArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .direct_deny(&args.peer_id, args.network.as_deref())
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_kick(args: KickArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .direct_kick(&args.peer_id, args.network.as_deref())
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_connect(args: ConnectArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    if let Some(cmd) = args.cmd {
        match cmd {
            ConnectCommand::Allow { contact_id } => {
                let resp = client.direct_connect_allow(contact_id).await?;
                println!("{}", resp.message);
            }
            ConnectCommand::Pending => {
                let resp = client.direct_connect_pending().await?;
                if resp.requests.is_empty() {
                    println!("(no pending connect requests)");
                }
                for r in resp.requests {
                    println!(
                        "{}  {}  {}  {}",
                        r.contact_id, r.hostname, r.endpoint_id, r.received_at
                    );
                }
            }
            ConnectCommand::Accept { contact_id } => {
                let resp = client.direct_connect_accept(&contact_id).await?;
                println!("{}", resp.message);
            }
            ConnectCommand::Deny { contact_id } => {
                let resp = client.direct_connect_deny(&contact_id).await?;
                println!("{}", resp.message);
            }
            ConnectCommand::Rotate => {
                let resp = client.direct_connect_rotate().await?;
                println!("New contact id: {}", resp.contact_id);
                println!("Restart the agent (`tunnet service restart`) for the new identity.");
            }
        }
    } else if let Some(contact_id) = args.contact_id {
        let resp = client.direct_connect(contact_id).await?;
        println!("{}", resp.message);
    } else {
        anyhow::bail!("usage: tunnet connect <tt_…> | allow|pending|accept|deny|rotate");
    }
    Ok(())
}

pub async fn run_firewall(cmd: FirewallCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    match cmd {
        FirewallCommand::Show => {
            let resp = client.direct_firewall_show(None).await?;
            println!("enabled={}", resp.enabled);
            println!(
                "conntrack={} allowed={} denied={} rejected={} suggested={}",
                resp.conntrack_entries,
                resp.packets_allowed,
                resp.packets_denied,
                resp.packets_rejected,
                resp.suggested_rules
            );
            for r in resp.rules {
                println!(
                    "{}: {} {} {} ports={:?} peer={:?}",
                    r.index, r.direction, r.action, r.protocol, r.ports, r.peer
                );
            }
        }
        FirewallCommand::Off => {
            let resp = client.direct_firewall_off(None).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::Add(a) => {
            let body = DirectFirewallAddRequest {
                network: a.network,
                direction: a.direction,
                action: a.action,
                protocol: a.protocol,
                port: a.port,
                peer: a.peer,
            };
            let resp = client.direct_firewall_add(&body).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::Remove { index } => {
            let resp = client.direct_firewall_remove(index, None).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::Reset => {
            let resp = client.direct_firewall_reset(None).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::FlushConntrack => {
            let resp = client.direct_firewall_flush_conntrack(None).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::Pending => {
            let resp = client.direct_firewall_pending(None).await?;
            match resp.pending {
                Some(s) => println!("{s}"),
                None => println!("(no pending suggestion)"),
            }
        }
        FirewallCommand::Accept => {
            let resp = client.direct_firewall_accept_suggestion(None).await?;
            println!("{}", resp.message);
        }
        FirewallCommand::RejectSuggestion => {
            let resp = client.direct_firewall_reject_suggestion(None).await?;
            println!("{}", resp.message);
        }
    }
    Ok(())
}

pub async fn run_policy(cmd: PolicyCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    match cmd {
        PolicyCommand::Show => {
            let resp = client.direct_policy_show(None).await?;
            match resp.json {
                Some(s) => println!("{s}"),
                None => println!("(no published policy)"),
            }
        }
        PolicyCommand::Set { file } => {
            let toml = std::fs::read_to_string(&file)
                .with_context(|| format!("read policy file {file}"))?;
            let body = DirectPolicySetRequest {
                network: None,
                toml,
            };
            let resp = client.direct_policy_set(&body).await?;
            println!("{}", resp.message);
        }
        PolicyCommand::Clear => {
            let resp = client.direct_policy_clear(None).await?;
            println!("{}", resp.message);
        }
    }
    Ok(())
}

pub async fn run_keep_alive(args: KeepAliveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let body = DirectKeepAliveRequest {
        hostname: args.hostname,
        enable: !args.off,
    };
    let resp = client.direct_keep_alive(&body).await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    tunnet_service::ensure_admin()?;
    let client = ipc_or_err(state_dir).await?;
    let body = NetworkUpgradeRequest {
        control_url: args.control_url,
        token: args.token,
    };
    let resp = client.network_upgrade(&body).await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_leave(args: LeaveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    tunnet_service::ensure_admin()?;

    match ipc_or_err(state_dir).await {
        Ok(client) => {
            let body = NetworkLeaveRequest {
                network: args.network,
                name: args.name,
            };
            let resp = client.network_leave(&body).await?;
            println!("{}", resp.message);
            Ok(())
        }
        Err(_) => {
            let paths = tunnet_core::StatePaths::resolve(state_dir);
            let policy = tunnet_core::SealPolicy::from_env_and_flag(false);
            let name = args.network.or(args.name);
            let nname = tunnet_core::leave_direct_network(&paths, policy, name.as_deref())?;
            println!("Left Direct network '{nname}'.");
            match tunnet_service::reload_after_config(state_dir) {
                Ok(()) => {
                    if let Err(e) = crate::cmds::wait_until_daemon(state_dir, 20).await {
                        println!("Note: {e}");
                    } else {
                        println!("Agent is up.");
                    }
                }
                Err(e) => {
                    println!(
                        "Note: could not reload agent ({e:#}). Start with `tunnet service start`."
                    );
                }
            }
            Ok(())
        }
    }
}
