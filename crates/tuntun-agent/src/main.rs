mod accept;
mod auto_update;
mod cli;
mod cmds;
mod cmds_device;
mod cmds_direct;
mod cmds_login;
mod cmds_send;
mod cmds_ssh;
mod cmds_update;
mod dataplane;
mod forward;
mod gossip_presence;
mod ip;
mod magic_dns;
mod metrics;
#[cfg(target_os = "linux")]
mod offload;
mod output;
mod recorder;
mod runtime;
#[cfg(unix)]
mod sd_notify;
mod service;
mod ssh;
mod stream_proxy;
mod system_dns;
mod system_info;
mod system_routes;
mod tun_io;
#[cfg(unix)]
mod upgrade;
#[cfg(windows)]
mod wintun_path;

use crate::cli::Cli;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();

    let quiet = matches!(
        cli.command,
        crate::cli::Command::Status(_)
            | crate::cli::Command::Ping(_)
            | crate::cli::Command::Dns(_)
            | crate::cli::Command::Route(_)
            | crate::cli::Command::Diag(_)
            | crate::cli::Command::Netcheck(_)
            | crate::cli::Command::Serve(_)
            | crate::cli::Command::Tunnel(_)
            | crate::cli::Command::Ssh(_)
            | crate::cli::Command::Send(_)
            | crate::cli::Command::Login(_)
            | crate::cli::Command::Logout(_)
            | crate::cli::Command::Invite(_)
            | crate::cli::Command::Requests(_)
            | crate::cli::Command::Firewall(_)
            | crate::cli::Command::Up
            | crate::cli::Command::Down
            | crate::cli::Command::Service(_)
            | crate::cli::Command::Update(_)
            | crate::cli::Command::Validate(_)
            | crate::cli::Command::Reload(_)
    );
    if !quiet || std::env::var_os("RUST_LOG").is_some() {
        crate::cli::init_logging(&cli);
    }

    match cli.command {
        crate::cli::Command::Enroll(a) => crate::cli::run_enroll(a, cli.state_dir.as_deref()).await,
        crate::cli::Command::Run(a) => crate::cli::run_agent(a, cli.state_dir.as_deref()).await,
        crate::cli::Command::Up => crate::cmds::run_up(cli.state_dir.as_deref()).await,
        crate::cli::Command::Down => crate::cmds::run_down(cli.state_dir.as_deref()).await,
        crate::cli::Command::Service(a) => match a {
            crate::cli::ServiceCommand::Install => {
                crate::service::install(cli.state_dir.as_deref())
            }
            crate::cli::ServiceCommand::Uninstall => crate::service::uninstall(),
            crate::cli::ServiceCommand::Start => crate::service::start(cli.state_dir.as_deref()),
            crate::cli::ServiceCommand::Stop => crate::service::stop(cli.state_dir.as_deref()),
            crate::cli::ServiceCommand::Restart => {
                crate::service::restart(cli.state_dir.as_deref())
            }
            crate::cli::ServiceCommand::Status => crate::service::status(),
        },
        crate::cli::Command::Reset(a) => crate::cli::run_reset(a, cli.state_dir.as_deref()).await,
        crate::cli::Command::Status(a) => crate::cmds::run_status(a).await,
        crate::cli::Command::Ping(a) => crate::cmds::run_ping(a).await,
        crate::cli::Command::Dns(crate::cli::DnsCommand::Status(a)) => {
            crate::cmds::run_dns_status(a).await
        }
        crate::cli::Command::Route(crate::cli::RouteCommand::List(a)) => {
            crate::cmds::run_route_list(a).await
        }
        crate::cli::Command::Route(crate::cli::RouteCommand::Add(a)) => {
            crate::cmds::run_route_add(a).await
        }
        crate::cli::Command::Diag(a) => crate::cmds::run_diag(a).await,
        crate::cli::Command::Netcheck(a) => crate::cmds::run_netcheck(a).await,
        crate::cli::Command::Serve(a) => crate::cmds::run_serve(a).await,
        crate::cli::Command::Tunnel(a) => crate::cmds::run_tunnel(a).await,
        crate::cli::Command::Ssh(a) => crate::cmds_ssh::run_ssh(a).await,
        crate::cli::Command::Send(a) => crate::cmds_send::run(a).await,
        crate::cli::Command::Login(a) => crate::cmds_login::run_login(a).await,
        crate::cli::Command::Logout(a) => crate::cmds_login::run_logout(a).await,
        crate::cli::Command::Update(a) => crate::cmds_update::run(a).await,
        crate::cli::Command::Validate(a) => crate::cmds::run_validate(a).await,
        crate::cli::Command::Reload(a) => crate::cmds::run_reload(a).await,
        crate::cli::Command::Labels(a) => {
            crate::cmds_device::run_labels(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Machine(a) => {
            crate::cmds_device::run_machine(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Create(a) => {
            crate::cmds_direct::run_create(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Join(a) => {
            crate::cmds_direct::run_join(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Invite(a) => {
            crate::cmds_direct::run_invite(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Requests(a) => {
            crate::cmds_direct::run_requests(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Accept(a) => {
            crate::cmds_direct::run_accept(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Deny(a) => {
            crate::cmds_direct::run_deny(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Kick(a) => {
            crate::cmds_direct::run_kick(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Connect(a) => {
            crate::cmds_direct::run_connect(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Firewall(a) => {
            crate::cmds_direct::run_firewall(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Policy(a) => {
            crate::cmds_direct::run_policy(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::KeepAlive(a) => {
            crate::cmds_direct::run_keep_alive(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::UpgradeToManaged(a) => {
            crate::cmds_direct::run_upgrade(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::Leave(a) => {
            crate::cmds_direct::run_leave(a, cli.state_dir.as_deref()).await
        }
        crate::cli::Command::OverrideIp(a) => {
            crate::cmds_direct::run_override_ip(a, cli.state_dir.as_deref()).await
        }
    }
}
