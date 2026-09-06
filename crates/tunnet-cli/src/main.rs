mod cli;
mod cmds;
mod cmds_bootstrap;
mod cmds_device;
mod cmds_direct;
mod cmds_policy;
mod cmds_posture;
mod cmds_send;
mod cmds_ssh;
mod cmds_update;
mod known_hosts;
mod output;
mod state;

use clap::Parser;

fn main() {
    #[cfg(windows)]
    tunnet_service::setup_elevation_capture();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to create tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = rt.block_on(async_main()) {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

async fn async_main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    #[cfg(windows)]
    let cli = cli::Cli::parse_from(tunnet_service::args_for_clap());
    #[cfg(not(windows))]
    let cli = cli::Cli::parse();

    let quiet = matches!(
        cli.command,
        cli::Command::Status(_)
            | cli::Command::Ping(_)
            | cli::Command::Dns(_)
            | cli::Command::Route(_)
            | cli::Command::Diag(_)
            | cli::Command::Netcheck(_)
            | cli::Command::Serve(_)
            | cli::Command::Tunnel(_)
            | cli::Command::Ssh(_)
            | cli::Command::SshKeyscan(_)
            | cli::Command::SshProxy(_)
            | cli::Command::Send(_)
            | cli::Command::Login(_)
            | cli::Command::Logout(_)
            | cli::Command::Invite(_)
            | cli::Command::Requests(_)
            | cli::Command::Firewall(_)
            | cli::Command::Up
            | cli::Command::Down
            | cli::Command::Service(_)
            | cli::Command::Update(_)
            | cli::Command::Validate(_)
            | cli::Command::Reload(_)
    );
    if !quiet || std::env::var_os("RUST_LOG").is_some() {
        cli::init_logging(&cli);
    }

    let state_dir = cli.state_dir.as_deref();
    match cli.command {
        cli::Command::Enroll(a) => cmds_bootstrap::run_enroll(a, state_dir).await,
        cli::Command::Up => cmds::run_up(state_dir).await,
        cli::Command::Down => cmds::run_down(state_dir).await,
        cli::Command::Service(a) => match a {
            cli::ServiceCommand::Install => tunnet_service::install(state_dir),
            cli::ServiceCommand::Uninstall => tunnet_service::uninstall(),
            cli::ServiceCommand::Start => tunnet_service::start(state_dir),
            cli::ServiceCommand::Stop => tunnet_service::stop(state_dir),
            cli::ServiceCommand::Restart => tunnet_service::restart(state_dir),
            cli::ServiceCommand::Status => tunnet_service::status(),
        },
        cli::Command::Reset(a) => cmds_bootstrap::run_reset(a, state_dir).await,
        cli::Command::Status(a) => cmds::run_status(a).await,
        cli::Command::Ping(a) => cmds::run_ping(a).await,
        cli::Command::Dns(cli::DnsCommand::Status(a)) => cmds::run_dns_status(a).await,
        cli::Command::Route(cli::RouteCommand::List(a)) => cmds::run_route_list(a).await,
        cli::Command::Route(cli::RouteCommand::Add(a)) => cmds::run_route_add(a).await,
        cli::Command::Diag(a) => cmds::run_diag(a).await,
        cli::Command::Netcheck(a) => cmds::run_netcheck(a).await,
        cli::Command::Serve(a) => cmds::run_serve(a).await,
        cli::Command::Tunnel(a) => cmds::run_tunnel(a).await,
        cli::Command::Ssh(a) => cmds_ssh::run_ssh(a).await,
        cli::Command::SshKeyscan(a) => cmds_ssh::run_ssh_keyscan(a).await,
        cli::Command::SshProxy(a) => cmds_ssh::run_ssh_proxy(a).await,
        cli::Command::Send(a) => cmds_send::run(a).await,
        cli::Command::Login(a) => cmds_bootstrap::run_login(a, state_dir).await,
        cli::Command::Logout(a) => cmds_bootstrap::run_logout(a, state_dir).await,
        cli::Command::Update(a) => cmds_bootstrap::run_update(a, state_dir).await,
        cli::Command::Validate(a) => cmds::run_validate(a).await,
        cli::Command::Reload(a) => cmds::run_reload(a).await,
        cli::Command::Labels(a) => cmds_device::run_labels(a, state_dir).await,
        cli::Command::Tag(a) => cmds_device::run_tags(a, state_dir).await,
        cli::Command::Machine(a) => cmds_device::run_machine(a, state_dir).await,
        cli::Command::Posture(a) => cmds_posture::run(a, state_dir).await,
        cli::Command::Create(a) => cmds_direct::run_create(a, state_dir).await,
        cli::Command::Join(a) => cmds_direct::run_join(a, state_dir).await,
        cli::Command::Invite(a) => cmds_direct::run_invite(a, state_dir).await,
        cli::Command::Requests(a) => cmds_direct::run_requests(a, state_dir).await,
        cli::Command::Accept(a) => cmds_direct::run_accept(a, state_dir).await,
        cli::Command::Deny(a) => cmds_direct::run_deny(a, state_dir).await,
        cli::Command::Kick(a) => cmds_direct::run_kick(a, state_dir).await,
        cli::Command::Connect(a) => cmds_direct::run_connect(a, state_dir).await,
        cli::Command::Firewall(a) => cmds_direct::run_firewall(a, state_dir).await,
        cli::Command::Policy(a) => cmds_policy::run(a, state_dir).await,
        cli::Command::CoordinatorPolicy(a) => cmds_direct::run_policy(a, state_dir).await,
        cli::Command::KeepAlive(a) => cmds_direct::run_keep_alive(a, state_dir).await,
        cli::Command::UpgradeToManaged(a) => cmds_direct::run_upgrade(a, state_dir).await,
        cli::Command::Leave(a) => cmds_direct::run_leave(a, state_dir).await,
    }
}
