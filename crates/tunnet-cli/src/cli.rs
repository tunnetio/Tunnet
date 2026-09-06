use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tunnet",
    about = "Tunnet - mesh networking, serve, and tunnel",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Cli {
    #[arg(long, env = "TUNNET_STATE_DIR", global = true)]
    pub state_dir: Option<String>,
    #[arg(long, env = "TUNNET_JSON_LOGS", global = true)]
    pub json_logs: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Enroll(crate::cmds_bootstrap::EnrollArgs),
    Up,
    Down,
    #[command(subcommand)]
    Service(ServiceCommand),
    Reset(crate::cmds_bootstrap::ResetArgs),
    Status(crate::cmds::StatusArgs),
    Ping(crate::cmds::PingArgs),
    #[command(subcommand)]
    Dns(DnsCommand),
    #[command(subcommand)]
    Route(RouteCommand),
    Diag(crate::cmds::DiagArgs),
    Netcheck(crate::cmds::NetcheckArgs),
    Serve(crate::cmds::ServeArgs),
    Tunnel(crate::cmds::TunnelArgs),
    Ssh(crate::cmds_ssh::SshArgs),
    SshKeyscan(crate::cmds_ssh::SshKeyscanArgs),
    SshProxy(crate::cmds_ssh::SshProxyArgs),
    Send(crate::cmds_send::SendArgs),
    Login(crate::cmds_bootstrap::LoginArgs),
    Logout(crate::cmds_bootstrap::LogoutArgs),
    Update(crate::cmds_update::UpdateArgs),
    Validate(crate::cmds::ValidateArgs),
    Reload(crate::cmds::ReloadArgs),
    #[command(subcommand)]
    Labels(crate::cmds_device::LabelsCommand),
    #[command(subcommand)]
    Tag(crate::cmds_device::TagCommand),
    #[command(subcommand)]
    Machine(crate::cmds_device::MachineCommand),
    #[command(subcommand)]
    Posture(crate::cmds_posture::PostureCommand),
    Create(crate::cmds_direct::CreateArgs),
    Join(crate::cmds_direct::JoinArgs),
    Invite(crate::cmds_direct::InviteArgs),
    Requests(crate::cmds_direct::RequestsArgs),
    Accept(crate::cmds_direct::AcceptArgs),
    Deny(crate::cmds_direct::DenyArgs),
    Kick(crate::cmds_direct::KickArgs),
    Connect(crate::cmds_direct::ConnectArgs),
    #[command(subcommand)]
    Firewall(crate::cmds_direct::FirewallCommand),
    #[command(subcommand)]
    Policy(crate::cmds_policy::PolicyCommand),
    #[command(subcommand, name = "coordinator-policy")]
    CoordinatorPolicy(crate::cmds_direct::PolicyCommand),
    KeepAlive(crate::cmds_direct::KeepAliveArgs),
    UpgradeToManaged(crate::cmds_direct::UpgradeArgs),
    Leave(crate::cmds_direct::LeaveArgs),
}

#[derive(Subcommand, Debug)]
pub enum DnsCommand {
    Status(crate::cmds::DnsStatusArgs),
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    List(crate::cmds::RouteListArgs),
    Add(crate::cmds::RouteAddArgs),
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

pub fn init_logging(cli: &Cli) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tunnet_cli=debug"));
    let sub = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.json_logs {
        let _ = sub.json().try_init();
    } else {
        let _ = sub.try_init();
    }
}
