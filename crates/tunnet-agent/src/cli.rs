use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tunnet_core::{
    AgentIdentity, ManagedState, PersistedState, SealPolicy, StatePaths, load_agent, persist_agent,
};

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
    /// Enroll this machine into a Tunnet network
    Enroll(EnrollArgs),
    /// Run the Tunnet agent (requires root / admin for TUN)
    Run(RunArgs),
    /// Bring TUN + DNS + routes up (daemon must be running)
    Up,
    /// Tear down TUN + DNS + routes; keep mesh alive
    Down,
    /// Install / control the OS service
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Wipe local agent state
    Reset(ResetArgs),

    /// Show agent / network status
    Status(crate::cmds::StatusArgs),
    /// Measure mesh RTT to a peer
    Ping(crate::cmds::PingArgs),
    /// PeerDNS status
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Subnet / hostname / exit routes
    #[command(subcommand)]
    Route(RouteCommand),
    /// Full connectivity diagnostics
    Diag(crate::cmds::DiagArgs),
    /// Quick pass/fail connectivity check
    Netcheck(crate::cmds::NetcheckArgs),
    /// Expose a local port to the mesh (HTTPS/TCP)
    ///
    /// Examples: `tunnet serve 3000`, `tunnet serve status`, `tunnet serve off 3000`
    Serve(crate::cmds::ServeArgs),
    /// Expose a local port to the public internet via a relay
    ///
    /// Examples: `tunnet tunnel 3000`, `tunnet tunnel status`, `tunnet tunnel off 3000`
    Tunnel(crate::cmds::TunnelArgs),
    /// SSH to a peer over the mesh (identity-based, no SSH keys)
    ///
    /// Examples: `tunnet ssh db-server`, `tunnet ssh db-server -u root`, `tunnet ssh db-server -- uname -a`
    Ssh(crate::cmds_ssh::SshArgs),
    /// Print mesh SSH host keys
    ///
    /// Examples: `tunnet ssh-keyscan`, `tunnet ssh-keyscan db-server`, `tunnet ssh-keyscan -f`
    SshKeyscan(crate::cmds_ssh::SshKeyscanArgs),
    /// OpenSSH ProxyCommand helper: splice stdin/stdout to mesh `host:port`
    ///
    /// Examples: used as `ProxyCommand=tunnet ssh-proxy %h %p` (see `tunnet ssh config`)
    SshProxy(crate::cmds_ssh::SshProxyArgs),
    /// Send a file or directory to a peer over the mesh (P2P via iroh-blobs)
    ///
    /// Examples: `tunnet send ./file.txt db-server`, `tunnet send ./dir tag:production`
    Send(crate::cmds_send::SendArgs),
    /// Sign in via browser (device authorization) and store a management token
    Login(crate::cmds_login::LoginArgs),
    /// Clear stored management tokens
    Logout(crate::cmds_login::LogoutArgs),
    /// Update this binary from GitHub Releases
    ///
    /// Linux default: download + graceful reload (SIGHUP / ecdysis).
    /// Pass `--restart` for a hard service restart. Windows always restarts.
    Update(crate::cmds_update::UpdateArgs),
    /// Validate `tunnet.toml`. Exit non-zero on errors.
    Validate(crate::cmds::ValidateArgs),
    /// Reload firewall / DNS / logging / keep-alive from `tunnet.toml` without dropping connections
    Reload(crate::cmds::ReloadArgs),

    /// Manage machine labels
    #[command(subcommand)]
    Labels(crate::cmds_device::LabelsCommand),

    /// Machine lifecycle settings
    #[command(subcommand)]
    Machine(crate::cmds_device::MachineCommand),

    /// Device posture collectors and checks
    #[command(subcommand)]
    Posture(crate::cmds_posture::PostureCommand),

    // --- Direct mode ---
    /// Create a Direct (P2P) network - no control plane
    Create(crate::cmds_direct::CreateArgs),
    /// Join a Direct network with an invite code
    Join(crate::cmds_direct::JoinArgs),
    /// Create an invite code for a Direct network
    Invite(crate::cmds_direct::InviteArgs),
    /// List pending join requests (coordinator)
    Requests(crate::cmds_direct::RequestsArgs),
    /// Accept a pending join request
    Accept(crate::cmds_direct::AcceptArgs),
    /// Deny a pending join request
    Deny(crate::cmds_direct::DenyArgs),
    /// Kick a peer from a Direct network
    Kick(crate::cmds_direct::KickArgs),
    /// Connect directly to a contact id (2-peer ephemeral)
    Connect(crate::cmds_direct::ConnectArgs),
    /// Manage the local Direct firewall
    #[command(subcommand)]
    Firewall(crate::cmds_direct::FirewallCommand),
    /// Policy-as-Code document operations
    #[command(subcommand)]
    Policy(crate::cmds_policy::PolicyCommand),
    /// Coordinator firewall policy (Direct mode)
    #[command(subcommand, name = "coordinator-policy")]
    CoordinatorPolicy(crate::cmds_direct::PolicyCommand),
    /// Keep a Direct peer connection always open
    KeepAlive(crate::cmds_direct::KeepAliveArgs),
    /// Upgrade a Direct network to Managed mode
    UpgradeToManaged(crate::cmds_direct::UpgradeArgs),
    /// Leave one Direct network
    Leave(crate::cmds_direct::LeaveArgs),
    /// Override a peer IP for birthday collisions
    OverrideIp(crate::cmds_direct::OverrideIpArgs),
}

#[derive(Subcommand, Debug)]
pub enum DnsCommand {
    /// Show PeerDNS configuration and cache
    Status(crate::cmds::DnsStatusArgs),
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    /// List active routes
    List(crate::cmds::RouteListArgs),
    /// Advertise a subnet route from this machine
    Add(crate::cmds::RouteAddArgs),
}

#[derive(Args, Debug)]
pub struct EnrollArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    /// One-time enrollment token (primary path).
    #[arg(long, env = "TUNNET_ENROLL_TOKEN", conflicts_with = "org")]
    pub token: Option<String>,
    /// Organization slug for quick enroll (awaits admin approval).
    #[arg(long, env = "TUNNET_ORG_SLUG", conflicts_with = "token")]
    pub org: Option<String>,
    /// Network id or name for quick enroll (defaults to "default").
    #[arg(long, env = "TUNNET_NETWORK")]
    pub network: Option<String>,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    /// How long to wait for quick-enroll approval (seconds).
    #[arg(long, default_value_t = 600)]
    pub wait_secs: u64,
    /// Comma-separated labels (key=value pairs)
    #[arg(long, env = "TUNNET_LABELS", conflicts_with = "labels_json")]
    pub labels: Option<String>,
    /// Labels as JSON object
    #[arg(long, env = "TUNNET_LABELS_JSON", conflicts_with = "labels")]
    pub labels_json: Option<String>,
    /// Auto-delete after inactivity (e.g. 3d, 12h, never)
    #[arg(long, env = "TUNNET_EXPIRES_IN")]
    pub expires_in: Option<String>,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal).
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Write systemd/launchd/Windows service unit (needs root/admin once)
    Install,
    /// Remove the OS service unit
    Uninstall,
    /// Start the daemon via the OS service manager
    Start,
    /// Stop the daemon completely
    Stop,
    /// Restart the daemon
    Restart,
    /// Show service status
    Status,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(long, env = "TUNNET_IFNAME", default_value = "tunnet0")]
    pub ifname: String,
    #[arg(long, env = "TUNNET_POLL_SECS", default_value_t = 30)]
    pub poll_secs: u64,
    #[arg(long, env = "TUNNET_METRICS_BIND", default_value = "127.0.0.1:9100")]
    pub metrics_bind: String,
    #[arg(long, env = "TUNNET_DISABLE_GOSSIP")]
    pub disable_gossip: bool,
    #[arg(long, env = "TUNNET_RECORDER")]
    pub recorder: bool,
    /// Disable mDNS LAN address lookup (Direct mode).
    #[arg(long, env = "TUNNET_NO_MDNS")]
    pub no_mdns: bool,
    /// Keep peer connections always open (disables on-demand). Default off in Direct.
    #[arg(long, env = "TUNNET_KEEP_ALIVE")]
    pub keep_alive: bool,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal). For containers/CI only.
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
    #[arg(long, hide = true)]
    pub service: bool,
    #[cfg(windows)]
    #[arg(long, env = "TUNNET_WINTUN_FILE")]
    pub wintun_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct ResetArgs {
    #[arg(long)]
    pub yes: bool,
}

pub fn init_logging(cli: &Cli) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,tunnet_agent=debug,tunnet_core=debug")
    });

    #[cfg(windows)]
    if std::env::var_os("TUNNET_SERVICE_MODE").is_some() {
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};

        let path = tunnet_core::StatePaths::system_dir().join("service.log");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
        {
            #[derive(Clone)]
            struct FileWriter(Arc<Mutex<std::fs::File>>);
            impl std::io::Write for FileWriter {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap_or_else(|e| e.into_inner()).write(buf)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
                }
            }
            impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
                type Writer = FileWriter;
                fn make_writer(&'a self) -> Self::Writer {
                    self.clone()
                }
            }

            let writer = FileWriter(Arc::new(Mutex::new(file)));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(writer)
                .try_init();
            return;
        }
    }

    let sub = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.json_logs {
        let _ = sub.json().try_init();
    } else {
        let _ = sub.try_init();
    }
}

fn paths(cli_state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(cli_state_dir)
}

pub async fn run_enroll(args: EnrollArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    crate::service::ensure_service_state_aligned(state_dir, &paths)?;
    paths.ensure()?;

    let control_loopback = args.control_url.contains("127.0.0.1")
        || args.control_url.contains("localhost")
        || args.control_url.contains("[::1]");
    if control_loopback {
        eprintln!(
            "warning: control URL is loopback ({}).\n\
             This machine can reach the control plane, but other hosts/VMs must enroll with\n\
             the control plane's LAN or public URL, e.g.:\n\
               tunnet enroll --control-url http://<this-host-lan-ip>:8080 --token …\n\
             Otherwise they stay offline on the dashboard and never appear as peers.",
            args.control_url
        );
    }

    if let Ok(existing) = PersistedState::load(&paths) {
        if existing.is_direct() {
            anyhow::bail!(
                "agent is in Direct mode; run `tunnet reset --yes` before enrolling into Managed"
            );
        }
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            existing.primary_network_name().unwrap_or("?")
        );
    }

    let token = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let org = args
        .org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if token.is_none() && org.is_none() {
        anyhow::bail!("provide --token <TOKEN> or --org <slug>");
    }

    let hostname = args
        .hostname
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-node".into());

    let identity = AgentIdentity::generate();
    tracing::info!(endpoint_id = %identity.endpoint_id_hex(), "generated new agent identity");

    let client = tunnet_core::UnauthedClient::new(args.control_url.clone())?;
    let metadata =
        crate::system_info::collect_system_metadata(&hostname, env!("CARGO_PKG_VERSION"));

    let (network_id, network_name) = parse_network_arg(args.network.as_deref())?;

    let labels = match (&args.labels, &args.labels_json) {
        (Some(csv), None) => Some(crate::cmds_device::parse_label_csv(csv)?),
        (None, Some(json)) => Some(crate::cmds_device::parse_labels_json(json)?),
        (None, None) => None,
        _ => unreachable!("clap conflicts_with"),
    };

    let mut resp = client
        .enroll(tunnet_common::EnrollRequest {
            enrollment_token: token,
            organization_slug: org,
            network_id,
            network_name,
            endpoint_id: identity.endpoint_id_hex(),
            hostname: hostname.clone(),
            os: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: Some(metadata),
            labels,
            expires_in: args.expires_in.clone(),
        })
        .await
        .context("enroll with control plane")?;

    if resp.status == "pending" {
        println!(
            "Quick enroll pending approval. endpoint_id={} network={} (waiting up to {}s)",
            identity.endpoint_id_hex(),
            resp.network_name,
            args.wait_secs,
        );
        resp = wait_for_approval(&client, &identity, resp, args.wait_secs).await?;
    }

    let membership = resp
        .snapshot
        .memberships
        .iter()
        .find(|m| m.network_id == resp.network_id)
        .context("enrolled network missing from snapshot")?;

    tracing::info!(
        assigned_ip = %membership.assigned_ipv4,
        network = %resp.network_name,
        peers = membership.ipv4_peers.len(),
        "enrollment successful"
    );

    let persisted = PersistedState::Managed(ManagedState {
        control_url: args.control_url,
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: chrono::Utc::now(),
    });
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

    println!(
        "Enrolled. endpoint_id={} ip={} network={} (secrets: {})",
        identity.endpoint_id_hex(),
        membership.assigned_ipv4,
        resp.network_name,
        tier.as_str(),
    );
    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = crate::cmds::wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
    } else {
        println!("Agent is up. Bring the data plane online with `tunnet up` if needed.");
    }
    Ok(())
}

fn parse_network_arg(
    network: Option<&str>,
) -> anyhow::Result<(Option<uuid::Uuid>, Option<String>)> {
    let Some(raw) = network.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok((None, None));
    };
    if let Ok(id) = uuid::Uuid::parse_str(raw) {
        return Ok((Some(id), None));
    }
    Ok((None, Some(raw.to_string())))
}

async fn wait_for_approval(
    client: &tunnet_core::UnauthedClient,
    identity: &AgentIdentity,
    pending: tunnet_common::EnrollResponse,
    wait_secs: u64,
) -> anyhow::Result<tunnet_common::EnrollResponse> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for enrollment approval");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let status = client
            .enroll_status(tunnet_common::EnrollStatusRequest {
                endpoint_id: identity.endpoint_id_hex(),
                network_id: pending.network_id,
            })
            .await
            .context("poll enroll status")?;

        match status {
            tunnet_common::EnrollStatusResponse::Pending { .. } => continue,
            tunnet_common::EnrollStatusResponse::Rejected => {
                anyhow::bail!("enrollment was rejected by an organization admin");
            }
            tunnet_common::EnrollStatusResponse::Active {
                organization_id,
                network_id,
                network_name,
                snapshot,
            } => {
                return Ok(tunnet_common::EnrollResponse {
                    organization_id,
                    network_id,
                    network_name,
                    status: "active".into(),
                    snapshot: *snapshot,
                });
            }
        }
    }
}

pub async fn run_reset(args: ResetArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    // Only `--state-dir` limits the wipe to one path. A machine-wide
    // TUNNET_STATE_DIR (set by service install) must not skip the user profile
    // copy, or `service start` will migrate it back into ProgramData.
    let targets: Vec<std::path::PathBuf> = if state_dir.is_some() {
        vec![paths(state_dir).dir]
    } else {
        let mut dirs = tunnet_core::StatePaths::default_state_dirs();
        let current = paths(None).dir;
        if !dirs.contains(&current) {
            dirs.push(current);
        }
        dirs
    };

    if !args.yes {
        eprintln!("Re-run with --yes to wipe:");
        for dir in &targets {
            eprintln!("  {}", dir.display());
        }
        return Ok(());
    }

    let mut wiped_any = false;
    for dir in &targets {
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
            println!("Wiped {}", dir.display());
            wiped_any = true;
        }
    }
    if !wiped_any {
        println!("Nothing to wipe.");
    }
    Ok(())
}

pub async fn run_agent(args: RunArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    run_agent_with_shutdown(args, state_dir, None, None).await
}

/// Same as [`run_agent`], but accepts an optional SCM / external shutdown token
/// (used when running as a Windows service) and an optional readiness signal
/// (fired once local IPC is bound).
pub async fn run_agent_with_shutdown(
    args: RunArgs,
    state_dir: Option<&str>,
    shutdown: Option<tokio_util::sync::CancellationToken>,
    on_ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;

    #[cfg(unix)]
    crate::sd_notify::ready("waiting for create/enroll/join");

    wait_for_network_state(&paths, shutdown.as_ref()).await?;

    if let Some(token) = &shutdown
        && token.is_cancelled()
    {
        return Ok(());
    }

    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let (identity, persisted, tier) = load_agent(&paths, policy).with_context(|| {
        format!(
            "no persisted identity in {}; run `tunnet enroll` or `tunnet create` first",
            paths.dir.display()
        )
    })?;
    match &persisted {
        PersistedState::Managed(m) => {
            tracing::info!(
                endpoint_id = %identity.endpoint_id_hex(),
                network = %m.network_name,
                control = %m.control_url,
                mode = "managed",
                seal = %tier.as_str(),
                "starting agent",
            );
        }
        PersistedState::Direct { networks } => {
            let names: Vec<_> = networks.iter().map(|d| d.network_name.as_str()).collect();
            tracing::info!(
                endpoint_id = %identity.endpoint_id_hex(),
                networks = %names.join(","),
                mode = "direct",
                seal = %tier.as_str(),
                "starting agent",
            );
        }
    }
    crate::runtime::run(identity, persisted, paths, args, shutdown, on_ready).await
}

async fn wait_for_network_state(
    paths: &StatePaths,
    shutdown: Option<&tokio_util::sync::CancellationToken>,
) -> anyhow::Result<()> {
    let mut logged = false;
    loop {
        if let Some(token) = shutdown
            && token.is_cancelled()
        {
            return Ok(());
        }
        let has_secrets = paths.secrets_file().is_file();
        if has_secrets && let Ok(Some(_)) = PersistedState::try_load(paths) {
            return Ok(());
        }
        if !logged {
            tracing::info!(
                dir = %paths.dir.display(),
                "agent idle - waiting for `tunnet create`, `tunnet enroll`, or `tunnet join`"
            );
            logged = true;
        }
        if let Some(token) = shutdown {
            tokio::select! {
                _ = token.cancelled() => {
                    return Ok(());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
}
