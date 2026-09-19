//! Internal enroll/reset used by [`api_bootstrap`] (not exposed as CLI in `tunnetd`).

use anyhow::Context;
use clap::Args;
use tunnet_core::{
    AgentIdentity, ManagedState, PersistedState, SealPolicy, StatePaths, persist_agent,
};

#[derive(Args, Debug)]
pub struct EnrollArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    #[arg(long, env = "TUNNET_ENROLL_TOKEN", conflicts_with = "org")]
    pub token: Option<String>,
    #[arg(long, env = "TUNNET_ORG_SLUG", conflicts_with = "token")]
    pub org: Option<String>,
    #[arg(long, env = "TUNNET_NETWORK")]
    pub network: Option<String>,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long, default_value_t = 600)]
    pub wait_secs: u64,
    #[arg(long, env = "TUNNET_LABELS", conflicts_with = "labels_json")]
    pub labels: Option<String>,
    #[arg(long, env = "TUNNET_LABELS_JSON", conflicts_with = "labels")]
    pub labels_json: Option<String>,
    #[arg(long, env = "TUNNET_EXPIRES_IN")]
    pub expires_in: Option<String>,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
    #[arg(long, env = "TUNNET_MANAGEMENT_URL")]
    pub management_url: Option<String>,
    #[arg(long, env = "TUNNET_DASHBOARD_URL")]
    pub dashboard_url: Option<String>,
}

#[derive(Args, Debug)]
pub struct ResetArgs {
    #[arg(long)]
    pub yes: bool,
}

fn paths(cli_state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(cli_state_dir)
}

pub async fn run_enroll(args: EnrollArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
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

    let management_url = args
        .management_url
        .or(resp.management_url)
        .filter(|s| !s.is_empty());
    let dashboard_url = args
        .dashboard_url
        .or(resp.dashboard_url)
        .filter(|s| !s.is_empty());

    let persisted = PersistedState::Managed(ManagedState {
        control_url: args.control_url,
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: jiff::Timestamp::now(),
        management_url,
        dashboard_url,
        local_ui: tunnet_common::local_api::LocalUiPolicy::default(),
    });
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

    tracing::info!(
        endpoint_id = %identity.endpoint_id_hex(),
        ip = %membership.assigned_ipv4,
        network = %resp.network_name,
        seal = %tier.as_str(),
        "enrolled"
    );
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
                    management_url: None,
                    dashboard_url: None,
                });
            }
        }
    }
}

pub async fn run_reset(args: ResetArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    tunnet_service::ensure_admin()?;

    let targets: Vec<std::path::PathBuf> = if let Some(dir) = state_dir {
        vec![std::path::PathBuf::from(dir)]
    } else if let Ok(env_dir) = std::env::var("TUNNET_STATE_DIR") {
        let env_dir = std::path::PathBuf::from(env_dir);
        let system = tunnet_core::StatePaths::system_dir();
        if env_dir == system {
            vec![system]
        } else {
            vec![system, env_dir]
        }
    } else {
        vec![tunnet_core::StatePaths::system_dir()]
    };

    if !args.yes {
        eprintln!("Re-run with --yes to wipe:");
        for dir in &targets {
            eprintln!("  {}", dir.display());
        }
        return Ok(());
    }

    // Daemon holds open files under the state dir; stop it before wiping.
    match tunnet_service::stop_for_reset() {
        Ok(()) => {
            if tunnet_service::probe().installed {
                println!("Stopped tunnet service.");
            }
        }
        Err(e) => {
            eprintln!("warning: could not stop service before reset: {e:#}");
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut wiped_any = false;
    for dir in &targets {
        if !dir.exists() {
            continue;
        }
        tunnet_service::wipe_state_dir(dir).with_context(|| format!("wipe {}", dir.display()))?;
        println!("Wiped {}", dir.display());
        wiped_any = true;
    }
    if !wiped_any {
        println!("Nothing to wipe.");
    }

    // Restart so the Local API comes back in idle bootstrap mode.
    if tunnet_service::probe().installed {
        match tunnet_service::start(state_dir) {
            Ok(()) => println!("Started tunnet service."),
            Err(e) => eprintln!("warning: could not start service after reset: {e:#}"),
        }
    }
    Ok(())
}
