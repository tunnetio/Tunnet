//! Bootstrap commands via the Local API (`tunnetd` must be running).

use std::collections::HashMap;

use anyhow::Context;
use clap::Args;
use tunnet_common::local_api::{
    AuthLoginRequest, CoreUpdatePhase, CoreUpdateStatus, DeviceExpiryRequest,
    DeviceLabelDeleteRequest, DeviceLabelRequest, DeviceTagAddRequest, DeviceTagRemoveRequest,
    LocalEnrollRequest, UpdateRequest,
};

use crate::cmds::ipc_or_err;
use tunnet_client::TunnetClient;

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

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(long, env = "MANAGEMENT_URL")]
    pub management_url: Option<String>,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

pub async fn run_enroll(args: EnrollArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = crate::cmds::ensure_daemon_running(state_dir, "enroll").await?;
    tunnet_service::ensure_admin()?;
    let labels = parse_labels(&args)?;
    let body = LocalEnrollRequest {
        control_url: args.control_url,
        token: args.token,
        org: args.org,
        network: args.network,
        hostname: args.hostname,
        wait_secs: args.wait_secs,
        labels,
        expires_in: args.expires_in,
        no_encrypt_state: args.no_encrypt_state,
        management_url: args.management_url,
        dashboard_url: args.dashboard_url,
    };
    let resp = client.enroll(&body).await?;
    println!("{}", resp.message);
    wait_for_managed_network_ready(90).await?;
    Ok(())
}

async fn wait_for_managed_network_ready(secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let client = TunnetClient::connect();
    let mut last_error = None;
    while tokio::time::Instant::now() < deadline {
        match client.node().await {
            Ok(node) if node.data_plane_up && !node.networks.is_empty() => return Ok(()),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("daemon did not make the enrolled network ready")))
    .context(format!(
        "enrolled state did not become network-ready within {secs}s"
    ))
}

pub async fn run_reset(args: ResetArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    tunnet_service::ensure_admin()?;

    let targets: Vec<std::path::PathBuf> = if let Some(dir) = state_dir {
        vec![std::path::PathBuf::from(dir)]
    } else if let Ok(env_dir) = std::env::var("TUNNET_STATE_DIR") {
        let env_dir = std::path::PathBuf::from(env_dir);
        let system = crate::state::StatePaths::system_dir();
        if env_dir == system {
            vec![system]
        } else {
            vec![system, env_dir]
        }
    } else {
        vec![crate::state::StatePaths::system_dir()]
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
    // Give the process a moment to release file handles.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut wiped_any = false;
    for dir in &targets {
        if !dir.exists() {
            continue;
        }
        // Preserve `bin/` (staged service binaries under %ProgramData%\tunnet\bin).
        tunnet_service::wipe_state_dir(dir).with_context(|| format!("wipe {}", dir.display()))?;
        println!("Wiped {}", dir.display());
        wiped_any = true;
    }
    if !wiped_any {
        println!("Nothing to wipe.");
    }

    // Restart so Local API cold-boots into idle bootstrap (mode=idle / enroll).
    if tunnet_service::probe().installed {
        match tunnet_service::start(state_dir) {
            Ok(()) => println!("Started tunnet service."),
            Err(e) => eprintln!("warning: could not start service after reset: {e:#}"),
        }
    }
    Ok(())
}

pub async fn run_login(args: LoginArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir.or(args.state_dir.as_deref())).await?;
    let body = AuthLoginRequest {
        management_url: args.management_url,
    };
    let resp = client.auth_login(&body).await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_logout(args: LogoutArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir.or(args.state_dir.as_deref())).await?;
    let resp = client.auth_logout().await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_update(
    args: crate::cmds_update::UpdateArgs,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    if args.check {
        println!("{}", check_core_update(state_dir).await?);
        return Ok(());
    }

    tunnet_service::ensure_admin()?;
    let client = ipc_or_err(state_dir).await?;
    let body = UpdateRequest {
        force: args.force,
        restart: args.restart,
        version: args.version,
    };
    let resp = client.update(&body).await?;
    println!("{}", format_update_status(&resp));
    Ok(())
}

async fn check_core_update(state_dir: Option<&str>) -> anyhow::Result<String> {
    if tunnet_client::endpoint_reachable(TunnetClient::connect().path()).await {
        let client = ipc_or_err(state_dir).await?;
        return Ok(format_update_status(&client.update_check().await?));
    }

    let current = env!("CARGO_PKG_VERSION");
    let (_, manifest) =
        tunnet_update::fetch_manifest(concat!("tunnet/", env!("CARGO_PKG_VERSION")))
            .await
            .context("check the Core update channel")?;
    let current_v = semver::Version::parse(current)?;
    let target = semver::Version::parse(manifest.version.trim_start_matches('v'))?;
    if target > current_v {
        Ok(format!(
            "Update available: v{current} -> v{}",
            manifest.version.trim_start_matches('v')
        ))
    } else {
        Ok(format!("Tunnet Core is up to date (v{current})"))
    }
}

fn format_update_status(status: &CoreUpdateStatus) -> String {
    if let Some(error) = &status.error {
        return format!("Tunnet Core update failed: {error}");
    }
    match status.phase {
        CoreUpdatePhase::Idle => match &status.available_version {
            Some(version) => format!(
                "Update available: v{} -> v{version}",
                status.current_version
            ),
            None => format!("Tunnet Core is up to date (v{})", status.current_version),
        },
        CoreUpdatePhase::Checking => "Checking for Tunnet Core updates…".into(),
        CoreUpdatePhase::Available => match &status.available_version {
            Some(version) => format!(
                "Update available: v{} -> v{version}",
                status.current_version
            ),
            None => format!("Tunnet Core is up to date (v{})", status.current_version),
        },
        CoreUpdatePhase::Downloading => match (&status.available_version, status.total) {
            (Some(version), Some(total)) => format!(
                "Downloading Tunnet Core v{version} ({}/{} bytes)…",
                status.downloaded, total
            ),
            (Some(version), None) => format!("Downloading Tunnet Core v{version}…"),
            _ => "Downloading Tunnet Core…".into(),
        },
        CoreUpdatePhase::Verifying => "Verifying the Tunnet Core update…".into(),
        CoreUpdatePhase::Staged | CoreUpdatePhase::Activating => match &status.available_version {
            Some(version) => {
                format!("Update staged. The service will restart onto v{version} shortly.")
            }
            None => "Update staged. The service will restart shortly.".into(),
        },
        CoreUpdatePhase::HealthCheck => {
            "Verifying that the new Tunnet Core version is healthy…".into()
        }
        CoreUpdatePhase::Complete => {
            format!("Updated Tunnet Core to v{}", status.current_version)
        }
        CoreUpdatePhase::Error => "Tunnet Core update failed.".into(),
        CoreUpdatePhase::Rollback => "Rolling Tunnet Core back to the previous version…".into(),
    }
}

pub async fn device_labels_set(pairs: &[String], state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let labels = parse_label_pairs(pairs)?;
    let resp = client
        .device_labels_set(&DeviceLabelRequest { labels })
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn device_labels_delete(key: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .device_labels_delete(&DeviceLabelDeleteRequest {
            key: key.to_string(),
        })
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn device_tags_add(tag: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .device_tags_add(&DeviceTagAddRequest {
            tag: tag.to_string(),
        })
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn device_tags_remove(tag: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .device_tags_remove(&DeviceTagRemoveRequest {
            tag: tag.to_string(),
        })
        .await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn device_expiry(duration: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client
        .device_expiry(&DeviceExpiryRequest {
            duration: duration.to_string(),
        })
        .await?;
    println!("{}", resp.message);
    Ok(())
}

fn parse_labels(args: &EnrollArgs) -> anyhow::Result<Option<HashMap<String, String>>> {
    match (&args.labels, &args.labels_json) {
        (Some(csv), None) => Ok(Some(parse_label_csv(csv)?)),
        (None, Some(json)) => Ok(Some(parse_labels_json(json)?)),
        (None, None) => Ok(None),
        _ => unreachable!("clap conflicts_with"),
    }
}

fn parse_label_csv(csv: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for part in csv.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .with_context(|| format!("invalid label pair {part:?} (expected key=value)"))?;
        out.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(out)
}

fn parse_labels_json(json: &str) -> anyhow::Result<HashMap<String, String>> {
    serde_json::from_str(json).context("parse labels JSON")
}

fn parse_label_pairs(pairs: &[String]) -> anyhow::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .with_context(|| format!("invalid label {p:?} (expected key=value)"))?;
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(phase: CoreUpdatePhase) -> CoreUpdateStatus {
        CoreUpdateStatus {
            phase,
            current_version: "0.4.0".into(),
            available_version: Some("0.5.0".into()),
            api_version: tunnet_common::local_api::API_VERSION,
            downloaded: 0,
            total: None,
            error: None,
        }
    }

    #[test]
    fn update_status_is_a_sentence() {
        let idle = CoreUpdateStatus {
            available_version: None,
            ..status(CoreUpdatePhase::Idle)
        };
        assert_eq!(
            format_update_status(&idle),
            "Tunnet Core is up to date (v0.4.0)"
        );
        assert!(format_update_status(&status(CoreUpdatePhase::Activating)).contains("0.5.0"));
        let failed = CoreUpdateStatus {
            error: Some("checksum mismatch".into()),
            ..status(CoreUpdatePhase::Error)
        };
        assert!(format_update_status(&failed).contains("checksum mismatch"));
    }
}
