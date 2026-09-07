//! Daemon entry (`tunnetd`) - run args and agent lifecycle.

use anyhow::Context;
use clap::Parser;
use tunnet_core::{PersistedState, SealPolicy, StatePaths, load_agent};

#[derive(Parser, Debug)]
#[command(
    name = "tunnetd",
    about = "Tunnet mesh agent daemon",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct DaemonCli {
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
    #[arg(long, env = "TUNNET_JSON_LOGS")]
    pub json_logs: bool,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    pub service: bool,
    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Parser, Debug)]
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
    #[arg(long, env = "TUNNET_NO_MDNS")]
    pub no_mdns: bool,
    #[arg(long, env = "TUNNET_KEEP_ALIVE")]
    pub keep_alive: bool,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

pub fn init_logging(cli: &DaemonCli) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    #[cfg(windows)]
    if std::env::var_os("TUNNET_SERVICE_MODE").is_some() {
        return init_service_logging(filter);
    }

    let sub = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.json_logs {
        let _ = sub.json().try_init();
    } else {
        let _ = sub.try_init();
    }
    None
}

/// Windows service log sink with a hard disk budget.
///
/// `service.log` is size-rotated with gzip compression and a fixed file count,
/// so disk usage is bounded regardless of event rate. The non-blocking layer
/// drops lines instead of stalling dataplane threads when the disk is slow.
/// The returned guard owns the background writer: dropping it flushes the
/// remaining lines, so the service runner holds it for process lifetime.
#[cfg(windows)]
fn init_service_logging(
    filter: tracing_subscriber::EnvFilter,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    // 8 MiB × (1 active + 10 rotated, compressed) ≈ ≤ 88 MiB on disk worst case.
    const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
    const MAX_FILES: usize = 10;
    const QUEUE_LINES: usize = 8192;

    let path = tunnet_core::StatePaths::system_dir().join("service.log");
    let (writer, guard) = service_log_pipeline(&path, MAX_FILE_BYTES, MAX_FILES, QUEUE_LINES);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
    Some(guard)
}

/// Size-rotated file appender behind a bounded lossy queue.
fn service_log_pipeline(
    path: &std::path::Path,
    max_file_bytes: usize,
    max_files: usize,
    queue_lines: usize,
) -> (
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let appender = file_rotate::FileRotate::new(
        path,
        file_rotate::suffix::AppendCount::new(max_files),
        file_rotate::ContentLimit::Bytes(max_file_bytes),
        file_rotate::compression::Compression::OnRotate(0),
        None,
    );
    tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(queue_lines)
        .finish(appender)
}

fn paths(cli_state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(cli_state_dir)
}

pub async fn run(state_dir: Option<&str>, args: RunArgs) -> anyhow::Result<()> {
    run_with_shutdown(args, state_dir, None, None).await
}

pub async fn run_with_shutdown(
    args: RunArgs,
    state_dir: Option<&str>,
    shutdown: Option<tokio_util::sync::CancellationToken>,
    mut on_ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;

    let bootstrap_api = if !has_network_state(&paths) {
        let handle = start_idle_bootstrap(&paths, &mut on_ready).await?;
        wait_for_network_state(&paths, shutdown.as_ref()).await?;
        Some(handle)
    } else {
        None
    };
    if let Some(handle) = bootstrap_api {
        handle.abort();
        // Let the pipe / socket release before the full API rebinds.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

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

fn has_network_state(paths: &StatePaths) -> bool {
    paths.secrets_file().is_file() && matches!(PersistedState::try_load(paths), Ok(Some(_)))
}

async fn start_idle_bootstrap(
    paths: &StatePaths,
    on_ready: &mut Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use std::sync::Arc;

    use tunnet_core::local_api::{BootstrapApiState, spawn_bootstrap_api};

    let (events_tx, _) = tokio::sync::broadcast::channel(256);
    let bootstrap = Arc::new(crate::api_bootstrap::AgentBootstrapOps::new(
        paths.clone(),
        events_tx.clone(),
    ));
    let handle = spawn_bootstrap_api(BootstrapApiState {
        bootstrap,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        events: events_tx,
    })
    .await
    .context("start idle Local Management API")?;
    if let Some(tx) = on_ready.take() {
        let _ = tx.send(());
    }
    #[cfg(unix)]
    crate::sd_notify::ready("idle - Local API ready");
    Ok(handle)
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
            // Allow in-flight create/enroll HTTP responses to finish before we
            // tear down the bootstrap API listener.
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::service_log_pipeline;

    fn dir_total_bytes(dir: &std::path::Path) -> (usize, u64) {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        let total = entries
            .iter()
            .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
            .sum();
        (entries.len(), total)
    }

    /// A synthetic log storm must stay within a deterministic disk budget:
    /// at most `MAX_FILES + 1` files of at most `MAX_FILE_BYTES` each.
    #[test]
    fn rotation_bounds_disk_under_log_storm() {
        const MAX_FILE_BYTES: usize = 1024;
        const MAX_FILES: usize = 3;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("service.log");
        let mut appender = file_rotate::FileRotate::new(
            &path,
            file_rotate::suffix::AppendCount::new(MAX_FILES),
            file_rotate::ContentLimit::Bytes(MAX_FILE_BYTES),
            file_rotate::compression::Compression::OnRotate(0),
            None,
        );
        let line = vec![b'x'; 256];
        for _ in 0..2000 {
            appender.write_all(&line).expect("write");
            appender.write_all(b"\n").expect("write");
        }
        appender.flush().ok();

        let (count, total) = dir_total_bytes(dir.path());
        assert!(
            count <= MAX_FILES + 1,
            "rotation must cap file count, found {count}"
        );
        assert!(
            total <= (MAX_FILES as u64 + 1) * MAX_FILE_BYTES as u64,
            "disk use must stay bounded, found {total} bytes"
        );
    }

    /// The composed pipeline (bounded lossy queue over rotation) swallows a
    /// multi-threaded storm without blocking and stays within budget.
    #[test]
    fn pipeline_absorbs_storm_without_blocking() {
        const MAX_FILE_BYTES: usize = 4096;
        const MAX_FILES: usize = 2;

        let dir = tempfile::tempdir().expect("tempdir");
        let (writer, guard) = service_log_pipeline(
            &dir.path().join("service.log"),
            MAX_FILE_BYTES,
            MAX_FILES,
            16,
        );
        let line = vec![b'y'; 128];
        std::thread::scope(|s| {
            for _ in 0..8 {
                let mut writer = writer.clone();
                let line = line.clone();
                s.spawn(move || {
                    for _ in 0..5000 {
                        let _ = writer.write_all(&line);
                        let _ = writer.write_all(b"\n");
                    }
                });
            }
        });
        drop(guard);

        let (count, total) = dir_total_bytes(dir.path());
        assert!(
            count <= MAX_FILES + 1,
            "rotation must cap file count, found {count}"
        );
        assert!(
            total <= (MAX_FILES as u64 + 1) * MAX_FILE_BYTES as u64,
            "disk use must stay bounded, found {total} bytes"
        );
    }

    /// Below capacity nothing is dropped: guard shutdown flushes every line.
    #[test]
    fn pipeline_flushes_everything_on_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("service.log");
        let (mut writer, guard) = service_log_pipeline(&path, 1024 * 1024, 2, 4096);
        for i in 0..100u32 {
            writeln!(writer, "line-{i:04}").expect("write");
        }
        drop(guard);

        let body = std::fs::read_to_string(&path).expect("read log");
        assert_eq!(body.lines().count(), 100);
        assert!(body.contains("line-0000"));
        assert!(body.contains("line-0099"));
    }
}
