//! Daemon entry (`tunnetd`) - run args and agent lifecycle.

use anyhow::Context;
use clap::Parser;
use tunnet_core::StatePaths;

use crate::runtime::AgentRuntime;

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
    #[arg(long, env = "TUNNET_RELAY_MODE")]
    pub relay_mode: Option<String>,
    #[arg(long, env = "TUNNET_RELAY_URLS")]
    pub relay_urls: Option<String>,
    #[arg(long, env = "TUNNET_KEEP_ALIVE")]
    pub keep_alive: bool,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
    /// Name this node presents to peers.
    ///
    /// Falls back to `HOSTNAME`/`COMPUTERNAME` when unset, which is what the
    /// CLI relies on. Embedders that cannot use the environment pass it here
    /// instead: writing to the environment needs `std::env::set_var`, which is
    /// unsound in an already-multi-threaded process such as an Android app.
    #[arg(skip)]
    pub hostname: Option<String>,
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
#[cfg(any(windows, test))]
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

    let config = agent_config(args, &paths);
    let runtime = AgentRuntime::start(config, shutdown.clone()).await?;
    let handle = runtime.handle();

    let (events_tx, _) = tokio::sync::broadcast::channel(256);
    let bootstrap = std::sync::Arc::new(
        crate::api_bootstrap::AgentBootstrapOps::new(paths.clone(), events_tx.clone())
            .with_handle(handle.clone()),
    );
    let api_server = tunnet_core::local_api::spawn_switching_api(
        tunnet_core::local_api::BootstrapApiState {
            bootstrap,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            events: events_tx,
        },
        handle.watch_mesh_api(),
    )
    .await
    .context("start Local Management API")?;
    if let Some(tx) = on_ready.take() {
        let _ = tx.send(());
    }
    #[cfg(all(unix, not(target_os = "android")))]
    crate::sd_notify::ready("running");

    wait_for_host_shutdown(shutdown).await;

    api_server.shutdown().await;
    runtime.shutdown().await;
    Ok(())
}

fn agent_config(args: RunArgs, paths: &StatePaths) -> crate::runtime::AgentConfig {
    let hostname = args
        .hostname
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok());
    crate::runtime::AgentConfig {
        state_dir: paths.root().to_path_buf(),
        hostname,
        ifname: args.ifname,
        poll_secs: args.poll_secs,
        metrics_bind: args.metrics_bind,
        disable_gossip: args.disable_gossip,
        recorder: args.recorder,
        no_mdns: args.no_mdns,
        relay_mode: args.relay_mode,
        relay_urls: args.relay_urls,
        keep_alive: args.keep_alive,
        no_encrypt_state: args.no_encrypt_state,
    }
}

async fn wait_for_host_shutdown(shutdown: Option<tokio_util::sync::CancellationToken>) {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        match crate::upgrade::UpgradeGuard::install() {
            Ok(upgrade) => {
                if let Some(token) = shutdown {
                    tokio::select! {
                        reason = upgrade.wait() => {
                            tracing::info!(?reason, "shutdown signal; draining");
                        }
                        _ = token.cancelled() => {
                            tracing::info!("shutdown token; draining");
                        }
                    }
                } else {
                    let reason = upgrade.wait().await;
                    tracing::info!(?reason, "shutdown signal; draining");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upgrade guard unavailable; waiting for stop");
                if let Some(token) = shutdown {
                    token.cancelled().await;
                } else {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
    }
    #[cfg(not(all(unix, not(target_os = "android"))))]
    {
        if let Some(token) = shutdown {
            token.cancelled().await;
            tracing::info!("service stop, shutting down");
        } else if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "ctrl-c listener failed");
        } else {
            tracing::info!("ctrl-c, shutting down");
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
