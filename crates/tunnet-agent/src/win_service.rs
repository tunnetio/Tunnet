//! Windows SCM integration for `tunnetd --service`.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::daemon::DaemonCli;

pub const SERVICE_NAME: &str = "tunnet";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Enter the SCM dispatcher. Blocks until the service stops.
/// Must be called from the process entry point before a tokio runtime is built.
pub fn run_as_service() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("StartServiceCtrlDispatcher failed (run via `tunnet service start`, not console)")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("tunnet service failed: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("RegisterServiceCtrlHandler")?;
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .context("report StartPending")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime")?;

    let token = CancellationToken::new();

    let exit = runtime.block_on(async {
        let app_token = token.clone();
        let status_handle_stop = status_handle;
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
            token.cancel();
            let _ = status_handle_stop.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_secs(30),
                process_id: None,
            });
        });

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut agent = std::pin::pin!(run_agent_service(app_token, ready_tx));

        let mut checkpoint = 1u32;
        let mut ready_rx = ready_rx;
        loop {
            tokio::select! {
                result = &mut agent => {
                    return result;
                }
                ready = &mut ready_rx => {
                    if ready.is_err() {
                        tracing::warn!("agent exited before signaling Local API ready");
                    }
                    let _ = status_handle.set_service_status(ServiceStatus {
                        service_type: SERVICE_TYPE,
                        current_state: ServiceState::Running,
                        controls_accepted: ServiceControlAccept::STOP
                            | ServiceControlAccept::SHUTDOWN,
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 0,
                        wait_hint: Duration::default(),
                        process_id: None,
                    });
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    checkpoint = checkpoint.saturating_add(1);
                    let _ = status_handle.set_service_status(ServiceStatus {
                        service_type: SERVICE_TYPE,
                        current_state: ServiceState::StartPending,
                        controls_accepted: ServiceControlAccept::empty(),
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint,
                        wait_hint: Duration::from_secs(30),
                        process_id: None,
                    });
                }
            }
        }

        agent.await
    });

    if let Err(ref e) = exit {
        append_service_log(&format!("FATAL: {e:#}"));
    }

    let win32_exit = if exit.is_ok() { 0 } else { 1 };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(win32_exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    exit
}

async fn run_agent_service(
    shutdown: CancellationToken,
    on_ready: tokio::sync::oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    // SAFETY: service entry; no concurrent env readers yet.
    unsafe { std::env::set_var("TUNNET_SERVICE_MODE", "1") };
    // Do not pass `--service` here: main already routed us into the SCM path.
    // Parsing only daemon options avoids clap aborting before Local API binds.
    let cli = DaemonCli::parse_from(std::env::args().filter(|a| a != "--service"));
    // Own the log worker guard past daemon shutdown so the error below flushes.
    let _log_guard = crate::daemon::init_logging(&cli);

    let result = crate::daemon::run_with_shutdown(
        cli.run,
        cli.state_dir.as_deref(),
        Some(shutdown),
        Some(on_ready),
    )
    .await;
    if let Err(ref e) = result {
        tracing::error!(error = %e, "agent service exiting with error");
        append_service_log(&format!("FATAL: {e:#}"));
    }
    result
}

fn service_log_path() -> PathBuf {
    tunnet_core::StatePaths::system_dir().join("service.log")
}

fn append_service_log(line: &str) {
    use std::io::Write;
    let path = service_log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}
