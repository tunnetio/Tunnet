//! Windows Service Control Manager (SCM) integration.
//!
//! When launched as `tunnet.exe run --service`, the process must call
//! `StartServiceCtrlDispatcher` promptly, report `SERVICE_RUNNING`, and honor
//! `SERVICE_CONTROL_STOP`. Without this, SCM leaves the service stuck in
//! "Starting" and cannot stop it cleanly.

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
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::cli::Cli;

pub const SERVICE_NAME: &str = "tunnet";
const SERVICE_DISPLAY_NAME: &str = "Tunnet Agent";
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
        // No console under SCM - best-effort log if tracing was initialized.
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

    // Stay in StartPending until local IPC is bound (signaled via on_ready).
    // TUN/SSH continue after Running so `tunnet service start` returns promptly.
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
                        // Agent dropped the sender without signaling (early exit).
                        tracing::warn!("agent exited before signaling IPC ready");
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
    let cli = Cli::parse();
    crate::cli::init_logging(&cli);

    let result = match cli.command {
        crate::cli::Command::Run(args) => {
            crate::cli::run_agent_with_shutdown(
                args,
                cli.state_dir.as_deref(),
                Some(shutdown),
                Some(on_ready),
            )
            .await
        }
        _ => anyhow::bail!("Windows service must be started as `tunnet run --service`"),
    };
    if let Err(ref e) = result {
        tracing::error!(error = %e, "agent service exiting with error");
        append_service_log(&format!("FATAL: {e:#}"));
    }
    result
}

pub(crate) fn service_log_path() -> PathBuf {
    tunnet_core::StatePaths::system_dir().join("service.log")
}

/// Fail early with a clear message when wintun.dll is missing beside the service binary.
pub fn ensure_wintun_present() -> anyhow::Result<()> {
    let path = crate::wintun_path::resolve(None);
    if path.is_file() {
        return Ok(());
    }
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"));
    anyhow::bail!(
        "wintun.dll not found (looked for {}).\n\
         Copy wintun.dll next to tunnet.exe before starting the service.\n\
         Download: https://www.wintun.net/",
        beside.display()
    );
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

/// Install (or update) the Tunnet service via the SCM API - avoids `sc create` quoting bugs.
pub fn install(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let dir = state_dir
        .map(str::to_string)
        .unwrap_or_else(|| tunnet_core::StatePaths::system_dir().display().to_string());
    // setx only updates future shells; apply for this process too.
    // SAFETY: single-threaded install path; no concurrent env readers in this process yet.
    unsafe { std::env::set_var("TUNNET_STATE_DIR", &dir) };
    let _ = std::process::Command::new("setx")
        .args(["TUNNET_STATE_DIR", &dir, "/M"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    migrate_user_state_into_system(PathBuf::from(&dir))?;

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("open Service Control Manager (need Administrator)")?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(exe),
        launch_arguments: vec![OsString::from("run"), OsString::from("--service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    ) {
        Ok(service) => {
            service
                .change_config(&service_info)
                .context("update existing tunnet service config")?;
            let _ = service.set_description("Tunnet mesh agent");
        }
        Err(_) => {
            let service = manager
                .create_service(
                    &service_info,
                    ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
                )
                .context("create tunnet service")?;
            let _ = service.set_description("Tunnet mesh agent");
        }
    }

    // Failure restart policy (same intent as former `sc failure`).
    let _ = std::process::Command::new("sc")
        .args(["failure", SERVICE_NAME, "reset= 0", "actions= restart/2000"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    Ok(())
}

/// If the operator enrolled into %LOCALAPPDATA% before installing the service,
/// copy that state into the machine dir the service will read.
///
/// Returns `true` when a migration was performed.
pub(crate) fn migrate_user_state_into_system(system: PathBuf) -> anyhow::Result<bool> {
    if system.join("state.json").is_file() {
        return Ok(false);
    }
    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return Ok(false);
    };
    let user = PathBuf::from(local).join("tunnet");
    if !user.join("state.json").is_file() {
        return Ok(false);
    }
    if user == system {
        return Ok(false);
    }

    println!(
        "Migrating agent state from {} → {}\n\
         (restoring a previous enrollment from the user profile)",
        user.display(),
        system.display()
    );
    copy_dir_recursive(&user, &system)
        .with_context(|| format!("migrate {} → {}", user.display(), system.display()))?;
    Ok(true)
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open Service Control Manager")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)
        .context("open tunnet service")?;
    let _ = service.stop();
    let _ = wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30));
    service.delete().context("delete tunnet service")?;
    Ok(())
}

/// Probe whether the Tunnet service is installed / running via the SCM API.
/// Prefer this over parsing `sc` stdout (locale-sensitive and PATH-fragile).
pub fn probe() -> crate::service::ServiceProbe {
    match open_service(ServiceAccess::QUERY_STATUS) {
        Ok(service) => match service.query_status() {
            Ok(status) => {
                let active = matches!(
                    status.current_state,
                    ServiceState::Running | ServiceState::StartPending
                );
                let state = match status.current_state {
                    ServiceState::Stopped => "inactive",
                    ServiceState::StartPending => "starting",
                    ServiceState::StopPending => "stopping",
                    ServiceState::Running => "active",
                    ServiceState::ContinuePending => "continuing",
                    ServiceState::PausePending => "pausing",
                    ServiceState::Paused => "paused",
                };
                crate::service::ServiceProbe {
                    installed: true,
                    active,
                    state: state.into(),
                }
            }
            Err(_) => crate::service::ServiceProbe {
                installed: true,
                active: false,
                state: "unknown".into(),
            },
        },
        Err(_) => crate::service::ServiceProbe::not_installed(),
    }
}

/// Start the service and wait until it is Running (or timeout).
pub fn start_and_wait() -> anyhow::Result<()> {
    let service = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .context("open tunnet service (is it installed? run `tunnet service install`)")?;
    let status = service
        .query_status()
        .context("query tunnet service status")?;
    match status.current_state {
        ServiceState::Running => return Ok(()),
        ServiceState::StartPending => {}
        ServiceState::StopPending => {
            wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30))
                .context("wait for tunnet service to finish stopping before start")?;
            service.start::<&str>(&[]).context("start tunnet service")?;
        }
        _ => {
            service.start::<&str>(&[]).context("start tunnet service")?;
        }
    }
    wait_for_running(&service, Duration::from_secs(90))?;
    Ok(())
}

fn wait_for_running(
    service: &windows_service::service::Service,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = service.query_status().context("query service status")?;
        match status.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped => {
                let win32 = match status.exit_code {
                    ServiceExitCode::Win32(c) => c,
                    ServiceExitCode::ServiceSpecific(c) => c,
                };
                let log = service_log_path();
                anyhow::bail!(
                    "tunnet service exited during startup (win32={win32}).\n\
                     Check {} or run interactively:\n\
                       tunnet run\n\
                     Common cause on a fresh Windows host: missing wintun.dll next to tunnet.exe.",
                    log.display()
                );
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for tunnet service to become Running (last state: {:?}).\n\
                 Check {} for details.",
                status.current_state,
                service_log_path().display()
            );
        }
        // Poll quickly; SCM wait_hint is often 30–60s and would stall the CLI.
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stop the service and wait until it is Stopped (or timeout).
pub fn stop_and_wait() -> anyhow::Result<()> {
    let service = match open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) {
        Ok(s) => s,
        Err(e) => {
            // Distinguish "missing" from "need elevation".
            if !probe().installed {
                return Ok(());
            }
            anyhow::bail!("cannot stop tunnet service: {e}\nRun elevated: tunnet service stop");
        }
    };
    let status = service
        .query_status()
        .context("query tunnet service status")?;
    match status.current_state {
        ServiceState::Stopped => return Ok(()),
        ServiceState::StopPending => {}
        _ => {
            service.stop().context("stop tunnet service")?;
        }
    }
    wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(45))
        .context("wait for tunnet service to reach Stopped")?;
    Ok(())
}

fn open_service(
    access: ServiceAccess,
) -> windows_service::Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    manager.open_service(SERVICE_NAME, access)
}

fn wait_for_state(
    service: &windows_service::service::Service,
    want: ServiceState,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = service.query_status().context("query service status")?;
        if status.current_state == want {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for tunnet service to become {:?} (last state: {:?})",
                want,
                status.current_state
            );
        }
        // Honor SCM wait hint when present, but keep polling responsive.
        let sleep = status
            .wait_hint
            .min(Duration::from_secs(2))
            .max(Duration::from_millis(200));
        std::thread::sleep(sleep);
    }
}
