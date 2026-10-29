//! Windows Service Control Manager integration for `tunnet-service`.

#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::paths::{resolve_state_dir, system_state_dir};
use crate::{ServiceProbe, ServiceProbe as Probe};

pub const SERVICE_NAME: &str = "tunnet";
const SERVICE_DISPLAY_NAME: &str = "Tunnet Agent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

pub fn service_log_path() -> PathBuf {
    system_state_dir().join("service.log")
}

pub fn install(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let manager =
        open_scm_admin(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

    let dir = resolve_state_dir(state_dir).display().to_string();
    unsafe { std::env::set_var("TUNNET_STATE_DIR", &dir) };
    let _ = std::process::Command::new("setx")
        .args(["TUNNET_STATE_DIR", &dir, "/M"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(exe),
        launch_arguments: vec![OsString::from("--service")],
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

    let _ = std::process::Command::new("sc")
        .args(["failure", SERVICE_NAME, "reset= 0", "actions= restart/2000"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = open_scm_admin(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)
        .context("open tunnet service")?;
    let _ = service.stop();
    let _ = wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30));
    service.delete().context("delete tunnet service")?;
    Ok(())
}

pub fn probe() -> Probe {
    match open_service(ServiceAccess::QUERY_STATUS) {
        Ok(service) => match service.query_status() {
            Ok(status) => {
                let active = matches!(status.current_state, ServiceState::Running);
                let state = match status.current_state {
                    ServiceState::Stopped => "inactive",
                    ServiceState::StartPending => "starting",
                    ServiceState::StopPending => "stopping",
                    ServiceState::Running => "active",
                    ServiceState::ContinuePending => "continuing",
                    ServiceState::PausePending => "pausing",
                    ServiceState::Paused => "paused",
                };
                ServiceProbe {
                    installed: true,
                    active,
                    state: state.into(),
                }
            }
            Err(_) => ServiceProbe {
                installed: true,
                active: false,
                state: "unknown".into(),
            },
        },
        Err(_) => ServiceProbe::not_installed(),
    }
}

pub fn start_and_wait() -> anyhow::Result<()> {
    let service = open_service_admin(ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .context("open tunnet service (is it installed? run `tunnet service start`)")?;
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
    use windows_service::service::ServiceExitCode;

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
                       tunnetd\n",
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
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn stop_and_wait() -> anyhow::Result<()> {
    if !probe().installed {
        return Ok(());
    }
    let service = open_service_admin(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)
        .context("cannot stop tunnet service")?;
    let status = service
        .query_status()
        .context("query tunnet service status")?;
    if status.current_state == ServiceState::Stopped && status.process_id.is_none_or(|pid| pid == 0)
    {
        return Ok(());
    }
    let pid = status
        .process_id
        .context("service did not report its process ID")?;
    let handle = unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        return Err(error).context("open service process");
    }
    let process = unsafe { OwnedHandle::from_raw_handle(handle) };
    let deadline = Instant::now() + Duration::from_secs(45);
    if !matches!(
        status.current_state,
        ServiceState::Stopped | ServiceState::StopPending
    ) && let Err(error) = service.stop()
        && !matches!(
            service.query_status()?.current_state,
            ServiceState::Stopped | ServiceState::StopPending
        )
    {
        return Err(error).context("stop tunnet service");
    }
    wait_for_state(
        &service,
        ServiceState::Stopped,
        deadline.saturating_duration_since(Instant::now()),
    )
    .context("wait for tunnet service to reach Stopped")?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let result = unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(
            process.as_raw_handle(),
            remaining.as_millis() as u32,
        )
    };
    match result {
        windows_sys::Win32::Foundation::WAIT_OBJECT_0 => {}
        windows_sys::Win32::Foundation::WAIT_FAILED => {
            return Err(std::io::Error::last_os_error()).context("wait for service process");
        }
        _ => anyhow::bail!("service process did not exit before the stop deadline"),
    }
    Ok(())
}

fn open_scm_admin(access: ServiceManagerAccess) -> anyhow::Result<ServiceManager> {
    let access = access | ServiceManagerAccess::CREATE_SERVICE;
    match ServiceManager::local_computer(None::<&str>, access) {
        Ok(manager) => Ok(manager),
        Err(_) => {
            relaunch_elevated()?;
            unreachable!("relaunch_elevated exits on success")
        }
    }
}

pub fn ensure_elevated() -> anyhow::Result<()> {
    let _manager = open_scm_admin(ServiceManagerAccess::CONNECT)?;
    Ok(())
}

/// Relaunch via UAC when this process is not elevated.
/// Used for Local API lifecycle commands (reset / enroll / create).
pub fn ensure_process_elevated() -> anyhow::Result<()> {
    if process_token_elevated() {
        return Ok(());
    }
    relaunch_elevated()?;
    unreachable!("relaunch_elevated exits on success")
}

pub(crate) fn process_token_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &raw mut elevation as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn open_service(
    access: ServiceAccess,
) -> windows_service::Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    manager.open_service(SERVICE_NAME, access)
}

fn open_service_admin(access: ServiceAccess) -> anyhow::Result<windows_service::service::Service> {
    let manager = open_scm_admin(ServiceManagerAccess::CONNECT)?;
    manager
        .open_service(SERVICE_NAME, access)
        .context("open tunnet service")
}

fn relaunch_elevated() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("resolve current executable")?;
    let out_file = std::env::temp_dir().join(format!("tunnet-elevated-{}.log", std::process::id()));
    let _ = std::fs::File::create(&out_file);

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    args.insert(0, out_file.to_string_lossy().into_owned());
    args.insert(0, "--tunnet-elevation-output".to_string());

    let hint = format!(
        "tunnet {}",
        std::env::args()
            .skip(1)
            .map(quote_cmd_arg)
            .collect::<Vec<_>>()
            .join(" ")
    );

    let exit_code = shell_execute_elevated(&exe, &args, Some(&hint))?;

    // Stream captured output from the elevated child (written via SetStdHandle).
    let mut offset = 0u64;
    let mut chunk = Vec::new();
    let mut captured = Vec::new();
    drain_capture_buf(&out_file, &mut offset, &mut chunk, &mut captured);
    if !captured.is_empty() {
        let mut stdout = std::io::stdout();
        let _ = std::io::Write::write_all(&mut stdout, &captured);
        let _ = std::io::Write::flush(&mut stdout);
    }
    let _ = std::fs::remove_file(&out_file);
    std::process::exit(exit_code);
}

/// Launch `exe` with `args` via UAC (`runas`) and wait for exit.
///
/// Unlike [`ensure_process_elevated`], this does **not** exit the calling process - suitable for GUI hosts.
pub fn run_elevated(
    exe: &std::path::Path,
    args: &[impl AsRef<std::ffi::OsStr>],
) -> anyhow::Result<i32> {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect();
    let hint = format!(
        "{} {}",
        exe.display(),
        args.iter()
            .map(|a| quote_cmd_arg(a.clone()))
            .collect::<Vec<_>>()
            .join(" ")
    );
    shell_execute_elevated(exe, &args, Some(&hint))
}

fn shell_execute_elevated(
    exe: &std::path::Path,
    args: &[String],
    hint: Option<&str>,
) -> anyhow::Result<i32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HWND, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };

    let args_str = args
        .iter()
        .cloned()
        .map(quote_cmd_arg)
        .collect::<Vec<_>>()
        .join(" ");
    let hint = hint.unwrap_or("elevated command");

    let verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters: Vec<u16> = std::ffi::OsStr::new(&args_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.hwnd = 0 as HWND;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = 0;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 || info.hProcess.is_null() {
        anyhow::bail!(
            "UAC elevation failed or was cancelled.\n\
             Run manually in an elevated Command Prompt:\n  \
             {hint}"
        );
    }

    loop {
        let wait = unsafe { WaitForSingleObject(info.hProcess, 50) };
        if wait == WAIT_OBJECT_0 {
            break;
        }
    }

    let exit_code = unsafe {
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hProcess);
        exit_code
    };

    Ok(exit_code as i32)
}

fn drain_capture_buf(
    path: &std::path::Path,
    offset: &mut u64,
    chunk: &mut Vec<u8>,
    out: &mut Vec<u8>,
) {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    if f.seek(SeekFrom::Start(*offset)).is_err() {
        return;
    }
    chunk.clear();
    if f.read_to_end(chunk).is_ok() && !chunk.is_empty() {
        out.extend_from_slice(chunk);
        *offset += chunk.len() as u64;
    }
}

fn quote_cmd_arg(arg: String) -> String {
    if arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"') {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg
    }
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
        let sleep = status
            .wait_hint
            .min(Duration::from_secs(2))
            .max(Duration::from_millis(200));
        std::thread::sleep(sleep);
    }
}

use std::sync::OnceLock;

const ELEVATION_OUTPUT_FLAG: &str = "--tunnet-elevation-output";

static FILTERED_ARGS: OnceLock<Vec<String>> = OnceLock::new();

/// Args for clap after stripping the elevation capture flag (call after [`setup_elevation_capture`]).
pub fn args_for_clap() -> Vec<String> {
    FILTERED_ARGS
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::args().collect())
}

/// Capture stdout/stderr of an elevated relaunch into a temp file, then strip the flag from argv.
/// Must run before clap parses args.
pub fn setup_elevation_capture() {
    let mut args: Vec<String> = std::env::args().collect();
    let path = take_elevation_output_path(&mut args);
    let _ = FILTERED_ARGS.set(args);

    let Some(path) = path else {
        return;
    };

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    unsafe {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::{
            STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };
        let handle = file.as_raw_handle();
        SetStdHandle(STD_OUTPUT_HANDLE, handle);
        SetStdHandle(STD_ERROR_HANDLE, handle);
    }

    std::mem::forget(file);

    let _ = std::thread::Builder::new()
        .name("elevation-flush".into())
        .spawn(|| {
            loop {
                std::thread::sleep(Duration::from_millis(20));
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        });
}

fn take_elevation_output_path(args: &mut Vec<String>) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == ELEVATION_OUTPUT_FLAG {
            if i + 1 < args.len() {
                let path = args[i + 1].clone();
                args.drain(i..=i + 1);
                return Some(path);
            }
            args.remove(i);
            return None;
        }
        if let Some(path) = arg.strip_prefix(&format!("{ELEVATION_OUTPUT_FLAG}=")) {
            let path = path.to_string();
            args.remove(i);
            return Some(path);
        }
        i += 1;
    }
    None
}
