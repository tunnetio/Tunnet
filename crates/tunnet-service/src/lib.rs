//! OS service install and control for Tunnet (`tunnetd`).
//!
//! This crate has no dependency on `tunnet-core` or `iroh`. State directories
//! use fixed system paths (`/var/lib/tunnet`, `%ProgramData%\tunnet`).

// Targets with no service manager (Android embeds this crate) reach only the
// "not supported on this OS" arm: the body bails, so what follows is
// unreachable, its parameters go unused, and the `paths` helpers that install
// would have called are never reached. That is the intended shape rather than
// neglect, so it is named here once instead of leaving warnings on every
// Android build. Scoped so the platforms that do install a service keep the
// full checks.
#![cfg_attr(
    not(any(windows, target_os = "linux", target_os = "macos")),
    allow(dead_code, unreachable_code, unused_variables)
)]

mod api_ready;
mod paths;

#[cfg(windows)]
mod win_service;

pub use api_ready::wait_for_local_api;
pub use paths::{resolve_state_dir, system_state_dir, wipe_state_dir};

#[cfg(windows)]
pub use paths::{installed_bin_dir, installed_daemon_exe, stage_daemon_exe};

#[cfg(windows)]
pub use win_service::{args_for_clap, run_elevated, setup_elevation_capture};

/// Ensure this process can perform admin-only Local API / service ops.
///
/// - Windows: triggers UAC and relaunches elevated if needed
/// - Unix: requires root (`sudo`)
pub fn ensure_admin() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        win_service::ensure_process_elevated()
    }
    #[cfg(unix)]
    {
        if !is_admin() {
            anyhow::bail!(
                "this command needs root.\n\
                 Re-run with sudo, e.g.:\n  \
                 sudo tunnet <command>"
            );
        }
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(())
    }
}

/// True when this process already has admin/root privileges.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        win_service::process_token_elevated()
    }
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "tunnet";
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.tunnet.agent";

/// Snapshot of the OS-managed Tunnet service (systemd / launchd / SCM).
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub installed: bool,
    pub active: bool,
    pub state: String,
}

impl ServiceProbe {
    pub fn not_installed() -> Self {
        Self {
            installed: false,
            active: false,
            state: "not-installed".into(),
        }
    }
}

pub fn install(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, true)
}

/// Rewrite the service unit without printing the install banner.
#[cfg(target_os = "linux")]
pub fn refresh_unit(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, false)
}

#[cfg(not(target_os = "linux"))]
pub fn refresh_unit(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, false)
}

fn install_inner(state_dir: Option<&str>, announce: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    let exe = {
        win_service::ensure_elevated()?;
        if paths::daemon_outdated(state_dir).unwrap_or(true) && win_service::probe().active {
            win_service::stop_and_wait()?;
        }
        let staged = paths::stage_daemon_exe(state_dir)?;
        staged
            .canonicalize()
            .unwrap_or(staged)
            .display()
            .to_string()
    };
    #[cfg(not(windows))]
    let exe = {
        let exe = paths::resolve_daemon_exe()?;
        exe.canonicalize().unwrap_or(exe).display().to_string()
    };
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("service install needs root: sudo tunnet service install");
        }
        install_systemd(&exe, state_dir)?;
        let _ = run_cmd("systemctl", &["enable", SERVICE_NAME]);
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("service install needs root: sudo tunnet service install");
        }
        install_launchd(&exe, state_dir)?;
    }
    #[cfg(windows)]
    {
        win_service::install(&exe, state_dir)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (exe, state_dir);
        anyhow::bail!("service install is not supported on this OS");
    }
    if announce {
        let dir = resolve_state_dir(state_dir).display().to_string();
        #[cfg(windows)]
        {
            println!("Service installed (state dir {dir}). Start with `tunnet service start`.");
        }
        #[cfg(not(windows))]
        {
            println!(
                "Service installed (state dir {dir}). Start with `sudo tunnet service start`."
            );
        }
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    #[cfg(windows)]
    win_service::ensure_elevated()?;
    let _ = stop(None);
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("service uninstall needs root: sudo tunnet service uninstall");
        }
        uninstall_systemd()?;
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("service uninstall needs root: sudo tunnet service uninstall");
        }
        uninstall_launchd()?;
    }
    #[cfg(windows)]
    {
        win_service::uninstall()?;
    }
    println!("Service uninstalled.");
    Ok(())
}

pub fn start(state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("starting the system service needs root: sudo tunnet service start");
        }
        println!("Starting tunnet service…");
        install_inner(state_dir, false)?;
        run_cmd("systemctl", &["start", SERVICE_NAME])?;
        let _ = run_cmd("systemctl", &["enable", SERVICE_NAME]);
        wait_for_local_api(std::time::Duration::from_secs(60))?;
        println!("Service is running.");
    }
    #[cfg(target_os = "macos")]
    {
        let plist = launchd_plist_path();
        if !plist.exists() {
            if is_root() {
                println!("LaunchDaemon not found; installing…");
                install_inner(state_dir, false)?;
            } else {
                anyhow::bail!("starting the service needs root: sudo tunnet service start");
            }
        } else if is_root() {
            install_inner(state_dir, false)?;
        }
        if !is_root() {
            anyhow::bail!("starting the service needs root: sudo tunnet service start");
        }
        println!("Starting tunnet service…");
        run_cmd(
            "launchctl",
            &["bootstrap", "system", &plist.display().to_string()],
        )
        .or_else(|_| run_cmd("launchctl", &["load", "-w", &plist.display().to_string()]))?;
        wait_for_local_api(std::time::Duration::from_secs(60))?;
        println!("Service is running.");
    }
    #[cfg(windows)]
    {
        win_service::ensure_elevated()?;
        install_inner(state_dir, false).map_err(|e| {
            anyhow::anyhow!("{e:#}\nRun an elevated Command Prompt: tunnet service start")
        })?;
        println!("Starting tunnet service…");
        win_service::start_and_wait()?;
        wait_for_local_api(std::time::Duration::from_secs(60))?;
        println!("Service is running.");
    }
    Ok(())
}

pub fn stop(_state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("stopping the service needs root: sudo tunnet service stop");
        }
        if !unit_path().exists() {
            anyhow::bail!("service unit not installed (nothing to stop)");
        }
        run_cmd("systemctl", &["stop", SERVICE_NAME])?;
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("stopping the service needs root: sudo tunnet service stop");
        }
        let _ = run_cmd(
            "launchctl",
            &["bootout", &format!("system/{LAUNCHD_LABEL}")],
        );
        let plist = launchd_plist_path();
        let _ = run_cmd("launchctl", &["unload", &plist.display().to_string()]);
    }
    #[cfg(windows)]
    {
        win_service::ensure_elevated()?;
        win_service::stop_and_wait()?;
    }
    println!("Service stopped.");
    Ok(())
}

/// Best-effort stop used by `tunnet reset` before wiping state files.
/// No-op when the service is not installed; does not print.
pub fn stop_for_reset() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unit_path().exists() {
            run_cmd("systemctl", &["stop", SERVICE_NAME])?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = run_cmd(
            "launchctl",
            &["bootout", &format!("system/{LAUNCHD_LABEL}")],
        );
        let plist = launchd_plist_path();
        if plist.exists() {
            let _ = run_cmd("launchctl", &["unload", &plist.display().to_string()]);
        }
    }
    #[cfg(windows)]
    {
        win_service::stop_and_wait()?;
    }
    Ok(())
}

pub fn restart(state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        win_service::ensure_elevated()?;
        println!("Restarting tunnet service…");
        install_inner(state_dir, false)?;
        if win_service::probe().active {
            win_service::stop_and_wait()?;
        }
        win_service::start_and_wait()?;
        wait_for_local_api(std::time::Duration::from_secs(60))?;
        println!("Service is running.");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = stop(state_dir);
        start(state_dir)
    }
}

pub fn probe() -> ServiceProbe {
    #[cfg(target_os = "linux")]
    {
        if !unit_path().exists() {
            return ServiceProbe::not_installed();
        }
        let output = std::process::Command::new("systemctl")
            .args(["is-active", SERVICE_NAME])
            .output();
        let state = match output {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    String::from_utf8_lossy(&o.stderr).trim().to_string()
                } else {
                    s
                }
            }
            Err(_) => "unknown".into(),
        };
        let state = if state.is_empty() {
            "unknown".into()
        } else {
            state
        };
        let active = state == "active";
        ServiceProbe {
            installed: true,
            active,
            state,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = launchd_plist_path();
        if !plist.exists() {
            return ServiceProbe::not_installed();
        }
        let output = std::process::Command::new("launchctl")
            .args(["print", &format!("system/{LAUNCHD_LABEL}")])
            .output();
        let ok = output.map(|o| o.status.success()).unwrap_or(false);
        ServiceProbe {
            installed: true,
            active: ok,
            state: if ok {
                "active".into()
            } else {
                "inactive".into()
            },
        }
    }
    #[cfg(windows)]
    {
        win_service::probe()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        ServiceProbe {
            installed: false,
            active: false,
            state: "unsupported".into(),
        }
    }
}

pub fn status() -> anyhow::Result<()> {
    let p = probe();
    if !p.installed {
        println!("Tunnet service is not installed.");
        #[cfg(windows)]
        println!("Start it with `tunnet service start`");
        #[cfg(not(windows))]
        println!("Start it with `sudo tunnet service start`");
    } else if p.active {
        println!("running ({})", p.state);
    } else {
        println!("installed, not running ({})", p.state);
        #[cfg(windows)]
        println!("Start it with `tunnet service start`.");
        #[cfg(not(windows))]
        println!("Start it with `sudo tunnet service start`.");
    }
    Ok(())
}

/// After create / enroll / join: restart the service if installed.
pub fn reload_after_config(state_dir: Option<&str>) -> anyhow::Result<()> {
    let dir = resolve_state_dir(state_dir);
    let probe = probe();

    #[cfg(target_os = "linux")]
    {
        if !probe.installed {
            println!(
                "State written to {}. Start the agent with:\n  sudo tunnet service start",
                dir.display()
            );
            return Ok(());
        }
        if !is_root() {
            println!(
                "State written to {}.\nRun: sudo tunnet service restart",
                dir.display()
            );
            return Ok(());
        }
        install_inner(state_dir, false)?;
        let _ = run_cmd("systemctl", &["restart", SERVICE_NAME]);
        wait_for_local_api(std::time::Duration::from_secs(60))?;
        println!("Agent loading network from {}…", dir.display());
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        if !probe.installed {
            println!(
                "State written to {}. Start with: sudo tunnet service start",
                dir.display()
            );
            return Ok(());
        }
        if is_root() {
            let _ = stop(state_dir);
            let _ = start(state_dir);
            println!("Agent reloading from {}…", dir.display());
        } else {
            println!(
                "State written to {}.\nRun: sudo tunnet service restart",
                dir.display()
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if probe.installed {
            if let Err(e) = install_inner(state_dir, false) {
                eprintln!("warning: refresh agent binary before reload: {e:#}");
            }
            let _ = win_service::stop_and_wait();
            win_service::start_and_wait()?;
            wait_for_local_api(std::time::Duration::from_secs(60))?;
            println!("Agent reloading from {}…", dir.display());
        } else {
            println!(
                "State written to {}. Start with: tunnet service start",
                dir.display()
            );
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (state_dir, dir, probe);
        Ok(())
    }
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_cmd(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(bin).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{bin} {} failed with {status}", args.join(" "));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unit_path() -> &'static std::path::Path {
    std::path::Path::new("/etc/systemd/system/tunnet.service")
}

#[cfg(any(test, target_os = "linux"))]
pub fn render_systemd_unit(exe: &str, state_dir: Option<&str>) -> String {
    let dir = resolve_state_dir(state_dir).display().to_string();
    format!(
        "[Unit]\n\
         Description=Tunnet mesh agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=notify-reload\n\
         ExecStart={exe}\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=always\n\
         RestartSec=2\n\
         KillMode=mixed\n\
         TimeoutStartSec=30\n\
         TimeoutStopSec=30\n\
         StateDirectory=tunnet\n\
         RuntimeDirectory=tunnet\n\
         RuntimeDirectoryMode=0755\n\
         Environment=TUNNET_STATE_DIR={dir}\n\
         Environment=TUNNET_RUNTIME_DIR=/run/tunnet\n\
         Environment=TUNNET_SERVICE_MODE=1\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
fn install_systemd(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    use anyhow::Context;
    let unit = render_systemd_unit(exe, state_dir);
    let path = std::path::Path::new("/etc/systemd/system/tunnet.service");
    std::fs::write(path, unit).with_context(|| format!("write {}", path.display()))?;
    run_cmd("systemctl", &["daemon-reload"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);
    let path = std::path::Path::new("/etc/systemd/system/tunnet.service");
    if path.exists() {
        std::fs::remove_file(path)?;
        let _ = run_cmd("systemctl", &["daemon-reload"]);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn install_launchd(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    use anyhow::Context;
    let dir = resolve_state_dir(state_dir).display().to_string();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>2</integer>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TUNNET_STATE_DIR</key>
    <string>{dir}</string>
  </dict>
</dict>
</plist>
"#
    );
    let path = launchd_plist_path();
    std::fs::write(&path, plist).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> anyhow::Result<()> {
    let path = launchd_plist_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_uses_tunnetd() {
        let unit = render_systemd_unit("/usr/bin/tunnetd", Some("/var/lib/tunnet"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=2"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("ExecStart=/usr/bin/tunnetd"));
        assert!(!unit.contains(" run"));
        assert!(unit.contains("Type=notify-reload"));
        assert!(unit.contains("TimeoutStartSec=30"));
        assert!(unit.contains("ExecReload=/bin/kill -HUP $MAINPID"));
        assert!(unit.contains("TUNNET_STATE_DIR=/var/lib/tunnet"));
        assert!(unit.contains("StateDirectory=tunnet"));
        assert!(unit.contains("RuntimeDirectory=tunnet"));
        assert!(unit.contains("RuntimeDirectoryMode=0755"));
        assert!(unit.contains("TUNNET_RUNTIME_DIR=/run/tunnet"));
        assert!(unit.contains("TUNNET_SERVICE_MODE=1"));
    }

    #[test]
    fn systemd_unit_defaults_system_state_dir() {
        let unit = render_systemd_unit("/usr/bin/tunnetd", None);
        let expected = format!("TUNNET_STATE_DIR={}", system_state_dir().display());
        assert!(unit.contains(&expected), "unit missing {expected}: {unit}");
    }
}
