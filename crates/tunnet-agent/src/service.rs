//! OS service install / control (systemd, launchd, Windows SCM).

#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

use anyhow::Context;

#[cfg(any(target_os = "macos", windows))]
use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_NAME: &str = "tunnet";
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.tunnet.agent";

#[cfg(target_os = "linux")]
fn unit_path() -> &'static Path {
    Path::new("/etc/systemd/system/tunnet.service")
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn install(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, true)
}

/// Rewrite the service unit without printing the install banner.
#[cfg(target_os = "linux")]
pub fn refresh_unit(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, false)
}

fn install_inner(state_dir: Option<&str>, announce: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("resolve current executable")?;
    let exe = exe.canonicalize().unwrap_or(exe).display().to_string();
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
        crate::win_service::install(&exe, state_dir)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (exe, state_dir);
        anyhow::bail!("service install is not supported on this OS");
    }
    if announce {
        let dir = state_dir
            .map(str::to_string)
            .unwrap_or_else(|| tunnet_core::StatePaths::system_dir().display().to_string());
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
        crate::win_service::uninstall()?;
    }
    println!("Service uninstalled.");
    Ok(())
}

pub fn start(state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            if !unit_path().exists() {
                anyhow::bail!(
                    "service unit not installed. Run:\n  sudo tunnet service install\n  sudo tunnet service start"
                );
            }
            anyhow::bail!("starting the system service needs root: sudo tunnet service start");
        }
        println!("Starting tunnet service…");
        // Always refresh the unit so state dir / RestartSec stay current.
        install_inner(state_dir, false)?;
        run_cmd("systemctl", &["start", SERVICE_NAME])?;
        let _ = run_cmd("systemctl", &["enable", SERVICE_NAME]);
        if Command::new("systemctl")
            .args(["is-active", "--quiet", SERVICE_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            println!("Service is running.");
            println!(
                "Next: `tunnet create` or `tunnet enroll` if this host is not on a network yet."
            );
        } else {
            println!("Service start issued; check status with: systemctl status tunnet");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = launchd_plist_path();
        if !plist.exists() {
            if is_root() {
                println!("LaunchDaemon not found; installing…");
                install_inner(state_dir, false)?;
            } else {
                anyhow::bail!(
                    "service not installed. Run:\n  sudo tunnet service install\n  sudo tunnet service start"
                );
            }
        } else if is_root() {
            // Refresh plist / env on start.
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
        println!("Service is running.");
    }
    #[cfg(windows)]
    {
        let initial = crate::win_service::probe();
        if !initial.installed {
            println!("Service not installed; installing…");
            install_inner(state_dir, false).map_err(|e| {
                anyhow::anyhow!(
                    "{e:#}\nRun an elevated Command Prompt: tunnet service install && tunnet service start"
                )
            })?;
        } else {
            // Heal enroll-then-install: copy user profile state into ProgramData.
            let dir = state_dir
                .map(PathBuf::from)
                .unwrap_or_else(tunnet_core::StatePaths::system_dir);
            let migrated = crate::win_service::migrate_user_state_into_system(dir)?;
            if migrated && initial.active {
                // Idle service was waiting on an empty ProgramData; restart to load state.
                crate::win_service::stop_and_wait()?;
            }
            if state_dir.is_some() {
                let _ = install_inner(state_dir, false);
            }
        }
        println!("Starting tunnet service…");
        crate::win_service::ensure_wintun_present()?;
        crate::win_service::start_and_wait()?;
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
        crate::win_service::stop_and_wait()?;
    }
    println!("Service stopped.");
    Ok(())
}

pub fn restart(state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        // Stop+wait then start+wait - avoid sc's 1056 "already running" race.
        let _ = state_dir;
        println!("Restarting tunnet service…");
        crate::win_service::stop_and_wait()?;
        crate::win_service::start_and_wait()?;
        println!("Service is running.");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = stop(state_dir);
        start(state_dir)
    }
}

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

/// When a system service is installed, create/enroll/join must write the same
/// state dir the service reads - otherwise SCM looks healthy while the CLI sees
/// a different (offline) network.
pub fn ensure_service_state_aligned(
    state_dir: Option<&str>,
    paths: &tunnet_core::StatePaths,
) -> anyhow::Result<()> {
    let probe = probe();
    if !probe.installed {
        return Ok(());
    }
    let system = tunnet_core::StatePaths::system_dir();
    if paths.dir == system {
        return Ok(());
    }
    if state_dir.is_some() {
        // Explicit --state-dir / env: allow, but warn.
        eprintln!(
            "warning: writing to {} while the system service uses {}",
            paths.dir.display(),
            system.display()
        );
        return Ok(());
    }
    #[cfg(windows)]
    {
        anyhow::bail!(
            "a system service is installed and uses {}\n\
             you are about to write to {} instead\n\n\
             Re-run elevated so both use the same directory:\n\
               tunnet enroll --control-url <URL> --token <TOKEN>\n\n\
             Or point both at one directory:\n\
               set TUNNET_STATE_DIR={}\n\
               tunnet enroll ...\n\
               tunnet service restart",
            system.display(),
            paths.dir.display(),
            system.display()
        );
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!(
            "a system service is installed and uses {}\n\
             you are about to write to {} instead\n\n\
             Re-run with sudo so both use the same directory:\n\
               sudo tunnet create --name <name> [--secret <passphrase>]\n\n\
             Or point both at one directory:\n\
               sudo TUNNET_STATE_DIR={} tunnet create ...\n\
               sudo tunnet service restart",
            system.display(),
            paths.dir.display(),
            system.display()
        );
    }
}

/// Probe whether the system service unit is installed and running.
/// Does not require network state; used by `tunnet status`.
pub fn probe() -> ServiceProbe {
    #[cfg(target_os = "linux")]
    {
        if !unit_path().exists() {
            return ServiceProbe::not_installed();
        }
        let output = Command::new("systemctl")
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
        let output = Command::new("launchctl")
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
        crate::win_service::probe()
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
        println!("not-installed");
    } else {
        println!("{}", p.state);
    }
    Ok(())
}

/// After create / enroll / join: ensure the agent process loads the new state.
/// With an idle-waiting service this is a no-op restart if already watching the
/// same directory; restart still covers crash-loop leftovers and mid-run resets.
pub fn reload_after_config(state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = tunnet_core::StatePaths::resolve(state_dir);
    let probe = probe();

    #[cfg(target_os = "linux")]
    {
        if !probe.installed {
            println!(
                "State written to {}. Start the agent with:\n  sudo tunnet service start",
                paths.dir.display()
            );
            return Ok(());
        }
        if !is_root() {
            println!(
                "State written to {}.\nRun: sudo tunnet service restart",
                paths.dir.display()
            );
            return Ok(());
        }
        // Make sure the unit points at the same state dir, then restart so a
        // previously crash-looping process picks up idle-wait + new state.
        install_inner(state_dir, false)?;
        let _ = run_cmd("systemctl", &["restart", SERVICE_NAME]);
        println!("Agent loading network from {}…", paths.dir.display());
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        if !probe.installed {
            println!(
                "State written to {}. Start with: sudo tunnet service start",
                paths.dir.display()
            );
            return Ok(());
        }
        if is_root() {
            let _ = stop(state_dir);
            let _ = start(state_dir);
            println!("Agent reloading from {}…", paths.dir.display());
        } else {
            println!(
                "State written to {}.\nRun: sudo tunnet service restart",
                paths.dir.display()
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        if probe.installed {
            if let Err(e) = crate::win_service::stop_and_wait() {
                eprintln!("warning: stop before reload: {e:#}");
            }
            crate::win_service::start_and_wait()?;
            println!("Agent reloading from {}…", paths.dir.display());
        } else {
            println!(
                "State written to {}. Start with: tunnet service start",
                paths.dir.display()
            );
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (state_dir, paths, probe);
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_cmd(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(bin).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{bin} {} failed with {status}", args.join(" "));
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
pub fn render_systemd_unit(exe: &str, state_dir: Option<&str>) -> String {
    let dir = state_dir
        .map(str::to_string)
        .unwrap_or_else(|| tunnet_core::StatePaths::system_dir().display().to_string());
    format!(
        "[Unit]\n\
         Description=Tunnet mesh agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=notify-reload\n\
         ExecStart={exe} run\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=always\n\
         RestartSec=2\n\
         KillMode=mixed\n\
         TimeoutStartSec=30\n\
         TimeoutStopSec=30\n\
         StateDirectory=tunnet\n\
         Environment=TUNNET_STATE_DIR={dir}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
fn install_systemd(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let unit = render_systemd_unit(exe, state_dir);
    let path = Path::new("/etc/systemd/system/tunnet.service");
    std::fs::write(path, unit).with_context(|| format!("write {}", path.display()))?;
    run_cmd("systemctl", &["daemon-reload"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);
    let path = Path::new("/etc/systemd/system/tunnet.service");
    if path.exists() {
        std::fs::remove_file(path)?;
        let _ = run_cmd("systemctl", &["daemon-reload"]);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn install_launchd(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let dir = state_dir
        .map(str::to_string)
        .unwrap_or_else(|| tunnet_core::StatePaths::system_dir().display().to_string());
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
    <string>run</string>
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
    fn systemd_unit_contains_restart() {
        let unit = render_systemd_unit("/usr/bin/tunnet", Some("/var/lib/tunnet"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=2"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("ExecStart=/usr/bin/tunnet run"));
        assert!(unit.contains("Type=notify-reload"));
        assert!(unit.contains("TimeoutStartSec=30"));
        assert!(unit.contains("ExecReload=/bin/kill -HUP $MAINPID"));
        assert!(unit.contains("TUNNET_STATE_DIR=/var/lib/tunnet"));
        assert!(unit.contains("StateDirectory=tunnet"));
    }

    #[test]
    fn systemd_unit_defaults_system_state_dir() {
        let unit = render_systemd_unit("/usr/bin/tunnet", None);
        let expected = format!(
            "TUNNET_STATE_DIR={}",
            tunnet_core::StatePaths::system_dir().display()
        );
        assert!(unit.contains(&expected), "unit missing {expected}: {unit}");
    }
}
