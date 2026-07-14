//! OS service install / control (systemd, launchd, Windows SCM).

#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;

use anyhow::Context;

#[cfg(target_os = "macos")]
use std::path::PathBuf;

const SERVICE_NAME: &str = "tuntun";
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.tuntun.agent";

#[cfg(target_os = "linux")]
fn unit_path() -> &'static Path {
    Path::new("/etc/systemd/system/tuntun.service")
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn install(state_dir: Option<&str>) -> anyhow::Result<()> {
    install_inner(state_dir, true)
}

fn install_inner(state_dir: Option<&str>, announce: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("resolve current executable")?;
    let exe = exe.canonicalize().unwrap_or(exe).display().to_string();
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("service install needs root: sudo tuntun service install");
        }
        install_systemd(&exe, state_dir)?;
        let _ = run_cmd("systemctl", &["enable", SERVICE_NAME]);
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("service install needs root: sudo tuntun service install");
        }
        install_launchd(&exe, state_dir)?;
    }
    #[cfg(windows)]
    {
        install_windows(&exe, state_dir)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (exe, state_dir);
        anyhow::bail!("service install is not supported on this OS");
    }
    if announce {
        let dir = state_dir
            .map(str::to_string)
            .unwrap_or_else(|| tuntun_core::StatePaths::system_dir().display().to_string());
        println!("Service installed (state dir {dir}). Start with `sudo tuntun service start`.");
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let _ = stop(None);
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("service uninstall needs root: sudo tuntun service uninstall");
        }
        uninstall_systemd()?;
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("service uninstall needs root: sudo tuntun service uninstall");
        }
        uninstall_launchd()?;
    }
    #[cfg(windows)]
    {
        uninstall_windows()?;
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
                    "service unit not installed. Run:\n  sudo tuntun service install\n  sudo tuntun service start"
                );
            }
            anyhow::bail!("starting the system service needs root: sudo tuntun service start");
        }
        // Always refresh the unit so state dir / RestartSec stay current.
        install_inner(state_dir, false)?;
        run_cmd("systemctl", &["start", SERVICE_NAME])?;
        let _ = run_cmd("systemctl", &["enable", SERVICE_NAME]);
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
                    "service not installed. Run:\n  sudo tuntun service install\n  sudo tuntun service start"
                );
            }
        } else if is_root() {
            // Refresh plist / env on start.
            install_inner(state_dir, false)?;
        }
        if !is_root() {
            anyhow::bail!("starting the service needs root: sudo tuntun service start");
        }
        run_cmd(
            "launchctl",
            &["bootstrap", "system", &plist.display().to_string()],
        )
        .or_else(|_| run_cmd("launchctl", &["load", "-w", &plist.display().to_string()]))?;
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        if let Err(e) = run_cmd("sc", &["start", SERVICE_NAME]) {
            anyhow::bail!("{e}\nIf the service is missing, run elevated: tuntun service install");
        }
    }
    println!("Service started.");
    Ok(())
}

pub fn stop(_state_dir: Option<&str>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            anyhow::bail!("stopping the service needs root: sudo tuntun service stop");
        }
        if !unit_path().exists() {
            anyhow::bail!("service unit not installed (nothing to stop)");
        }
        run_cmd("systemctl", &["stop", SERVICE_NAME])?;
    }
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            anyhow::bail!("stopping the service needs root: sudo tuntun service stop");
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
        let _ = run_cmd("sc", &["stop", SERVICE_NAME]);
    }
    println!("Service stopped.");
    Ok(())
}

pub fn restart(state_dir: Option<&str>) -> anyhow::Result<()> {
    let _ = stop(state_dir);
    start(state_dir)
}

/// Snapshot of the OS-managed TunTun service (systemd / launchd / SCM).
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

/// Probe whether the system service unit is installed and running.
/// Does not require network state; used by `tuntun status`.
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
        let output = Command::new("sc").args(["query", SERVICE_NAME]).output();
        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let active = text.contains("RUNNING");
                let state = if active {
                    "active"
                } else if text.contains("STOPPED") {
                    "inactive"
                } else {
                    "unknown"
                };
                ServiceProbe {
                    installed: true,
                    active,
                    state: state.into(),
                }
            }
            _ => ServiceProbe::not_installed(),
        }
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
    let paths = tuntun_core::StatePaths::resolve(state_dir);
    let probe = probe();

    #[cfg(target_os = "linux")]
    {
        if !probe.installed {
            println!(
                "State written to {}. Start the agent with:\n  sudo tuntun service start",
                paths.dir.display()
            );
            return Ok(());
        }
        if !is_root() {
            println!(
                "State written to {}.\nRun: sudo tuntun service restart",
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
                "State written to {}. Start with: sudo tuntun service start",
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
                "State written to {}.\nRun: sudo tuntun service restart",
                paths.dir.display()
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        if probe.installed {
            let _ = run_cmd("sc", &["stop", SERVICE_NAME]);
            let _ = run_cmd("sc", &["start", SERVICE_NAME]);
            println!("Agent reloading from {}…", paths.dir.display());
        } else {
            println!(
                "State written to {}. Start with: tuntun service start (elevated)",
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
        .unwrap_or_else(|| tuntun_core::StatePaths::system_dir().display().to_string());
    format!(
        "[Unit]\n\
         Description=TunTun mesh agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} run\n\
         Restart=always\n\
         RestartSec=2\n\
         StateDirectory=tuntun\n\
         Environment=TUNTUN_STATE_DIR={dir}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
fn install_systemd(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let unit = render_systemd_unit(exe, state_dir);
    let path = Path::new("/etc/systemd/system/tuntun.service");
    std::fs::write(path, unit).with_context(|| format!("write {}", path.display()))?;
    run_cmd("systemctl", &["daemon-reload"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);
    let path = Path::new("/etc/systemd/system/tuntun.service");
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
        .unwrap_or_else(|| tuntun_core::StatePaths::system_dir().display().to_string());
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
    <key>TUNTUN_STATE_DIR</key>
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

#[cfg(windows)]
fn install_windows(exe: &str, state_dir: Option<&str>) -> anyhow::Result<()> {
    let bin_path = format!("\"{exe}\" run --service");
    let dir = state_dir
        .map(str::to_string)
        .unwrap_or_else(|| tuntun_core::StatePaths::system_dir().display().to_string());
    let _ = Command::new("setx")
        .args(["TUNTUN_STATE_DIR", &dir, "/M"])
        .status();
    run_cmd(
        "sc",
        &[
            "create",
            SERVICE_NAME,
            &format!("binPath= {bin_path}"),
            "start= auto",
            "DisplayName= TunTun Agent",
        ],
    )?;
    let _ = run_cmd(
        "sc",
        &["failure", SERVICE_NAME, "reset= 0", "actions= restart/2000"],
    );
    Ok(())
}

#[cfg(windows)]
fn uninstall_windows() -> anyhow::Result<()> {
    let _ = run_cmd("sc", &["delete", SERVICE_NAME]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_contains_restart() {
        let unit = render_systemd_unit("/usr/bin/tuntun", Some("/var/lib/tuntun"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=2"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("ExecStart=/usr/bin/tuntun run"));
        assert!(unit.contains("TUNTUN_STATE_DIR=/var/lib/tuntun"));
        assert!(unit.contains("StateDirectory=tuntun"));
    }

    #[test]
    fn systemd_unit_defaults_system_state_dir() {
        let unit = render_systemd_unit("/usr/bin/tuntun", None);
        let expected = format!(
            "TUNTUN_STATE_DIR={}",
            tuntun_core::StatePaths::system_dir().display()
        );
        assert!(unit.contains(&expected), "unit missing {expected}: {unit}");
    }
}
