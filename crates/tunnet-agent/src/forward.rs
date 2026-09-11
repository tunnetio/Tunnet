//! IP forwarding + NAT (MASQUERADE) for exit-node / subnet gateways.

// Every caller is inside a `cfg(target_os = "linux")` block: nftables and
// iptables are the only NAT backends here, so other targets never shell out.
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Mutex;

static NAT_STATE: Mutex<Option<NatGuardInner>> = Mutex::new(None);

struct NatGuardInner {
    uplink: String,
    #[cfg(target_os = "linux")]
    used_nft: bool,
}

/// Enable forwarding + MASQUERADE when this node advertises an exit / subnet gateway.
pub fn ensure_exit_nat(advertise: bool) {
    if !advertise {
        teardown_exit_nat();
        return;
    }
    let Some(uplink) = crate::underlay::default_uplink_name() else {
        tracing::warn!("exit NAT: could not detect uplink interface");
        return;
    };
    enable_forwarding();
    if install_masquerade(&uplink) {
        let mut g = NAT_STATE.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(NatGuardInner {
            uplink,
            #[cfg(target_os = "linux")]
            used_nft: prefer_nft(),
        });
        tracing::info!("exit NAT (MASQUERADE) enabled");
    }
}

pub fn teardown_exit_nat() {
    let mut g = NAT_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = g.take() else {
        return;
    };
    remove_masquerade(&state.uplink, cfg_nft(&state));
    tracing::info!(uplink = %state.uplink, "exit NAT torn down");
}

#[cfg(target_os = "linux")]
fn cfg_nft(state: &NatGuardInner) -> bool {
    state.used_nft
}

#[cfg(not(target_os = "linux"))]
fn cfg_nft(_: &NatGuardInner) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn prefer_nft() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn enable_forwarding() {
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1") {
            tracing::warn!(?e, "failed to enable net.ipv4.ip_forward");
        } else {
            tracing::info!("enabled net.ipv4.ip_forward");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .status();
        tracing::info!("enabled net.inet.ip.forwarding");
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue",
            ])
            .status();
        tracing::info!("requested Windows IP forwarding");
    }
}

fn install_masquerade(uplink: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        if prefer_nft() {
            // Tunnet-owned table; replace on each enable.
            let script = format!(
                "table ip tunnet_nat {{\n  chain postrouting {{\n    type nat hook postrouting priority 100;\n    oifname \"{uplink}\" masquerade\n  }}\n}}\n"
            );
            let _ = Command::new("nft")
                .args(["delete", "table", "ip", "tunnet_nat"])
                .status();
            let status = Command::new("nft")
                .arg("-f")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(mut stdin) = child.stdin.take() {
                        stdin.write_all(script.as_bytes())?;
                    }
                    child.wait()
                });
            match status {
                Ok(s) if s.success() => return true,
                Ok(s) => tracing::warn!(?s, "nft masquerade failed; trying iptables"),
                Err(e) => tracing::warn!(?e, "nft spawn failed; trying iptables"),
            }
        }
        // iptables fallback with Tunnet comment.
        let _ = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                "tunnet-exit",
            ])
            .status();
        let ok = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                "tunnet-exit",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            tracing::warn!(uplink, "iptables MASQUERADE failed");
        }
        return ok;
    }
    #[cfg(target_os = "macos")]
    {
        // pf anchor owned by Tunnet.
        let rules = format!("nat on {uplink} from any to any -> ({uplink})\n");
        let path = "/tmp/tunnet-nat.conf";
        if std::fs::write(path, &rules).is_err() {
            tracing::warn!("failed to write pf nat rules");
            return false;
        }
        let _ = Command::new("pfctl")
            .args(["-a", "com.tunnet/nat", "-f", path])
            .status();
        let _ = Command::new("pfctl").args(["-e"]).status();
        tracing::info!(uplink, "installed pf nat anchor com.tunnet/nat");
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        // Best-effort Hyper-V style NAT; fail loud if unavailable.
        let ps = "if (-not (Get-NetNat -Name 'TunnetExit' -ErrorAction SilentlyContinue)) { New-NetNat -Name 'TunnetExit' -InternalIPInterfaceAddressPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue }; Write-Output 'ok'";
        let ok = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            tracing::warn!(
                uplink,
                "Windows New-NetNat failed; exit return traffic needs manual NAT"
            );
        }
        return ok;
    }
    #[allow(unreachable_code)]
    {
        let _ = uplink;
        false
    }
}

fn remove_masquerade(uplink: &str, used_nft: bool) {
    #[cfg(not(target_os = "linux"))]
    let _ = (uplink, used_nft);
    #[cfg(target_os = "linux")]
    {
        if used_nft {
            let _ = Command::new("nft")
                .args(["delete", "table", "ip", "tunnet_nat"])
                .status();
        }
        let _ = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                "tunnet-exit",
            ])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = uplink;
        let _ = Command::new("pfctl")
            .args(["-a", "com.tunnet/nat", "-F", "all"])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = uplink;
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Remove-NetNat -Name 'TunnetExit' -Confirm:$false -ErrorAction SilentlyContinue",
            ])
            .status();
    }
    let _ = used_nft;
}
