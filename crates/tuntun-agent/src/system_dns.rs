//! Platform DNS configuration so the OS uses TunTun PeerDNS.

use std::net::Ipv4Addr;

/// Configure the system to prefer `dns_ip` for resolution. Best-effort;
/// failures are logged and non-fatal.
pub fn configure(dns_ip: Ipv4Addr, suffix: &str) -> anyhow::Result<DnsGuard> {
    #[cfg(target_os = "linux")]
    {
        linux::configure(dns_ip, suffix)
    }
    #[cfg(target_os = "macos")]
    {
        macos::configure(dns_ip, suffix)
    }
    #[cfg(target_os = "windows")]
    {
        windows::configure(dns_ip, suffix)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (dns_ip, suffix);
        tracing::warn!("PeerDNS system configuration unsupported on this OS");
        Ok(DnsGuard::noop())
    }
}

pub struct DnsGuard {
    _restore: Option<Box<dyn FnOnce() + Send>>,
}

impl DnsGuard {
    fn noop() -> Self {
        Self { _restore: None }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Some(restore) = self._restore.take() {
            restore();
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use std::fs;
    use std::path::PathBuf;

    pub fn configure(dns_ip: Ipv4Addr, suffix: &str) -> anyhow::Result<DnsGuard> {
        // Prefer systemd-resolved drop-in when available.
        let resolved_dir = PathBuf::from("/etc/systemd/resolved.conf.d");
        if resolved_dir.parent().is_some_and(|p| p.exists()) {
            let _ = fs::create_dir_all(&resolved_dir);
            let conf_path = resolved_dir.join("tuntun-PeerDNS.conf");
            let body = format!("[Resolve]\nDNS={dns_ip}\nDomains=~{suffix}\n");
            match fs::write(&conf_path, body) {
                Ok(()) => {
                    let _ = std::process::Command::new("systemctl")
                        .args(["restart", "systemd-resolved"])
                        .status();
                    tracing::info!(%dns_ip, %suffix, "configured systemd-resolved for PeerDNS");
                    return Ok(DnsGuard {
                        _restore: Some(Box::new(move || {
                            let _ = fs::remove_file(&conf_path);
                            let _ = std::process::Command::new("systemctl")
                                .args(["restart", "systemd-resolved"])
                                .status();
                        })),
                    });
                }
                Err(e) => tracing::warn!(?e, "could not write systemd-resolved drop-in"),
            }
        }

        // Fallback: prepend to /etc/resolv.conf with backup.
        let resolv = PathBuf::from("/etc/resolv.conf");
        let backup = PathBuf::from("/etc/resolv.conf.tuntun.bak");
        if resolv.exists() && !backup.exists() {
            let _ = fs::copy(&resolv, &backup);
        }
        let existing = fs::read_to_string(&resolv).unwrap_or_default();
        if existing.contains(&format!("nameserver {dns_ip}")) {
            return Ok(DnsGuard::noop());
        }
        let mut new_content = format!("# TunTun PeerDNS\nnameserver {dns_ip}\n");
        new_content.push_str(&existing);
        fs::write(&resolv, new_content).context("write /etc/resolv.conf")?;
        tracing::info!(%dns_ip, "prepended PeerDNS to /etc/resolv.conf");
        Ok(DnsGuard {
            _restore: Some(Box::new(move || {
                if backup.exists() {
                    let _ = fs::copy(&backup, &resolv);
                    let _ = fs::remove_file(&backup);
                }
            })),
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::path::PathBuf;

    pub fn configure(dns_ip: Ipv4Addr, suffix: &str) -> anyhow::Result<DnsGuard> {
        // Create a resolver domain file under /etc/resolver/<suffix>
        let path = PathBuf::from(format!("/etc/resolver/{suffix}"));
        let _ = std::fs::create_dir_all("/etc/resolver");
        std::fs::write(&path, format!("nameserver {dns_ip}\n"))?;
        tracing::info!(%dns_ip, %suffix, "configured /etc/resolver for PeerDNS");
        Ok(DnsGuard {
            _restore: Some(Box::new(move || {
                let _ = std::fs::remove_file(&path);
            })),
        })
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    pub fn configure(dns_ip: Ipv4Addr, _suffix: &str) -> anyhow::Result<DnsGuard> {
        let status = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                "name=tuntun0",
                "static",
                &dns_ip.to_string(),
            ])
            .status();
        match status {
            Ok(s) if s.success() => {
                tracing::info!(%dns_ip, "configured Windows DNS for tuntun0");
            }
            Ok(s) => tracing::warn!(?s, "netsh DNS set returned non-zero"),
            Err(e) => tracing::warn!(?e, "netsh DNS set failed"),
        }
        Ok(DnsGuard::noop())
    }
}
