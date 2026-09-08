mod antivirus;
mod app_check;
mod custom_script;
mod disk_encryption;
mod domain_joined;
mod file_check;
mod firewall;
mod mac_security;
mod mdm;
mod os_info;
mod os_updates;
mod screen_lock;
mod secure_boot;
mod tpm;

pub use antivirus::AntivirusCollector;
pub use app_check::{AppCheckConfig, ApplicationCheckCollector};
pub use custom_script::{CustomScriptCollector, CustomScriptConfig};
pub use disk_encryption::DiskEncryptionCollector;
pub use domain_joined::DomainJoinedCollector;
pub use file_check::{FileCheckCollector, FileCheckConfig};
pub use firewall::FirewallCollector;
pub use mac_security::MacSecurityCollector;
pub use mdm::MdmCollector;
pub use os_info::OsCollector;
pub use os_updates::OsUpdatesCollector;
pub use screen_lock::ScreenLockCollector;
pub use secure_boot::SecureBootCollector;
pub use tpm::TpmCollector;

use std::process::Stdio;
use tokio::process::Command;

/// Run a shell command and return stdout as a trimmed string.
pub(crate) async fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(windows)]
pub(crate) async fn run_powershell(script: &str) -> Option<String> {
    run_command(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
    .await
}
