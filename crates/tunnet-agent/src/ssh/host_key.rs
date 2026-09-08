//! SSH host key load-or-create in the agent state directory.

use anyhow::Context;
use russh::keys::{Algorithm, PrivateKey};
use tunnet_core::StatePaths;

/// Load an OpenSSH Ed25519 host key from the agent state directory, or generate and persist one.
pub fn load_or_create_host_key(paths: &StatePaths) -> anyhow::Result<PrivateKey> {
    let path = paths.ssh_host_key_file();
    if path.is_file() {
        let key = PrivateKey::read_openssh_file(&path)
            .with_context(|| format!("read host key {}", path.display()))?;
        return Ok(key);
    }
    paths
        .ensure()
        .with_context(|| format!("create state dir {}", paths.root().display()))?;
    let key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).context("generate host key")?;
    key.write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)
        .with_context(|| format!("write host key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %path.display(), "generated SSH host key");
    Ok(key)
}

/// OpenSSH public key line for the local host key (`ssh-ed25519 AAAA...`).
pub fn host_pubkey_openssh(paths: &StatePaths) -> anyhow::Result<String> {
    let key = load_or_create_host_key(paths)?;
    key.public_key().to_openssh().context("encode host pubkey")
}
