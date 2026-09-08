//! Internal Windows TUN backend.
//!
//! The architecture-specific Wintun library is compiled into `tunnetd`.
//! `tun-rs` still needs a filesystem path, so the bytes are written to a
//! private runtime file when the TUN device is created. That file is not a
//! product artifact and is not installed, packaged, or updated separately.

use std::path::PathBuf;

use anyhow::Context;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "x86_64")]
const WINTUN: &[u8] = include_bytes!("../resources/wintun/amd64/wintun.dll");
#[cfg(target_arch = "aarch64")]
const WINTUN: &[u8] = include_bytes!("../resources/wintun/arm64/wintun.dll");

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Windows TUN backend is vendored only for x86_64 and aarch64");

pub fn materialize() -> anyhow::Result<PathBuf> {
    let hash = hex::encode(Sha256::digest(WINTUN));
    let dir = tunnet_core::StatePaths::resolve(None).runtime_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let dest = dir.join(format!("wintun-{}.dll", &hash[..16]));
    if dest.is_file()
        && let Ok(existing) = std::fs::read(&dest)
        && existing.as_slice() == WINTUN
    {
        return Ok(dest);
    }
    let tmp = dest.with_extension("dll.tmp");
    std::fs::write(&tmp, WINTUN).with_context(|| format!("write {}", tmp.display()))?;
    match std::fs::rename(&tmp, &dest) {
        Ok(()) => Ok(dest),
        Err(_) if dest.is_file() => {
            let _ = std::fs::remove_file(&tmp);
            Ok(dest)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            Err(error).with_context(|| format!("replace {}", dest.display()))
        }
    }
}
