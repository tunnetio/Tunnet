//! Machine-bound wrap key: HKDF-SHA256(machine-id || boot-id, salt).

#[cfg(any(target_os = "macos", windows))]
use anyhow::Context;
// Only the linux/macOS/Windows machine-id readers fail; the portable arm
// returns a constant.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use anyhow::bail;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const INFO: &[u8] = b"tunnet-state-enc-v1";

pub fn derive_wrap_key(salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let machine = read_machine_id()?;
    let boot = read_boot_id().unwrap_or_default();
    let mut ikm = Vec::with_capacity(machine.len() + boot.len());
    ikm.extend_from_slice(machine.as_bytes());
    ikm.push(b'|');
    ikm.extend_from_slice(boot.as_bytes());

    // HKDF-Extract: PRK = HMAC(salt, IKM)
    let mut extract = HmacSha256::new_from_slice(if salt.is_empty() { &[0u8; 32] } else { salt })
        .map_err(|_| anyhow::anyhow!("HMAC key"))?;
    extract.update(&ikm);
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC(PRK, info || 0x01)
    let mut expand = HmacSha256::new_from_slice(&prk).map_err(|_| anyhow::anyhow!("HMAC key"))?;
    expand.update(INFO);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    okm.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("derived key must be 32 bytes"))
}

fn read_machine_id() -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let t = s.trim();
                if !t.is_empty() {
                    return Ok(t.to_string());
                }
            }
        }
        bail!("no machine-id found");
    }
    #[cfg(target_os = "macos")]
    {
        // IOPlatformUUID via ioreg
        let out = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .context("ioreg")?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(rest) = line.split("IOPlatformUUID").nth(1)
                && let Some(start) = rest.find('"')
            {
                let rest = &rest[start + 1..];
                if let Some(end) = rest.find('"') {
                    return Ok(rest[..end].to_string());
                }
            }
        }
        bail!("IOPlatformUUID not found");
    }
    #[cfg(windows)]
    {
        // MachineGuid from registry
        let out = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .context("reg query MachineGuid")?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("MachineGuid") {
                let parts: Vec<_> = line.split_whitespace().collect();
                if let Some(guid) = parts.last() {
                    return Ok(guid.to_string());
                }
            }
        }
        bail!("MachineGuid not found");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok("unknown-machine".into())
    }
}

fn read_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
