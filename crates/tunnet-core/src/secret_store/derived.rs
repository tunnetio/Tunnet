//! Machine-bound wrapping keys for persistent state.

#[cfg(any(target_os = "macos", windows))]
use anyhow::Context;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_os = "android"
))]
use anyhow::bail;
use hkdf::Hkdf;
use sha2::Sha256;

const INFO: &[u8] = b"tunnet-state-enc-v1";

#[cfg_attr(target_os = "android", allow(dead_code))]
#[derive(Clone)]
pub(super) struct StableMachineId(String);

impl StableMachineId {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub(super) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

pub fn derive_wrap_key(salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    derive_wrap_key_for_machine(&read_machine_id()?, salt)
}

#[cfg_attr(target_os = "android", allow(dead_code))]
pub(super) fn derive_wrap_key_for_machine(
    machine_id: &StableMachineId,
    salt: &[u8],
) -> anyhow::Result<[u8; 32]> {
    hkdf(machine_id.0.as_bytes(), salt)
}

fn hkdf(ikm: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    // `None` requests RFC 5869's HashLen zero-byte default salt.
    let salt = (!salt.is_empty()).then_some(salt);
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut key = [0u8; 32];
    hkdf.expand(INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("derived key length is invalid"))?;
    Ok(key)
}

fn read_machine_id() -> anyhow::Result<StableMachineId> {
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let t = s.trim();
                if !t.is_empty() {
                    return Ok(StableMachineId::new(t));
                }
            }
        }
        bail!("no machine-id found");
    }
    #[cfg(target_os = "macos")]
    {
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
                    return Ok(StableMachineId::new(&rest[..end]));
                }
            }
        }
        bail!("IOPlatformUUID not found");
    }
    #[cfg(windows)]
    {
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
                    return Ok(StableMachineId::new(*guid));
                }
            }
        }
        bail!("MachineGuid not found");
    }
    #[cfg(target_os = "android")]
    {
        bail!("derived sealing is not available on Android");
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        windows,
        target_os = "android"
    )))]
    {
        Ok(StableMachineId::new("unknown-machine"))
    }
}
