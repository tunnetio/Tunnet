//! Platform-specific DEK wrapping: Windows DPAPI (TPM-capable), macOS Keychain.

use super::SealTier;
use anyhow::bail;

/// Prefer the strongest available local seal.
pub fn best_tier() -> SealTier {
    #[cfg(windows)]
    {
        SealTier::Tpm // DPAPI; uses TPM when available for system keys
    }
    #[cfg(target_os = "macos")]
    {
        SealTier::Keychain
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        // Full TSS TPM seal is not wired yet; derived is the portable Linux tier.
        SealTier::Derived
    }
}

#[cfg(windows)]
pub fn wrap_dek_tpm(dek: &[u8]) -> anyhow::Result<Vec<u8>> {
    windows_dpapi::protect(dek)
}

#[cfg(windows)]
pub fn unwrap_dek_tpm(wrapped: &[u8]) -> anyhow::Result<[u8; 32]> {
    let plain = windows_dpapi::unprotect(wrapped)?;
    if plain.len() != 32 {
        bail!("DPAPI unwrapped DEK wrong length");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plain);
    Ok(out)
}

#[cfg(not(windows))]
pub fn wrap_dek_tpm(_dek: &[u8]) -> anyhow::Result<Vec<u8>> {
    bail!("TPM/DPAPI seal not available on this platform")
}

#[cfg(not(windows))]
pub fn unwrap_dek_tpm(_wrapped: &[u8]) -> anyhow::Result<[u8; 32]> {
    bail!("TPM/DPAPI seal not available on this platform")
}

#[cfg(target_os = "macos")]
pub fn store_dek_keychain(dek: &[u8]) -> anyhow::Result<()> {
    macos_keychain::store(dek)
}

#[cfg(target_os = "macos")]
pub fn load_dek_keychain() -> anyhow::Result<[u8; 32]> {
    macos_keychain::load()
}

#[cfg(target_os = "macos")]
pub fn delete_dek_keychain() -> anyhow::Result<()> {
    macos_keychain::delete()
}

#[cfg(not(target_os = "macos"))]
pub fn store_dek_keychain(_dek: &[u8]) -> anyhow::Result<()> {
    bail!("Keychain not available on this platform")
}

#[cfg(not(target_os = "macos"))]
pub fn load_dek_keychain() -> anyhow::Result<[u8; 32]> {
    bail!("Keychain not available on this platform")
}

#[cfg(not(target_os = "macos"))]
pub fn delete_dek_keychain() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows_dpapi {
    use anyhow::Context;
    use std::ptr;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let inn = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // LOCAL_MACHINE so the service (SYSTEM) and elevated agent can unwrap.
        unsafe {
            CryptProtectData(
                &inn,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out,
            )
        }
        .context("CryptProtectData failed")?;
        let slice = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) };
        let v = slice.to_vec();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
        }
        Ok(v)
    }

    pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let inn = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        unsafe {
            CryptUnprotectData(
                &inn,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out,
            )
        }
        .context("CryptUnprotectData failed")?;
        let slice = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) };
        let v = slice.to_vec();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
        }
        Ok(v)
    }
}

#[cfg(target_os = "macos")]
mod macos_keychain {
    use super::*;
    use anyhow::Context;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const SERVICE: &str = "com.tuntun.agent";
    const ACCOUNT: &str = "state-dek";

    pub fn store(dek: &[u8]) -> anyhow::Result<()> {
        let _ = delete_generic_password(SERVICE, ACCOUNT);
        set_generic_password(SERVICE, ACCOUNT, dek).context("Keychain set_generic_password")?;
        Ok(())
    }

    pub fn load() -> anyhow::Result<[u8; 32]> {
        let data =
            get_generic_password(SERVICE, ACCOUNT).context("Keychain get_generic_password")?;
        if data.len() != 32 {
            bail!("Keychain DEK wrong length");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&data);
        Ok(out)
    }

    pub fn delete() -> anyhow::Result<()> {
        let _ = delete_generic_password(SERVICE, ACCOUNT);
        Ok(())
    }
}
