//! Resolve a destination OS account. Never uses the agent process environment.

use std::path::PathBuf;

use anyhow::bail;

#[derive(Debug, Clone)]
pub struct LocalAccount {
    pub username: String,
    pub home_dir: PathBuf,
    pub shell: PathBuf,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    #[cfg(unix)]
    pub groups: Vec<u32>,
    #[cfg(windows)]
    pub sid: String,
}

pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
    let username = username.trim();
    if username.is_empty() {
        bail!("empty username");
    }
    #[cfg(unix)]
    {
        unix::resolve(username)
    }
    #[cfg(windows)]
    {
        windows::resolve(username)
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("OS account lookup is not supported on this platform");
    }
}

/// Interactive local accounts for Managed `autogroup:local`.
pub fn interactive_usernames() -> Vec<String> {
    #[cfg(unix)]
    {
        unix::interactive_usernames()
    }
    #[cfg(windows)]
    {
        windows::interactive_usernames()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

#[cfg(unix)]
mod unix {
    use super::LocalAccount;
    use anyhow::{Context, bail};
    use std::ffi::{CStr, CString};
    use std::io;
    use std::path::PathBuf;

    pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
        let c_user = CString::new(username).context("username")?;
        let Some((pwd, _buf)) = lookup_passwd(|pwd, buf, result| unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                result,
            )
        })
        .with_context(|| format!("look up user `{username}`"))?
        else {
            bail!("user `{username}` not found");
        };
        let username = cstr(pwd.pw_name)?.to_string();
        let home_dir = PathBuf::from(cstr(pwd.pw_dir)?.to_string());
        let shell = {
            let s = cstr(pwd.pw_shell)?.to_string();
            if s.is_empty() {
                PathBuf::from("/bin/sh")
            } else {
                PathBuf::from(s)
            }
        };
        let uid = pwd.pw_uid;
        let gid = pwd.pw_gid;
        let groups = supplementary_groups(&username, gid);
        Ok(LocalAccount {
            username,
            home_dir,
            shell,
            uid,
            gid,
            groups,
        })
    }

    fn supplementary_groups(username: &str, gid: u32) -> Vec<u32> {
        let Ok(c_user) = CString::new(username) else {
            return vec![gid];
        };
        #[cfg(target_os = "macos")]
        let Ok(base_gid) = libc::c_int::try_from(gid) else {
            return vec![gid];
        };
        #[cfg(target_os = "macos")]
        let mut groups: Vec<libc::c_int> = vec![0; 64];
        #[cfg(not(target_os = "macos"))]
        let base_gid = gid;
        #[cfg(not(target_os = "macos"))]
        let mut groups: Vec<libc::gid_t> = vec![0; 64];
        let mut n = 64i32;
        // SAFETY: getgrouplist fills `groups` up to `n`.
        let rc =
            unsafe { libc::getgrouplist(c_user.as_ptr(), base_gid, groups.as_mut_ptr(), &mut n) };
        if rc < 0 {
            groups.resize(n.max(1) as usize, 0);
            let rc = unsafe {
                libc::getgrouplist(c_user.as_ptr(), base_gid, groups.as_mut_ptr(), &mut n)
            };
            if rc < 0 {
                return vec![gid];
            }
        }
        groups.truncate(n as usize);
        #[cfg(target_os = "macos")]
        let groups: Vec<u32> = groups
            .into_iter()
            .filter_map(|group| u32::try_from(group).ok())
            .collect();
        let mut out = groups;
        if !out.contains(&gid) {
            out.insert(0, gid);
        }
        out
    }

    pub fn interactive_usernames() -> Vec<String> {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Vec::new();
        }
        resolve_uid(euid)
            .map(|a| vec![a.username])
            .unwrap_or_default()
    }

    fn resolve_uid(uid: u32) -> anyhow::Result<LocalAccount> {
        let Some((pwd, _buf)) = lookup_passwd(|pwd, buf, result| unsafe {
            libc::getpwuid_r(uid, pwd, buf.as_mut_ptr().cast(), buf.len(), result)
        })
        .with_context(|| format!("look up uid {uid}"))?
        else {
            bail!("uid {uid} not found");
        };
        let username = cstr(pwd.pw_name)?.to_string();
        resolve(&username)
    }

    fn lookup_passwd(
        mut lookup: impl FnMut(&mut libc::passwd, &mut [u8], &mut *mut libc::passwd) -> libc::c_int,
    ) -> io::Result<Option<(libc::passwd, Vec<u8>)>> {
        let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let mut buffer_len = usize::try_from(configured_size)
            .ok()
            .filter(|size| *size > 0)
            .unwrap_or(16 * 1024);

        loop {
            let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
            let mut buffer = vec![0u8; buffer_len];
            let mut result = std::ptr::null_mut();
            let rc = lookup(&mut pwd, &mut buffer, &mut result);
            if rc == libc::ERANGE {
                buffer_len = buffer_len.checked_mul(2).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::OutOfMemory, "password entry is too large")
                })?;
                continue;
            }
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            if result.is_null() {
                return Ok(None);
            }
            return Ok(Some((pwd, buffer)));
        }
    }

    fn cstr(ptr: *const libc::c_char) -> anyhow::Result<String> {
        if ptr.is_null() {
            return Ok(String::new());
        }
        Ok(unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned())
    }

    #[cfg(test)]
    mod tests {
        use super::lookup_passwd;

        #[test]
        fn passwd_lookup_retries_erange() {
            let mut attempts = 0;
            let (pwd, _buffer) = lookup_passwd(|pwd, _buffer, result| {
                attempts += 1;
                if attempts == 1 {
                    return libc::ERANGE;
                }
                pwd.pw_uid = 42;
                *result = pwd;
                0
            })
            .unwrap()
            .unwrap();

            assert_eq!(attempts, 2);
            assert_eq!(pwd.pw_uid, 42);
        }

        #[test]
        fn passwd_lookup_preserves_real_errors() {
            let error = lookup_passwd(|_, _, _| libc::EIO).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }

        #[test]
        fn passwd_lookup_reports_missing_entry_separately() {
            let result = lookup_passwd(|_, _, _| 0).unwrap();
            assert!(result.is_none());
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::LocalAccount;
    use anyhow::{Context, bail};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, SidTypeUser};
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName,
    };

    pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
        let sid = lookup_sid(username)?;
        let home_dir = std::env::var_os("SYSTEMDRIVE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:"));
        Ok(LocalAccount {
            username: username.to_string(),
            home_dir,
            shell: PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            sid,
        })
    }

    pub fn interactive_usernames() -> Vec<String> {
        logged_on_usernames()
    }

    fn lookup_sid(username: &str) -> anyhow::Result<String> {
        let wide: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_use = 0i32;
        unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                wide.as_ptr(),
                std::ptr::null_mut(),
                &mut sid_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut sid_use,
            );
        }
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
            bail!("Windows account `{username}` not found");
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                wide.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if ok == 0 {
            bail!("Windows account `{username}` not found");
        }
        if sid_use != SidTypeUser {
            bail!("`{username}` is not a user account");
        }
        let mut sid_str: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut sid_str) };
        if ok == 0 || sid_str.is_null() {
            bail!("could not encode SID for `{username}`");
        }
        let encoded = wide_ptr_to_string(sid_str);
        unsafe { LocalFree(sid_str.cast()) };
        encoded.context("SID string")
    }

    fn logged_on_usernames() -> Vec<String> {
        let mut info = std::ptr::null_mut();
        let mut count = 0u32;
        let ok = unsafe {
            WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count)
        };
        if ok == 0 || info.is_null() {
            return Vec::new();
        }
        let mut names = Vec::new();
        for i in 0..count {
            let session = unsafe { &*info.add(i as usize) };
            if session.State != WTSActive {
                continue;
            }
            let mut buf = std::ptr::null_mut();
            let mut bytes = 0u32;
            let ok = unsafe {
                WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    session.SessionId,
                    WTSUserName,
                    &mut buf,
                    &mut bytes,
                )
            };
            if ok != 0 && !buf.is_null() {
                if let Ok(name) = wide_ptr_to_string(buf.cast())
                    && !name.is_empty()
                {
                    names.push(name);
                }
                unsafe { WTSFreeMemory(buf.cast()) };
            }
        }
        unsafe { WTSFreeMemory(info.cast()) };
        names.sort();
        names.dedup();
        names
    }

    fn wide_ptr_to_string(ptr: *const u16) -> anyhow::Result<String> {
        if ptr.is_null() {
            bail!("null wide string");
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Ok(std::ffi::OsString::from_wide(slice)
            .to_string_lossy()
            .into_owned())
    }
}
