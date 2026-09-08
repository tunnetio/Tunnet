//! Platform user lookup for SSH sessions.

use std::path::PathBuf;

#[cfg(unix)]
use anyhow::Context;
use anyhow::bail;

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub home_dir: PathBuf,
    /// Login shell (read on Unix; constructed for validation on Windows).
    #[cfg_attr(windows, allow(dead_code))]
    pub shell: PathBuf,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
}

pub fn lookup(username: &str) -> anyhow::Result<UserInfo> {
    #[cfg(unix)]
    {
        lookup_unix(username)
    }
    #[cfg(windows)]
    {
        lookup_windows(username)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = username;
        bail!("user lookup is not supported on this platform");
    }
}

#[cfg(unix)]
fn lookup_unix(username: &str) -> anyhow::Result<UserInfo> {
    use std::ffi::CString;

    let user = CString::new(username).context("username")?;
    // SAFETY: getpwnam is the standard libc lookup; we only read the returned struct.
    let passwd = unsafe { libc::getpwnam(user.as_ptr()) };
    if passwd.is_null() {
        bail!("user `{username}` not found");
    }
    // SAFETY: passwd is non-null and points to a valid passwd from getpwnam.
    Ok(unsafe { user_from_passwd(&*passwd) })
}

#[cfg(unix)]
unsafe fn user_from_passwd(pw: &libc::passwd) -> UserInfo {
    // SAFETY: caller guarantees `pw` fields are valid pointers from getpwnam/getpwuid.
    let shell = if pw.pw_shell.is_null() {
        PathBuf::from("/bin/sh")
    } else {
        PathBuf::from(
            unsafe { std::ffi::CStr::from_ptr(pw.pw_shell) }
                .to_string_lossy()
                .as_ref(),
        )
    };
    let home_dir = if pw.pw_dir.is_null() {
        PathBuf::from("/")
    } else {
        PathBuf::from(
            unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }
                .to_string_lossy()
                .as_ref(),
        )
    };
    let username = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }
        .to_string_lossy()
        .into_owned();
    UserInfo {
        username,
        home_dir,
        shell,
        uid: pw.pw_uid,
        gid: pw.pw_gid,
    }
}

#[cfg(windows)]
fn lookup_windows(username: &str) -> anyhow::Result<UserInfo> {
    let current = std::env::var("USERNAME").unwrap_or_default();
    if !username.is_empty()
        && !username.eq_ignore_ascii_case(&current)
        && username != "autogroup:local"
        && !current.is_empty()
    {
        bail!(
            "user `{username}` not found (Windows SSH currently supports only the agent user `{current}`)"
        );
    }
    let home_dir = std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\"));
    Ok(UserInfo {
        username: if current.is_empty() {
            username.to_string()
        } else {
            current
        },
        home_dir,
        shell: PathBuf::from("powershell.exe"),
    })
}
