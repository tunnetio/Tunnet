use std::path::{Path, PathBuf};

/// System-wide state directory used by the Tunnet service.
pub fn system_state_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/tunnet")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
        PathBuf::from(base).join("tunnet")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("./tunnet-state")
    }
}

pub fn resolve_state_dir(state_dir: Option<&str>) -> PathBuf {
    state_dir
        .map(PathBuf::from)
        .unwrap_or_else(system_state_dir)
}

fn daemon_name() -> &'static str {
    if cfg!(windows) {
        "tunnetd.exe"
    } else {
        "tunnetd"
    }
}

#[cfg(windows)]
fn cli_name() -> &'static str {
    "tunnet.exe"
}

/// Canonical directory for service/daemon binaries on Windows.
///
/// Layout (Windows): `%ProgramData%\tunnet\bin\` holds the *active* copies of
/// `tunnet.exe` and `tunnetd.exe`. SCM always points at `tunnetd.exe` here.
/// The desktop app may live under Program Files / NSIS `$INSTDIR`;
/// install/update paths must stage into this directory via [`stage_daemon_exe`]
/// so users never have competing "active" daemon copies.
#[cfg(windows)]
pub fn installed_bin_dir(state_dir: Option<&str>) -> PathBuf {
    resolve_state_dir(state_dir).join("bin")
}

#[cfg(windows)]
pub fn installed_daemon_exe(state_dir: Option<&str>) -> PathBuf {
    installed_bin_dir(state_dir).join(daemon_name())
}

fn path_is_release(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "release")
}

fn newest_workspace_daemon(start: &Path, name: &str) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if !path.is_file() {
            return;
        }
        let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
            return;
        };
        let take = match &best {
            None => true,
            Some((best_time, best_path)) => {
                modified > *best_time
                    || (modified == *best_time
                        && path_is_release(&path)
                        && !path_is_release(best_path))
            }
        };
        if take {
            best = Some((modified, path));
        }
    };

    consider(start.join(name));
    for ancestor in start.ancestors() {
        for profile in ["debug", "release"] {
            consider(ancestor.join("target").join(profile).join(name));
        }
    }
    best.map(|(_, path)| path)
}

pub fn resolve_daemon_exe() -> anyhow::Result<PathBuf> {
    let name = daemon_name();
    if let Ok(current) = std::env::current_exe()
        && let Some(dir) = current.parent()
        && let Some(found) = newest_workspace_daemon(dir, name)
    {
        return Ok(found);
    }
    if let Some(path) = find_on_path(name) {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        let staged = installed_daemon_exe(None);
        if staged.is_file() {
            return Ok(staged);
        }
    }
    anyhow::bail!("could not find {name}; place it next to tunnet or on PATH")
}

#[cfg(windows)]
pub fn daemon_outdated(state_dir: Option<&str>) -> anyhow::Result<bool> {
    let source = resolve_daemon_exe()?;
    let dest = installed_daemon_exe(state_dir);
    // Source may already *be* the staged binary (e.g. running from ProgramData).
    let source_canon = source.canonicalize().unwrap_or_else(|_| source.clone());
    let dest_canon = dest.canonicalize().unwrap_or_else(|_| dest.clone());
    if source_canon == dest_canon {
        return Ok(false);
    }
    if !dest.is_file() {
        return Ok(true);
    }
    Ok(!same_artifact(&source, &dest))
}

/// Stage daemon and CLI into [`installed_bin_dir`] and return the
/// staged `tunnetd` path. This is the only path SCM should run.
#[cfg(windows)]
pub fn stage_daemon_exe(state_dir: Option<&str>) -> anyhow::Result<PathBuf> {
    let source = {
        let s = resolve_daemon_exe()?;
        s.canonicalize().unwrap_or(s)
    };
    let dest_dir = installed_bin_dir(state_dir);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", dest_dir.display()))?;
    let dest = installed_daemon_exe(state_dir);

    let source_is_dest = source
        .canonicalize()
        .ok()
        .zip(dest.canonicalize().ok())
        .is_some_and(|(a, b)| a == b);
    if !source_is_dest {
        stage_binary(&source, &dest)?;
    }

    if let Some(dir) = source.parent() {
        let cli = dir.join(cli_name());
        let cli_dest = dest_dir.join(cli_name());
        if cli.is_file() {
            stage_binary(&cli, &cli_dest)?;
        }
    }

    Ok(dest)
}

/// Wipe enrollment/config state under `dir`, preserving `bin/` (staged service binaries).
pub fn wipe_state_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?;
        let path = entry.path();
        if entry.file_name() == "bin" {
            continue;
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path).map_err(|e| {
                anyhow::anyhow!("wipe {} (is tunnetd still running?): {e}", path.display())
            })?;
        } else {
            std::fs::remove_file(&path).map_err(|e| {
                anyhow::anyhow!("wipe {} (is tunnetd still running?): {e}", path.display())
            })?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn stage_binary(source: &Path, dest: &Path) -> anyhow::Result<()> {
    if same_artifact(source, dest) {
        return Ok(());
    }
    // SCM may report Stopped while the executable image is still mapped.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match std::fs::OpenOptions::new().write(true).open(dest) {
            Ok(file) => {
                drop(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                use windows_sys::Win32::Foundation::{
                    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
                };
                let locked = error.raw_os_error().is_some_and(|code| {
                    matches!(
                        code as u32,
                        ERROR_ACCESS_DENIED | ERROR_LOCK_VIOLATION | ERROR_SHARING_VIOLATION
                    )
                });
                if !locked || std::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(
                        "open {} for staging: {error}",
                        dest.display()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    tunnet_common::persistence::atomic_copy(source, dest).map_err(|error| {
        anyhow::anyhow!("copy {} to {}: {error}", source.display(), dest.display())
    })?;
    Ok(())
}

#[cfg(windows)]
fn same_artifact(a: &Path, b: &Path) -> bool {
    use std::io::Read;

    let (Ok(mut a), Ok(mut b)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    let (Ok(ma), Ok(mb)) = (a.metadata(), b.metadata()) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    let mut remaining = ma.len();
    let mut left = [0; 64 * 1024];
    let mut right = [0; 64 * 1024];
    while remaining != 0 {
        let n = remaining.min(left.len() as u64) as usize;
        if a.read_exact(&mut left[..n]).is_err()
            || b.read_exact(&mut right[..n]).is_err()
            || left[..n] != right[..n]
        {
            return false;
        }
        remaining -= n as u64;
    }
    matches!(a.read(&mut left[..1]), Ok(0)) && matches!(b.read(&mut right[..1]), Ok(0))
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{newest_workspace_daemon, system_state_dir};

    #[cfg(windows)]
    #[test]
    fn artifact_identity_uses_contents() {
        let root = test_root();
        std::fs::create_dir_all(&root).unwrap();
        let a = root.join("a.exe");
        let b = root.join("b.exe");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"two").unwrap();
        let time = std::fs::metadata(&a).unwrap().modified().unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&b)
            .unwrap()
            .set_modified(time)
            .unwrap();
        assert!(!super::same_artifact(&a, &b));
        std::fs::write(&b, b"one").unwrap();
        assert!(super::same_artifact(&a, &b));
        assert!(super::same_artifact(&a, &a));
        use std::os::windows::fs::OpenOptionsExt;
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .open(&b)
            .unwrap();
        super::stage_binary(&a, &b).unwrap();
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunnet-ws-daemon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn daemon_name_for_tests() -> &'static str {
        if cfg!(windows) {
            "tunnetd.exe"
        } else {
            "tunnetd"
        }
    }

    #[test]
    fn workspace_daemon_is_found_from_nested_desktop_target() {
        let root = test_root();
        let name = daemon_name_for_tests();
        let daemon = root.join("target").join("debug").join(name);
        std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
        std::fs::write(&daemon, b"daemon").unwrap();
        let desktop_dir = root
            .join("apps")
            .join("desktop")
            .join("src-tauri")
            .join("target")
            .join("debug");
        std::fs::create_dir_all(&desktop_dir).unwrap();
        let found = newest_workspace_daemon(&desktop_dir, name);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found.as_deref(), Some(daemon.as_path()));
    }

    #[test]
    fn newer_release_tunnetd_wins_over_stale_debug_sibling() {
        let root = test_root();
        let name = daemon_name_for_tests();
        let debug_dir = root.join("target").join("debug");
        let release_dir = root.join("target").join("release");
        std::fs::create_dir_all(&debug_dir).unwrap();
        std::fs::create_dir_all(&release_dir).unwrap();
        let debug = debug_dir.join(name);
        let release = release_dir.join(name);
        std::fs::write(&debug, b"old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(&release, b"new").unwrap();
        let found = newest_workspace_daemon(&debug_dir, name);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found.as_deref(), Some(release.as_path()));
    }

    #[test]
    fn system_dir_matches_platform() {
        #[cfg(unix)]
        assert_eq!(
            system_state_dir(),
            std::path::PathBuf::from("/var/lib/tunnet")
        );
        #[cfg(windows)]
        {
            let dir = system_state_dir();
            assert!(dir.ends_with("tunnet"), "got {}", dir.display());
        }
    }
}
