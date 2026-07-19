//! Cross-platform local IPC transport: Unix domain sockets / Windows named pipes.

use std::io;
use std::path::{Path, PathBuf};

/// Resolve the fixed agent IPC endpoint path / pipe name.
pub fn default_ipc_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("TUNNET_IPC_PATH") {
        return PathBuf::from(override_path);
    }
    #[cfg(unix)]
    {
        let base = std::env::var("TUNNET_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(base).join("tunnet-agent.sock")
    }
    #[cfg(windows)]
    {
        // Machine-wide marker so a user CLI can see a Local System service.
        // (Per-user %LOCALAPPDATA% put SYSTEM's marker under systemprofile.)
        system_ipc_marker_path()
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("tunnet-agent.ipc")
    }
}

#[cfg(windows)]
fn system_ipc_marker_path() -> PathBuf {
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(base)
        .join("tunnet")
        .join("ipc")
        .join("tunnet-agent.pipe")
}

#[cfg(windows)]
fn user_ipc_marker_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    PathBuf::from(base)
        .join("tunnet")
        .join("ipc")
        .join("tunnet-agent.pipe")
}

#[cfg(windows)]
pub fn pipe_name_for() -> String {
    r"\\.\pipe\tunnet-agent".to_string()
}

/// Abstract listener accepting framed JSON connections.
pub struct IpcListener {
    #[cfg(unix)]
    unix: tokio::net::UnixListener,
    #[cfg(windows)]
    windows: WindowsListener,
    path: PathBuf,
}

#[cfg(windows)]
struct WindowsListener {
    /// Next server instance waiting for a client.
    pending: tokio::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeServer>>,
    marker: PathBuf,
}

/// Accepted duplex connection.
pub enum IpcStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(tokio::net::windows::named_pipe::NamedPipeServer),
}

impl IpcListener {
    pub async fn bind() -> anyhow::Result<(Self, PathBuf)> {
        let path = default_ipc_path();
        #[cfg(unix)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let unix = tokio::net::UnixListener::bind(&path)?;
            tracing::info!(path = %path.display(), "IPC listening (unix)");
            Ok((
                Self {
                    unix,
                    path: path.clone(),
                },
                path,
            ))
        }
        #[cfg(windows)]
        {
            let marker = resolve_bind_marker(&path)?;
            if let Some(parent) = marker.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let name = pipe_name_for();
            std::fs::write(&marker, &name)?;
            let first = create_server_pipe(&name, true)?;
            tracing::info!(pipe = %name, marker = %marker.display(), "IPC listening (windows)");
            Ok((
                Self {
                    windows: WindowsListener {
                        pending: tokio::sync::Mutex::new(Some(first)),
                        marker: marker.clone(),
                    },
                    path: marker.clone(),
                },
                marker,
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("IPC not supported on this platform");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn accept(&self) -> anyhow::Result<IpcStream> {
        #[cfg(unix)]
        {
            let (stream, _) = self.unix.accept().await?;
            Ok(IpcStream::Unix(stream))
        }
        #[cfg(windows)]
        {
            let name = pipe_name_for();
            let mut guard = self.windows.pending.lock().await;
            let server = guard.take().ok_or_else(|| {
                anyhow::anyhow!("IPC listener has no pending named pipe instance")
            })?;
            // Create the next instance before serving this one so clients never miss a window.
            let next = create_server_pipe(&name, false)?;
            *guard = Some(next);
            drop(guard);

            server.connect().await?;
            Ok(IpcStream::Windows(server))
        }
        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("IPC not supported on this platform");
        }
    }
}

#[cfg(windows)]
fn resolve_bind_marker(preferred: &Path) -> io::Result<PathBuf> {
    if let Some(parent) = preferred.parent() {
        match std::fs::create_dir_all(parent) {
            Ok(()) => return Ok(preferred.to_path_buf()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Non-elevated `tunnet run`: fall back to the user profile.
                let fallback = user_ipc_marker_path();
                if let Some(p) = fallback.parent() {
                    std::fs::create_dir_all(p)?;
                }
                return Ok(fallback);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(preferred.to_path_buf())
}

/// Create a named-pipe server instance that Authenticated Users can open.
///
/// Default SECURITY_ATTRIBUTES under Local System only allow SYSTEM, so a
/// normal user CLI (`tunnet status`) gets Access Denied even when the service
/// is healthy.
#[cfg(windows)]
fn create_server_pipe(
    name: &str,
    first_instance: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::core::w;

    // SYSTEM + Administrators + Authenticated Users: full access.
    // GRGW alone is not enough for CreateFile(GENERIC_READ|GENERIC_WRITE) on
    // named pipes under Local System - user CLIs get Access Denied.
    let sddl = w!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &mut sd, None)
            .map_err(|e| io::Error::other(format!("pipe SDDL: {e}")))?;
    }

    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let result = unsafe {
        let mut opts = ServerOptions::new();
        if first_instance {
            opts.first_pipe_instance(true);
        }
        opts.create_with_security_attributes_raw(name, (&raw mut attrs).cast())
    };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0 as _)));
    }

    result
}

impl Drop for IpcListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.path);
        }
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(&self.windows.marker);
        }
    }
}

impl IpcStream {
    pub fn split(
        self,
    ) -> (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                let (r, w) = stream.into_split();
                (Box::new(r), Box::new(w))
            }
            #[cfg(windows)]
            Self::Windows(pipe) => {
                let (r, w) = tokio::io::split(pipe);
                (Box::new(r), Box::new(w))
            }
        }
    }
}

/// Client-side connect to a running agent IPC endpoint.
pub async fn connect(path: &Path) -> io::Result<ClientStream> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(ClientStream::Unix(stream))
    }
    #[cfg(windows)]
    {
        use std::time::Duration;
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = resolve_windows_pipe_name(path);

        let mut last = None;
        for _ in 0..40 {
            match ClientOptions::new().open(&pipe_name) {
                Ok(pipe) => return Ok(ClientStream::Windows(pipe)),
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("named pipe connect failed")))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPC not supported on this platform",
        ))
    }
}

#[cfg(windows)]
fn resolve_windows_pipe_name(path: &Path) -> String {
    let candidates = [
        path.to_path_buf(),
        system_ipc_marker_path(),
        user_ipc_marker_path(),
    ];
    for candidate in &candidates {
        if let Ok(s) = std::fs::read_to_string(candidate) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    // Named pipe is machine-global even when no marker is visible to this user.
    pipe_name_for()
}

/// Returns true when a live agent IPC endpoint is reachable.
pub async fn endpoint_reachable(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe_name = resolve_windows_pipe_name(path);
        ClientOptions::new().open(&pipe_name).is_ok()
    }
    #[cfg(unix)]
    {
        path.exists() && tokio::net::UnixStream::connect(path).await.is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

pub enum ClientStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl ClientStream {
    pub fn split(
        self,
    ) -> (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                let (r, w) = stream.into_split();
                (Box::new(r), Box::new(w))
            }
            #[cfg(windows)]
            Self::Windows(pipe) => {
                let (r, w) = tokio::io::split(pipe);
                (Box::new(r), Box::new(w))
            }
        }
    }
}
