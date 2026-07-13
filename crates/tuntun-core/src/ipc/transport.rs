//! Cross-platform local IPC transport: Unix domain sockets / Windows named pipes.

use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Resolve the IPC endpoint path / pipe name for a network.
pub fn default_ipc_path(network_id: Uuid) -> PathBuf {
    if let Ok(override_path) = std::env::var("TUNTUN_IPC_PATH") {
        return PathBuf::from(override_path);
    }
    #[cfg(unix)]
    {
        let base = std::env::var("TUNTUN_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(base).join(format!("tuntun-{network_id}.sock"))
    }
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(base)
            .join("tuntun")
            .join("ipc")
            .join(format!("{network_id}.pipe"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = network_id;
        PathBuf::from("tuntun.ipc")
    }
}

#[cfg(windows)]
pub fn pipe_name_for(network_id: Uuid) -> String {
    format!(r"\\.\pipe\tuntun-{network_id}")
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
    network_id: Uuid,
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
    pub async fn bind(network_id: Uuid) -> anyhow::Result<(Self, PathBuf)> {
        let path = default_ipc_path(network_id);
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
            use tokio::net::windows::named_pipe::ServerOptions;

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let name = pipe_name_for(network_id);
            std::fs::write(&path, &name)?;
            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)?;
            tracing::info!(pipe = %name, marker = %path.display(), "IPC listening (windows)");
            Ok((
                Self {
                    windows: WindowsListener {
                        network_id,
                        pending: tokio::sync::Mutex::new(Some(first)),
                        marker: path.clone(),
                    },
                    path: path.clone(),
                },
                path,
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
            use tokio::net::windows::named_pipe::ServerOptions;

            let name = pipe_name_for(self.windows.network_id);
            let mut guard = self.windows.pending.lock().await;
            let server = guard.take().ok_or_else(|| {
                anyhow::anyhow!("IPC listener has no pending named pipe instance")
            })?;
            // Create the next instance before serving this one so clients never miss a window.
            let next = ServerOptions::new().create(&name)?;
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

        let pipe_name = std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| path.display().to_string());

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
