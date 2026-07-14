//! IPC client used by CLI subcommands.

use std::path::Path;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use super::protocol::{IpcRequest, IpcResponse};
use super::transport::{self, default_ipc_path};

pub struct IpcClient {
    path: std::path::PathBuf,
}

impl IpcClient {
    pub fn for_network(network_id: Uuid) -> Self {
        Self {
            path: default_ipc_path(network_id),
        }
    }

    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Send a request and read a single response line.
    pub async fn request(&self, req: IpcRequest) -> anyhow::Result<IpcResponse> {
        let stream = transport::connect(&self.path).await.with_context(|| {
            format!(
                "cannot connect to agent IPC at {} - is the agent running?",
                self.path.display()
            )
        })?;
        let (read, mut write) = stream.split();
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;
        write.flush().await?;

        let mut reader = BufReader::new(read);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            bail!("agent closed IPC connection without a response");
        }
        let resp: IpcResponse = serde_json::from_str(line.trim())
            .with_context(|| format!("bad IPC response: {}", line.trim()))?;
        if let IpcResponse::Error { message } = &resp {
            bail!("{message}");
        }
        Ok(resp)
    }

    /// Send a request and stream all response lines until the connection closes.
    /// Used by `ping` (multiple probes + summary).
    pub async fn request_stream(
        &self,
        req: IpcRequest,
        mut on_response: impl FnMut(IpcResponse) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let stream = transport::connect(&self.path).await.with_context(|| {
            format!(
                "cannot connect to agent IPC at {} - is the agent running?",
                self.path.display()
            )
        })?;
        let (read, mut write) = stream.split();
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;
        write.flush().await?;

        let mut reader = BufReader::new(read);
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            let resp: IpcResponse = serde_json::from_str(line.trim())
                .with_context(|| format!("bad IPC response: {}", line.trim()))?;
            let is_summary = matches!(&resp, IpcResponse::PingSummary(_));
            on_response(resp)?;
            if is_summary {
                break;
            }
        }
        Ok(())
    }
}

/// Discover network id from persisted agent state on this machine.
pub fn discover_network_id(
    state_dir: Option<&str>,
) -> anyhow::Result<(Uuid, crate::state::PersistedState)> {
    let paths = crate::state::StatePaths::resolve(state_dir);
    let persisted = crate::state::PersistedState::try_load(&paths)?.with_context(|| {
        format!(
            "not connected to a network yet (no state in {}). \
                 Use `tuntun create` for Direct or `tuntun enroll` for Managed",
            paths.dir.display()
        )
    })?;
    Ok((persisted.network_id(), persisted))
}
