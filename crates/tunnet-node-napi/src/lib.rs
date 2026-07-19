#![deny(clippy::all)]

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

mod init;

/// Thin napi bindings over the `tunnet` Rust SDK.

#[napi(object)]
pub struct EnrollConfig {
    pub control_url: String,
    /// One-time enrollment token (agent-style enrolment).
    pub token: Option<String>,
    /// Management API base URL for API-key SDK enrolment.
    pub management_url: Option<String>,
    pub api_key: Option<String>,
    pub organization_id: Option<String>,
    pub network_id: Option<String>,
    pub hostname: Option<String>,
    pub state_dir: Option<String>,
    pub process_name: Option<String>,
    pub runtime: Option<String>,
}

#[napi(object)]
pub struct NodeConfig {
    /// Path to the state directory (identity + persisted state).
    /// If not provided we use `TUNNET_STATE_DIR`, `XDG_STATE_HOME`, etc.
    pub state_dir: Option<String>,
    pub hostname: Option<String>,
    pub poll_secs: Option<u32>,
    /// When true, avoids the coordinator dance and always creates a private
    /// endpoint for this process. Useful in tests or single-process scenarios.
    pub standalone: Option<bool>,
    /// Control plane URL used after enrolment.
    pub control_url: Option<String>,
    /// Auto-enrol via API key when no persisted identity exists.
    pub management_url: Option<String>,
    pub api_key: Option<String>,
    pub organization_id: Option<String>,
    pub network_id: Option<String>,
    pub process_name: Option<String>,
    pub runtime: Option<String>,
}

#[napi(object)]
pub struct EnrollResult {
    pub endpoint_id: String,
    pub ip: String,
    pub network: String,
}

#[napi(object)]
pub struct PeerJs {
    pub ip: String,
    pub hostname: String,
    pub endpoint_id: String,
    pub tags: Vec<String>,
}

/// One-shot enrolment. Persists identity+state to `state_dir` so subsequent
/// `TunnetNode.create()` calls can bootstrap without a token.
#[napi]
pub async fn enroll(cfg: EnrollConfig) -> Result<EnrollResult> {
    init::init_logging_once();
    let result = tunnet::enroll(tunnet::EnrollConfig {
        control_url: Some(cfg.control_url),
        token: cfg.token,
        management_url: cfg.management_url,
        api_key: cfg.api_key,
        organization_id: cfg.organization_id,
        network_id: cfg.network_id,
        hostname: cfg.hostname,
        state_dir: cfg.state_dir,
        process_name: cfg.process_name,
        runtime: cfg.runtime,
    })
    .await
    .map_err(sdk_err)?;

    Ok(EnrollResult {
        endpoint_id: result.endpoint_id,
        ip: result.ip,
        network: result.network,
    })
}

/// A handle to the local overlay. Depending on whether this process won the
/// coordinator race, this is either a full coordinator (owning the iroh
/// endpoint) or a lightweight client relaying via UDS.
#[napi]
pub struct TunnetNode {
    inner: Arc<tunnet::TunnetNode>,
}

#[napi]
impl TunnetNode {
    /// Create (or connect to) a local overlay node.
    #[napi(factory)]
    pub async fn create(cfg: NodeConfig) -> Result<TunnetNode> {
        init::init_logging_once();

        let mut builder = tunnet::TunnetNode::builder().standalone(cfg.standalone.unwrap_or(false));

        if let Some(v) = cfg.state_dir {
            builder = builder.state_dir(v);
        }
        if let Some(v) = cfg.hostname {
            builder = builder.hostname(v);
        }
        if let Some(v) = cfg.poll_secs {
            builder = builder.poll_secs(v as u64);
        }
        if let Some(v) = cfg.control_url {
            builder = builder.control_url(v);
        }
        if let Some(v) = cfg.management_url {
            builder = builder.management_url(v);
        }
        if let Some(v) = cfg.api_key {
            builder = builder.api_key(v);
        }
        if let Some(v) = cfg.organization_id {
            builder = builder.organization_id(v);
        }
        if let Some(v) = cfg.network_id {
            builder = builder.network_id(v);
        }
        if let Some(v) = cfg.process_name {
            builder = builder.process_name(v);
        }
        if let Some(v) = cfg.runtime {
            builder = builder.runtime(v);
        }

        let node = builder.start().await.map_err(sdk_err)?;
        Ok(Self {
            inner: Arc::new(node),
        })
    }

    /// Our own endpoint id (hex).
    #[napi]
    pub fn endpoint_id(&self) -> String {
        self.inner.endpoint_id()
    }

    /// Are we currently acting as the coordinator for this machine?
    #[napi]
    pub fn is_coordinator(&self) -> bool {
        self.inner.is_coordinator()
    }

    /// List peers currently known to the routing table.
    #[napi]
    pub async fn list_peers(&self) -> Result<Vec<PeerJs>> {
        let peers = self.inner.list_peers().await.map_err(sdk_err)?;
        Ok(peers
            .into_iter()
            .map(|p| PeerJs {
                ip: p.ip,
                hostname: p.hostname,
                endpoint_id: p.endpoint_id,
                tags: p.tags,
            })
            .collect())
    }

    /// Open a duplex stream to `host:port` where `host` is a peer overlay IP,
    /// hostname, or endpoint id.
    #[napi]
    pub async fn open_stream(&self, host: String, port: u16) -> Result<TunnetStream> {
        let stream = self.inner.open_stream(host, port).await.map_err(sdk_err)?;
        Ok(TunnetStream::from_sdk(stream))
    }

    /// Best-effort shutdown. Multiple calls are safe.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.inner.shutdown().await;
        Ok(())
    }

    /// Send a local file or directory to a mesh peer.
    #[napi]
    pub async fn send_file(
        &self,
        path: String,
        target: String,
        message: Option<String>,
    ) -> Result<Vec<TransferJs>> {
        let records = self
            .inner
            .send_file(path, target, message)
            .await
            .map_err(sdk_err)?;
        Ok(records.into_iter().map(TransferJs::from).collect())
    }

    /// Accept a pending inbound transfer offer.
    #[napi]
    pub async fn accept_transfer(&self, transfer_id: String) -> Result<TransferJs> {
        let record = self
            .inner
            .accept_transfer(&transfer_id)
            .await
            .map_err(sdk_err)?;
        Ok(TransferJs::from(record))
    }

    /// Reject a pending inbound transfer offer.
    #[napi]
    pub async fn reject_transfer(&self, transfer_id: String, reason: Option<String>) -> Result<()> {
        self.inner
            .reject_transfer(&transfer_id, reason)
            .await
            .map_err(sdk_err)?;
        Ok(())
    }

    /// List pending inbound offers (prompt consent mode).
    #[napi]
    pub async fn list_pending_transfers(&self) -> Result<Vec<TransferJs>> {
        let records = self.inner.list_pending_transfers().map_err(sdk_err)?;
        Ok(records.into_iter().map(TransferJs::from).collect())
    }

    /// List active transfers.
    #[napi]
    pub async fn list_transfers(&self) -> Result<Vec<TransferJs>> {
        let records = self.inner.list_transfers().map_err(sdk_err)?;
        Ok(records.into_iter().map(TransferJs::from).collect())
    }
}

#[napi(object)]
pub struct TransferJs {
    pub transfer_id: String,
    pub direction: String,
    pub peer_endpoint_id: String,
    pub peer_hostname: Option<String>,
    pub file_name: String,
    pub size: i64,
    pub hash: String,
    pub status: String,
    pub percent: f64,
    pub bytes_transferred: i64,
    pub message: Option<String>,
    pub error: Option<String>,
    pub inbox_path: Option<String>,
    pub is_directory: bool,
}

impl From<tunnet::Transfer> for TransferJs {
    fn from(r: tunnet::Transfer) -> Self {
        Self {
            transfer_id: r.transfer_id,
            direction: r.direction.into(),
            peer_endpoint_id: r.peer_endpoint_id,
            peer_hostname: r.peer_hostname,
            file_name: r.file_name,
            size: r.size as i64,
            hash: r.hash,
            status: r.status,
            percent: r.percent as f64,
            bytes_transferred: r.bytes_transferred as i64,
            message: r.message,
            error: r.error,
            inbox_path: r.inbox_path,
            is_directory: r.is_directory,
        }
    }
}

/// A duplex byte stream. Read via `read()`, write via `write()`, close via `close()`.
#[napi]
pub struct TunnetStream {
    inner: Arc<Mutex<tunnet::TunnetStream>>,
}

#[napi]
impl TunnetStream {
    fn from_sdk(stream: tunnet::TunnetStream) -> Self {
        Self {
            inner: Arc::new(Mutex::new(stream)),
        }
    }

    /// Read up to `max_len` bytes. Returns an empty buffer at EOF.
    #[napi]
    pub async fn read(&self, max_len: u32) -> Result<Buffer> {
        let mut guard = self.inner.lock().await;
        let mut buf = vec![0u8; max_len as usize];
        let n = guard.read(&mut buf).await.map_err(io_err)?;
        buf.truncate(n);
        Ok(buf.into())
    }

    /// Write all `data` bytes.
    #[napi]
    pub async fn write(&self, data: Buffer) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.write_all(data.as_ref()).await.map_err(io_err)?;
        Ok(())
    }

    #[napi]
    pub async fn end(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.shutdown().await.map_err(io_err)?;
        Ok(())
    }
}

fn sdk_err(e: tunnet::Error) -> Error {
    Error::from_reason(e.to_string())
}

fn io_err(e: std::io::Error) -> Error {
    Error::from_reason(format!("{e:#}"))
}
