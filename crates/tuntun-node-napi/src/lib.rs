#![deny(clippy::all)]

use std::path::PathBuf;
use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

mod duplex;
mod init;

use tuntun_core::{
    AgentIdentity, CoreNode, CoreNodeConfig, PersistedState, StatePaths, stream::dial_stream,
};

#[cfg(unix)]
use tuntun_core::coordinator::{self, Role, spawn_coord_server};

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
    /// If not provided we use `TUNTUN_STATE_DIR`, `XDG_STATE_HOME`, etc.
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
/// `TunTunNode.create()` calls can bootstrap without a token.
#[napi]
pub async fn enroll(cfg: EnrollConfig) -> Result<EnrollResult> {
    init::init_logging_once();
    let paths = StatePaths::resolve(cfg.state_dir.as_deref());
    paths.ensure().map_err(err)?;

    let identity = AgentIdentity::generate();
    let hostname = cfg
        .hostname
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "tuntun-sdk".into()));

    let mut metadata =
        tuntun_core::control::basic_metadata(&hostname, env!("CARGO_PKG_VERSION"), "sdk");
    if let Some(name) = cfg.process_name {
        metadata["processName"] = name.into();
    }
    if let Some(runtime) = cfg.runtime {
        metadata["runtime"] = runtime.into();
    }

    let resp = if let (Some(api_key), Some(org_id), Some(network_id)) = (
        cfg.api_key.as_deref(),
        cfg.organization_id.as_deref(),
        cfg.network_id.as_deref(),
    ) {
        let management_url = cfg
            .management_url
            .clone()
            .or_else(|| std::env::var("TUNTUN_MANAGEMENT_URL").ok())
            .ok_or_else(|| {
                Error::from_reason("management_url is required for API key enrolment")
            })?;
        let client = tuntun_core::control::ManagementClient::new(management_url).map_err(err)?;
        let network_uuid = uuid::Uuid::parse_str(network_id)
            .map_err(|_| Error::from_reason("invalid network_id"))?;
        client
            .register_sdk_node(
                api_key,
                org_id,
                network_uuid,
                &identity.endpoint_id_hex(),
                &hostname,
                Some(metadata.clone()),
            )
            .await
            .map_err(err)?
    } else {
        let token = cfg.token.ok_or_else(|| {
            Error::from_reason("either token or api_key + organization_id + network_id is required")
        })?;
        let client = tuntun_core::UnauthedClient::new(cfg.control_url.clone()).map_err(err)?;
        client
            .enroll(tuntun_common::EnrollRequest {
                enrollment_token: Some(token),
                organization_slug: None,
                network_id: None,
                network_name: None,
                endpoint_id: identity.endpoint_id_hex(),
                hostname: hostname.clone(),
                os: std::env::consts::OS.to_string(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                metadata: Some(metadata.clone()),
            })
            .await
            .map_err(err)?
    };

    let membership = resp
        .snapshot
        .memberships
        .iter()
        .find(|m| m.network_id == resp.network_id)
        .ok_or_else(|| Error::from_reason("enrolled network missing from snapshot"))?;

    let persisted = PersistedState::Managed(tuntun_core::ManagedState {
        control_url: cfg.control_url,
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id.clone(),
        enrolled_at: chrono::Utc::now(),
    });
    identity.save_to(&paths.key_file()).map_err(err)?;
    persisted.save(&paths).map_err(err)?;
    tuntun_core::state::save_snapshot_cache(&paths, &resp.snapshot).map_err(err)?;

    Ok(EnrollResult {
        endpoint_id: identity.endpoint_id_hex(),
        ip: membership.assigned_ipv4.to_string(),
        network: resp.network_name,
    })
}

/// A handle to the local overlay. Depending on whether this process won the
/// coordinator race, this is either a full coordinator (owning the iroh
/// endpoint) or a lightweight client relaying via UDS.
#[napi]
pub struct TunTunNode {
    inner: Arc<NodeInner>,
}

enum NodeInner {
    Coordinator {
        node: Arc<CoreNode>,
        _sock_path: PathBuf,
    },
    #[cfg(unix)]
    Client {
        sock_path: PathBuf,
        _network_id: uuid::Uuid,
    },
}

#[napi]
impl TunTunNode {
    /// Create (or connect to) a local overlay node.
    #[napi(factory)]
    pub async fn create(cfg: NodeConfig) -> Result<TunTunNode> {
        init::init_logging_once();

        let paths = StatePaths::resolve(cfg.state_dir.as_deref());
        let identity = match AgentIdentity::load_from(&paths.key_file()) {
            Ok(id) => id,
            Err(_) => {
                if let (Some(api_key), Some(org_id), Some(network_id)) = (
                    cfg.api_key.as_deref(),
                    cfg.organization_id.as_deref(),
                    cfg.network_id.as_deref(),
                ) {
                    let control_url = cfg
                        .control_url
                        .clone()
                        .or_else(|| std::env::var("TUNTUN_CONTROL_URL").ok())
                        .ok_or_else(|| {
                            Error::from_reason("control_url is required for API key enrolment")
                        })?;
                    enroll(EnrollConfig {
                        control_url,
                        token: None,
                        management_url: cfg.management_url.clone(),
                        api_key: Some(api_key.to_string()),
                        organization_id: Some(org_id.to_string()),
                        network_id: Some(network_id.to_string()),
                        hostname: cfg.hostname.clone(),
                        state_dir: cfg.state_dir.clone(),
                        process_name: cfg.process_name.clone(),
                        runtime: cfg.runtime.clone(),
                    })
                    .await?;
                    AgentIdentity::load_from(&paths.key_file()).map_err(|_| {
                        Error::from_reason("enrolment succeeded but identity was not persisted")
                    })?
                } else {
                    return Err(Error::from_reason(
                        "no persisted identity; run `enroll()` first or pass api_key credentials",
                    ));
                }
            }
        };
        let persisted = PersistedState::load(&paths).map_err(err)?;

        let standalone = cfg.standalone.unwrap_or(false);
        let hostname = cfg
            .hostname
            .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "tuntun-sdk".into()));
        let poll_secs = cfg.poll_secs.unwrap_or(30) as u64;

        // Standalone → don't try to be a coordinator, just spin up an
        // isolated CoreNode.
        if standalone {
            let node = CoreNode::bootstrap(
                identity,
                persisted,
                paths,
                CoreNodeConfig {
                    hostname,
                    poll_secs,
                    kind: "sdk",
                    agent_version: env!("CARGO_PKG_VERSION"),
                    advertise_datagram_alpn: false,
                    ..Default::default()
                },
            )
            .await
            .map_err(err)?;
            let node = Arc::new(node);
            spawn_stream_acceptor(node.clone());
            return Ok(Self {
                inner: Arc::new(NodeInner::Coordinator {
                    node,
                    _sock_path: PathBuf::new(),
                }),
            });
        }

        #[cfg(unix)]
        {
            let network_id = persisted.network_id();
            match coordinator::acquire(network_id).await.map_err(err)? {
                Role::Client {
                    conn: _drop_conn,
                    sock_path,
                } => {
                    // We just needed the connect to prove the coordinator is alive.
                    // Real request/response cycles happen per-openStream.
                    Ok(Self {
                        inner: Arc::new(NodeInner::Client {
                            sock_path,
                            _network_id: network_id,
                        }),
                    })
                }
                Role::Coordinator {
                    listener,
                    _lock,
                    sock_path,
                } => {
                    let node = CoreNode::bootstrap(
                        identity,
                        persisted,
                        paths,
                        CoreNodeConfig {
                            hostname,
                            poll_secs,
                            kind: "sdk",
                            agent_version: env!("CARGO_PKG_VERSION"),
                            advertise_datagram_alpn: false,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(err)?;
                    let node = Arc::new(node);
                    spawn_stream_acceptor(node.clone());
                    // Keep lock alive alongside the node.
                    let lock_holder: Arc<coordinator::LockFile> = Arc::new(_lock);
                    std::mem::forget(lock_holder); // held for process lifetime
                    spawn_coord_server(listener, node.clone());
                    Ok(Self {
                        inner: Arc::new(NodeInner::Coordinator {
                            node,
                            _sock_path: sock_path,
                        }),
                    })
                }
            }
        }
        #[cfg(not(unix))]
        {
            // TODO: named-pipe coordinator on Windows. For now, always solo.
            let node = CoreNode::bootstrap(
                identity,
                persisted,
                paths,
                CoreNodeConfig {
                    hostname,
                    poll_secs,
                    kind: "sdk",
                    agent_version: env!("CARGO_PKG_VERSION"),
                    advertise_datagram_alpn: false,
                    ..Default::default()
                },
            )
            .await
            .map_err(err)?;
            let node = Arc::new(node);
            spawn_stream_acceptor(node.clone());
            Ok(Self {
                inner: Arc::new(NodeInner::Coordinator {
                    node,
                    _sock_path: PathBuf::new(),
                }),
            })
        }
    }

    /// Our own endpoint id (hex).
    #[napi]
    pub fn endpoint_id(&self) -> String {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => node.endpoint_id_hex(),
            #[cfg(unix)]
            NodeInner::Client { .. } => String::new(),
        }
    }

    /// Are we currently acting as the coordinator for this machine?
    #[napi]
    pub fn is_coordinator(&self) -> bool {
        matches!(&*self.inner, NodeInner::Coordinator { .. })
    }

    /// List peers currently known to the routing table.
    #[napi]
    pub async fn list_peers(&self) -> Result<Vec<PeerJs>> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Ok(node
                .routes
                .peers()
                .into_iter()
                .map(|p| PeerJs {
                    ip: p.ip.to_string(),
                    hostname: p.hostname.clone(),
                    endpoint_id: p.endpoint_hex.clone(),
                    tags: p.tags.clone(),
                })
                .collect()),
            #[cfg(unix)]
            NodeInner::Client { sock_path, .. } => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut conn = tokio::net::UnixStream::connect(sock_path)
                    .await
                    .map_err(err_io)?;
                let req = coordinator::ClientReq::ListPeers;
                let mut buf = serde_json::to_vec(&req).map_err(err_json)?;
                buf.push(b'\n');
                conn.write_all(&buf).await.map_err(err_io)?;
                let mut br = BufReader::new(conn);
                let mut line = String::new();
                br.read_line(&mut line).await.map_err(err_io)?;
                let resp: coordinator::CoordResp =
                    serde_json::from_str(line.trim()).map_err(err_json)?;
                match resp {
                    coordinator::CoordResp::Peers { peers } => Ok(peers
                        .into_iter()
                        .map(|p| PeerJs {
                            ip: p.ip,
                            hostname: p.hostname,
                            endpoint_id: p.endpoint_id,
                            tags: p.tags,
                        })
                        .collect()),
                    coordinator::CoordResp::Error { message } => Err(Error::from_reason(message)),
                    _ => Err(Error::from_reason("unexpected coord response")),
                }
            }
        }
    }

    /// Open a duplex stream to `host:port` where `host` is a peer overlay IP,
    /// hostname, or endpoint id.
    #[napi]
    pub async fn open_stream(&self, host: String, port: u16) -> Result<TunTunStream> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => {
                let peer = resolve_peer(node, &host)
                    .ok_or_else(|| Error::from_reason(format!("no peer matches host {host}")))?;
                let (send, recv) = dial_stream(&node.pool, peer.endpoint, port, host)
                    .await
                    .map_err(err)?;
                Ok(TunTunStream::from_iroh(send, recv))
            }
            #[cfg(unix)]
            NodeInner::Client { sock_path, .. } => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut conn = tokio::net::UnixStream::connect(sock_path)
                    .await
                    .map_err(err_io)?;
                let req = coordinator::ClientReq::OpenStream { host, port };
                let mut buf = serde_json::to_vec(&req).map_err(err_json)?;
                buf.push(b'\n');
                conn.write_all(&buf).await.map_err(err_io)?;

                let mut br = BufReader::new(&mut conn);
                let mut line = String::new();
                br.read_line(&mut line).await.map_err(err_io)?;
                let resp: coordinator::CoordResp =
                    serde_json::from_str(line.trim()).map_err(err_json)?;
                match resp {
                    coordinator::CoordResp::Ready => {
                        // Any buffered bytes past the newline stay in the BufReader;
                        // drain into a leftover buffer.
                        let leftover = br.buffer().to_vec();
                        drop(br);
                        Ok(TunTunStream::from_uds(conn, leftover))
                    }
                    coordinator::CoordResp::Error { message } => Err(Error::from_reason(message)),
                    _ => Err(Error::from_reason("unexpected coord response")),
                }
            }
        }
    }

    /// Best-effort shutdown. Multiple calls are safe.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => {
                node.shutdown().await;
            }
            #[cfg(unix)]
            NodeInner::Client { .. } => {}
        }
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
        let node = self.require_coordinator()?;
        let records = node
            .send
            .send_file(std::path::Path::new(&path), &target, message)
            .await
            .map_err(err)?;
        Ok(records.into_iter().map(TransferJs::from).collect())
    }

    /// Accept a pending inbound transfer offer.
    #[napi]
    pub async fn accept_transfer(&self, transfer_id: String) -> Result<TransferJs> {
        let node = self.require_coordinator()?;
        let record = node.send.accept_pending(&transfer_id).await.map_err(err)?;
        Ok(TransferJs::from(record))
    }

    /// Reject a pending inbound transfer offer.
    #[napi]
    pub async fn reject_transfer(&self, transfer_id: String, reason: Option<String>) -> Result<()> {
        let node = self.require_coordinator()?;
        node.send
            .reject_pending(&transfer_id, reason)
            .await
            .map_err(err)?;
        Ok(())
    }

    /// List pending inbound offers (prompt consent mode).
    #[napi]
    pub async fn list_pending_transfers(&self) -> Result<Vec<TransferJs>> {
        let node = self.require_coordinator()?;
        Ok(node
            .send
            .list_pending()
            .into_iter()
            .map(TransferJs::from)
            .collect())
    }

    /// List active transfers.
    #[napi]
    pub async fn list_transfers(&self) -> Result<Vec<TransferJs>> {
        let node = self.require_coordinator()?;
        Ok(node
            .send
            .list_active()
            .into_iter()
            .chain(node.send.list_pending())
            .map(TransferJs::from)
            .collect())
    }

    fn require_coordinator(&self) -> Result<&CoreNode> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Ok(node),
            #[cfg(unix)]
            NodeInner::Client { .. } => Err(Error::from_reason(
                "send APIs require the coordinator process (standalone or primary SDK node)",
            )),
        }
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

impl From<tuntun_core::TransferRecord> for TransferJs {
    fn from(r: tuntun_core::TransferRecord) -> Self {
        use tuntun_core::TransferDirection;
        Self {
            transfer_id: r.transfer_id,
            direction: match r.direction {
                TransferDirection::Outbound => "outbound".into(),
                TransferDirection::Inbound => "inbound".into(),
            },
            peer_endpoint_id: r.peer_endpoint_id,
            peer_hostname: r.peer_hostname,
            file_name: r.file_name,
            size: r.size as i64,
            hash: r.hash,
            status: r.status.as_str().into(),
            percent: r.percent as f64,
            bytes_transferred: r.bytes_transferred as i64,
            message: r.message,
            error: r.error,
            inbox_path: r.inbox_path,
            is_directory: r.is_directory,
        }
    }
}

fn resolve_peer(node: &CoreNode, host: &str) -> Option<Arc<tuntun_core::PeerInfo>> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

fn spawn_stream_acceptor(node: Arc<CoreNode>) {
    let ep = node.endpoint.clone();
    let send_mgr = node.send.clone();
    let handler: tuntun_core::stream::StreamHandler = Arc::new(|accepted| {
        Box::pin(async move {
            tracing::info!(
                peer = %accepted.peer_hex,
                host = %accepted.header.host,
                port = accepted.header.dst_port,
                "inbound stream (no handler registered - dropping)"
            );
            drop(accepted);
        })
    });
    tokio::spawn(async move {
        tracing::info!("SDK unified ALPN acceptor started");
        while let Some(incoming) = ep.accept().await {
            let handler = handler.clone();
            let send_mgr = send_mgr.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(?e, "handshake");
                        return;
                    }
                };
                let alpn = conn.alpn();
                if alpn == tuntun_core::TUNNEL_STREAM_ALPN {
                    tuntun_core::serve_stream_connection(conn, handler).await;
                } else if alpn == tuntun_common::SEND_ALPN {
                    send_mgr.handle_offer_connection(conn).await;
                } else if alpn == iroh_blobs::ALPN {
                    send_mgr.handle_blobs_connection(conn).await;
                }
            });
        }
        tracing::error!("SDK ALPN acceptor exited");
    });
}

/// A duplex byte stream. Read via `read()`, write via `write()`, close via `close()`.
#[napi]
pub struct TunTunStream {
    inner: Arc<Mutex<duplex::Duplex>>,
}

#[napi]
impl TunTunStream {
    pub(crate) fn from_iroh(
        send: iroh::endpoint::SendStream,
        recv: iroh::endpoint::RecvStream,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(duplex::Duplex::Iroh { send, recv })),
        }
    }

    #[cfg(unix)]
    pub(crate) fn from_uds(sock: tokio::net::UnixStream, leftover: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(duplex::Duplex::Uds { sock, leftover })),
        }
    }

    /// Read up to `max_len` bytes. Returns an empty buffer at EOF.
    #[napi]
    pub async fn read(&self, max_len: u32) -> Result<Buffer> {
        let mut guard = self.inner.lock().await;
        let mut buf = vec![0u8; max_len as usize];
        let n = guard.read(&mut buf).await.map_err(err)?;
        buf.truncate(n);
        Ok(buf.into())
    }

    /// Write all `data` bytes.
    #[napi]
    pub async fn write(&self, data: Buffer) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.write_all(data.as_ref()).await.map_err(err)?;
        Ok(())
    }

    #[napi]
    pub async fn end(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.shutdown().await.map_err(err)?;
        Ok(())
    }
}

fn err(e: anyhow::Error) -> Error {
    Error::from_reason(format!("{e:#}"))
}

#[cfg(unix)]
fn err_io(e: std::io::Error) -> Error {
    err(e.into())
}

#[cfg(unix)]
fn err_json(e: serde_json::Error) -> Error {
    err(e.into())
}
