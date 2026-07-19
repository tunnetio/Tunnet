//! [`TunnetNode`] - embed a Tunnet mesh node in your process.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tunnet_core::{
    AgentIdentity, CoreNode, CoreNodeConfig, PersistedState, StatePaths, stream::dial_stream,
};

#[cfg(any(unix, windows))]
use tunnet_core::coordinator::{self, Role, spawn_coord_server};

#[cfg(feature = "managed")]
use crate::enroll::{EnrollConfig, enroll};
use crate::error::{Error, Result};
use crate::listener::{InboundConnection, StreamListener};
use crate::peer::Peer;
use crate::stream::TunnetStream;
use crate::types::StreamHeader;

/// Builder for [`TunnetNode`].
#[derive(Debug, Clone, Default)]
pub struct TunnetNodeBuilder {
    hostname: Option<String>,
    state_dir: Option<String>,
    api_key: Option<String>,
    organization_id: Option<String>,
    network_id: Option<String>,
    control_url: Option<String>,
    management_url: Option<String>,
    standalone: bool,
    poll_secs: Option<u64>,
    process_name: Option<String>,
    runtime: Option<String>,
}

impl TunnetNodeBuilder {
    /// Set the hostname advertised to the control plane / peers.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Directory for identity and persisted state.
    pub fn state_dir(mut self, dir: impl Into<String>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Management API key for auto-enrollment when no identity exists.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Organization id for API-key enrollment.
    pub fn organization_id(mut self, id: impl Into<String>) -> Self {
        self.organization_id = Some(id.into());
        self
    }

    /// Network id (UUID) for API-key enrollment.
    pub fn network_id(mut self, id: impl Into<String>) -> Self {
        self.network_id = Some(id.into());
        self
    }

    /// Control plane base URL.
    pub fn control_url(mut self, url: impl Into<String>) -> Self {
        self.control_url = Some(url.into());
        self
    }

    /// Management API base URL.
    pub fn management_url(mut self, url: impl Into<String>) -> Self {
        self.management_url = Some(url.into());
        self
    }

    /// When true, skip the coordinator dance and always create a private endpoint.
    pub fn standalone(mut self, standalone: bool) -> Self {
        self.standalone = standalone;
        self
    }

    /// Control-plane poll interval in seconds (default 30).
    pub fn poll_secs(mut self, secs: u64) -> Self {
        self.poll_secs = Some(secs);
        self
    }

    /// Optional process name metadata.
    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Optional runtime metadata.
    pub fn runtime(mut self, runtime: impl Into<String>) -> Self {
        self.runtime = Some(runtime.into());
        self
    }

    /// Resolve paths, enroll if needed, bootstrap the overlay, and return a running node.
    pub async fn start(self) -> Result<TunnetNode> {
        TunnetNode::start(self).await
    }
}

/// A running Tunnet mesh node (coordinator or multi-process client).
pub struct TunnetNode {
    inner: Arc<NodeInner>,
}

enum NodeInner {
    Coordinator {
        node: Arc<CoreNode>,
        listener_rx: Mutex<Option<mpsc::Receiver<InboundConnection>>>,
        _sock_path: PathBuf,
        _router: iroh::protocol::Router,
    },
    #[cfg(any(unix, windows))]
    Client {
        sock_path: PathBuf,
        _network_id: uuid::Uuid,
    },
}

impl TunnetNode {
    /// Start building a node.
    pub fn builder() -> TunnetNodeBuilder {
        TunnetNodeBuilder::default()
    }

    async fn start(cfg: TunnetNodeBuilder) -> Result<Self> {
        let paths = StatePaths::resolve(cfg.state_dir.as_deref());
        let policy = tunnet_core::SealPolicy::from_env_and_flag(false);

        let identity = match tunnet_core::load_agent(&paths, policy) {
            Ok((id, _, _)) => id,
            Err(_) => {
                #[cfg(feature = "managed")]
                {
                    if let (Some(api_key), Some(org_id), Some(network_id)) = (
                        cfg.api_key.as_deref(),
                        cfg.organization_id.as_deref(),
                        cfg.network_id.as_deref(),
                    ) {
                        let control_url = cfg
                            .control_url
                            .clone()
                            .or_else(|| std::env::var("CONTROL_PLANE_URL").ok())
                            .ok_or_else(|| {
                                Error::InvalidConfig(
                                    "control_url is required for API key enrolment".into(),
                                )
                            })?;
                        enroll(EnrollConfig {
                            control_url: Some(control_url),
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
                        tunnet_core::load_agent(&paths, policy)
                            .map(|(id, _, _)| id)
                            .map_err(|_| {
                                Error::EnrollmentFailed(
                                    "enrolment succeeded but identity was not persisted".into(),
                                )
                            })?
                    } else {
                        return Err(Error::NotEnrolled);
                    }
                }
                #[cfg(not(feature = "managed"))]
                {
                    let _ = cfg;
                    return Err(Error::NotEnrolled);
                }
            }
        };
        let (_, persisted, _) =
            tunnet_core::load_agent(&paths, policy).map_err(Error::from_anyhow)?;

        let hostname = cfg
            .hostname
            .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "tunnet-sdk".into()));
        let poll_secs = cfg.poll_secs.unwrap_or(30);
        let core_cfg = CoreNodeConfig {
            hostname,
            poll_secs,
            kind: "sdk",
            agent_version: env!("CARGO_PKG_VERSION"),
            advertise_datagram_alpn: false,
            ..Default::default()
        };

        if cfg.standalone {
            return Self::bootstrap_coordinator(
                identity,
                persisted,
                paths,
                core_cfg,
                PathBuf::new(),
            )
            .await;
        }

        #[cfg(any(unix, windows))]
        {
            let network_id = persisted
                .primary_network_id()
                .ok_or_else(|| Error::InvalidConfig("no network id in persisted state".into()))?;
            match coordinator::acquire(network_id)
                .await
                .map_err(Error::from_anyhow)?
            {
                Role::Client { sock_path } => {
                    // Coordinator owns the endpoint; this process is a thin IPC client.
                    drop((identity, persisted, paths, core_cfg));
                    Ok(Self {
                        inner: Arc::new(NodeInner::Client {
                            sock_path,
                            _network_id: network_id,
                        }),
                    })
                }
                Role::Coordinator {
                    #[cfg(unix)]
                    listener,
                    #[cfg(windows)]
                    pipe_name,
                    _lock,
                    sock_path,
                } => {
                    let node = Self::bootstrap_coordinator(
                        identity,
                        persisted,
                        paths,
                        core_cfg,
                        sock_path.clone(),
                    )
                    .await?;
                    if let NodeInner::Coordinator { node: core, .. } = &*node.inner {
                        let lock_holder: Arc<coordinator::LockFile> = Arc::new(_lock);
                        std::mem::forget(lock_holder);
                        #[cfg(unix)]
                        spawn_coord_server(listener, core.clone());
                        #[cfg(windows)]
                        spawn_coord_server(pipe_name, core.clone());
                    }
                    Ok(node)
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self::bootstrap_coordinator(identity, persisted, paths, core_cfg, PathBuf::new()).await
        }
    }

    async fn bootstrap_coordinator(
        identity: AgentIdentity,
        persisted: PersistedState,
        paths: StatePaths,
        core_cfg: CoreNodeConfig,
        sock_path: PathBuf,
    ) -> Result<Self> {
        let node = CoreNode::bootstrap(identity, persisted, paths, core_cfg)
            .await
            .map_err(Error::from_anyhow)?;
        let node = Arc::new(node);
        let (tx, rx) = mpsc::channel(64);
        let router = spawn_stream_acceptor(node.clone(), tx);
        Ok(Self {
            inner: Arc::new(NodeInner::Coordinator {
                node,
                listener_rx: Mutex::new(Some(rx)),
                _sock_path: sock_path,
                _router: router,
            }),
        })
    }

    /// Our own endpoint id (hex). Empty string in client mode.
    pub fn endpoint_id(&self) -> String {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => node.endpoint_id_hex(),
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => String::new(),
        }
    }

    /// Our overlay IPv4 address, if this process owns the endpoint.
    pub fn self_ip(&self) -> Option<Ipv4Addr> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Some(node.self_ipv4),
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => None,
        }
    }

    /// Whether this process owns the iroh endpoint (coordinator / standalone).
    pub fn is_coordinator(&self) -> bool {
        matches!(&*self.inner, NodeInner::Coordinator { .. })
    }

    /// List peers currently known to the routing table.
    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Ok(node
                .routes
                .peers()
                .into_iter()
                .map(|p| Peer::from_peer_info(p.as_ref()))
                .collect()),
            #[cfg(any(unix, windows))]
            NodeInner::Client { sock_path, .. } => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut conn = coordinator::connect_client(sock_path)
                    .await
                    .map_err(Error::from_anyhow)?;
                let req = coordinator::ClientReq::ListPeers;
                let mut buf = serde_json::to_vec(&req).map_err(Error::from_anyhow)?;
                buf.push(b'\n');
                conn.write_all(&buf).await?;
                let mut br = BufReader::new(conn);
                let mut line = String::new();
                br.read_line(&mut line).await?;
                let resp: coordinator::CoordResp =
                    serde_json::from_str(line.trim()).map_err(Error::from_anyhow)?;
                match resp {
                    coordinator::CoordResp::Peers { peers } => {
                        Ok(peers.into_iter().map(Peer::from_peer_lite).collect())
                    }
                    coordinator::CoordResp::Error { message } => Err(Error::Internal(message)),
                    _ => Err(Error::Internal("unexpected coord response".into())),
                }
            }
        }
    }

    /// Open a duplex stream to `host:port` where `host` is a peer overlay IP,
    /// hostname, or endpoint id.
    pub async fn open_stream(&self, host: impl AsRef<str>, port: u16) -> Result<TunnetStream> {
        let host = host.as_ref();
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => {
                let peer = resolve_peer(node, host)
                    .ok_or_else(|| Error::PeerNotFound(host.to_string()))?;
                let (send, recv) = dial_stream(&node.pool, peer.endpoint, port, host.to_string())
                    .await
                    .map_err(Error::stream)?;
                Ok(TunnetStream::from_iroh(send, recv))
            }
            #[cfg(any(unix, windows))]
            NodeInner::Client { sock_path, .. } => {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut conn = coordinator::connect_client(sock_path)
                    .await
                    .map_err(Error::from_anyhow)?;
                let req = coordinator::ClientReq::OpenStream {
                    host: host.to_string(),
                    port,
                };
                let mut buf = serde_json::to_vec(&req).map_err(Error::from_anyhow)?;
                buf.push(b'\n');
                conn.write_all(&buf).await?;

                let mut br = BufReader::new(&mut conn);
                let mut line = String::new();
                br.read_line(&mut line).await?;
                let resp: coordinator::CoordResp =
                    serde_json::from_str(line.trim()).map_err(Error::from_anyhow)?;
                match resp {
                    coordinator::CoordResp::Ready => {
                        let leftover = br.buffer().to_vec();
                        drop(br);
                        Ok(TunnetStream::from_local(conn, leftover))
                    }
                    coordinator::CoordResp::Error { message } => Err(Error::stream(message)),
                    _ => Err(Error::Internal("unexpected coord response".into())),
                }
            }
        }
    }

    /// Take the inbound stream listener (once).
    ///
    /// Returns [`Error::ListenerUnavailable`] in client mode and
    /// [`Error::ListenerTaken`] if already taken.
    pub async fn stream_listener(&self) -> Result<StreamListener> {
        match &*self.inner {
            NodeInner::Coordinator { listener_rx, .. } => {
                let mut guard = listener_rx.lock().await;
                let rx = guard.take().ok_or(Error::ListenerTaken)?;
                Ok(StreamListener::new(rx))
            }
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => Err(Error::ListenerUnavailable),
        }
    }

    /// Best-effort shutdown. Multiple calls are safe.
    pub async fn shutdown(&self) {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => {
                node.shutdown().await;
            }
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => {}
        }
    }

    #[cfg(feature = "send")]
    pub(crate) fn require_coordinator(&self) -> Result<&CoreNode> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Ok(node),
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => Err(Error::CoordinatorRequired("send APIs")),
        }
    }

    #[cfg(feature = "serve")]
    pub(crate) fn require_coordinator_serve(&self) -> Result<&CoreNode> {
        match &*self.inner {
            NodeInner::Coordinator { node, .. } => Ok(node),
            #[cfg(any(unix, windows))]
            NodeInner::Client { .. } => Err(Error::CoordinatorRequired("serve APIs")),
        }
    }

    /// Send a local file or directory to a mesh peer.
    #[cfg(feature = "send")]
    pub async fn send_file(
        &self,
        path: impl AsRef<std::path::Path>,
        target: impl AsRef<str>,
        message: Option<String>,
    ) -> Result<Vec<crate::Transfer>> {
        let node = self.require_coordinator()?;
        let records = node
            .send
            .send_file(path.as_ref(), target.as_ref(), message)
            .await
            .map_err(Error::from_anyhow)?;
        Ok(records.into_iter().map(crate::Transfer::from).collect())
    }

    /// Accept a pending inbound transfer offer.
    #[cfg(feature = "send")]
    pub async fn accept_transfer(&self, transfer_id: &str) -> Result<crate::Transfer> {
        let node = self.require_coordinator()?;
        let record = node
            .send
            .accept_pending(transfer_id)
            .await
            .map_err(Error::from_anyhow)?;
        Ok(crate::Transfer::from(record))
    }

    /// Reject a pending inbound transfer offer.
    #[cfg(feature = "send")]
    pub async fn reject_transfer(&self, transfer_id: &str, reason: Option<String>) -> Result<()> {
        let node = self.require_coordinator()?;
        node.send
            .reject_pending(transfer_id, reason)
            .await
            .map_err(Error::from_anyhow)?;
        Ok(())
    }

    /// List pending inbound offers (prompt consent mode).
    #[cfg(feature = "send")]
    pub fn list_pending_transfers(&self) -> Result<Vec<crate::Transfer>> {
        let node = self.require_coordinator()?;
        Ok(node
            .send
            .list_pending()
            .into_iter()
            .map(crate::Transfer::from)
            .collect())
    }

    /// List active and pending transfers.
    #[cfg(feature = "send")]
    pub fn list_transfers(&self) -> Result<Vec<crate::Transfer>> {
        let node = self.require_coordinator()?;
        Ok(node
            .send
            .list_active()
            .into_iter()
            .chain(node.send.list_pending())
            .map(crate::Transfer::from)
            .collect())
    }

    /// Start a TCP or TLS reverse proxy on the mesh IP.
    #[cfg(feature = "serve")]
    #[allow(clippy::too_many_arguments)]
    pub async fn serve(
        &self,
        id: impl Into<String>,
        port: u16,
        protocol: &str,
        internal_hostname: &str,
        certificate_pem: Option<&str>,
        private_key_pem: Option<&str>,
        acl: tunnet_core::ServeAcl,
        target_addr: Option<std::net::SocketAddr>,
    ) -> Result<crate::ServeInfo> {
        let node = self.require_coordinator_serve()?;
        let info = node
            .serves
            .start(
                id.into(),
                port,
                protocol,
                internal_hostname,
                certificate_pem,
                private_key_pem,
                acl,
                target_addr,
            )
            .await
            .map_err(Error::from_anyhow)?;
        Ok(crate::ServeInfo::from(info))
    }

    /// Stop a serve on `port`.
    #[cfg(feature = "serve")]
    pub fn stop_serve(&self, port: u16) -> Result<crate::ServeInfo> {
        let node = self.require_coordinator_serve()?;
        let info = node.serves.stop(port).map_err(Error::from_anyhow)?;
        Ok(crate::ServeInfo::from(info))
    }

    /// List active serves.
    #[cfg(feature = "serve")]
    pub fn list_serves(&self) -> Result<Vec<crate::ServeInfo>> {
        let node = self.require_coordinator_serve()?;
        Ok(node
            .serves
            .list()
            .into_iter()
            .map(crate::ServeInfo::from)
            .collect())
    }
}

fn resolve_peer(node: &CoreNode, host: &str) -> Option<Arc<tunnet_core::PeerInfo>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

fn spawn_stream_acceptor(
    node: Arc<CoreNode>,
    inbound_tx: mpsc::Sender<InboundConnection>,
) -> iroh::protocol::Router {
    use iroh::protocol::Router;
    use tunnet_core::StreamProtocolHandler;

    let routes = node.routes.clone();
    let handler: tunnet_core::stream::StreamHandler = Arc::new(move |accepted| {
        let tx = inbound_tx.clone();
        let routes = routes.clone();
        Box::pin(async move {
            let peer = routes
                .lookup_endpoint(&accepted.peer_hex)
                .map(|p| Peer::from_peer_info(&p))
                .unwrap_or_else(|| Peer::from_endpoint_hex(accepted.peer_hex.clone()));
            let header = StreamHeader::from(accepted.header);
            let stream = TunnetStream::from_iroh(accepted.send, accepted.recv);
            let _ = tx
                .send(InboundConnection {
                    stream,
                    peer,
                    header,
                })
                .await;
        })
    });

    let builder = Router::builder(node.endpoint.clone()).accept(
        tunnet_core::TUNNEL_STREAM_ALPN,
        StreamProtocolHandler::new(handler),
    );

    #[cfg(feature = "send")]
    let builder = {
        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Clone)]
        struct SendOfferHandler {
            send: tunnet_core::SendManager,
        }
        impl std::fmt::Debug for SendOfferHandler {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("SendOfferHandler").finish_non_exhaustive()
            }
        }
        impl ProtocolHandler for SendOfferHandler {
            async fn accept(
                &self,
                conn: iroh::endpoint::Connection,
            ) -> std::result::Result<(), AcceptError> {
                self.send.handle_offer_connection(conn).await;
                Ok(())
            }
        }

        #[derive(Clone)]
        struct BlobsHandler {
            send: tunnet_core::SendManager,
        }
        impl std::fmt::Debug for BlobsHandler {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("BlobsHandler").finish_non_exhaustive()
            }
        }
        impl ProtocolHandler for BlobsHandler {
            async fn accept(
                &self,
                conn: iroh::endpoint::Connection,
            ) -> std::result::Result<(), AcceptError> {
                self.send.handle_blobs_connection(conn).await;
                Ok(())
            }
        }

        builder
            .accept(
                tunnet_common::SEND_ALPN,
                SendOfferHandler {
                    send: node.send.clone(),
                },
            )
            .accept(
                iroh_blobs::ALPN,
                BlobsHandler {
                    send: node.send.clone(),
                },
            )
    };

    tracing::info!("SDK unified ALPN acceptor started");
    builder.spawn()
}
