use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::{BufMut, BytesMut};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TUNNEL_STREAM_ALPN: &[u8] = b"tunnet/stream/1";

pub const PROTO_VERSION: u8 = 1;
pub const MAX_HOST_LEN: usize = 253;
const MAX_STREAM_WORKERS: usize = 64;
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct StreamHeader {
    pub network: uuid::Uuid,
    pub dst_port: u16,
    pub host: String,
}

impl StreamHeader {
    pub async fn write_to(&self, send: &mut SendStream) -> anyhow::Result<()> {
        if self.host.len() > MAX_HOST_LEN {
            bail!("host too long");
        }
        let mut buf = BytesMut::with_capacity(21 + self.host.len());
        buf.put_u8(PROTO_VERSION);
        buf.extend_from_slice(self.network.as_bytes());
        buf.put_u16(self.dst_port);
        buf.put_u16(self.host.len() as u16);
        buf.extend_from_slice(self.host.as_bytes());
        send.write_all(&buf).await.context("write header")?;
        Ok(())
    }

    pub async fn read_from(recv: &mut RecvStream) -> anyhow::Result<Self> {
        let mut prefix = [0u8; 21];
        recv.read_exact(&mut prefix)
            .await
            .context("read header prefix")?;
        if prefix[0] != PROTO_VERSION {
            bail!("unsupported stream proto version {}", prefix[0]);
        }
        let network = uuid::Uuid::from_slice(&prefix[1..17])?;
        let dst_port = u16::from_be_bytes([prefix[17], prefix[18]]);
        let host_len = u16::from_be_bytes([prefix[19], prefix[20]]) as usize;
        if host_len > MAX_HOST_LEN {
            bail!("host too long ({host_len})");
        }
        let mut host = vec![0u8; host_len];
        if host_len > 0 {
            recv.read_exact(&mut host).await.context("read host")?;
        }
        Ok(Self {
            network,
            dst_port,
            host: String::from_utf8(host).context("host utf8")?,
        })
    }
}

struct StreamAuthority {
    forwarding: crate::forward::ForwardingStore,
    policy: crate::forward::PolicyEngine,
    peer: EndpointId,
    network: uuid::Uuid,
    port: u16,
    host: String,
    direction: tunnet_common::policy::Direction,
    epoch: crate::forward::snapshot::AuthorizationEpoch,
    posture: Option<Arc<bool>>,
    proof: Option<crate::forward::PostureAuthorization>,
}

impl StreamAuthority {
    fn allowed(&self) -> bool {
        let snap = self.forwarding.load();
        if snap.auth_epoch(self.network) != self.epoch
            || self
                .posture
                .as_ref()
                .is_some_and(|posture| !Arc::ptr_eq(&snap.posture_ok.load_full(), posture))
        {
            return false;
        }
        if self
            .proof
            .is_some_and(|proof| !proof.allows(&snap, self.network, self.peer))
        {
            return false;
        }
        authorize_flow(
            &snap,
            &self.policy,
            self.peer,
            self.network,
            self.port,
            &self.host,
            self.direction,
        )
    }

    async fn revoked(self: Arc<Self>) {
        let mut changes = self.forwarding.subscribe_changes();
        loop {
            let snap = self.forwarding.load();
            #[cfg(feature = "direct")]
            let auth = snap.direct_auth.clone();
            #[cfg(feature = "direct")]
            let mut auth_changes = auth.as_ref().map(|auth| auth.subscribe_changes());
            if !self.allowed() {
                return;
            }
            let expiry = self
                .proof
                .and_then(|proof| proof.valid_until(&snap, self.network, self.peer));
            #[cfg(feature = "direct")]
            let expiry = expiry
                .into_iter()
                .chain(auth.as_ref().and_then(|auth| {
                    auth.network_expiry(&self.peer.to_string(), self.network)
                        .into_iter()
                        .chain(auth.network_expiry(&snap.self_id.endpoint_hex, self.network))
                        .min()
                }))
                .min();
            tokio::select! {
                result = changes.changed() => if result.is_err() { return; },
                _ = async {
                    #[cfg(feature = "direct")]
                    if let Some(changes) = &mut auth_changes {
                        let _ = changes.changed().await;
                        return;
                    }
                    std::future::pending::<()>().await;
                } => {},
                _ = async {
                    if let Some(expiry) = expiry {
                        let millis = (expiry.as_millisecond() - jiff::Timestamp::now().as_millisecond()).max(0);
                        tokio::time::sleep(std::time::Duration::from_millis(millis as u64)).await;
                        return;
                    }
                    std::future::pending::<()>().await;
                } => {},
            }
        }
    }
}

fn local_posture(
    snap: &crate::forward::ForwardingSnapshot,
    proof: Option<crate::forward::PostureAuthorization>,
) -> Option<Arc<bool>> {
    proof
        .filter(|proof| proof.source == tunnet_common::policy::Direction::Outbound)
        .map(|_| snap.posture_ok.load_full())
}

fn flow_authorization(
    snap: &crate::forward::ForwardingSnapshot,
    policy: &crate::forward::PolicyEngine,
    endpoint: EndpointId,
    network: uuid::Uuid,
    port: u16,
    host: &str,
    direction: tunnet_common::policy::Direction,
) -> Option<Option<crate::forward::PostureAuthorization>> {
    use tunnet_common::policy::{Direction, FlowContext, FlowEndpoint, Protocol};
    if !snap.allows_network(network, endpoint) {
        return None;
    }
    let binding = snap.binding(network, endpoint)?;
    let local_ip = snap.local_ip(network)?;
    let mut src = snap.self_endpoint();
    src.ip = Some(local_ip);
    src.network = binding.network_name.clone();
    src.posture = snap.source_posture(network, endpoint, Direction::Outbound);
    let ip = host.parse().ok();
    let dst = if ip == Some(binding.ip) {
        snap.peer_endpoint(network, endpoint).unwrap()
    } else {
        FlowEndpoint::external(ip)
    };
    let (src, dst) = match direction {
        Direction::Outbound => {
            if !**snap.posture_ok.load() {
                src.posture = tunnet_common::PeerPosture::Unknown;
            }
            (src, dst)
        }
        Direction::Inbound => (snap.peer_endpoint(network, endpoint).unwrap(), src),
    };
    let flow = FlowContext {
        src,
        dst,
        protocol: Protocol::Tcp,
        dst_port: Some(port),
    };
    let peer = crate::forward::policy::PeerCtx {
        endpoint,
        hex: &binding.endpoint_hex,
        hostname: &binding.hostname,
        tags: &binding.tags,
        network_name: &binding.network_name,
    };
    match policy.evaluate_network_flow(snap, network, &peer, direction, &flow) {
        crate::forward::Decision::Allow { posture } => Some(posture),
        _ => None,
    }
}

fn authorize_flow(
    snap: &crate::forward::ForwardingSnapshot,
    policy: &crate::forward::PolicyEngine,
    endpoint: EndpointId,
    network: uuid::Uuid,
    port: u16,
    host: &str,
    direction: tunnet_common::policy::Direction,
) -> bool {
    flow_authorization(snap, policy, endpoint, network, port, host, direction).is_some()
}

pub struct AuthorizedStream {
    send: SendStream,
    recv: RecvStream,
    authority: Arc<StreamAuthority>,
    read_revoked: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_revoked: Pin<Box<dyn Future<Output = ()> + Send>>,
    denied: bool,
}

impl AuthorizedStream {
    fn check(&mut self, cx: &mut std::task::Context<'_>, read: bool) -> std::io::Result<()> {
        let revoked = if read {
            &mut self.read_revoked
        } else {
            &mut self.write_revoked
        };
        if self.denied || revoked.as_mut().poll(cx).is_ready() || !self.authority.allowed() {
            self.denied = true;
            let _ = self.send.reset(403u32.into());
            let _ = self.recv.stop(403u32.into());
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "stream authorization revoked",
            ));
        }
        Ok(())
    }
}

impl tokio::io::AsyncRead for AuthorizedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let gate = self.authority.forwarding.authorization_gate();
        let _guard = gate.read();
        self.check(cx, true)?;
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AuthorizedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let gate = self.authority.forwarding.authorization_gate();
        let _guard = gate.read();
        self.check(cx, false)?;
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let gate = self.authority.forwarding.authorization_gate();
        let _guard = gate.read();
        self.check(cx, false)?;
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let gate = self.authority.forwarding.authorization_gate();
        let _guard = gate.read();
        self.check(cx, false)?;
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

pub async fn dial_stream(
    node: &crate::node::CoreNode,
    peer: EndpointId,
    network: uuid::Uuid,
    dst_port: u16,
    host: String,
) -> anyhow::Result<AuthorizedStream> {
    let snap = node.forwarding.load();
    let Some(proof) = flow_authorization(
        &snap,
        &node.policy,
        peer,
        network,
        dst_port,
        &host,
        tunnet_common::policy::Direction::Outbound,
    ) else {
        bail!("stream policy denies destination");
    };
    let authority = Arc::new(StreamAuthority {
        forwarding: node.forwarding.clone(),
        policy: node.policy.clone(),
        peer,
        network,
        port: dst_port,
        host: host.clone(),
        direction: tunnet_common::policy::Direction::Outbound,
        epoch: snap.auth_epoch(network),
        posture: local_posture(&snap, proof),
        proof,
    });
    let revoked = authority.clone().revoked();
    tokio::pin!(revoked);
    let opening = async {
        let conn = node.pool.get_alpn(peer, TUNNEL_STREAM_ALPN).await?;
        let (mut send, recv) = conn.open_bi().await.context("open_bi")?;
        let header = StreamHeader {
            network,
            dst_port,
            host,
        };
        header.write_to(&mut send).await?;
        anyhow::Ok((send, recv))
    };
    let (send, recv) = tokio::select! {
        biased;
        _ = &mut revoked => bail!("stream authorization revoked"),
        result = opening => result?,
    };
    Ok(AuthorizedStream {
        send,
        recv,
        read_revoked: Box::pin(authority.clone().revoked()),
        write_revoked: Box::pin(authority.clone().revoked()),
        denied: false,
        authority,
    })
}

pub type StreamHandler = Arc<
    dyn Fn(AcceptedStream) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>
        + Send
        + Sync
        + 'static,
>;

pub struct AcceptedStream {
    pub peer: EndpointId,
    pub peer_hex: String,
    pub header: StreamHeader,
    pub send: SendStream,
    pub recv: RecvStream,
}

pub struct AcceptedAuthorizedStream {
    pub peer: EndpointId,
    pub peer_hex: String,
    pub header: StreamHeader,
    pub stream: AuthorizedStream,
}

pub fn accept_stream(
    node: &crate::node::CoreNode,
    accepted: AcceptedStream,
) -> anyhow::Result<AcceptedAuthorizedStream> {
    let gate = node.forwarding.authorization_gate();
    let _guard = gate.read();
    let snap = node.forwarding.load();
    let network = accepted.header.network;
    let Some(proof) = flow_authorization(
        &snap,
        &node.policy,
        accepted.peer,
        network,
        accepted.header.dst_port,
        &accepted.header.host,
        tunnet_common::policy::Direction::Inbound,
    ) else {
        bail!("stream policy denies incoming connection");
    };
    let authority = Arc::new(StreamAuthority {
        forwarding: node.forwarding.clone(),
        policy: node.policy.clone(),
        peer: accepted.peer,
        network,
        port: accepted.header.dst_port,
        host: accepted.header.host.clone(),
        direction: tunnet_common::policy::Direction::Inbound,
        epoch: snap.auth_epoch(network),
        posture: local_posture(&snap, proof),
        proof,
    });
    Ok(AcceptedAuthorizedStream {
        peer: accepted.peer,
        peer_hex: accepted.peer_hex,
        header: accepted.header,
        stream: AuthorizedStream {
            send: accepted.send,
            recv: accepted.recv,
            read_revoked: Box::pin(authority.clone().revoked()),
            write_revoked: Box::pin(authority.clone().revoked()),
            denied: false,
            authority,
        },
    })
}

/// Handle an already-accepted connection negotiated with [`TUNNEL_STREAM_ALPN`].
pub async fn serve_stream_connection(conn: Connection, handler: StreamHandler) {
    let peer = conn.remote_id();
    let peer_hex = format!("{peer}");
    let mut workers = tokio::task::JoinSet::new();
    loop {
        let incoming = tokio::select! {
            biased;
            _ = conn.closed() => break,
            _ = workers.join_next(), if !workers.is_empty() => continue,
            incoming = conn.accept_bi(), if workers.len() < MAX_STREAM_WORKERS => incoming,
        };
        let (send, mut recv) = match incoming {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(%peer_hex, ?e, "accept_bi closed");
                break;
            }
        };
        let h = handler.clone();
        let peer_hex = peer_hex.clone();
        workers.spawn(async move {
            let header = match tokio::time::timeout(
                HEADER_TIMEOUT,
                StreamHeader::read_from(&mut recv),
            )
            .await
            {
                Ok(Ok(header)) => header,
                Ok(Err(e)) => {
                    tracing::debug!(%peer_hex, ?e, "bad stream header");
                    return;
                }
                Err(_) => return,
            };
            h(AcceptedStream {
                peer,
                peer_hex,
                header,
                send,
                recv,
            })
            .await;
        });
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

/// [`ProtocolHandler`] for [`TUNNEL_STREAM_ALPN`].
#[derive(Clone)]
pub struct StreamProtocolHandler {
    handler: StreamHandler,
}

impl StreamProtocolHandler {
    pub fn new(handler: StreamHandler) -> Self {
        Self { handler }
    }
}

impl fmt::Debug for StreamProtocolHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamProtocolHandler")
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for StreamProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        serve_stream_connection(connection, self.handler.clone()).await;
        Ok(())
    }
}

pub async fn splice_bidirectional<R, W>(
    mut recv: RecvStream,
    mut send: SendStream,
    mut local_read: R,
    mut local_write: W,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let up = async move {
        // local → remote
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    };
    let down = async move {
        // remote → local
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match recv.read(&mut buf).await? {
                Some(n) => n,
                None => break,
            };
            local_write.write_all(&buf[..n]).await?;
        }
        local_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[rstest::rstest]
    #[case(true)]
    #[case(false)]
    #[tokio::test]
    async fn authorized_native_stream_wakes_and_stays_revoked(#[case] posture_change: bool) {
        use crate::forward::{ForwardingStore, PolicyEngine, SelfIdentity};
        use crate::routing::RoutingTable;
        use tunnet_common::policy::{
            Action, DefaultAction, PolicyBundle, PolicyRule, RuleScope, Selector,
        };
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let a = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![TUNNEL_STREAM_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![TUNNEL_STREAM_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(a.addr());
        lookup.add_endpoint_info(b.addr());
        let (client, server) = tokio::join!(a.connect(b.id(), TUNNEL_STREAM_ALPN), async {
            b.accept().await.unwrap().await.unwrap()
        });
        let client = client.unwrap();
        let routes = RoutingTable::new();
        let forwarding = ForwardingStore::new();
        let network = uuid::Uuid::nil();
        let self_hex = a.id().to_string();
        let peer_hex = b.id().to_string();
        routes.replace(
            &[
                tunnet_common::PeerEntry {
                    ip: "100.64.0.1".parse().unwrap(),
                    endpoint_id: self_hex.clone(),
                    hostname: "self".into(),
                    tags: vec![],
                    ssh_host_key: None,
                    posture: tunnet_common::PeerPosture::Unknown,
                },
                tunnet_common::PeerEntry {
                    ip: "100.64.0.2".parse().unwrap(),
                    endpoint_id: peer_hex,
                    hostname: "peer".into(),
                    tags: vec![],
                    ssh_host_key: None,
                    posture: tunnet_common::PeerPosture::Unknown,
                },
            ],
            &[],
            &[],
            &[],
            &Default::default(),
            &Default::default(),
            "net",
            network,
            &self_hex,
            1,
        );
        forwarding.set_managed_bundle(
            &routes,
            network,
            PolicyBundle {
                rules: vec![PolicyRule {
                    src: Selector::Any,
                    dst: Selector::Any,
                    action: Action::Allow,
                    ports: vec![],
                    protocol: None,
                    priority: 1,
                    order_index: 0,
                    scope: RuleScope::Network,
                    enabled: true,
                    slug: None,
                    src_posture: vec!["compliant".into()],
                }],
                default_action: DefaultAction::Deny,
                ..PolicyBundle::default()
            },
            SelfIdentity {
                endpoint_hex: self_hex,
                ip: "100.64.0.1".parse().unwrap(),
                tags: vec![],
                network: "net".into(),
                posture: tunnet_common::PeerPosture::verified(
                    ["compliant"],
                    jiff::Timestamp::now() + jiff::SignedDuration::from_secs(60),
                ),
            },
        );
        let policy = PolicyEngine::new();
        let snap = forwarding.load();
        assert!(!authorize_flow(
            &snap,
            &policy,
            b.id(),
            network,
            443,
            "100.64.0.1",
            tunnet_common::policy::Direction::Inbound
        ));
        assert!(!authorize_flow(
            &snap,
            &policy,
            b.id(),
            uuid::Uuid::from_u128(1),
            443,
            "100.64.0.2",
            tunnet_common::policy::Direction::Outbound
        ));
        let authority = Arc::new(StreamAuthority {
            forwarding: forwarding.clone(),
            policy: policy.clone(),
            peer: b.id(),
            network,
            port: 443,
            host: "100.64.0.2".into(),
            direction: tunnet_common::policy::Direction::Outbound,
            epoch: snap.auth_epoch(network),
            posture: local_posture(
                &snap,
                Some(crate::forward::PostureAuthorization {
                    source: tunnet_common::policy::Direction::Outbound,
                }),
            ),
            proof: Some(crate::forward::PostureAuthorization {
                source: tunnet_common::policy::Direction::Outbound,
            }),
        });
        assert!(authority.allowed());
        let (send, recv) = client.open_bi().await.unwrap();
        let mut stream = AuthorizedStream {
            send,
            recv,
            read_revoked: Box::pin(authority.clone().revoked()),
            write_revoked: Box::pin(authority.clone().revoked()),
            authority: authority.clone(),
            denied: false,
        };
        stream.write_all(b"x").await.unwrap();
        let (_send, mut recv) = server.accept_bi().await.unwrap();
        let mut byte = [0];
        recv.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"x");
        let mut buf = [0];
        let read = tokio::io::AsyncReadExt::read(&mut stream, &mut buf);
        tokio::pin!(read);
        assert!(futures_util::poll!(read.as_mut()).is_pending());
        if posture_change {
            let gate = forwarding.authorization_gate();
            let _guard = gate.write();
            forwarding.posture_source().store(Arc::new(false));
            forwarding.notify_authorization_changed();
        } else {
            forwarding.clear_managed(&routes, network);
        }
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), read)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        if posture_change {
            let gate = forwarding.authorization_gate();
            let _guard = gate.write();
            forwarding.posture_source().store(Arc::new(true));
            forwarding.notify_authorization_changed();
            assert!(authorize_flow(
                &forwarding.load(),
                &policy,
                b.id(),
                network,
                443,
                "100.64.0.2",
                tunnet_common::policy::Direction::Outbound
            ));
        }
        assert!(!authority.allowed());
        assert_eq!(
            stream.write_all(b"blocked").await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        a.close().await;
        b.close().await;
    }

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn stalled_headers_do_not_serialize_or_outlive_bounded_connection_workers() {
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let a = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![TUNNEL_STREAM_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![TUNNEL_STREAM_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(a.addr());
        lookup.add_endpoint_info(b.addr());
        let (client, server) = tokio::join!(a.connect(b.id(), TUNNEL_STREAM_ALPN), async {
            b.accept().await.unwrap().await.unwrap()
        });
        let client = client.unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let handler: StreamHandler = {
            let active = active.clone();
            let started = started.clone();
            Arc::new(move |_accepted| {
                let active = active.clone();
                let started = started.clone();
                Box::pin(async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(active);
                    started.add_permits(1);
                    std::future::pending::<()>().await;
                })
            })
        };
        let serve = tokio::spawn(serve_stream_connection(server, handler));
        let mut streams = Vec::new();
        let (mut send, recv) = client.open_bi().await.unwrap();
        send.write_all(&[PROTO_VERSION]).await.unwrap();
        streams.push((send, recv));
        for _ in 0..MAX_STREAM_WORKERS {
            let (mut send, recv) = client.open_bi().await.unwrap();
            StreamHeader {
                network: uuid::Uuid::nil(),
                dst_port: 443,
                host: "example.test".into(),
            }
            .write_to(&mut send)
            .await
            .unwrap();
            streams.push((send, recv));
        }
        let timeout = std::time::Duration::from_secs(5);
        tokio::time::timeout(
            timeout,
            started.acquire_many((MAX_STREAM_WORKERS - 1) as u32),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        assert_eq!(active.load(Ordering::SeqCst), MAX_STREAM_WORKERS - 1);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), started.acquire())
                .await
                .is_err()
        );
        client.close(0u32.into(), b"test_finished");
        tokio::time::timeout(timeout, serve).await.unwrap().unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
        a.close().await;
        b.close().await;
    }
}
