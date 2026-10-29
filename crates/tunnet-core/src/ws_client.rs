use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use jiff::Timestamp;
use parking_lot::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tunnet_common::{
    HDR_ENDPOINT_ID, HDR_SIGNATURE, HDR_TIMESTAMP,
    local_api::LocalEvent,
    signing,
    ws::{ClientMsg, ServerMsg},
};

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Wall-clock overrun past the requested sleep that indicates suspend/resume.
const RESUME_OVERSHOOT: Duration = Duration::from_secs(5);
/// Fast retry when the peer is not listening yet (common when co-located with CP).
const REFUSED_RETRY: Duration = Duration::from_secs(1);
/// Never let a stalled TLS/WebSocket handshake block reconnect state forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often to probe wall clock / send a WS ping while connected.
const KEEP_ALIVE_SECS: u64 = 5;
/// Wall-clock gap while connected that forces a reconnect (VM suspend/resume).
const CONNECTED_RESUME_GAP: Duration = Duration::from_secs(15);

/// Live WebSocket link to the control plane (Managed mode).
#[derive(Clone)]
pub struct ControlPlaneLink {
    inner: Arc<ControlPlaneLinkInner>,
}

struct ControlPlaneLinkInner {
    url: String,
    connected: AtomicBool,
    /// Unix ms when the current session started; 0 if disconnected.
    connected_since_ms: AtomicU64,
    /// Unix ms of last connect/disconnect/error.
    last_change_ms: AtomicU64,
    reconnects: AtomicU64,
    last_error: Mutex<Option<String>>,
    events: Mutex<Option<tokio::sync::broadcast::Sender<LocalEvent>>>,
}

/// Snapshot for IPC / CLI status.
#[derive(Debug, Clone)]
pub struct ControlPlaneLinkSnapshot {
    pub url: String,
    pub connected: bool,
    /// Seconds the current WS session has been up (None if disconnected).
    pub connected_for_secs: Option<u64>,
    /// Seconds since last connect/disconnect/error event.
    pub last_change_secs_ago: Option<u64>,
    pub reconnects: u64,
    pub last_error: Option<String>,
}

impl ControlPlaneLink {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(ControlPlaneLinkInner {
                url: url.into(),
                connected: AtomicBool::new(false),
                connected_since_ms: AtomicU64::new(0),
                last_change_ms: AtomicU64::new(0),
                reconnects: AtomicU64::new(0),
                last_error: Mutex::new(None),
                events: Mutex::new(None),
            }),
        }
    }

    pub fn set_events_tx(&self, tx: tokio::sync::broadcast::Sender<LocalEvent>) {
        *self.inner.events.lock() = Some(tx);
    }

    fn emit_event(&self, event: LocalEvent) {
        if let Some(tx) = self.inner.events.lock().as_ref() {
            let _ = tx.send(event);
        }
    }

    pub fn url(&self) -> &str {
        &self.inner.url
    }

    pub fn mark_connected(&self) {
        let now = u64::try_from(Timestamp::now().as_millisecond()).unwrap_or_default();
        let had_prior = self.inner.last_change_ms.swap(now, Ordering::SeqCst) != 0;
        self.inner.connected.store(true, Ordering::SeqCst);
        self.inner.connected_since_ms.store(now, Ordering::SeqCst);
        *self.inner.last_error.lock() = None;
        if had_prior {
            self.inner.reconnects.fetch_add(1, Ordering::SeqCst);
        }
        self.emit_event(LocalEvent::ControlConnected);
    }

    pub fn mark_disconnected(&self, error: Option<String>) {
        let now = u64::try_from(Timestamp::now().as_millisecond()).unwrap_or_default();
        let was_connected = self.inner.connected.load(Ordering::SeqCst);
        self.inner.connected.store(false, Ordering::SeqCst);
        self.inner.connected_since_ms.store(0, Ordering::SeqCst);
        self.inner.last_change_ms.store(now, Ordering::SeqCst);
        if let Some(e) = error {
            *self.inner.last_error.lock() = Some(e);
        }
        if was_connected {
            self.emit_event(LocalEvent::ControlDisconnected);
        }
    }

    pub fn snapshot(&self) -> ControlPlaneLinkSnapshot {
        let now = u64::try_from(Timestamp::now().as_millisecond()).unwrap_or_default();
        let connected = self.inner.connected.load(Ordering::SeqCst);
        let since = self.inner.connected_since_ms.load(Ordering::SeqCst);
        let change = self.inner.last_change_ms.load(Ordering::SeqCst);
        ControlPlaneLinkSnapshot {
            url: self.inner.url.clone(),
            connected,
            connected_for_secs: if connected && since > 0 && now >= since {
                Some((now - since) / 1000)
            } else {
                None
            },
            last_change_secs_ago: if change > 0 && now >= change {
                Some((now - change) / 1000)
            } else {
                None
            },
            reconnects: self.inner.reconnects.load(Ordering::SeqCst),
            last_error: self.inner.last_error.lock().clone(),
        }
    }
}

/// Kameo-free control transport.
///
/// Owns reconnect/auth/read/write and exposes bounded `ClientMsg` /
/// `ServerMsg` channels. Exposes an owned `run` future instead of secretly
/// detaching itself, so the agent `ControlPlaneActor` can own its lifecycle.
pub struct ControlTransport {
    endpoint: crate::control::ServiceEndpoint,
    pub endpoint_id: String,
    pub signing_key: SigningKey,
    pub link: ControlPlaneLink,
}

/// Unowned control transport + bounded channels, returned by
/// `CoreNode::bootstrap`. No task is spawned; the owner (agent
/// `ControlPlaneActor` or an explicit `ManagedControlDriver`) runs it.
pub struct PendingControl {
    pub transport: ControlTransport,
    pub server_tx: tokio::sync::mpsc::Sender<ServerMsg>,
    pub server_rx: tokio::sync::mpsc::Receiver<ServerMsg>,
    pub client_tx: tokio::sync::mpsc::Sender<ClientMsg>,
    pub client_rx: tokio::sync::mpsc::Receiver<ClientMsg>,
}

impl PendingControl {
    pub fn new(client: &crate::control::SignedClient) -> Self {
        let link = ControlPlaneLink::new(client.service_endpoint().base_url());
        let transport = ControlTransport::new(client, link);
        let (server_tx, server_rx) = tokio::sync::mpsc::channel::<ServerMsg>(128);
        let (client_tx, client_rx) = tokio::sync::mpsc::channel::<ClientMsg>(128);
        Self {
            transport,
            server_tx,
            server_rx,
            client_tx,
            client_rx,
        }
    }

    pub fn link(&self) -> ControlPlaneLink {
        self.transport.link()
    }
}

impl ControlTransport {
    pub fn new(client: &crate::control::SignedClient, link: ControlPlaneLink) -> Self {
        let endpoint = client.service_endpoint();
        Self {
            endpoint,
            endpoint_id: client.endpoint_id.clone(),
            signing_key: client.signing_key.clone(),
            link,
        }
    }

    pub fn link(&self) -> ControlPlaneLink {
        self.link.clone()
    }

    /// Run the reconnect loop until `client_rx` closes AND the task is
    /// cancelled via `cancel`. Normal disconnects reconnect with backoff;
    /// they are operational state, never actor failures.
    pub async fn run(
        self,
        server_tx: tokio::sync::mpsc::Sender<ServerMsg>,
        mut client_rx: tokio::sync::mpsc::Receiver<ClientMsg>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        ensure_rustls_crypto_provider();
        run(
            self.endpoint,
            self.endpoint_id,
            self.signing_key,
            server_tx,
            &mut client_rx,
            self.link,
            cancel,
        )
        .await;
    }
}

fn ensure_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        tracing::warn!(
            ?err,
            "rustls CryptoProvider already installed by another thread"
        );
    }
}

fn is_connection_refused(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::ConnectionRefused
        {
            return true;
        }
        let msg = cause.to_string();
        if msg.to_ascii_lowercase().contains("connection refused") {
            return true;
        }
    }
    false
}

async fn handle_server_frame(
    res: Result<Message, tokio_tungstenite::tungstenite::Error>,
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    server_tx: &tokio::sync::mpsc::Sender<ServerMsg>,
) -> bool {
    match res {
        Ok(Message::Text(t)) => {
            match serde_json::from_str::<ServerMsg>(t.as_str()) {
                Ok(m) => {
                    let _ = server_tx.send(m).await;
                }
                Err(e) => tracing::warn!(?e, "ws server msg parse"),
            }
            true
        }
        Ok(Message::Ping(p)) => ws.send(Message::Pong(p)).await.is_ok(),
        Ok(Message::Close(_)) => false,
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(?e, "ws error");
            false
        }
    }
}

async fn run(
    endpoint: crate::control::ServiceEndpoint,
    endpoint_id: String,
    signing_key: SigningKey,
    server_tx: tokio::sync::mpsc::Sender<ServerMsg>,
    client_rx: &mut tokio::sync::mpsc::Receiver<ClientMsg>,
    link: ControlPlaneLink,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut backoff = MIN_BACKOFF;
    let mut outbound_closed = false;
    tracing::info!(url = %link.url(), "ws reconnect loop starting");

    loop {
        if cancel.is_cancelled() {
            link.mark_disconnected(Some("control transport shutdown".into()));
            break;
        }
        let mut connection_refused = false;
        let connect_res = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                link.mark_disconnected(Some("control transport shutdown".into()));
                return;
            }
            res = connect_once(&endpoint, &endpoint_id, &signing_key) => res,
        };
        match connect_res {
            Ok(mut ws) => {
                backoff = MIN_BACKOFF;
                link.mark_connected();
                tracing::info!(outbound_closed, "ws connected to control plane");
                let mut keep_alive = tokio::time::interval(Duration::from_secs(KEEP_ALIVE_SECS));
                keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                keep_alive.tick().await;
                let mut last_wall = Timestamp::now();

                let disconnect_reason = loop {
                    tokio::select! {
                        maybe_msg = ws.next() => {
                            let Some(res) = maybe_msg else {
                                tracing::warn!("ws stream ended");
                                break Some("stream ended".to_string());
                            };
                            if !handle_server_frame(res, &mut ws, &server_tx).await {
                                break Some("ws frame error or close".to_string());
                            }
                        }
                        maybe_out = async {
                            if outbound_closed {
                                std::future::pending::<Option<ClientMsg>>().await
                            } else {
                                client_rx.recv().await
                            }
                        } => {
                            match maybe_out {
                                None => {
                                    tracing::warn!(
                                        "ws client tx dropped; continuing in read-only mode"
                                    );
                                    outbound_closed = true;
                                }
                                Some(m) => {
                                    if let Ok(t) = serde_json::to_string(&m)
                                        && ws.send(Message::text(t)).await.is_err()
                                    {
                                        break Some("send failed".to_string());
                                    }
                                }
                            }
                        }
                        _ = keep_alive.tick() => {
                            let now = Timestamp::now();
                            if std::time::Duration::try_from(now.duration_since(last_wall))
                                .is_ok_and(|duration| duration > CONNECTED_RESUME_GAP)
                            {
                                tracing::warn!(
                                    "ws: wall clock jumped while connected (likely suspend/resume), reconnecting"
                                );
                                break Some("suspend/resume clock jump".to_string());
                            }
                            last_wall = now;
                            if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                                tracing::warn!("ws ping failed");
                                break Some("keepalive ping failed".to_string());
                            }
                        }
                        _ = cancel.cancelled() => {
                            break Some("control transport shutdown".to_string());
                        }
                    }
                };
                link.mark_disconnected(disconnect_reason);
            }
            Err(e) => {
                connection_refused = is_connection_refused(&e);
                let wait_hint = if connection_refused {
                    REFUSED_RETRY
                } else {
                    backoff
                };
                link.mark_disconnected(Some(e.to_string()));
                tracing::warn!(
                    ?e,
                    connection_refused,
                    wait_ms = wait_hint.as_millis(),
                    "ws connect failed"
                );
            }
        }

        let wait = if connection_refused {
            REFUSED_RETRY + Duration::from_millis(rand::random_range(0..200))
        } else {
            backoff + Duration::from_millis(rand::random_range(0..500))
        };

        let wall_before = Timestamp::now();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                link.mark_disconnected(Some("control transport shutdown".into()));
                return;
            }
            _ = tokio::time::sleep(wait) => {}
        }

        if std::time::Duration::try_from(Timestamp::now().duration_since(wall_before))
            .is_ok_and(|elapsed| elapsed > wait + RESUME_OVERSHOOT)
        {
            tracing::info!(
                waited_ms = wait.as_millis(),
                "ws reconnect: sleep overran (likely suspend/resume), resetting backoff"
            );
            backoff = MIN_BACKOFF;
            continue;
        }

        if connection_refused {
            backoff = MIN_BACKOFF;
        } else {
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

async fn connect_once(
    endpoint: &crate::control::ServiceEndpoint,
    endpoint_id: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut ws_url = endpoint.url("v1/ws")?;
    let scheme = if ws_url.scheme() == "https" {
        "wss"
    } else {
        "ws"
    };
    ws_url
        .set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid websocket URL scheme"))?;

    let ts = Timestamp::now().as_second();
    let sig = signing::sign(signing_key, "GET", "/v1/ws", ts, &[]);

    let mut req = ws_url
        .as_str()
        .into_client_request()
        .context("build ws request")?;
    req.headers_mut()
        .insert(HDR_ENDPOINT_ID, endpoint_id.parse()?);
    req.headers_mut()
        .insert(HDR_TIMESTAMP, ts.to_string().parse()?);
    req.headers_mut().insert(HDR_SIGNATURE, sig.parse()?);

    let (ws, _resp) = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let stream = endpoint.connect_tcp().await?;
        tokio_tungstenite::client_async_tls(req, stream).await
    })
    .await
    .context("websocket connect timed out")??;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_permission(socket: &std::net::TcpStream) -> std::io::Result<()> {
        assert!(socket.peer_addr().is_err());
        Ok(())
    }

    fn refuse_socket(_: &std::net::TcpStream) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "test protection refused",
        ))
    }

    #[rstest::rstest]
    #[case::allow(Some(socket_permission as fn(&std::net::TcpStream) -> std::io::Result<()>), true)]
    #[case::refuse(Some(refuse_socket as fn(&std::net::TcpStream) -> std::io::Result<()>), false)]
    #[case::missing_family(None, false)]
    #[tokio::test]
    async fn protected_websocket_uses_pinned_authorized_socket(
        #[case] initialize: Option<fn(&std::net::TcpStream) -> std::io::Result<()>>,
        #[case] allowed: bool,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = crate::control::SignedClient::new_trusted_loopback(
            &format!("http://{}", listener.local_addr().unwrap()),
            SigningKey::generate(&mut rand::rng()),
        )
        .with_tcp_config(Some([
            initialize.map(|initialize| iroh::endpoint::TcpSocketConfig {
                interface: None,
                initialize: Some(initialize),
            }),
            None,
        ]))
        .unwrap();
        let endpoint = client.service_endpoint();
        let server = tokio::spawn(async move {
            let accepted =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
            if let Ok(Ok((stream, _))) = accepted {
                let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                true
            } else {
                false
            }
        });
        let connected = connect_once(&endpoint, &client.endpoint_id, &client.signing_key).await;
        assert_eq!(connected.is_ok(), allowed);
        assert_eq!(server.await.unwrap(), allowed);
    }

    /// A dead control plane is operational state, not failure: the transport
    /// must keep backing off (never return/terminate on its own) and must
    /// stop promptly on cancellation.
    #[tokio::test]
    async fn disconnect_is_operational_state_not_failure() {
        let key = SigningKey::generate(&mut rand::rng());
        let client = crate::control::SignedClient::new_trusted_loopback("http://127.0.0.1:9", key);
        let pending = PendingControl::new(&client);
        let link = pending.link();
        let PendingControl {
            transport,
            server_tx,
            server_rx,
            client_rx,
            ..
        } = pending;
        let _ = server_rx;
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        let handle = tokio::spawn(async move {
            transport.run(server_tx, client_rx, stop).await;
        });
        // Unreachable control plane (refused or connect timeout): the
        // transport records the error and backs off instead of terminating.
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let snap = link.snapshot();
                if !snap.connected && snap.last_error.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("transport records connect failure");
        assert!(
            !handle.is_finished(),
            "transport must not terminate on connect failure"
        );
        // Cancellation stops the reconnect loop promptly.
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("transport stops on cancel")
            .expect("transport task");
    }
}
