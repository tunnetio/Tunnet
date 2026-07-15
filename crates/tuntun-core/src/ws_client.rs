use std::time::{Duration, SystemTime};

use anyhow::Context;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tuntun_common::{
    HDR_ENDPOINT_ID, HDR_SIGNATURE, HDR_TIMESTAMP, signing,
    ws::{ClientMsg, ServerMsg},
};

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Wall-clock overrun past the requested sleep that indicates suspend/resume.
const RESUME_OVERSHOOT: Duration = Duration::from_secs(5);
/// Fast retry when the peer is not listening yet (common when co-located with CP).
const REFUSED_RETRY: Duration = Duration::from_secs(1);
/// How often to probe wall clock / send a WS ping while connected.
const KEEP_ALIVE_SECS: u64 = 5;
/// Wall-clock gap while connected that forces a reconnect (VM suspend/resume).
const CONNECTED_RESUME_GAP: Duration = Duration::from_secs(15);

pub struct WsChannel {
    pub rx: tokio::sync::mpsc::Receiver<ServerMsg>,
    pub tx: tokio::sync::mpsc::Sender<ClientMsg>,
}

pub fn spawn(control_url: String, endpoint_id: String, signing_key: SigningKey) -> WsChannel {
    let (server_tx, server_rx) = tokio::sync::mpsc::channel::<ServerMsg>(64);
    let (client_tx, client_rx) = tokio::sync::mpsc::channel::<ClientMsg>(64);

    tokio::spawn(async move {
        run(control_url, endpoint_id, signing_key, server_tx, client_rx).await;
    });

    WsChannel {
        rx: server_rx,
        tx: client_tx,
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
    control_url: String,
    endpoint_id: String,
    signing_key: SigningKey,
    server_tx: tokio::sync::mpsc::Sender<ServerMsg>,
    mut client_rx: tokio::sync::mpsc::Receiver<ClientMsg>,
) {
    let mut backoff = MIN_BACKOFF;
    let mut outbound_closed = false;

    loop {
        let mut connection_refused = false;
        match connect_once(&control_url, &endpoint_id, &signing_key).await {
            Ok(mut ws) => {
                backoff = MIN_BACKOFF;
                tracing::info!(outbound_closed, "ws connected to control plane");
                let mut keep_alive = tokio::time::interval(Duration::from_secs(KEEP_ALIVE_SECS));
                keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                keep_alive.tick().await;
                let mut last_wall = SystemTime::now();

                loop {
                    tokio::select! {
                        maybe_msg = ws.next() => {
                            let Some(res) = maybe_msg else {
                                tracing::warn!("ws stream ended");
                                break;
                            };
                            if !handle_server_frame(res, &mut ws, &server_tx).await {
                                break;
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
                                        break;
                                    }
                                }
                            }
                        }
                        _ = keep_alive.tick() => {
                            let now = SystemTime::now();
                            if now
                                .duration_since(last_wall)
                                .is_ok_and(|d| d > CONNECTED_RESUME_GAP)
                            {
                                tracing::warn!(
                                    "ws: wall clock jumped while connected (likely suspend/resume), reconnecting"
                                );
                                break;
                            }
                            last_wall = now;
                            if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                                tracing::warn!("ws ping failed");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                connection_refused = is_connection_refused(&e);
                let wait_hint = if connection_refused {
                    REFUSED_RETRY
                } else {
                    backoff
                };
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

        let wall_before = SystemTime::now();
        tokio::time::sleep(wait).await;

        if SystemTime::now()
            .duration_since(wall_before)
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
    control_url: &str,
    endpoint_id: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let ws_url = if let Some(rest) = control_url.strip_prefix("https://") {
        format!("wss://{rest}/v1/ws")
    } else if let Some(rest) = control_url.strip_prefix("http://") {
        format!("ws://{rest}/v1/ws")
    } else {
        anyhow::bail!("control url must start with http:// or https://");
    };

    let ts = Utc::now().timestamp();
    let sig = signing::sign(signing_key, "GET", "/v1/ws", ts, &[]);

    let mut req = ws_url.into_client_request().context("build ws request")?;
    req.headers_mut()
        .insert(HDR_ENDPOINT_ID, endpoint_id.parse()?);
    req.headers_mut()
        .insert(HDR_TIMESTAMP, ts.to_string().parse()?);
    req.headers_mut().insert(HDR_SIGNATURE, sig.parse()?);

    let (ws, _resp) = tokio_tungstenite::connect_async(req).await?;
    Ok(ws)
}
