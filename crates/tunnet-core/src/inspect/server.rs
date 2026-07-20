//! Local axum inspector HTTP server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::oneshot;

use super::http_tee::replay_exchange;
use super::store::{ExchangeStore, ExchangeSummary};
use super::ui::INDEX_HTML;

const DEFAULT_ADDR: &str = "127.0.0.1:4040";

#[derive(Clone)]
pub struct InspectorHub {
    inner: Arc<Mutex<HubInner>>,
    store: ExchangeStore,
}

struct HubInner {
    /// tunnel_id → upstream target for replay
    tunnels: HashMap<String, SocketAddr>,
    bind_addr: Option<SocketAddr>,
    inspector_url: Option<String>,
    stop: Option<oneshot::Sender<()>>,
}

impl Default for InspectorHub {
    fn default() -> Self {
        Self::new()
    }
}

impl InspectorHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                tunnels: HashMap::new(),
                bind_addr: None,
                inspector_url: None,
                stop: None,
            })),
            store: ExchangeStore::new(),
        }
    }

    pub fn store(&self) -> ExchangeStore {
        self.store.clone()
    }

    pub fn inspector_url(&self) -> Option<String> {
        self.inner.lock().inspector_url.clone()
    }

    /// Ensure the inspector server is running and register a tunnel for capture/replay.
    pub async fn register_tunnel(
        &self,
        tunnel_id: &str,
        target: SocketAddr,
        inspect_addr: Option<&str>,
    ) -> anyhow::Result<String> {
        let addr: SocketAddr = inspect_addr
            .unwrap_or(DEFAULT_ADDR)
            .parse()
            .context("invalid --inspect-addr")?;

        let (need_spawn, url, stop_rx) = {
            let mut guard = self.inner.lock();
            if let Some(existing) = guard.bind_addr
                && existing != addr
            {
                bail!("inspector already bound to {existing}; cannot also bind {addr}");
            }
            guard.tunnels.insert(tunnel_id.to_string(), target);
            if guard.stop.is_none() {
                let (stop_tx, stop_rx) = oneshot::channel();
                guard.stop = Some(stop_tx);
                guard.bind_addr = Some(addr);
                let url = format!("http://{addr}");
                guard.inspector_url = Some(url.clone());
                (true, url, Some(stop_rx))
            } else {
                let url = guard
                    .inspector_url
                    .clone()
                    .unwrap_or_else(|| format!("http://{addr}"));
                (false, url, None)
            }
        };

        if need_spawn {
            let stop_rx = stop_rx.expect("stop_rx when spawning");
            if let Err(e) = self.spawn_server(addr, stop_rx).await {
                self.unregister_tunnel(tunnel_id);
                return Err(e);
            }
        }
        Ok(url)
    }

    pub fn unregister_tunnel(&self, tunnel_id: &str) {
        let mut guard = self.inner.lock();
        guard.tunnels.remove(tunnel_id);
        if guard.tunnels.is_empty()
            && let Some(tx) = guard.stop.take()
        {
            let _ = tx.send(());
            guard.bind_addr = None;
            guard.inspector_url = None;
        }
    }

    pub fn target_for(&self, tunnel_id: &str) -> Option<SocketAddr> {
        self.inner.lock().tunnels.get(tunnel_id).copied()
    }

    async fn spawn_server(
        &self,
        addr: SocketAddr,
        stop_rx: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let state = AppState {
            hub: self.clone(),
            store: self.store.clone(),
        };
        let app = Router::new()
            .route("/", get(index))
            .route("/api/requests", get(list_requests).delete(clear_requests))
            .route("/api/requests/{id}", get(get_request))
            .route("/api/requests/{id}/replay", post(replay_request))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind inspector on {addr}"))?;

        tracing::info!(%addr, "tunnel inspector listening");

        tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            });
            if let Err(e) = server.await {
                tracing::warn!(?e, "inspector server ended");
            }
        });

        // Brief yield so bind errors from serve would already have surfaced for listen.
        tokio::task::yield_now().await;
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    hub: InspectorHub,
    store: ExchangeStore,
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn list_requests(State(state): State<AppState>) -> Json<Vec<ExchangeSummary>> {
    let list: Vec<_> = state
        .store
        .list()
        .iter()
        .map(ExchangeSummary::from)
        .collect();
    Json(list)
}

async fn get_request(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.store.get(&id) {
        Some(ex) => Json(ex).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn clear_requests(State(state): State<AppState>) -> StatusCode {
    state.store.clear();
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayResult {
    id: String,
}

async fn replay_request(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(ex) = state.store.get(&id) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let Some(target) = state.hub.target_for(&ex.tunnel_id) else {
        return (StatusCode::BAD_REQUEST, "tunnel is no longer inspecting").into_response();
    };
    match replay_exchange(&ex, target, &state.store).await {
        Ok(new_id) => Json(ReplayResult { id: new_id }).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Helper so CORS is not needed for same-origin; kept for completeness.
#[allow(dead_code)]
fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}
