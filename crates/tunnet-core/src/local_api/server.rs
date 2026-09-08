//! Local Management API HTTP server over Unix socket / Windows named pipe.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Extension;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use tower::Service;

use tunnet_common::local_api::LocalEvent;

use super::bootstrap_router::{self, BootstrapApiState};
use super::router;
use super::state::LocalApiState;
use super::transport::{ApiListener, ApiStream};

/// Spawn the Local Management API listener (full mesh runtime).
///
/// Binds before returning so callers can treat the API as ready.
pub async fn spawn(state: Arc<LocalApiState>) -> anyhow::Result<LocalApiServer> {
    spawn_listener(move |peer| router::app(state.clone()).layer(Extension(peer))).await
}

/// Spawn a bootstrap-only API (idle agent waiting for create / enroll / join).
pub async fn spawn_bootstrap(state: BootstrapApiState) -> anyhow::Result<LocalApiServer> {
    let events = state.events.clone();
    let handle = spawn_listener(move |peer| {
        bootstrap_router::bootstrap_app(state.clone()).layer(Extension(peer))
    })
    .await?;
    let _ = events.send(LocalEvent::DaemonReady);
    Ok(handle)
}

pub struct LocalApiServer {
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl LocalApiServer {
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

async fn spawn_listener<F>(make_app: F) -> anyhow::Result<LocalApiServer>
where
    F: Fn(super::auth::PeerIdentity) -> Router + Send + Sync + 'static,
{
    let (listener, path) = ApiListener::bind()
        .await
        .context("bind Local Management API listener")?;
    Ok(spawn_bound_listener(listener, path, make_app))
}

fn spawn_bound_listener<F>(
    listener: ApiListener,
    path: std::path::PathBuf,
    make_app: F,
) -> LocalApiServer
where
    F: Fn(super::auth::PeerIdentity) -> Router + Send + Sync + 'static,
{
    tracing::info!(path = %path.display(), "Local Management API ready");
    let make_app = Arc::new(make_app);
    let cancel = tokio_util::sync::CancellationToken::new();
    let run_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = run_cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok(stream) => {
                    let make_app = make_app.clone();
                    connections.spawn(async move {
                        if let Err(e) = serve_connection(stream, make_app.as_ref()).await {
                            tracing::debug!(?e, "Local API client session ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(?e, "Local API accept failed");
                }
            }
        }
        if tokio::time::timeout(Duration::from_secs(5), async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
    });
    LocalApiServer { cancel, task }
}

async fn serve_connection<F>(stream: ApiStream, make_app: &F) -> anyhow::Result<()>
where
    F: Fn(super::auth::PeerIdentity) -> Router,
{
    #[cfg(unix)]
    let peer = match &stream {
        ApiStream::Unix(s) => super::auth::peer_identity_from_unix(s),
    };
    #[cfg(windows)]
    let peer = match &stream {
        ApiStream::Windows(p) => super::auth::peer_identity_from_windows(p),
    };

    let app = make_app(peer);

    match stream {
        #[cfg(unix)]
        ApiStream::Unix(unix) => {
            let io = TokioIo::new(unix);
            HyperBuilder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: axum::http::Request<Incoming>| {
                        let mut svc = app.clone();
                        async move {
                            Ok::<_, InfallibleWrap>(
                                Service::call(&mut svc, req)
                                    .await
                                    .unwrap_or_else(|e| match e {}),
                            )
                        }
                    }),
                )
                .await
                .map_err(|e| anyhow::anyhow!("http serve: {e}"))?;
        }
        #[cfg(windows)]
        ApiStream::Windows(pipe) => {
            let io = TokioIo::new(pipe);
            HyperBuilder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: axum::http::Request<Incoming>| {
                        let mut svc = app.clone();
                        async move {
                            Ok::<_, InfallibleWrap>(
                                Service::call(&mut svc, req)
                                    .await
                                    .unwrap_or_else(|e| match e {}),
                            )
                        }
                    }),
                )
                .await
                .map_err(|e| anyhow::anyhow!("http serve: {e}"))?;
        }
    }
    Ok(())
}

/// hyper service errors must be Infallible for this wiring.
#[derive(Debug)]
struct InfallibleWrap;

impl std::fmt::Display for InfallibleWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "infallible")
    }
}

impl std::error::Error for InfallibleWrap {}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_releases_listener_before_returning() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("api.pipe");
        let pipe = format!(r"\\.\pipe\tunnet-test-{}", uuid::Uuid::new_v4());
        let (listener, path) = ApiListener::bind_test(marker.clone(), &pipe).unwrap();
        let first = spawn_bound_listener(listener, path, |_| Router::new());
        first.shutdown().await;
        let (listener, path) = ApiListener::bind_test(marker, &pipe).unwrap();
        let second = spawn_bound_listener(listener, path, |_| Router::new());
        second.shutdown().await;
    }
}
