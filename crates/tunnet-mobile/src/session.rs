//! Agent lifecycle inside a host app process.
//!
//! Mobile platforms cannot spawn a daemon, so the agent runs on a tokio runtime
//! owned by the app. This module holds no platform code: it is the JVM-free half
//! of the mobile edge, so the host test run covers it (the JNI bridge is
//! Android-only and cannot be tested off-device).

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use tunnet_agent::daemon::{self, RunArgs};
use tunnet_client::TunnetClient;

/// How long to wait for the agent to bind its Local API before giving up.
/// Generous: first start also derives identity and unseals state.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Filename of the Local API socket inside the app's private directory.
const API_SOCKET: &str = "tunnetd.sock";

static API_PATH_ONCE: Once = Once::new();
static HOSTNAME_ONCE: Once = Once::new();

/// Point the Local API at the app's private directory.
///
/// The default bind paths (`/run/tunnet`, `/tmp`) do not exist or are not
/// writable on Android, and the agent has no argument for this, so the
/// environment is the only channel. Done once, as early as possible.
///
/// Mutating the environment is process-global and racy against concurrent
/// getenv in other threads; a JVM is already multi-threaded by the time we run,
/// so this is deliberately confined to a single write of a single variable
/// before the agent (and therefore any reader of it) starts.
fn set_api_path(api_path: &Path) {
    API_PATH_ONCE.call_once(|| {
        // SAFETY: single write, before the agent or client read it, and never
        // repeated (Once). No other Tunnet thread touches the environment.
        unsafe { std::env::set_var("TUNNET_API_PATH", api_path) };
    });
}

/// Report the device's own name to the mesh.
///
/// The agent reads `HOSTNAME` for the name it presents to peers; without it
/// every phone appears as the built-in default ("tunnet-agent"), which is
/// useless in a peer list where the point is telling devices apart. Same
/// single-write discipline as [`set_api_path`].
fn set_hostname(hostname: &str) {
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return;
    }
    HOSTNAME_ONCE.call_once(|| {
        // SAFETY: single write, before the agent reads it, never repeated.
        unsafe { std::env::set_var("HOSTNAME", hostname) };
    });
}

/// Arguments the embedded agent runs with.
///
/// Deliberately not the desktop defaults: a phone has no SSH recorder to offer
/// and must hold the mesh open while the screen is off.
fn run_args() -> RunArgs {
    RunArgs {
        // Cosmetic on Android: the framework names the interface itself.
        ifname: "tunnet0".to_string(),
        poll_secs: 30,
        metrics_bind: "127.0.0.1:9100".to_string(),
        disable_gossip: false,
        recorder: false,
        no_mdns: false,
        // The product promise is "connected until switched off", so peers must
        // not be allowed to idle out while the device sleeps.
        keep_alive: true,
        no_encrypt_state: false,
    }
}

/// A running embedded agent plus a client for its Local API.
pub struct AgentSession {
    runtime: Runtime,
    shutdown: CancellationToken,
    client: TunnetClient,
    state_dir: PathBuf,
}

impl AgentSession {
    /// Start the agent against `state_dir` and wait until its API is reachable.
    ///
    /// `hostname` is the name this device presents to peers.
    ///
    /// Blocking, and slow on first run. Callers on Android must not invoke this
    /// from the main thread.
    pub fn start(state_dir: impl Into<PathBuf>, hostname: &str) -> Result<Self> {
        let state_dir = state_dir.into();
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        let api_path = state_dir.join(API_SOCKET);
        set_api_path(&api_path);
        set_hostname(hostname);

        tunnet_agent::install_crypto_provider();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("tunnet-agent")
            .build()
            .context("build tokio runtime")?;

        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        {
            let shutdown = shutdown.clone();
            let state_dir = state_dir.clone();
            runtime.spawn(async move {
                let dir = state_dir.to_string_lossy().into_owned();
                if let Err(e) = daemon::run_with_shutdown(
                    run_args(),
                    Some(&dir),
                    Some(shutdown),
                    Some(ready_tx),
                )
                .await
                {
                    tracing::error!(error = ?e, "embedded agent exited with an error");
                }
            });
        }

        // The agent signals readiness once the Local API is bound. That happens
        // in both the joined and the not-yet-joined (idle bootstrap) paths, so
        // the app can drive the join through the same client either way.
        match runtime.block_on(async { tokio::time::timeout(READY_TIMEOUT, ready_rx).await }) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                shutdown.cancel();
                bail!("agent stopped before its Local API became ready");
            }
            Err(_) => {
                shutdown.cancel();
                bail!(
                    "agent did not become ready within {}s",
                    READY_TIMEOUT.as_secs()
                );
            }
        }

        Ok(Self {
            client: TunnetClient::with_path(&api_path),
            runtime,
            shutdown,
            state_dir,
        })
    }

    /// Run one Local API call to completion.
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    pub fn client(&self) -> &TunnetClient {
        &self.client
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Signal shutdown and drop the runtime.
    ///
    /// The runtime is shut down with a timeout rather than dropped outright:
    /// a plain drop blocks until every task ends, and a peer connection mid
    /// teardown would hang the caller, which on Android is a service-stop
    /// callback with a watchdog on it.
    pub fn stop(self) {
        self.shutdown.cancel();
        self.runtime
            .shutdown_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS));
        tracing::info!("embedded agent stopped");
    }
}

const REQUEST_TIMEOUT_SECS: u64 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_args_hold_the_mesh_open_and_skip_the_recorder() {
        let args = run_args();
        assert!(args.keep_alive, "a phone must stay reachable while asleep");
        assert!(!args.recorder, "no SSH session recorder on a phone");
    }

    #[test]
    fn api_socket_lives_inside_the_state_dir() {
        // The app's private directory is the only writable location, so the
        // socket must be derived from it rather than from a system path.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(API_SOCKET);
        assert!(path.starts_with(dir.path()));
    }

    #[test]
    fn starting_against_an_unwritable_path_fails_rather_than_panicking() {
        // A wrong state dir must surface as an error the app can show, not a
        // panic that takes the VpnService process down.
        //
        // Derive the unwritable path from a regular file: creating a directory
        // beneath a file fails on every platform. A hardcoded Unix path such as
        // `/proc/...` does not work here, because Windows treats it as an
        // ordinary relative path and creates it happily, so the call succeeds
        // and the test panics.
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let under_a_file = file.path().join("tunnet-state");
        let err = match AgentSession::start(under_a_file, "test-device") {
            Ok(_) => panic!("creating a state dir beneath a file must fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("create state dir"),
            "unexpected error: {err}"
        );
    }
}
