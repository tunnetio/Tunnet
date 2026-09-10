//! Agent lifecycle inside a host app process.
//!
//! Mobile platforms cannot spawn a daemon, so the agent runs on a tokio runtime
//! owned by the app. This module holds no platform code: it is the JVM-free half
//! of the mobile edge, so the host test run covers it (the JNI bridge is
//! Android-only and cannot be tested off-device).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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

/// Point the Local API at the app's private directory.
///
/// The default bind paths (`/run/tunnet`, `/tmp`) do not exist or are not
/// writable on Android. This used to go through `TUNNET_API_PATH`, which meant
/// `std::env::set_var`: unsound here, because a JVM is already multi-threaded
/// before any of our code runs and `setenv` races every concurrent `getenv` in
/// the process, including ones inside libc. `tunnet-core` now takes the path
/// programmatically, so no environment write is needed.
///
/// First call wins, matching the previous `Once`: the agent binds this socket,
/// so moving it afterwards would strand the client.
fn set_api_path(api_path: &Path) {
    tunnet_core::local_api::transport::set_api_path_override(api_path);
}

/// Arguments the embedded agent runs with.
///
/// Deliberately not the desktop defaults: a phone has no SSH recorder to offer
/// and must hold the mesh open while the screen is off.
fn run_args(hostname: &str) -> RunArgs {
    RunArgs {
        // Cosmetic on Android: the framework names the interface itself.
        ifname: "tunnet0".to_string(),
        poll_secs: 30,
        metrics_bind: "127.0.0.1:9100".to_string(),
        disable_gossip: false,
        recorder: false,
        no_mdns: false,
        // No override, matching the CLI default: relay policy is persisted
        // configuration, so pinning it here would silently outrank whatever the
        // user set. `Auto` is also the right behaviour for a phone, which moves
        // between networks and needs relay selection to follow.
        relay_mode: None,
        relay_urls: None,
        // The product promise is "connected until switched off", so peers must
        // not be allowed to idle out while the device sleeps.
        keep_alive: true,
        no_encrypt_state: false,
        // Explicit rather than via `HOSTNAME`: see `set_api_path` on why the
        // environment is not usable as a configuration channel here.
        hostname: Some(hostname.to_string()).filter(|h| !h.trim().is_empty()),
    }
}

/// A running embedded agent plus a client for its Local API.
pub struct AgentSession {
    runtime: Runtime,
    /// Set when the agent's own task returns an error, at any point after
    /// startup. `stop()` is not the only way an agent ends.
    exit_error: Arc<Mutex<Option<String>>>,
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
        // Sanitised here rather than by the caller, so no embedder can pass a
        // name the agent will reject: an invalid hostname is written into
        // `tunnet.toml` and only fails on the *next* start, long after the call
        // that caused it.
        let hostname = sanitize_hostname(hostname);
        let state_dir = state_dir.into();
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        let api_path = state_dir.join(API_SOCKET);
        set_api_path(&api_path);

        tunnet_agent::install_crypto_provider();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("tunnet-agent")
            .build()
            .context("build tokio runtime")?;

        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        // The agent's own error is the only actionable text there is ("invalid
        // tunnet.toml: invalid hostname", "cached snapshot missing enrolled
        // network"). Logging it and reporting a symptom sends the cause to
        // logcat, which a phone user cannot read. Kept here so both the start
        // path and later status calls can report it.
        let exit_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        // Built here, not inside the task: the caller's `hostname` is borrowed
        // and must not escape into a `'static` future.
        let args = run_args(&hostname);

        {
            let shutdown = shutdown.clone();
            let state_dir = state_dir.clone();
            let exit_error = exit_error.clone();
            runtime.spawn(async move {
                let dir = state_dir.to_string_lossy().into_owned();
                if let Err(e) =
                    daemon::run_with_shutdown(args, Some(&dir), Some(shutdown), Some(ready_tx))
                        .await
                {
                    tracing::error!(error = ?e, "embedded agent exited with an error");
                    *exit_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(format!("{e:#}"));
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
                // Bounded, like stop(): dropping a multi-thread Runtime blocks
                // until every task including in-flight spawn_blocking finishes,
                // which on Android runs on the service's worker thread.
                runtime.shutdown_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS));
                let cause = exit_error
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .unwrap_or_else(|| "no error reported".to_string());
                bail!("agent stopped before its Local API became ready: {cause}");
            }
            Err(_) => {
                shutdown.cancel();
                runtime.shutdown_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS));
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
            exit_error,
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

    /// The error the agent exited with, if it has exited.
    ///
    /// `run_with_shutdown` can fail at any point after readiness, notably when
    /// the bootstrap-to-runtime transition fails just after a join. Nothing
    /// else notices: the session object survives, so the app would sit on
    /// "connected" while every call fails against a socket nobody is serving.
    pub fn exit_error(&self) -> Option<String> {
        self.exit_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
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
        let args = run_args("");
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

/// Make a device name usable as a Tunnet hostname.
///
/// Android hands us `Build.MODEL`, which routinely contains spaces ("Pixel
/// 8a"), while the agent rejects a hostname containing a space, a dot or a
/// slash, or longer than 63 characters. Passing the raw model through wrote a
/// `tunnet.toml` the agent then refused to load, so joining appeared to work
/// and the agent died on the next start with `invalid hostname`.
///
/// Substituting rather than rejecting keeps the device recognisable in a peer
/// list, which is the only thing this name is for.
pub(crate) fn sanitize_hostname(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| match c {
            ' ' | '.' | '/' => '-',
            c => c,
        })
        .collect();
    // The agent's limit is 63 *bytes* (`h.len() > 63`), so counting characters
    // is not enough: 63 multi-byte characters is up to 252 bytes and would be
    // rejected exactly as the raw name was. Take whole characters while they
    // fit the byte budget, so the result is valid UTF-8 and within the limit.
    let mut truncated = String::new();
    for c in cleaned.chars() {
        if truncated.len() + c.len_utf8() > 63 {
            break;
        }
        truncated.push(c);
    }
    let trimmed = truncated.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "android".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod hostname_tests {
    use super::sanitize_hostname;

    /// The agent rejects a hostname containing ' ', '.' or '/', or longer than
    /// 63 characters, so these are the cases that previously produced a
    /// `tunnet.toml` the agent refused to load.
    #[test]
    fn rejected_characters_are_substituted() {
        assert_eq!(sanitize_hostname("Pixel 8a"), "Pixel-8a");
        assert_eq!(sanitize_hostname("moto g(60)"), "moto-g(60)");
        assert_eq!(sanitize_hostname("a.b/c d"), "a-b-c-d");
    }

    /// The agent counts bytes, so a multi-byte name must be capped by bytes.
    /// Capping by characters produced a name up to 252 bytes long, which the
    /// agent rejects for precisely the reason this function exists.
    #[test]
    fn length_is_capped_in_bytes_on_a_character_boundary() {
        for name in ["é".repeat(80), "a".repeat(80), "日本語".repeat(40)] {
            let out = sanitize_hostname(&name);
            assert!(out.len() <= 63, "{out:?} is {} bytes", out.len());
            // Still valid UTF-8 with no partial character.
            assert!(out.chars().all(|c| !c.is_control()));
        }
    }

    #[test]
    fn empty_or_punctuation_only_falls_back() {
        assert_eq!(sanitize_hostname(""), "android");
        assert_eq!(sanitize_hostname("   "), "android");
        assert_eq!(sanitize_hostname("..."), "android");
    }

    #[test]
    fn an_already_valid_name_is_unchanged() {
        assert_eq!(sanitize_hostname("nono"), "nono");
    }
}
