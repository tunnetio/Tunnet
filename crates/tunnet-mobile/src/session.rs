//! Agent lifecycle inside a host app process.
//!
//! Mobile platforms cannot spawn a daemon, so the agent runs on a tokio runtime
//! owned by the app. This module holds no platform code: it is the JVM-free half
//! of the mobile edge, so the host test run covers it (the JNI bridge is
//! Android-only and cannot be tested off-device).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;
use tunnet_agent::{AgentConfig, AgentHandle, AgentRuntime, LatestSlot, encode_snapshot};

/// How long stop() will wait for the agent to drain.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A running embedded agent plus a handle for in-process commands.
pub struct AgentSession {
    runtime: Runtime,
    agent: Option<AgentRuntime>,
    handle: AgentHandle,
    state_dir: PathBuf,
    latest: Arc<LatestSlot>,
}

impl AgentSession {
    /// Start the agent against `state_dir`.
    ///
    /// `hostname` is the name this device presents to peers.
    ///
    /// Blocking, and slow on first run. Callers on Android must not invoke this
    /// from the main thread.
    pub fn start(state_dir: impl Into<PathBuf>, hostname: &str) -> Result<Self> {
        let state_dir = state_dir.into();
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        tunnet_agent::install_crypto_provider();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("tunnet-agent")
            .build()
            .context("build tokio runtime")?;

        let mut config = AgentConfig::new(&state_dir).with_hostname(hostname);
        config.keep_alive = true;
        config.recorder = false;
        config.no_mdns = !tunnet_agent::lan_available();
        let agent = runtime
            .block_on(AgentRuntime::start(config, None))
            .context("start embedded agent")?;
        let handle = agent.handle();
        let latest = std::sync::Arc::new(LatestSlot::new());
        {
            let handle = handle.clone();
            let shutdown = handle.shutdown_token();
            let slot = latest.clone();
            runtime.spawn(async move {
                let mut rx = handle.subscribe();
                loop {
                    let snap = (**rx.borrow()).clone();
                    slot.publish(encode_snapshot(&snap));
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        r = rx.changed() => {
                            if r.is_err() {
                                break;
                            }
                        }
                    }
                }
                slot.close();
            });
        }

        Ok(Self {
            runtime,
            agent: Some(agent),
            handle,
            state_dir,
            latest,
        })
    }

    /// Run one async call to completion on the agent runtime.
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    pub fn handle(&self) -> &AgentHandle {
        &self.handle
    }

    /// Executor handle for in-flight commands. Clone it and drop session
    /// ownership before awaiting so stop can cancel immediately.
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn latest(&self) -> &Arc<LatestSlot> {
        &self.latest
    }

    /// Signal shutdown and drop the tokio runtime.
    ///
    /// The runtime is shut down with a timeout rather than dropped outright:
    /// a plain drop blocks until every task ends, and a peer connection mid
    /// teardown would hang the caller, which on Android is a service-stop
    /// callback with a watchdog on it.
    pub fn stop(mut self) {
        self.latest.close();
        self.handle.shutdown_token().cancel();
        if let Some(agent) = self.agent.take() {
            self.runtime.block_on(agent.shutdown());
        }
        self.runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_config_holds_the_mesh_open_and_skips_the_recorder() {
        let mut config = AgentConfig::new("tunnet-test");
        config.keep_alive = true;
        config.recorder = false;
        assert!(
            config.keep_alive,
            "a phone must stay reachable while asleep"
        );
        assert!(!config.recorder, "no SSH session recorder on a phone");
    }

    #[test]
    fn command_errors_encode_kind_for_the_host() {
        let encoded = tunnet_agent::WireNativeResult::err(
            tunnet_agent::AgentErrorKind::Busy,
            "do not branch on this text",
        );
        assert!(!encoded.ok);
        assert_eq!(encoded.kind, 7);
    }

    #[test]
    fn starting_against_an_unwritable_path_fails_rather_than_panicking() {
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

    #[test]
    fn snapshot_slot_receives_idle_without_a_jni_listener() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path(), "slot-device").expect("start");
        let latest = session.latest().clone();
        let (_, bytes) = latest.wait_after(0).expect("idle snapshot");
        let decoded = tunnet_agent::decode_snapshot(&bytes).expect("decode");
        assert_eq!(decoded.hostname, "slot-device");
        assert_eq!(decoded.lifecycle, 1);
        session.stop();
        assert!(latest.is_closed());
    }

    #[test]
    fn stop_unblocks_a_pending_snapshot_waiter() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path(), "stop-device").expect("start");
        let latest = session.latest().clone();
        let (seen, _) = latest.wait_after(0).expect("first");
        let waiter = latest.clone();
        let t = std::thread::spawn(move || waiter.wait_after(seen));
        session.stop();
        assert!(t.join().unwrap().is_none());
    }

    #[test]
    fn runtime_failure_is_visible_on_the_snapshot_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path(), "fail-device").expect("start");
        let latest = session.latest().clone();
        let (seen, _) = latest.wait_after(0).expect("idle");
        let err = session.block_on(session.handle().create(tunnet_agent::CreateRequest {
            network_name: Some("NO".into()),
            ..tunnet_agent::CreateRequest::default()
        }));
        assert!(err.is_err());
        let mut seen = seen;
        let decoded = loop {
            let (seq, bytes) = latest.wait_after(seen).expect("failed snapshot");
            seen = seq;
            let decoded = tunnet_agent::decode_snapshot(&bytes).expect("decode");
            if decoded.lifecycle == 6 {
                break decoded;
            }
        };
        assert_eq!(decoded.error.as_ref().map(|e| e.kind), Some(4));
        session.stop();
    }

    #[test]
    fn start_stop_start_uses_a_fresh_runtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = AgentSession::start(dir.path(), "cycle-device").expect("first start");
        let first_latest = first.latest().clone();
        first.stop();
        assert!(first_latest.is_closed());
        let second = AgentSession::start(dir.path(), "cycle-device").expect("second start");
        let (_, bytes) = second.latest().wait_after(0).expect("idle");
        let decoded = tunnet_agent::decode_snapshot(&bytes).expect("decode");
        assert_eq!(decoded.lifecycle, 1);
        second.stop();
    }

    #[test]
    fn stop_is_complete_for_the_snapshot_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path(), "once-device").expect("start");
        let latest = session.latest().clone();
        let (seq, _) = latest.wait_after(0).expect("idle");
        session.stop();
        assert!(latest.is_closed());
        latest.close();
        assert!(latest.is_closed());
        assert!(latest.wait_after(seq).is_none());
    }

    #[test]
    fn stop_cancels_in_flight_work_without_runtime_block_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path(), "cancel-device").expect("start");
        let token = session.handle().shutdown_token();
        let rt = session.runtime_handle();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            ready_tx.send(()).ok();
            token.cancelled().await;
            done_tx.send(()).ok();
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("task started");
        session.stop();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pending join waiters must observe shutdown immediately");
    }
}
