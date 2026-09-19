//! Embeddable in-process agent runtime.
//!
//! The daemon binary and mobile hosts both own an [`AgentRuntime`]. Commands
//! and observation go through [`AgentHandle`]. The runtime does not bind a
//! Local Management API; a daemon host may bind one for external clients.

mod bridge;
mod handle;
mod mesh;
#[cfg(feature = "local-api")]
mod observe;
mod snapshot;
mod wire;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tunnet_core::{PersistedState, StatePaths};

pub use bridge::LatestSlot;
pub use handle::{
    AgentError, AgentErrorInfo, AgentErrorKind, AgentHandle, AgentLifecycle, AgentMode,
    AgentNetwork, AgentPeer, AgentRole, AgentSnapshot, CreateRequest, DataPlaneState, JoinOutcome,
    JoinRequest, PeerConnKind, PeerPath,
};
pub use wire::{
    NativeResult as WireNativeResult, Snapshot as WireSnapshot, decode_snapshot, encode_snapshot,
};

use handle::{Phase, new_inner};

/// Startup configuration for an embedded agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub state_dir: PathBuf,
    pub hostname: Option<String>,
    pub ifname: String,
    pub poll_secs: u64,
    pub metrics_bind: String,
    pub disable_gossip: bool,
    pub recorder: bool,
    pub no_mdns: bool,
    pub relay_mode: Option<String>,
    pub relay_urls: Option<String>,
    pub keep_alive: bool,
    pub no_encrypt_state: bool,
}

impl AgentConfig {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            hostname: None,
            ifname: "tunnet0".into(),
            poll_secs: 30,
            metrics_bind: "127.0.0.1:9100".into(),
            disable_gossip: false,
            recorder: false,
            no_mdns: false,
            relay_mode: None,
            relay_urls: None,
            keep_alive: false,
            no_encrypt_state: false,
        }
    }

    pub fn with_hostname(mut self, hostname: impl AsRef<str>) -> Self {
        self.hostname = Some(sanitize_hostname(hostname.as_ref()));
        self
    }
}

/// Owned in-process agent. Drop is not enough; call [`AgentRuntime::shutdown`].
pub struct AgentRuntime {
    handle: AgentHandle,
}

impl AgentRuntime {
    /// Start idle (no network yet) or start the mesh from persisted state.
    ///
    /// Ready to accept commands when this returns. Does not bind a Local API.
    pub async fn start(
        mut config: AgentConfig,
        shutdown: Option<tokio_util::sync::CancellationToken>,
    ) -> anyhow::Result<Self> {
        if let Some(hostname) = config.hostname.take() {
            config.hostname = Some(sanitize_hostname(&hostname));
        }

        let paths = StatePaths::resolve(Some(config.state_dir.to_string_lossy().as_ref()));
        paths
            .ensure()
            .with_context(|| format!("create state dir {}", paths.root().display()))?;

        let shutdown = shutdown.unwrap_or_default();
        let handle = AgentHandle {
            inner: Arc::new(new_inner(config, paths.clone(), shutdown)),
        };

        if has_network_state(&paths)
            && let Err(err) = handle.activate_persisted().await
        {
            tracing::error!(kind = ?err.kind, "persisted state could not be activated");
            #[cfg(not(target_os = "android"))]
            return Err(anyhow::Error::from(err));
        }

        Ok(Self { handle })
    }

    pub fn handle(&self) -> AgentHandle {
        self.handle.clone()
    }

    pub fn shutdown_token(&self) -> tokio_util::sync::CancellationToken {
        self.handle.inner.shutdown.clone()
    }

    /// Cancel and drain the mesh. Idempotent.
    pub async fn shutdown(self) {
        self.handle.inner.shutdown.cancel();
        #[cfg(feature = "local-api")]
        {
            self.handle.inner.api_watch.send_replace(None);
        }
        let mut phase = self.handle.inner.phase.write().await;
        self.handle
            .publish(self.handle.transition_snapshot(AgentLifecycle::Stopping));
        let previous = std::mem::replace(&mut *phase, Phase::Stopping);
        match previous {
            Phase::Mesh(mesh) => (*mesh).drain().await,
            Phase::Idle
            | Phase::Joining
            | Phase::PendingApproval
            | Phase::Activating
            | Phase::Stopping
            | Phase::Failed(_)
            | Phase::Stopped => {}
        }
        *phase = Phase::Stopped;
        self.handle
            .publish(self.handle.base_snapshot(AgentLifecycle::Stopped));
        tracing::info!("embedded agent stopped");
    }
}

pub(crate) fn has_network_state(paths: &StatePaths) -> bool {
    paths.secrets_file().is_file() && matches!(PersistedState::try_load(paths), Ok(Some(_)))
}

/// Make a device name usable as a Tunnet hostname.
///
/// The agent rejects a hostname containing a space, dot, or slash, or longer
/// than 63 bytes. Substituting keeps the name recognisable in a peer list.
pub fn sanitize_hostname(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| match c {
            ' ' | '.' | '/' => '-',
            c => c,
        })
        .collect();
    let mut truncated = String::new();
    for c in cleaned.chars() {
        if truncated.len() + c.len_utf8() > 63 {
            break;
        }
        truncated.push(c);
    }
    let trimmed = truncated.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "tunnet-agent".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::handle::Phase;
    use super::*;

    #[test]
    fn rejected_characters_are_substituted() {
        assert_eq!(sanitize_hostname("Pixel 8a"), "Pixel-8a");
        assert_eq!(sanitize_hostname("a.b/c d"), "a-b-c-d");
    }

    #[test]
    fn length_is_capped_in_bytes_on_a_character_boundary() {
        for name in ["é".repeat(80), "a".repeat(80), "日本語".repeat(40)] {
            let out = sanitize_hostname(&name);
            assert!(out.len() <= 63, "{out:?} is {} bytes", out.len());
            assert!(out.chars().all(|c| !c.is_control()));
        }
    }

    #[test]
    fn empty_or_punctuation_only_falls_back() {
        assert_eq!(sanitize_hostname(""), "tunnet-agent");
        assert_eq!(sanitize_hostname("   "), "tunnet-agent");
        assert_eq!(sanitize_hostname("..."), "tunnet-agent");
    }

    #[test]
    fn an_already_valid_name_is_unchanged() {
        assert_eq!(sanitize_hostname("nono"), "nono");
    }

    #[tokio::test]
    async fn start_idle_against_empty_state_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(
            AgentConfig::new(dir.path()).with_hostname("test-device"),
            None,
        )
        .await
        .expect("start idle");
        let snap = runtime.handle().snapshot().await;
        assert_eq!(snap.lifecycle, AgentLifecycle::Idle);
        assert_eq!(snap.mode, AgentMode::Idle);
        assert_eq!(snap.data_plane, DataPlaneState::Down);
        assert!(snap.networks.is_empty());
        assert!(snap.peers.is_empty());
        assert!(snap.error.is_none());
        assert_eq!(snap.hostname, "test-device");
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn start_against_unwritable_path_fails() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let under_a_file = file.path().join("tunnet-state");
        let err = match AgentRuntime::start(AgentConfig::new(under_a_file), None).await {
            Ok(_) => panic!("creating a state dir beneath a file must fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("create state dir"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn bring_up_while_idle_is_not_joined() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let err = runtime.handle().bring_up().await.expect_err("idle up");
        assert_eq!(err.kind, AgentErrorKind::NotJoined);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn join_rejects_empty_invite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let err = runtime
            .handle()
            .join(JoinRequest {
                invite_code: "  ".into(),
                hostname: None,
                auto_accept_firewall: true,
                no_encrypt_state: false,
            })
            .await
            .expect_err("empty invite");
        assert_eq!(err.kind, AgentErrorKind::InvalidRequest);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn create_rejects_invalid_network_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let err = runtime
            .handle()
            .create(CreateRequest {
                network_name: Some("NO".into()),
                ..CreateRequest::default()
            })
            .await
            .expect_err("invalid name");
        assert_eq!(err.kind, AgentErrorKind::JoinFailed);
        let snap = runtime.handle().snapshot().await;
        assert_eq!(snap.lifecycle, AgentLifecycle::Failed);
        assert_eq!(
            snap.error.as_ref().map(|e| e.kind),
            Some(AgentErrorKind::JoinFailed)
        );
        assert_eq!(snap.data_plane, DataPlaneState::Down);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn join_retries_after_failed_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        let _ = handle
            .create(CreateRequest {
                network_name: Some("NO".into()),
                ..CreateRequest::default()
            })
            .await
            .expect_err("invalid name");
        let err = handle
            .join(JoinRequest {
                invite_code: "not-an-invite".into(),
                hostname: None,
                auto_accept_firewall: true,
                no_encrypt_state: false,
            })
            .await
            .expect_err("bad invite");
        assert_eq!(err.kind, AgentErrorKind::JoinFailed);
        assert!(
            !err.to_string().contains("invalid network name")
                && !err.to_string().contains("network name"),
            "stale Failed error was replayed: {err:#}"
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_for_idle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        runtime.shutdown().await;
        let snap = handle.snapshot().await;
        assert_eq!(snap.lifecycle, AgentLifecycle::Stopped);
        assert_eq!(snap.data_plane, DataPlaneState::Down);
        let err = handle.bring_up().await.expect_err("stopped up");
        assert_eq!(err.kind, AgentErrorKind::Stopped);
    }

    #[tokio::test]
    async fn snapshot_does_not_wait_on_the_command_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        let locked = handle.clone();
        let (held, hold) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async move {
            let mut phase = locked.inner.phase.write().await;
            *phase = Phase::Joining;
            locked.publish(locked.transition_snapshot(AgentLifecycle::Joining));
            let _ = held.send(());
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            *phase = Phase::Idle;
        });
        hold.await.expect("lock held");
        let snap = tokio::time::timeout(std::time::Duration::from_millis(80), handle.snapshot())
            .await
            .expect("snapshot blocked on join lock");
        assert_eq!(snap.lifecycle, AgentLifecycle::Joining);
        join.await.expect("unlock");
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn subscribe_sees_idle_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(
            AgentConfig::new(dir.path()).with_hostname("watch-device"),
            None,
        )
        .await
        .expect("start idle");
        let rx = runtime.handle().subscribe();
        let snap = rx.borrow().clone();
        assert_eq!(snap.lifecycle, AgentLifecycle::Idle);
        assert_eq!(snap.hostname, "watch-device");
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn subscribe_delivers_subsequent_phase_updates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        let mut rx = handle.subscribe();
        assert_eq!(rx.borrow().lifecycle, AgentLifecycle::Idle);
        handle.publish(handle.transition_snapshot(AgentLifecycle::Joining));
        rx.changed().await.expect("joining");
        assert_eq!(rx.borrow().lifecycle, AgentLifecycle::Joining);
        handle.publish(handle.transition_snapshot(AgentLifecycle::Activating));
        rx.changed().await.expect("activating");
        assert_eq!(rx.borrow().lifecycle, AgentLifecycle::Activating);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn recreated_subscriber_gets_current_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        handle.publish(handle.transition_snapshot(AgentLifecycle::Joining));
        drop(handle.subscribe());
        let rx = handle.subscribe();
        assert_eq!(rx.borrow().lifecycle, AgentLifecycle::Joining);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn subscribe_sees_stopped_after_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        let mut rx = handle.subscribe();
        runtime.shutdown().await;
        if rx.borrow().lifecycle != AgentLifecycle::Stopped {
            rx.changed().await.expect("stopped");
        }
        assert_eq!(rx.borrow().lifecycle, AgentLifecycle::Stopped);
        let err = handle
            .join(JoinRequest {
                invite_code: "x".into(),
                hostname: None,
                auto_accept_firewall: true,
                no_encrypt_state: false,
            })
            .await
            .expect_err("stopped");
        assert_eq!(err.kind, AgentErrorKind::Stopped);
    }

    #[tokio::test]
    async fn slow_watch_consumer_does_not_block_snapshot_now() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let handle = runtime.handle();
        let mut rx = handle.subscribe();
        let stalled = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let _ = rx.changed().await;
        });
        let start = std::time::Instant::now();
        for _ in 0..50 {
            handle.publish(handle.transition_snapshot(AgentLifecycle::Joining));
            let _ = handle.snapshot_now();
        }
        assert!(
            start.elapsed() < std::time::Duration::from_millis(50),
            "snapshot_now waited on a stalled subscriber"
        );
        let _ = stalled.await;
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn failed_create_is_visible_as_a_failed_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .expect("start idle");
        let mut rx = runtime.handle().subscribe();
        let err = runtime
            .handle()
            .create(CreateRequest {
                network_name: Some("NO".into()),
                ..CreateRequest::default()
            })
            .await
            .expect_err("invalid name");
        assert_eq!(err.kind, AgentErrorKind::JoinFailed);
        while rx.borrow().lifecycle != AgentLifecycle::Failed {
            rx.changed().await.expect("failed snapshot");
        }
        runtime.shutdown().await;
    }
}
