//! Cloneable command and observation surface for an [`super::AgentRuntime`].

use std::sync::Arc;
use std::time::Instant;

use tunnet_core::local_api::DataPlaneControl;
use tunnet_core::{PersistedState, SealPolicy, StatePaths, load_agent};
use uuid::Uuid;

use super::mesh::MeshSession;
use super::snapshot::{empty_snapshot, membership_from_persisted, snapshot_from_node, with_error};
use super::{AgentConfig, sanitize_hostname};

pub use super::snapshot::{
    AgentError, AgentErrorInfo, AgentErrorKind, AgentLifecycle, AgentMode, AgentNetwork, AgentPeer,
    AgentRole, AgentSnapshot, DataPlaneState, PeerConnKind, PeerPath,
};

use super::mesh::start_mesh;

/// Direct-network join request.
#[derive(Debug, Clone)]
pub struct JoinRequest {
    pub invite_code: String,
    pub hostname: Option<String>,
    pub auto_accept_firewall: bool,
    pub no_encrypt_state: bool,
}

/// Direct-network create request.
#[derive(Debug, Clone, Default)]
pub struct CreateRequest {
    pub hostname: Option<String>,
    pub open: bool,
    pub network_name: Option<String>,
    pub secret: Option<String>,
    pub cidr: Option<String>,
    pub no_encrypt_state: bool,
}

/// Result of a successful Direct join.
#[derive(Debug, Clone)]
pub struct JoinOutcome {
    pub network_id: String,
    pub network_name: String,
    pub ipv4: String,
    pub endpoint_id: String,
}

pub(crate) enum Phase {
    Idle,
    Joining,
    PendingApproval,
    Activating,
    Mesh(Box<MeshSession>),
    Stopping,
    Failed(AgentError),
    Stopped,
}

pub(crate) struct HandleInner {
    pub(crate) config: AgentConfig,
    pub(crate) paths: StatePaths,
    pub(crate) shutdown: tokio_util::sync::CancellationToken,
    pub(crate) started_at: Instant,
    pub(crate) src_posture_ok: Arc<arc_swap::ArcSwap<bool>>,
    pub(crate) phase: tokio::sync::RwLock<Phase>,
    pub(crate) published: arc_swap::ArcSwap<AgentSnapshot>,
    pub(crate) watch: tokio::sync::watch::Sender<Arc<AgentSnapshot>>,
    #[cfg(not(target_os = "android"))]
    underlay_monitor: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(not(target_os = "android"))]
    pub(super) underlay_recovery: parking_lot::Mutex<Option<UnderlayRecovery>>,
    #[cfg(feature = "local-api")]
    pub(crate) api_watch:
        tokio::sync::watch::Sender<Option<std::sync::Arc<tunnet_core::local_api::LocalApiState>>>,
}

#[cfg(not(target_os = "android"))]
#[derive(Clone)]
pub(super) struct UnderlayRecovery {
    desired_up: bool,
    observed: Arc<crate::underlay::TransportUnderlay>,
    retry_at: Instant,
    delay: std::time::Duration,
}

/// Cloneable handle for commands and snapshots.
#[derive(Clone)]
pub struct AgentHandle {
    pub(crate) inner: Arc<HandleInner>,
}

impl AgentHandle {
    pub(crate) async fn managed_client(&self) -> anyhow::Result<Option<tunnet_core::SignedClient>> {
        let phase = self.inner.phase.read().await;
        match &*phase {
            Phase::Idle => Ok(None),
            Phase::Mesh(mesh) if mesh.is_alive() => Ok(Some(mesh.node.require_signed()?.clone())),
            _ => anyhow::bail!("managed client unavailable during lifecycle transition"),
        }
    }

    /// Point-in-time view. Never waits on join/activate/shutdown.
    ///
    /// While a command holds the exclusive phase lock, this returns the last
    /// published transition snapshot (Joining/Activating/Stopping). While the
    /// mesh is live, peers and dataplane are composed from current runtime
    /// state. A dead supervisor is never reported as `Running`.
    pub fn snapshot_now(&self) -> AgentSnapshot {
        match self.inner.phase.try_read() {
            Ok(phase) => match &*phase {
                Phase::Idle => self.base_snapshot(AgentLifecycle::Idle),
                Phase::Joining => self.transition_snapshot(AgentLifecycle::Joining),
                Phase::PendingApproval => self.transition_snapshot(AgentLifecycle::PendingApproval),
                Phase::Activating => self.transition_snapshot(AgentLifecycle::Activating),
                Phase::Stopping => self.transition_snapshot(AgentLifecycle::Stopping),
                Phase::Stopped => self.base_snapshot(AgentLifecycle::Stopped),
                Phase::Failed(err) => with_error(self.base_snapshot(AgentLifecycle::Failed), err),
                Phase::Mesh(mesh) => {
                    if !mesh.is_alive() {
                        let err =
                            AgentError::new(AgentErrorKind::Failed, "mesh supervisor stopped");
                        with_error(self.base_snapshot(AgentLifecycle::Failed), &err)
                    } else {
                        snapshot_from_mesh(mesh, self.inner.started_at)
                    }
                }
            },
            Err(_) => (**self.inner.published.load()).clone(),
        }
    }

    pub async fn snapshot(&self) -> AgentSnapshot {
        let snap = self.snapshot_now();
        if snap.lifecycle == AgentLifecycle::Failed {
            self.record_dead_mesh().await;
            return self.snapshot_now();
        }
        snap
    }

    /// Current snapshot plus subsequent publications.
    ///
    /// Phase changes publish immediately. Live mesh membership and dataplane
    /// changes are republished by the mesh view pump (route watch + events),
    /// coalesced so peer churn cannot stall the runtime.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<AgentSnapshot>> {
        self.inner.watch.subscribe()
    }

    pub fn shutdown_token(&self) -> tokio_util::sync::CancellationToken {
        self.inner.shutdown.clone()
    }

    pub async fn peers(&self, network_id: &str) -> Result<Vec<AgentPeer>, AgentError> {
        let id = network_id.trim();
        if Uuid::parse_str(id).is_err() {
            return Err(AgentError::new(
                AgentErrorKind::InvalidRequest,
                format!("invalid network id {network_id}"),
            ));
        }
        Ok(self.snapshot().await.peers_for_network(id))
    }

    pub async fn join(&self, request: JoinRequest) -> Result<JoinOutcome, AgentError> {
        let invite = request.invite_code.trim();
        if invite.is_empty() {
            return Err(AgentError::new(
                AgentErrorKind::InvalidRequest,
                "invite code is empty",
            ));
        }

        {
            let mut phase = self.inner.phase.write().await;
            self.require_idle(&phase)?;
            *phase = Phase::Joining;
            self.publish(self.transition_snapshot(AgentLifecycle::Joining));
        }

        let hostname = request
            .hostname
            .as_deref()
            .filter(|h| !h.trim().is_empty())
            .map(sanitize_hostname)
            .or_else(|| self.inner.config.hostname.clone());

        let pending_handle = self.clone();
        let on_pending = std::sync::Arc::new(move || {
            let handle = pending_handle.clone();
            tokio::spawn(async move {
                let mut phase = handle.inner.phase.write().await;
                if matches!(*phase, Phase::Joining | Phase::PendingApproval) {
                    *phase = Phase::PendingApproval;
                    handle.publish(handle.transition_snapshot(AgentLifecycle::PendingApproval));
                }
            });
        });
        let args = crate::cmds_direct::JoinArgs {
            invite_code: invite.to_string(),
            hostname,
            auto_accept_firewall: request.auto_accept_firewall,
            no_encrypt_state: request.no_encrypt_state || self.inner.config.no_encrypt_state,
            on_pending: Some(on_pending),
            cancel: Some(self.inner.shutdown.clone()),
        };
        let state_dir = self.inner.paths.root().to_string_lossy().into_owned();
        let outcome = match crate::cmds_direct::persist_direct_join(args, Some(&state_dir)).await {
            Ok(o) => o,
            Err(e) => {
                let err = AgentError::new(AgentErrorKind::JoinFailed, format!("{e:#}"));
                let mut phase = self.inner.phase.write().await;
                if matches!(*phase, Phase::Stopping | Phase::Stopped) {
                    return Err(AgentError::new(
                        AgentErrorKind::Stopped,
                        "runtime is stopped",
                    ));
                }
                self.fail_locked(&mut phase, err.clone());
                return Err(err);
            }
        };

        let mut phase = self.inner.phase.write().await;
        if matches!(*phase, Phase::Stopping | Phase::Stopped) {
            return Err(AgentError::new(
                AgentErrorKind::Stopped,
                "runtime is stopped",
            ));
        }
        *phase = Phase::Activating;
        self.publish(self.transition_snapshot(AgentLifecycle::Activating));

        if let Err(err) = activate_locked(self, &mut phase).await {
            self.fail_locked(&mut phase, err.clone());
            return Err(err);
        }

        Ok(JoinOutcome {
            network_id: outcome.network_id.to_string(),
            network_name: outcome.network_name,
            ipv4: outcome.ipv4.to_string(),
            endpoint_id: outcome.endpoint_id,
        })
    }

    pub async fn create(&self, request: CreateRequest) -> Result<JoinOutcome, AgentError> {
        let mut phase = self.inner.phase.write().await;
        self.require_idle(&phase)?;
        *phase = Phase::Joining;
        self.publish(self.transition_snapshot(AgentLifecycle::Joining));

        let hostname = request
            .hostname
            .as_deref()
            .filter(|h| !h.trim().is_empty())
            .map(sanitize_hostname)
            .or_else(|| self.inner.config.hostname.clone());

        let args = crate::cmds_direct::CreateArgs {
            hostname,
            open: request.open,
            network_name: request.network_name,
            secret: request.secret,
            cidr: request.cidr,
            no_encrypt_state: request.no_encrypt_state || self.inner.config.no_encrypt_state,
        };
        let state_dir = self.inner.paths.root().to_string_lossy().into_owned();
        let outcome = match crate::cmds_direct::persist_direct_create(args, Some(&state_dir)).await
        {
            Ok(o) => o,
            Err(e) => {
                let err = AgentError::new(AgentErrorKind::JoinFailed, format!("{e:#}"));
                self.fail_locked(&mut phase, err.clone());
                return Err(err);
            }
        };

        *phase = Phase::Activating;
        self.publish(self.transition_snapshot(AgentLifecycle::Activating));

        if let Err(err) = activate_locked(self, &mut phase).await {
            self.fail_locked(&mut phase, err.clone());
            return Err(err);
        }

        Ok(JoinOutcome {
            network_id: outcome.network_id.to_string(),
            network_name: outcome.network_name,
            ipv4: outcome.ipv4.to_string(),
            endpoint_id: outcome.endpoint_id,
        })
    }

    /// Load persisted network state and start the mesh. No-op if already running.
    pub async fn activate_persisted(&self) -> Result<(), AgentError> {
        let mut phase = self.inner.phase.write().await;
        match &*phase {
            Phase::Mesh(_) => return Ok(()),
            Phase::Joining | Phase::PendingApproval | Phase::Activating | Phase::Stopping => {
                return Err(AgentError::new(
                    AgentErrorKind::Busy,
                    "runtime is already changing state",
                ));
            }
            Phase::Stopped => {
                return Err(AgentError::new(
                    AgentErrorKind::Stopped,
                    "runtime is stopped",
                ));
            }
            Phase::Failed(err) => return Err(err.clone()),
            Phase::Idle => {}
        }
        *phase = Phase::Activating;
        self.publish(self.transition_snapshot(AgentLifecycle::Activating));
        if let Err(err) = activate_locked(self, &mut phase).await {
            self.fail_locked(&mut phase, err.clone());
            return Err(err);
        }
        Ok(())
    }

    pub async fn bring_up(&self) -> Result<(), AgentError> {
        let dataplane = {
            let phase = self.inner.phase.read().await;
            match &*phase {
                Phase::Mesh(mesh) if mesh.is_alive() => mesh.dataplane.clone(),
                Phase::Mesh(_) => {
                    return Err(AgentError::new(
                        AgentErrorKind::Failed,
                        "mesh supervisor stopped",
                    ));
                }
                Phase::Idle | Phase::Joining | Phase::PendingApproval | Phase::Activating => {
                    return Err(AgentError::new(
                        AgentErrorKind::NotJoined,
                        "not joined to a network",
                    ));
                }
                Phase::Stopping | Phase::Stopped => {
                    return Err(AgentError::new(
                        AgentErrorKind::Stopped,
                        "runtime is stopped",
                    ));
                }
                Phase::Failed(err) => return Err(err.clone()),
            }
        };
        dataplane
            .bring_up()
            .await
            .map_err(|e| AgentError::new(AgentErrorKind::DataPlane, e))
    }

    pub async fn bring_down(&self) -> Result<(), AgentError> {
        let dataplane = {
            let phase = self.inner.phase.read().await;
            match &*phase {
                Phase::Mesh(mesh) if mesh.is_alive() => mesh.dataplane.clone(),
                Phase::Idle
                | Phase::Joining
                | Phase::PendingApproval
                | Phase::Activating
                | Phase::Stopping
                | Phase::Stopped => {
                    return Ok(());
                }
                Phase::Failed(err) => return Err(err.clone()),
                Phase::Mesh(_) => {
                    return Err(AgentError::new(
                        AgentErrorKind::Failed,
                        "mesh supervisor stopped",
                    ));
                }
            }
        };
        dataplane
            .bring_down()
            .await
            .map_err(|e| AgentError::new(AgentErrorKind::DataPlane, e))
    }

    #[cfg(feature = "local-api")]
    pub(crate) fn watch_mesh_api(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<std::sync::Arc<tunnet_core::local_api::LocalApiState>>>
    {
        self.inner.api_watch.subscribe()
    }

    fn require_idle(&self, phase: &Phase) -> Result<(), AgentError> {
        match phase {
            Phase::Failed(error) if error.kind == AgentErrorKind::CleanupFailed => {
                Err(error.clone())
            }
            Phase::Idle | Phase::Failed(_) => Ok(()),
            Phase::Mesh(_) => Err(AgentError::new(
                AgentErrorKind::AlreadyJoined,
                "already joined to a network",
            )),
            Phase::Joining | Phase::PendingApproval | Phase::Activating | Phase::Stopping => Err(
                AgentError::new(AgentErrorKind::Busy, "runtime is already changing state"),
            ),
            Phase::Stopped => Err(AgentError::new(
                AgentErrorKind::Stopped,
                "runtime is stopped",
            )),
        }
    }

    fn hostname(&self) -> String {
        self.inner.config.hostname.clone().unwrap_or_default()
    }

    pub(crate) fn base_snapshot(&self, lifecycle: AgentLifecycle) -> AgentSnapshot {
        let mut snap = empty_snapshot(
            self.hostname(),
            self.inner.started_at.elapsed().as_secs(),
            lifecycle,
        );
        if let Ok(Some(persisted)) = PersistedState::try_load(&self.inner.paths) {
            let (mode, networks) = membership_from_persisted(&persisted, None, &[]);
            snap.mode = mode;
            snap.networks = networks;
        }
        snap
    }

    pub(crate) fn transition_snapshot(&self, lifecycle: AgentLifecycle) -> AgentSnapshot {
        let mut snap = self.base_snapshot(lifecycle);
        snap.lifecycle = lifecycle;
        snap.data_plane = super::snapshot::DataPlaneState::Down;
        snap.peers.clear();
        snap
    }

    pub(crate) fn publish(&self, snap: AgentSnapshot) {
        let arc = Arc::new(snap);
        self.inner.published.store(arc.clone());
        self.inner.watch.send_replace(arc);
    }

    fn fail_locked(&self, phase: &mut Phase, err: AgentError) {
        #[cfg(not(target_os = "android"))]
        if err.kind == AgentErrorKind::CleanupFailed {
            *self.inner.underlay_recovery.lock() = None;
        }
        *phase = Phase::Failed(err.clone());
        self.publish(with_error(self.base_snapshot(AgentLifecycle::Failed), &err));
    }

    pub(crate) async fn record_dead_mesh(&self) {
        let mut phase = self.inner.phase.write().await;
        let Phase::Mesh(mesh) = &*phase else {
            return;
        };
        if mesh.is_alive() {
            return;
        }
        let err = AgentError::new(AgentErrorKind::Failed, "mesh supervisor stopped");
        let old = std::mem::replace(&mut *phase, Phase::Failed(err.clone()));
        #[cfg(feature = "local-api")]
        self.inner.api_watch.send_replace(None);
        #[cfg(not(target_os = "android"))]
        {
            *self.inner.underlay_recovery.lock() = None;
        }
        self.publish(with_error(self.base_snapshot(AgentLifecycle::Failed), &err));
        if let Phase::Mesh(mesh) = old
            && let Err(error) = mesh.drain().await
        {
            self.fail_locked(
                &mut phase,
                AgentError::new(
                    AgentErrorKind::CleanupFailed,
                    format!("failed mesh cleanup: {error:#}"),
                ),
            );
        }
    }
}

#[cfg(not(target_os = "android"))]
impl AgentHandle {
    fn monitor_underlay(&self) {
        let mut task = self.inner.underlay_monitor.lock();
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let owner = Arc::downgrade(&self.inner);
        let shutdown = self.inner.shutdown.clone();
        *task = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    _ = tick.tick() => {},
                }
                let Some(inner) = owner.upgrade() else { break };
                let handle = AgentHandle { inner };
                handle.check_underlay().await;
            }
        }));
    }

    async fn check_underlay(&self) {
        let dead = {
            let phase = self.inner.phase.read().await;
            matches!(&*phase, Phase::Mesh(mesh) if !mesh.is_alive())
        };
        if dead {
            self.record_dead_mesh().await;
            return;
        }
        let (current, overlay, recovery) = {
            let phase = self.inner.phase.read().await;
            match &*phase {
                Phase::Mesh(mesh) => {
                    let snapshot = mesh.node.forwarding.load();
                    let ips = snapshot
                        .tables
                        .local_ips
                        .values()
                        .copied()
                        .chain(std::iter::once(snapshot.self_id.ip))
                        .filter(|ip| !ip.is_unspecified())
                        .map(std::net::IpAddr::V4)
                        .collect::<Vec<_>>();
                    (Some(mesh.underlay.clone()), ips, None)
                }
                Phase::Failed(_) => {
                    let Some(recovery) = self.inner.underlay_recovery.lock().clone() else {
                        return;
                    };
                    (None, Vec::new(), Some(recovery))
                }
                _ => return,
            }
        };
        let discovered = tokio::select! {
            biased;
            _ = self.inner.shutdown.cancelled() => return,
            result = tokio::time::timeout(std::time::Duration::from_secs(10), crate::underlay::discover_transport(&self.inner.config.ifname, &overlay)) => result,
        };
        let observed = match discovered {
            Ok(Ok(observed)) => Arc::new(observed),
            Ok(Err(error)) => {
                tracing::debug!(%error, "underlay observation unavailable");
                return;
            }
            Err(_) => {
                tracing::debug!("underlay observation timed out");
                return;
            }
        };
        if current
            .as_ref()
            .is_some_and(|current| current.same_network(&observed))
            || recovery.as_ref().is_some_and(|recovery| {
                recovery.observed.same_network(&observed) && Instant::now() < recovery.retry_at
            })
        {
            return;
        }
        self.refresh_underlay(current, observed).await;
    }

    async fn refresh_underlay(
        &self,
        expected: Option<Arc<crate::underlay::TransportUnderlay>>,
        observed: Arc<crate::underlay::TransportUnderlay>,
    ) {
        let mut phase = self.inner.phase.write().await;
        if self.inner.shutdown.is_cancelled() {
            return;
        }
        let desired_up = match (&*phase, expected) {
            (Phase::Mesh(mesh), Some(expected)) if Arc::ptr_eq(&mesh.underlay, &expected) => {
                mesh.desired_up.load(std::sync::atomic::Ordering::Acquire)
            }
            (Phase::Failed(_), None) => {
                let Some(recovery) = self.inner.underlay_recovery.lock().clone() else {
                    return;
                };
                recovery.desired_up
            }
            _ => return,
        };
        {
            let mut recovery = self.inner.underlay_recovery.lock();
            if recovery
                .as_ref()
                .is_none_or(|recovery| !recovery.observed.same_network(&observed))
            {
                *recovery = Some(UnderlayRecovery {
                    desired_up,
                    observed,
                    retry_at: Instant::now(),
                    delay: std::time::Duration::from_secs(5),
                });
            }
        }
        #[cfg(feature = "local-api")]
        self.inner.api_watch.send_replace(None);
        let old = std::mem::replace(&mut *phase, Phase::Activating);
        self.publish(self.transition_snapshot(AgentLifecycle::Activating));
        if let Phase::Mesh(mesh) = old {
            tracing::info!("underlay changed; rebuilding protected networking resources");
            if let Err(error) = mesh.drain().await {
                *self.inner.underlay_recovery.lock() = None;
                self.fail_locked(
                    &mut phase,
                    AgentError::new(
                        AgentErrorKind::CleanupFailed,
                        format!("underlay teardown failed: {error:#}"),
                    ),
                );
                return;
            }
        }
        if self.inner.shutdown.is_cancelled() {
            *phase = Phase::Stopped;
            self.publish(self.base_snapshot(AgentLifecycle::Stopped));
            return;
        }
        if let Err(error) = activate_locked(self, &mut phase).await {
            if let Some(recovery) = self.inner.underlay_recovery.lock().as_mut() {
                recovery.retry_at = Instant::now() + recovery.delay;
                recovery.delay = (recovery.delay * 2).min(std::time::Duration::from_secs(300));
            }
            tracing::warn!(%error, "protected networking recovery pending");
            self.fail_locked(&mut phase, error);
        }
    }
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        #[cfg(not(target_os = "android"))]
        if let Some(task) = self.underlay_monitor.get_mut().take() {
            task.abort();
        }
    }
}

pub(crate) fn new_inner(
    config: AgentConfig,
    paths: StatePaths,
    shutdown: tokio_util::sync::CancellationToken,
) -> HandleInner {
    let started_at = Instant::now();
    let hostname = config.hostname.clone().unwrap_or_default();
    let initial = Arc::new(empty_snapshot(hostname, 0, AgentLifecycle::Idle));
    let (watch, _) = tokio::sync::watch::channel(initial.clone());
    HandleInner {
        config,
        paths,
        shutdown,
        started_at,
        src_posture_ok: Arc::new(arc_swap::ArcSwap::from_pointee(false)),
        phase: tokio::sync::RwLock::new(Phase::Idle),
        published: arc_swap::ArcSwap::from(initial),
        watch,
        #[cfg(not(target_os = "android"))]
        underlay_monitor: parking_lot::Mutex::new(None),
        #[cfg(not(target_os = "android"))]
        underlay_recovery: parking_lot::Mutex::new(None),
        #[cfg(feature = "local-api")]
        api_watch: tokio::sync::watch::channel(None).0,
    }
}

fn snapshot_from_mesh(mesh: &MeshSession, started_at: Instant) -> AgentSnapshot {
    snapshot_from_node(
        &mesh.node,
        &mesh.hostname,
        mesh.dataplane.is_up(),
        &mesh.peer_rtt,
        started_at,
    )
}

async fn activate_locked(handle: &AgentHandle, phase: &mut Phase) -> Result<(), AgentError> {
    let inner = &*handle.inner;
    if !super::has_network_state(&inner.paths) {
        return Err(AgentError::new(
            AgentErrorKind::NotJoined,
            "no persisted network state",
        ));
    }
    let policy = SealPolicy::from_env_and_flag(inner.config.no_encrypt_state);
    let (identity, persisted, _) = load_agent(&inner.paths, policy)
        .map_err(|e| AgentError::new(AgentErrorKind::ActivateFailed, format!("{e:#}")))?;
    let desired_up = {
        #[cfg(not(target_os = "android"))]
        {
            inner
                .underlay_recovery
                .lock()
                .as_ref()
                .is_none_or(|recovery| recovery.desired_up)
        }
        #[cfg(target_os = "android")]
        {
            true
        }
    };
    let mesh = start_mesh(
        identity,
        persisted,
        inner.paths.clone(),
        &inner.config,
        handle.clone(),
        desired_up,
    )
    .await
    .map_err(|error| match error.downcast::<AgentError>() {
        Ok(error) => error,
        Err(error) => AgentError::new(AgentErrorKind::ActivateFailed, format!("{error:#}")),
    })?;
    #[cfg(feature = "local-api")]
    {
        inner.api_watch.send_replace(Some(mesh.api_state.clone()));
    }
    let snap = snapshot_from_mesh(&mesh, inner.started_at);
    *phase = Phase::Mesh(Box::new(mesh));
    handle.publish(snap);
    #[cfg(not(target_os = "android"))]
    {
        *inner.underlay_recovery.lock() = None;
        handle.monitor_underlay();
    }
    Ok(())
}

#[cfg(feature = "local-api")]
impl AgentHandle {
    pub(crate) fn observe_mesh(&self) -> tunnet_core::local_api::MeshObservation {
        crate::runtime::observe::from_snapshot(&self.snapshot_now())
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[tokio::test]
    async fn unresolved_cleanup_blocks_new_network_activation() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = super::super::AgentRuntime::start(AgentConfig::new(dir.path()), None)
            .await
            .unwrap();
        let handle = runtime.handle();
        *handle.inner.phase.write().await = Phase::Failed(AgentError::new(
            AgentErrorKind::CleanupFailed,
            "DNS restoration failed",
        ));
        let error = handle.create(CreateRequest::default()).await.unwrap_err();
        assert_eq!(error.kind, AgentErrorKind::CleanupFailed);
        let error = handle
            .join(JoinRequest {
                invite_code: "invite".into(),
                hostname: None,
                auto_accept_firewall: false,
                no_encrypt_state: false,
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind, AgentErrorKind::CleanupFailed);
        runtime.shutdown().await;
    }
}
