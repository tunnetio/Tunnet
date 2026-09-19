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
    pub(crate) phase: tokio::sync::RwLock<Phase>,
    pub(crate) published: arc_swap::ArcSwap<AgentSnapshot>,
    pub(crate) watch: tokio::sync::watch::Sender<Arc<AgentSnapshot>>,
    #[cfg(feature = "local-api")]
    pub(crate) api_watch:
        tokio::sync::watch::Sender<Option<std::sync::Arc<tunnet_core::local_api::LocalApiState>>>,
}

/// Cloneable handle for commands and snapshots.
#[derive(Clone)]
pub struct AgentHandle {
    pub(crate) inner: Arc<HandleInner>,
}

impl AgentHandle {
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
        self.publish(with_error(self.base_snapshot(AgentLifecycle::Failed), &err));
        if let Phase::Mesh(mesh) = old {
            tokio::spawn(async move {
                mesh.drain().await;
            });
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
        phase: tokio::sync::RwLock::new(Phase::Idle),
        published: arc_swap::ArcSwap::from(initial),
        watch,
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
    let mesh = start_mesh(
        identity,
        persisted,
        inner.paths.clone(),
        &inner.config,
        handle.clone(),
    )
    .await
    .map_err(|e| AgentError::new(AgentErrorKind::ActivateFailed, format!("{e:#}")))?;
    #[cfg(feature = "local-api")]
    {
        inner.api_watch.send_replace(Some(mesh.api_state.clone()));
    }
    let snap = snapshot_from_mesh(&mesh, inner.started_at);
    *phase = Phase::Mesh(Box::new(mesh));
    handle.publish(snap);
    Ok(())
}

#[cfg(feature = "local-api")]
impl AgentHandle {
    pub(crate) fn observe_mesh(&self) -> tunnet_core::local_api::MeshObservation {
        crate::runtime::observe::from_snapshot(&self.snapshot_now())
    }
}
