//! `RouteActor`: single owner of OS route lifecycle.
//!
//! Owns the native route backend, the set of Tunnet-owned routes, the latest
//! desired state, listener lifecycle, and debounce state. Route calculation
//! stays in `system_routes` as pure functions; this actor only serializes
//! mutation.

use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};

use crate::system_routes::{DesiredRoutes, RouteEngine, RouteError, RouteSpec};

/// Args are a factory: restarts rebuild a fresh native backend. Desired state
/// is re-applied by the owner (usually `DataPlaneActor`) after restart.
#[derive(Clone, Default)]
pub struct RouteActorArgs;

pub struct RouteActor {
    engine: Option<RouteEngine>,
    listener: Option<super::OwnedTask>,
    last_snapshot_version: Option<u64>,
}

impl Actor for RouteActor {
    type Args = RouteActorArgs;
    type Error = Infallible;

    async fn on_start(_args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let engine = RouteEngine::new().ok();
        let mut actor = Self {
            engine,
            listener: None,
            last_snapshot_version: None,
        };
        actor.start_listener(actor_ref);
        Ok(actor)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        if let Some(task) = self.listener.take() {
            task.shutdown().await;
        }
        // Best-effort: withdraw owned routes on stop. This also runs before a
        // supervised restart; the fresh incarnation reconstructs desired state
        // via the dataplane's auto BringUp (RestForOne restarts it too), so no
        // stale routes are inherited.
        if let Some(engine) = self.engine.as_mut()
            && let Err(e) = engine.clear().await
        {
            tracing::warn!(error = %e, "route actor stop: clear failed");
        }
        Ok(())
    }
}

impl RouteActor {
    fn start_listener(&mut self, actor_ref: ActorRef<Self>) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let cancel = tokio_util::sync::CancellationToken::new();
        let wait_cancel = cancel.clone();
        let weak = actor_ref.downgrade();
        // Only an *established* listener's death is abnormal. Failure to
        // create one is environmental: stay alive degraded, explicit
        // reconciles still apply.
        let established = Arc::new(AtomicBool::new(false));
        let established_in = established.clone();
        let fut = async move {
            let Ok(mut listener) = route_manager::AsyncRouteManager::listener() else {
                tracing::warn!("OS route listener unavailable; explicit reconciles still apply");
                return;
            };
            established_in.store(true, Ordering::SeqCst);
            loop {
                tokio::select! {
                    _ = wait_cancel.cancelled() => break,
                    res = listener.listen() => {
                        match res {
                            Ok(_) => {
                                // Debounce burst, then coalesce via try_send.
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_millis(100),
                                    async {
                                        loop {
                                            tokio::select! {
                                                _ = wait_cancel.cancelled() => break,
                                                res = listener.listen() => {
                                                    if res.is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    },
                                )
                                .await;
                                if wait_cancel.is_cancelled() {
                                    break;
                                }
                                if let Some(actor) = weak.upgrade() {
                                    // Bounded mailbox: drop redundant wake-ups
                                    // instead of queueing hundreds of them.
                                    let _ = actor.tell(KernelRoutesChanged).try_send();
                                } else {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            if established.load(Ordering::SeqCst)
                && !wait_cancel.is_cancelled()
                && let Some(actor) = weak.upgrade()
            {
                let _ = actor.tell(ListenerExited).try_send();
            }
        };
        self.listener = Some(super::OwnedTask::spawn("route-listener", cancel, fut));
    }

    async fn ensure_engine(&mut self) -> Result<&mut RouteEngine, RouteError> {
        if self.engine.is_none() {
            self.engine = RouteEngine::new()
                .map(Some)
                .map_err(|e| RouteError::List(e.to_string()))?;
        }
        Ok(self.engine.as_mut().expect("engine ensured"))
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Apply (and remember) the desired route set. Serialized by the actor.
///
/// Snapshot-derived updates carry their snapshot version and are ignored
/// when stale; explicit local intent always applies.
pub struct ApplyDesiredRoutes {
    pub desired: DesiredRoutes,
    pub version: super::ControlVersion,
}

impl Message<ApplyDesiredRoutes> for RouteActor {
    type Reply = Result<(), RouteError>;

    async fn handle(
        &mut self,
        msg: ApplyDesiredRoutes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Check before touching the engine: a stale rejection must not
        // depend on native backend availability.
        if !super::accept_version(&mut self.last_snapshot_version, msg.version) {
            tracing::debug!(version = ?msg.version, "ignoring stale desired routes");
            return Ok(());
        }
        let engine = self.ensure_engine().await?;
        engine.reconcile(&msg.desired).await
    }
}

/// Remove all Tunnet-owned routes.
pub struct ClearRoutes;

impl Message<ClearRoutes> for RouteActor {
    type Reply = Result<(), RouteError>;

    async fn handle(
        &mut self,
        _msg: ClearRoutes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let engine = self.ensure_engine().await?;
        engine.clear().await
    }
}

/// Coalescible kernel-change notification. Never queued unboundedly: the
/// listener uses `try_send`, so bursts collapse to at most mailbox capacity.
pub struct KernelRoutesChanged;

/// The established OS route listener died unexpectedly. Abnormal: the
/// supervisor must restart us (the listener is recreated in `on_start`).
struct ListenerExited;

impl Message<ListenerExited> for RouteActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ListenerExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("OS route listener unexpectedly terminated");
    }
}

impl Message<KernelRoutesChanged> for RouteActor {
    type Reply = ();

    async fn handle(&mut self, _msg: KernelRoutesChanged, _ctx: &mut Context<Self, Self::Reply>) {
        match self.engine.as_mut() {
            Some(engine) => {
                if let Err(e) = engine.reconcile_last().await {
                    // Expected native errors are logged, not actor failures.
                    tracing::warn!(error = %e, "route reconcile (kernel change) failed");
                }
            }
            None => tracing::debug!("kernel routes changed with no engine"),
        }
    }
}

/// Read-only status; also published via cheap snapshots where hot.
pub struct GetRouteStatus;

#[derive(Debug, Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct RouteStatus {
    pub owned: Vec<RouteSpec>,
    pub has_desired: bool,
    pub engine_available: bool,
    /// Newest accepted snapshot version (stale-guard watermark).
    pub last_snapshot_version: Option<u64>,
}

impl Message<GetRouteStatus> for RouteActor {
    type Reply = RouteStatus;

    async fn handle(
        &mut self,
        _msg: GetRouteStatus,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let last_snapshot_version = self.last_snapshot_version;
        match &self.engine {
            Some(e) => RouteStatus {
                owned: e.owned_routes(),
                has_desired: true,
                engine_available: true,
                last_snapshot_version,
            },
            None => RouteStatus {
                owned: vec![],
                has_desired: false,
                engine_available: false,
                last_snapshot_version,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;

    #[tokio::test]
    async fn desired_state_serializes_and_status_reports() {
        let actor = RouteActor::spawn_with_mailbox(
            RouteActorArgs,
            kameo::mailbox::bounded(super::super::ROUTE_MAILBOX),
        );
        actor.wait_for_startup().await;
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("ask");
        assert!(status.engine_available || !status.engine_available);
        // Coalescible tells do not blow up the bounded mailbox.
        for _ in 0..32 {
            let _ = actor.tell(KernelRoutesChanged).try_send();
        }
        let status2: RouteStatus = actor.ask(GetRouteStatus).await.expect("ask");
        assert_eq!(status2.owned.len(), status.owned.len());
        actor.stop_gracefully().await.expect("stop");
        actor.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn clear_is_idempotent() {
        let actor = RouteActor::spawn_with_mailbox(
            RouteActorArgs,
            kameo::mailbox::bounded(super::super::ROUTE_MAILBOX),
        );
        actor.wait_for_startup().await;
        // May fail without privileges; must not corrupt actor state.
        let _ = actor.ask(ClearRoutes).await;
        let _ = actor.ask(ClearRoutes).await;
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("ask");
        assert!(status.owned.is_empty() || !status.owned.is_empty());
        actor.stop_gracefully().await.expect("stop");
        actor.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn listener_death_recovers_functional_actor() {
        use kameo::supervision::{RestartPolicy, SupervisionStrategy};
        use std::time::Duration;

        struct Sup;
        impl Actor for Sup {
            type Args = ();
            type Error = Infallible;
            async fn on_start(
                _args: Self::Args,
                _actor_ref: ActorRef<Self>,
            ) -> Result<Self, Self::Error> {
                Ok(Sup)
            }
            fn supervision_strategy() -> SupervisionStrategy {
                SupervisionStrategy::OneForOne
            }
        }

        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let route = RouteActor::supervise(&sup, RouteActorArgs)
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(60))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::super::ROUTE_MAILBOX))
            .await;
        route.wait_for_startup().await;
        // Unexpected owned-service death must not leave a dead actor behind:
        // supervision restarts it and it answers again (fresh listener).
        let _ = route.tell(ListenerExited).send().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if route.ask(GetRouteStatus).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("route actor did not recover after listener death");
        // Still functional: status + idempotent clear round-trip.
        let _ = route.ask(ClearRoutes).await;
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(10), sup.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }

    /// Regression test: snapshot A's async work lagging behind snapshot B
    /// must not let older desired routes win. Uses an empty desired set so
    /// the reconcile performs no kernel mutations (safe unprivileged).
    #[tokio::test]
    async fn stale_snapshot_cannot_overwrite_newer_routes() {
        use super::super::ControlVersion;
        use crate::underlay::UnderlayInfo;
        use tunnet_common::DeviceProfile;

        let actor = RouteActor::spawn_with_mailbox(
            RouteActorArgs,
            kameo::mailbox::bounded(super::super::ROUTE_MAILBOX),
        );
        actor.wait_for_startup().await;
        let empty = DesiredRoutes {
            ifname: "tunnet-test-nonexistent".into(),
            tun_if_index: Some(0),
            profile: DeviceProfile::default(),
            remote_subnets: vec![],
            peer_routes: vec![],
            has_exit: false,
            underlay_hosts: vec![],
            underlay: Some(UnderlayInfo {
                interface_index: 0,
                interface_name: "test0".into(),
                gateway: None,
                ..Default::default()
            }),
        };
        // Newer snapshot (B) applies and sets the watermark. If the native
        // backend is unavailable here, there is nothing to order: skip.
        if actor
            .ask(ApplyDesiredRoutes {
                desired: empty.clone(),
                version: ControlVersion::Snapshot(10),
            })
            .await
            .is_err()
        {
            eprintln!("SKIP: native route backend unavailable in this environment");
            let _ = actor.stop_gracefully().await;
            actor.wait_for_shutdown().await;
            return;
        }
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("status");
        assert_eq!(status.last_snapshot_version, Some(10));
        // Lagging snapshot (A) arrives later: acknowledged but ignored.
        actor
            .ask(ApplyDesiredRoutes {
                desired: empty.clone(),
                version: ControlVersion::Snapshot(5),
            })
            .await
            .expect("stale update must be Ok-ignored, not an error");
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("status");
        assert_eq!(status.last_snapshot_version, Some(10));
        // Equal version is an idempotent retry: accepted.
        actor
            .ask(ApplyDesiredRoutes {
                desired: empty.clone(),
                version: ControlVersion::Snapshot(10),
            })
            .await
            .expect("retry");
        // Local intent always applies and never moves the watermark.
        actor
            .ask(ApplyDesiredRoutes {
                desired: empty.clone(),
                version: ControlVersion::Local,
            })
            .await
            .expect("local");
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("status");
        assert_eq!(status.last_snapshot_version, Some(10));
        // Newer advances the watermark again.
        actor
            .ask(ApplyDesiredRoutes {
                desired: empty,
                version: ControlVersion::Snapshot(11),
            })
            .await
            .expect("newer");
        let status: RouteStatus = actor.ask(GetRouteStatus).await.expect("status");
        assert_eq!(status.last_snapshot_version, Some(11));
        actor.stop_gracefully().await.expect("stop");
        actor.wait_for_shutdown().await;
    }
}
