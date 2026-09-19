//! `UpdateActor`: owns updater scheduling and explicit update state.
//!
//! Large download bytes stay in `CoreUpdater` async work outside the mailbox;
//! the actor owns state transitions, timers, and lifecycle.

use std::sync::Arc;

use arc_swap::ArcSwap;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use tunnet_common::local_api::CoreUpdatePhase;
use tunnet_core::StatePaths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, kameo::Reply)]
pub enum UpdateState {
    Idle,
    Checking,
    Downloading,
    Verifying,
    Staged,
    Activating,
}

impl From<CoreUpdatePhase> for UpdateState {
    fn from(p: CoreUpdatePhase) -> Self {
        match p {
            CoreUpdatePhase::Idle => Self::Idle,
            CoreUpdatePhase::Checking => Self::Checking,
            CoreUpdatePhase::Downloading => Self::Downloading,
            CoreUpdatePhase::Verifying => Self::Verifying,
            CoreUpdatePhase::Staged => Self::Staged,
            CoreUpdatePhase::Activating => Self::Activating,
            _ => Self::Idle,
        }
    }
}

#[derive(Clone)]
pub struct UpdateActorArgs {
    pub paths: StatePaths,
    pub store: Option<tunnet_core::EffectiveConfigStore>,
    pub updater: Arc<crate::core_update::CoreUpdater>,
    pub state: Arc<ArcSwap<UpdateState>>,
}

pub struct UpdateActor {
    args: UpdateActorArgs,
    task: Option<super::OwnedTask>,
}

impl Actor for UpdateActor {
    type Args = UpdateActorArgs;
    type Error = Infallible;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let mut actor = Self { args, task: None };
        actor.start_scheduler(actor_ref);
        Ok(actor)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        if let Some(task) = self.task.take() {
            task.shutdown().await;
        }
        Ok(())
    }
}

impl UpdateActor {
    /// (enabled, interval_hours) from the single source of truth: the
    /// effective config store when present, else local TOML.
    fn schedule_params(
        paths: &tunnet_core::StatePaths,
        store: &Option<tunnet_core::EffectiveConfigStore>,
    ) -> (bool, u64) {
        if let Some(store) = store {
            let effective = store.load();
            (
                effective.effective.auto_update_enabled.value,
                effective.effective.auto_update_check_interval_hours.value,
            )
        } else {
            let config = tunnet_core::TunnetConfig::try_load(paths)
                .ok()
                .flatten()
                .unwrap_or_default();
            (
                config.update.enabled.unwrap_or(false),
                config.update.check_interval_hours.unwrap_or(6),
            )
        }
    }

    /// Next check delay, re-read every tick - same semantics as the pre-actor
    /// updater. Disabled means a quiet 1h re-poll of the flag.
    fn check_interval(
        paths: &tunnet_core::StatePaths,
        store: &Option<tunnet_core::EffectiveConfigStore>,
    ) -> std::time::Duration {
        let (enabled, interval_hours) = Self::schedule_params(paths, store);
        std::time::Duration::from_secs(if enabled {
            interval_hours.max(1) * 3600
        } else {
            3600
        })
    }

    fn start_scheduler(&mut self, actor_ref: ActorRef<Self>) {
        let weak = actor_ref.downgrade();
        let monitor_weak = actor_ref.downgrade();
        let cancel = tokio_util::sync::CancellationToken::new();
        let wait_cancel = cancel.clone();
        let paths = self.args.paths.clone();
        let store = self.args.store.clone();
        self.task = Some(super::OwnedTask::spawn_monitored(
            "update-scheduler",
            cancel,
            monitor_weak,
            SchedulerExited,
            async move {
                // Initial delay is cancellable: shutdown never waits out sleeps.
                tokio::select! {
                    _ = wait_cancel.cancelled() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                }
                loop {
                    let interval = Self::check_interval(&paths, &store);
                    tokio::select! {
                        _ = wait_cancel.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            if let Some(actor) = weak.upgrade() {
                                let _ = actor.tell(CheckNow).try_send();
                            } else {
                                break;
                            }
                        }
                    }
                }
            },
        ));
    }
}

/// The owned update scheduler ended without cancellation. Abnormal:
/// supervision must restart us.
struct SchedulerExited;

impl Message<SchedulerExited> for UpdateActor {
    type Reply = ();
    async fn handle(&mut self, _msg: SchedulerExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("update scheduler unexpectedly terminated");
    }
}

pub struct CheckNow;
pub struct GetUpdateState;
pub struct ShutdownUpdate;

impl Message<CheckNow> for UpdateActor {
    type Reply = ();
    async fn handle(&mut self, _msg: CheckNow, ctx: &mut Context<Self, Self::Reply>) {
        let updater = self.args.updater.clone();
        let state = self.args.state.clone();
        let paths = self.args.paths.clone();
        let store = self.args.store.clone();
        // Bounded one-shot work piped back; bytes never touch the mailbox.
        ctx.pipe(async move {
            state.store(Arc::new(UpdateState::Checking));
            let (enabled, _) = UpdateActor::schedule_params(&paths, &store);
            if enabled && !paths.update_pending_file().exists() {
                match updater.check().await {
                    Ok(status) => {
                        state.store(Arc::new(UpdateState::from(status.phase)));
                        if status.phase == CoreUpdatePhase::Available
                            && let Err(error) = updater.stage_and_activate(false).await
                        {
                            tracing::warn!(?error, "automatic Core update failed");
                            state.store(Arc::new(UpdateState::Idle));
                        }
                    }
                    Err(error) => {
                        tracing::warn!(?error, "automatic Core update check failed");
                        state.store(Arc::new(UpdateState::Idle));
                    }
                }
            } else {
                state.store(Arc::new(UpdateState::Idle));
            }
            UpdateChecked
        });
    }
}

pub struct UpdateChecked;
impl Message<UpdateChecked> for UpdateActor {
    type Reply = ();
    async fn handle(&mut self, _msg: UpdateChecked, _ctx: &mut Context<Self, Self::Reply>) {}
}

impl Message<GetUpdateState> for UpdateActor {
    type Reply = UpdateState;
    async fn handle(
        &mut self,
        _msg: GetUpdateState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        **self.args.state.load()
    }
}

impl Message<ShutdownUpdate> for UpdateActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ShutdownUpdate, ctx: &mut Context<Self, Self::Reply>) {
        // `on_stop` cancels and joins the owned scheduler with a bounded timeout.
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use std::time::Duration;

    fn test_paths() -> (tunnet_core::StatePaths, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = tunnet_core::StatePaths::resolve(Some(tmp.path().to_str().expect("utf8")));
        (paths, tmp)
    }

    #[test]
    fn disabled_means_quiet_hourly_repoll() {
        // No store and no TOML: updates off, scheduler re-checks the flag hourly.
        let (paths, _tmp) = test_paths();
        let (enabled, _) = UpdateActor::schedule_params(&paths, &None);
        assert!(!enabled);
        assert_eq!(
            UpdateActor::check_interval(&paths, &None),
            Duration::from_secs(3600)
        );
    }

    #[tokio::test]
    async fn check_now_when_disabled_settles_idle() {
        let (paths, _tmp) = test_paths();
        let (events_tx, _) = tokio::sync::broadcast::channel(4);
        let updater = crate::core_update::CoreUpdater::shared(paths.clone(), events_tx);
        let state = Arc::new(ArcSwap::from_pointee(UpdateState::Idle));
        let actor = UpdateActor::spawn_with_mailbox(
            UpdateActorArgs {
                paths,
                store: None,
                updater,
                state: state.clone(),
            },
            kameo::mailbox::bounded(crate::actors::UPDATE_MAILBOX),
        );
        actor.wait_for_startup().await;
        actor.tell(CheckNow).send().await.expect("check");
        // Disabled path performs no I/O; the piped completion lands promptly.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status: UpdateState = actor.ask(GetUpdateState).await.expect("status");
        assert_eq!(status, UpdateState::Idle);
        actor.stop_gracefully().await.expect("stop");
        tokio::time::timeout(Duration::from_secs(10), actor.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }
}
