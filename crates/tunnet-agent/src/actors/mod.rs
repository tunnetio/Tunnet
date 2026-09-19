//! Kameo process-local orchestration for the Tunnet agent.
//!
//! Rule: **actor = owner of durable process-local state or lifecycle,
//! task = transient or high-throughput work.** Packet forwarding never passes
//! through actor mailboxes; Iroh remains the network transport.

pub mod control;
pub mod dataplane;
#[cfg(feature = "posture")]
pub mod posture;
pub mod presence;
pub mod routes;
#[cfg(feature = "ssh")]
pub mod ssh_registry;
pub mod supervisor;
#[cfg(test)]
pub mod test_support;
#[cfg(feature = "updater")]
pub mod update;

/// Bounded mailbox capacities, chosen by traffic semantics (not arbitrary).
pub(crate) const ROUTE_MAILBOX: usize = 16;
pub(crate) const DATAPLANE_MAILBOX: usize = 16;
#[cfg(feature = "posture")]
pub(crate) const POSTURE_MAILBOX: usize = 32;
pub(crate) const CONTROL_MAILBOX: usize = 128;
pub(crate) const PRESENCE_MAILBOX: usize = 16;
#[cfg(feature = "updater")]
pub(crate) const UPDATE_MAILBOX: usize = 16;
#[cfg(feature = "ssh")]
pub(crate) const SSH_REGISTRY_MAILBOX: usize = 32;
pub(crate) const SUPERVISOR_MAILBOX: usize = 32;

/// Control-plane generation attached to snapshot-derived updates.
///
/// The control actor fans snapshot work out to spawned tasks that can
/// complete out of order; the version lets owners reject stale state so an
/// older snapshot can never become authoritative after a newer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlVersion {
    /// Snapshot-derived state with the snapshot's monotonic version.
    Snapshot(u64),
    /// Explicit local intent (e.g. dataplane BringUp, direct operator
    /// commands): always applies, never touches the watermark.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    Local,
}

/// Returns true if `incoming` may be applied, recording it when versioned.
/// Equal versions are accepted (idempotent retry); only strictly older
/// snapshot state is rejected.
pub(crate) fn accept_version(last: &mut Option<u64>, incoming: ControlVersion) -> bool {
    match incoming {
        ControlVersion::Local => true,
        ControlVersion::Snapshot(v) => {
            if last.is_some_and(|last| v < last) {
                return false;
            }
            *last = Some(v);
            true
        }
    }
}

use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Graceful drain budget for one owned task.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A raw Tokio task owned by an actor.
///
/// Shutdown is always: cancel the token, wait bounded time for graceful
/// completion, explicitly abort on timeout, then await the handle so task
/// termination is actually observed. Dropping a `JoinHandle` never cancels
/// the task, so the abort-then-await step is load-bearing: after shutdown
/// returns, none of the actor's owned tasks may still be running.
pub(crate) struct OwnedTask {
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl OwnedTask {
    pub(crate) fn spawn<F>(name: &'static str, cancel: CancellationToken, fut: F) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let token = cancel.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {},
                _ = fut => {},
            }
            let _ = name;
        });
        Self {
            cancel,
            handle: Some(handle),
        }
    }

    /// Spawn `fut`; if it completes while `cancel` is not cancelled, deliver
    /// `msg` to `owner` with bounded backpressure (`send().await`, never a
    /// lossy `try_send`): unexpected service death is supervision-critical
    /// and must not disappear under mailbox pressure. Shutdown completions
    /// stay silent, and a gone actor is fine. The owner must treat the
    /// message as abnormal failure (panic) so supervision restarts it - a
    /// long-lived owned service must never terminate silently while its
    /// actor lives on.
    ///
    /// No deadlock: `send()` only waits for mailbox *capacity*, never for
    /// the actor to process the message, and shutdown always cancels first
    /// (taking the silent early return) with an abort fallback below.
    pub(crate) fn spawn_monitored<A, M, F>(
        name: &'static str,
        cancel: CancellationToken,
        owner: kameo::actor::WeakActorRef<A>,
        msg: M,
        fut: F,
    ) -> Self
    where
        A: kameo::actor::Actor + kameo::message::Message<M>,
        M: Send + 'static,
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let wait = cancel.clone();
        let wrapped = async move {
            fut.await;
            if wait.is_cancelled() {
                return; // intentional shutdown: stay silent
            }
            let Some(actor) = owner.upgrade() else {
                return; // actor already gone: fine
            };
            let _ = actor.tell(msg).send().await;
        };
        Self::spawn(name, cancel, wrapped)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub(crate) async fn shutdown(self) {
        self.shutdown_with(SHUTDOWN_TIMEOUT).await;
    }

    pub(crate) async fn shutdown_with(mut self, timeout: Duration) {
        self.cancel.cancel();
        if let Some(mut handle) = self.handle.take() {
            // Borrow, don't move, the handle into the timeout: moving it in
            // would detach (not cancel) the task on timeout expiry.
            if tokio::time::timeout(timeout, &mut handle).await.is_err() {
                tracing::warn!(?timeout, "owned task ignored cancellation; aborting");
                handle.abort();
                // Observe the abort (`abort()` is asynchronous). Awaiting a
                // completed handle would panic, so this only runs after a
                // real timeout. Graceful completions are already reaped by
                // the timeout poll above - nothing is left detached either way.
                let _ = handle.await;
            }
        }
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    };
    use std::time::Duration;

    /// Drop guard proving a task actually terminated (vs. detached).
    struct DiedFlag(Arc<AtomicBool>);
    impl Drop for DiedFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_completes_gracefully_and_leaves_nothing_running() {
        let cancel = CancellationToken::new();
        let died = Arc::new(AtomicBool::new(false));
        let flag = DiedFlag(died.clone());
        let task = OwnedTask::spawn("test-graceful", cancel, async move {
            let _flag = flag;
            tokio::task::yield_now().await;
        });
        tokio::time::timeout(Duration::from_secs(5), task.shutdown())
            .await
            .expect("shutdown must complete");
        assert!(died.load(Ordering::SeqCst), "task must have terminated");
    }

    #[tokio::test]
    async fn shutdown_aborts_task_that_ignores_cancellation() {
        let cancel = CancellationToken::new();
        let died = Arc::new(AtomicBool::new(false));
        let flag = DiedFlag(died.clone());
        // Ignores cancellation forever: only an explicit abort can end it.
        // (The old timeout implementation merely detached such tasks.)
        let task = OwnedTask::spawn("test-stubborn", cancel, async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });
        let start = std::time::Instant::now();
        task.shutdown_with(Duration::from_millis(100)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown must not wait out the task"
        );
        assert!(
            died.load(Ordering::SeqCst),
            "abort must be observed, not detached"
        );
    }

    /// Supervision-critical exit signals must survive a temporarily full
    /// mailbox: bounded `send()`, never lossy `try_send`.
    #[tokio::test]
    async fn monitored_death_is_not_lost_under_mailbox_pressure() {
        use kameo::actor::{Actor, ActorRef, Spawn};
        use kameo::error::Infallible;
        use kameo::message::{Context, Message};

        #[derive(Clone, Default)]
        struct Worker {
            starts: Arc<AtomicU32>,
        }
        impl Actor for Worker {
            type Args = Self;
            type Error = Infallible;
            async fn on_start(state: Self::Args, _: ActorRef<Self>) -> Result<Self, Self::Error> {
                state.starts.fetch_add(1, Ordering::SeqCst);
                Ok(state)
            }
        }
        /// Occupies the handler while the mailbox fills.
        struct Block;
        impl Message<Block> for Worker {
            type Reply = ();
            async fn handle(&mut self, _: Block, _: &mut Context<Self, Self::Reply>) {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
        struct Filler;
        impl Message<Filler> for Worker {
            type Reply = ();
            async fn handle(&mut self, _: Filler, _: &mut Context<Self, Self::Reply>) {}
        }
        struct Boom;
        impl Message<Boom> for Worker {
            type Reply = ();
            async fn handle(&mut self, _: Boom, _: &mut Context<Self, Self::Reply>) {
                panic!("service died");
            }
        }

        struct Sup;
        impl Actor for Sup {
            type Args = ();
            type Error = Infallible;
            async fn on_start(_: Self::Args, _: ActorRef<Self>) -> Result<Self, Self::Error> {
                Ok(Sup)
            }
        }

        let starts = Arc::new(AtomicU32::new(0));
        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let worker = Worker::supervise(
            &sup,
            Worker {
                starts: starts.clone(),
            },
        )
        .restart_policy(kameo::supervision::RestartPolicy::Transient)
        .restart_limit(5, Duration::from_secs(60))
        .spawn_with_mailbox(kameo::mailbox::bounded(1))
        .await;
        worker.wait_for_startup().await;
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        // Occupy the handler, then fill the single mailbox slot.
        worker.tell(Block).send().await.expect("block");
        worker.tell(Filler).send().await.expect("filler");
        // Service dies while the mailbox is full: with `try_send` this
        // signal would be dropped and the worker would never restart.
        let cancel = CancellationToken::new();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let _monitor = OwnedTask::spawn_monitored(
            "test-monitor",
            cancel,
            worker.downgrade(),
            Boom,
            async move {
                let _ = done_rx.await;
            },
        );
        let _ = done_tx.send(());
        // Bounded wait for the restart the signal must trigger.
        tokio::time::timeout(Duration::from_secs(10), async {
            while starts.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("lost exit signal: worker never restarted");
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(10), sup.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }

    #[tokio::test]
    async fn intentional_cancellation_reports_no_failure() {
        use kameo::actor::{Actor, ActorRef, Spawn};
        use kameo::error::Infallible;
        use kameo::message::{Context, Message};

        #[derive(Clone, Default)]
        struct Quiet;
        impl Actor for Quiet {
            type Args = Self;
            type Error = Infallible;
            async fn on_start(state: Self::Args, _: ActorRef<Self>) -> Result<Self, Self::Error> {
                Ok(state)
            }
        }
        struct Boom;
        impl Message<Boom> for Quiet {
            type Reply = ();
            async fn handle(&mut self, _: Boom, _: &mut Context<Self, Self::Reply>) {
                panic!("must never fire");
            }
        }
        struct Ping;
        impl Message<Ping> for Quiet {
            type Reply = ();
            async fn handle(&mut self, _: Ping, _: &mut Context<Self, Self::Reply>) {}
        }

        let actor = Quiet::spawn_with_mailbox(Quiet, kameo::mailbox::bounded(8));
        actor.wait_for_startup().await;
        // Cancel first: the monitored end must stay silent.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let task =
            OwnedTask::spawn_monitored("test-cancelled", cancel, actor.downgrade(), Boom, async {});
        task.shutdown().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(actor.is_alive(), "no false failure may be reported");
        actor.ask(Ping).await.expect("actor responsive");
        let _ = actor.stop_gracefully().await;
        actor.wait_for_shutdown().await;
    }

    #[test]
    fn version_guard_accepts_first_and_newer_and_equal_but_rejects_stale() {
        let mut last = None;
        assert!(accept_version(&mut last, ControlVersion::Snapshot(10)));
        assert_eq!(last, Some(10));
        // Stale loses.
        assert!(!accept_version(&mut last, ControlVersion::Snapshot(5)));
        assert_eq!(last, Some(10));
        // Equal is an idempotent retry: accepted, watermark unchanged.
        assert!(accept_version(&mut last, ControlVersion::Snapshot(10)));
        assert_eq!(last, Some(10));
        // Newer advances.
        assert!(accept_version(&mut last, ControlVersion::Snapshot(11)));
        assert_eq!(last, Some(11));
        // Local intent never touches the watermark.
        assert!(accept_version(&mut last, ControlVersion::Local));
        assert_eq!(last, Some(11));
        assert!(!accept_version(&mut last, ControlVersion::Snapshot(9)));
    }
}
