//! Root + dataplane supervision trees.
//!
//! ```text
//! AgentSupervisor (OneForOne)
//! ├── DataPlaneSupervisor (RestForOne)
//! │   ├── RouteActor
//! │   └── DataPlaneActor
//! ├── ControlPlaneActor (managed)
//! ├── PostureActor (managed)
//! ├── PresenceActor(s)
//! ├── UpdateActor
//! └── SshRegistryActor
//! ```

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use kameo::supervision::{RestartPolicy, SupervisionStrategy};
use tunnet_common::local_api::LocalEvent;
use tunnet_core::CoreNode;
use tunnet_core::local_api::DataPlaneStatusSnapshot;

use super::control::{ControlPlaneActor, ControlPlaneActorArgs};
use super::dataplane::{
    DataPlaneActor, DataPlaneActorArgs, DataPlaneActorConfig, PublishedPlane, ShutdownPlane,
};
use super::posture::{PostureActor, PostureActorArgs};
use super::presence::{PresenceActor, PresenceActorArgs, ShutdownPresence};
use super::routes::{RouteActor, RouteActorArgs};
use super::ssh_registry::{ShutdownSshRegistry, SshRegistryActor};
use super::update::{ShutdownUpdate, UpdateActor, UpdateActorArgs};
use crate::metrics::AgentMetrics;

// ---------------------------------------------------------------------------
// DataPlaneSupervisor (RestForOne: route failure restarts dataplane too)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DataPlaneSupervisorArgs {
    pub route_args: RouteActorArgs,
    pub dataplane_config: DataPlaneActorConfig,
    pub node: CoreNode,
    pub metrics: AgentMetrics,
    pub peer_dns_active: Arc<AtomicBool>,
    pub events: tokio::sync::broadcast::Sender<LocalEvent>,
    pub published: PublishedPlane,
    pub status: DataPlaneStatusSnapshot,
    pub ingress: crate::ingress::IngressRegistry,
    pub initially_up: bool,
    pub initial_generation: u64,
    /// Reconstruct the up state after a supervised restart (see
    /// `DataPlaneActorArgs::auto_up`).
    pub auto_up: bool,
}

pub struct DataPlaneSupervisor {
    route_actor: Option<ActorRef<RouteActor>>,
    dataplane_actor: Option<ActorRef<DataPlaneActor>>,
}

impl Actor for DataPlaneSupervisor {
    type Args = DataPlaneSupervisorArgs;
    type Error = Infallible;

    fn supervision_strategy() -> SupervisionStrategy {
        SupervisionStrategy::RestForOne
    }

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        // Route first: dataplane depends on it.
        let route_actor = RouteActor::supervise(&actor_ref, args.route_args.clone())
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(60))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::ROUTE_MAILBOX))
            .await;
        let dp_args = DataPlaneActorArgs {
            config: args.dataplane_config.clone(),
            node: args.node.clone(),
            metrics: args.metrics.clone(),
            peer_dns_active: args.peer_dns_active.clone(),
            events: args.events.clone(),
            route_actor: route_actor.clone(),
            published: args.published.clone(),
            status: args.status.clone(),
            ingress: args.ingress.clone(),
            initially_up: args.initially_up,
            initial_generation: args.initial_generation,
            auto_up: args.auto_up,
        };
        let dataplane_actor = DataPlaneActor::supervise(&actor_ref, dp_args)
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(60))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::DATAPLANE_MAILBOX))
            .await;
        Ok(Self {
            route_actor: Some(route_actor),
            dataplane_actor: Some(dataplane_actor),
        })
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Dependency-aware drain: dataplane down first, then routes stop.
        if let Some(dp) = self.dataplane_actor.take() {
            let _ = tokio::time::timeout(Duration::from_secs(20), dp.ask(ShutdownPlane)).await;
            let _ = dp.stop_gracefully().await;
            dp.wait_for_shutdown().await;
        }
        if let Some(route) = self.route_actor.take() {
            let _ = route.stop_gracefully().await;
            route.wait_for_shutdown().await;
        }
        Ok(())
    }
}

impl DataPlaneSupervisor {}

pub struct GetDataPlaneChildren;
#[derive(Clone, kameo::Reply)]
pub struct DataPlaneChildren {
    pub route_actor: Option<ActorRef<RouteActor>>,
    pub dataplane_actor: Option<ActorRef<DataPlaneActor>>,
}

impl Message<GetDataPlaneChildren> for DataPlaneSupervisor {
    type Reply = DataPlaneChildren;
    async fn handle(
        &mut self,
        _msg: GetDataPlaneChildren,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        DataPlaneChildren {
            route_actor: self.route_actor.clone(),
            dataplane_actor: self.dataplane_actor.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// AgentSupervisor (OneForOne: unrelated subsystems stay alive)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PostureSpawnConfig {
    pub agent_version: String,
    pub src_posture_ok: Arc<arc_swap::ArcSwap<bool>>,
}

#[derive(Clone)]
pub struct AgentSupervisorArgs {
    pub dataplane: DataPlaneSupervisorArgs,
    pub control: Option<ControlPlaneActorArgs>,
    pub posture: Option<PostureSpawnConfig>,
    pub presence: Vec<PresenceActorArgs>,
    pub update: Option<UpdateActorArgs>,
}

pub struct AgentSupervisor {
    dataplane_sup: Option<ActorRef<DataPlaneSupervisor>>,
    control_actor: Option<ActorRef<ControlPlaneActor>>,
    posture_actor: Option<ActorRef<PostureActor>>,
    presence_actors: Vec<ActorRef<PresenceActor>>,
    update_actor: Option<ActorRef<UpdateActor>>,
    ssh_registry: Option<ActorRef<SshRegistryActor>>,
}

impl Actor for AgentSupervisor {
    type Args = AgentSupervisorArgs;
    type Error = Infallible;

    fn supervision_strategy() -> SupervisionStrategy {
        SupervisionStrategy::OneForOne
    }

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let dataplane_sup = DataPlaneSupervisor::supervise(&actor_ref, args.dataplane.clone())
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(120))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::SUPERVISOR_MAILBOX))
            .await;

        let ssh_registry = SshRegistryActor::supervise(&actor_ref, ())
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(60))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::SSH_REGISTRY_MAILBOX))
            .await;

        // Control needs the ssh registry ref; patch args with the supervised one.
        // Spawned before posture so posture reports can forward through it.
        let control_actor = if let Some(mut c) = args.control.clone() {
            // SshRegistryActor restarts in place; the ref stays valid.
            c.ssh_registry = Some(ssh_registry.clone());
            Some(
                ControlPlaneActor::supervise(&actor_ref, c)
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(10, Duration::from_secs(120))
                    .spawn_with_mailbox(kameo::mailbox::bounded(super::CONTROL_MAILBOX))
                    .await,
            )
        } else {
            None
        };

        let posture_actor = match (args.posture.clone(), control_actor.clone()) {
            (Some(p), Some(control)) => Some(
                PostureActor::supervise(
                    &actor_ref,
                    PostureActorArgs {
                        agent_version: p.agent_version,
                        control: control.clone(),
                        src_posture_ok: p.src_posture_ok,
                    },
                )
                .restart_policy(RestartPolicy::Transient)
                .restart_limit(5, Duration::from_secs(60))
                .spawn_with_mailbox(kameo::mailbox::bounded(super::POSTURE_MAILBOX))
                .await,
            ),
            _ => None,
        };

        // Wire late-bound subsystem refs into the control actor. Refs stay
        // valid across supervised restarts (restart is in place).
        if let Some(control) = &control_actor {
            use super::control::{SetPostureActor, SetRouteActor};
            let mut route_ref = None;
            if let Ok(children) = dataplane_sup.ask(GetDataPlaneChildren).await {
                route_ref = children.route_actor;
            }
            let _ = control.tell(SetRouteActor(route_ref)).send().await;
            let _ = control
                .tell(SetPostureActor(posture_actor.clone()))
                .send()
                .await;
        }

        let mut presence_actors = Vec::new();
        for p in &args.presence {
            let a = PresenceActor::supervise(&actor_ref, p.clone())
                .restart_policy(RestartPolicy::Transient)
                .restart_limit(3, Duration::from_secs(120))
                .spawn_with_mailbox(kameo::mailbox::bounded(super::PRESENCE_MAILBOX))
                .await;
            presence_actors.push(a);
        }

        let update_actor = if let Some(u) = args.update.clone() {
            Some(
                UpdateActor::supervise(&actor_ref, u)
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(3, Duration::from_secs(300))
                    .spawn_with_mailbox(kameo::mailbox::bounded(super::UPDATE_MAILBOX))
                    .await,
            )
        } else {
            None
        };

        Ok(Self {
            dataplane_sup: Some(dataplane_sup),
            control_actor,
            posture_actor,
            presence_actors,
            update_actor,
            ssh_registry: Some(ssh_registry),
        })
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        use super::control::ShutdownControl;
        use super::posture::ShutdownPosture;
        // Reverse dependency order with bounded waits; abort only as fallback.
        if let Some(c) = self.control_actor.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), c.ask(ShutdownControl)).await;
            let _ = c.stop_gracefully().await;
            c.wait_for_shutdown().await;
        }
        for p in self.presence_actors.drain(..) {
            let _ = p.tell(ShutdownPresence).send().await;
            let _ = p.stop_gracefully().await;
            p.wait_for_shutdown().await;
        }
        if let Some(p) = self.posture_actor.take() {
            let _ = p.tell(ShutdownPosture).send().await;
            let _ = p.stop_gracefully().await;
            p.wait_for_shutdown().await;
        }
        if let Some(u) = self.update_actor.take() {
            let _ = u.tell(ShutdownUpdate).send().await;
            let _ = u.stop_gracefully().await;
            u.wait_for_shutdown().await;
        }
        if let Some(dp) = self.dataplane_sup.take() {
            let _ = dp.stop_gracefully().await;
            dp.wait_for_shutdown().await;
        }
        if let Some(s) = self.ssh_registry.take() {
            let _ = s.tell(ShutdownSshRegistry).send().await;
            let _ = s.stop_gracefully().await;
            s.wait_for_shutdown().await;
        }
        Ok(())
    }
}

impl AgentSupervisor {}

pub struct GetAgentChildren;
#[derive(Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct AgentChildren {
    pub dataplane_sup: Option<ActorRef<DataPlaneSupervisor>>,
    pub control_actor: Option<ActorRef<ControlPlaneActor>>,
    pub posture_actor: Option<ActorRef<PostureActor>>,
    pub update_actor: Option<ActorRef<UpdateActor>>,
    pub ssh_registry: Option<ActorRef<SshRegistryActor>>,
}

impl Message<GetAgentChildren> for AgentSupervisor {
    type Reply = AgentChildren;
    async fn handle(
        &mut self,
        _msg: GetAgentChildren,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        AgentChildren {
            dataplane_sup: self.dataplane_sup.clone(),
            control_actor: self.control_actor.clone(),
            posture_actor: self.posture_actor.clone(),
            update_actor: self.update_actor.clone(),
            ssh_registry: self.ssh_registry.clone(),
        }
    }
}

pub struct ShutdownAgent;
impl Message<ShutdownAgent> for AgentSupervisor {
    type Reply = ();
    async fn handle(&mut self, _msg: ShutdownAgent, ctx: &mut Context<Self, Self::Reply>) {
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use kameo::message::Message;

    /// Minimal supervised worker: restart resets `count` to the spawn value.
    #[derive(Clone, Default)]
    struct CounterWorker {
        count: u32,
    }

    impl Actor for CounterWorker {
        type Args = Self;
        type Error = Infallible;

        async fn on_start(
            state: Self::Args,
            _actor_ref: ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            Ok(state)
        }
    }

    struct Incr;
    struct GetCount;
    struct Boom;

    impl Message<Incr> for CounterWorker {
        type Reply = ();
        async fn handle(&mut self, _msg: Incr, _ctx: &mut Context<Self, Self::Reply>) {
            self.count += 1;
        }
    }

    impl Message<GetCount> for CounterWorker {
        type Reply = u32;
        async fn handle(
            &mut self,
            _msg: GetCount,
            _ctx: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            self.count
        }
    }

    impl Message<Boom> for CounterWorker {
        type Reply = ();
        async fn handle(&mut self, _msg: Boom, _ctx: &mut Context<Self, Self::Reply>) {
            panic!("injected test failure");
        }
    }

    struct TestSup {
        a: Option<ActorRef<CounterWorker>>,
        b: Option<ActorRef<CounterWorker>>,
    }

    impl Actor for TestSup {
        type Args = ();
        type Error = Infallible;

        async fn on_start(
            _args: Self::Args,
            actor_ref: ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            let a = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                .restart_policy(RestartPolicy::Transient)
                .restart_limit(5, Duration::from_secs(60))
                .spawn()
                .await;
            let b = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                .restart_policy(RestartPolicy::Transient)
                .restart_limit(5, Duration::from_secs(60))
                .spawn()
                .await;
            Ok(Self {
                a: Some(a),
                b: Some(b),
            })
        }

        async fn on_stop(
            &mut self,
            _actor_ref: WeakActorRef<Self>,
            _reason: ActorStopReason,
        ) -> Result<(), Self::Error> {
            for child in self.a.take().into_iter().chain(self.b.take()) {
                let _ = child.stop_gracefully().await;
                child.wait_for_shutdown().await;
            }
            Ok(())
        }
    }

    async fn poll_until<F, Fut>(mut f: F, timeout: Duration)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let start = std::time::Instant::now();
        loop {
            if f().await {
                return;
            }
            assert!(start.elapsed() < timeout, "poll timed out");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn one_for_one_failed_child_restarts_sibling_keeps_state() {
        struct Sup;
        impl Actor for Sup {
            type Args = ();
            type Error = Infallible;
            async fn on_start(
                _args: Self::Args,
                actor_ref: ActorRef<Self>,
            ) -> Result<Self, Self::Error> {
                let a = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(10, Duration::from_secs(60))
                    .spawn()
                    .await;
                let b = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(10, Duration::from_secs(60))
                    .spawn()
                    .await;
                // Stash refs where the test can reach them.
                assert!(CHILDREN.set((a, b)).is_ok());
                Ok(Sup)
            }
        }
        static CHILDREN: std::sync::OnceLock<(ActorRef<CounterWorker>, ActorRef<CounterWorker>)> =
            std::sync::OnceLock::new();

        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let (a, b) = CHILDREN.get().expect("children").clone();
        a.ask(Incr).await.expect("incr");
        b.ask(Incr).await.expect("incr");
        b.ask(Incr).await.expect("incr");
        assert_eq!(a.ask(GetCount).await.expect("get"), 1);
        assert_eq!(b.ask(GetCount).await.expect("get"), 2);
        // Injected panic: child must restart with fresh state.
        let _ = a.tell(Boom).send().await;
        poll_until(
            || {
                let a = a.clone();
                async move { a.ask(GetCount).await.unwrap_or(u32::MAX) == 0 }
            },
            Duration::from_secs(10),
        )
        .await;
        // Sibling untouched (OneForOne).
        assert_eq!(b.ask(GetCount).await.expect("get"), 2);
        // Process survived the injected panic (isolation).
        let _ = sup.stop_gracefully().await;
        sup.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn restart_limit_stops_restart_storm() {
        struct Sup;
        impl Actor for Sup {
            type Args = ();
            type Error = Infallible;
            async fn on_start(
                _args: Self::Args,
                actor_ref: ActorRef<Self>,
            ) -> Result<Self, Self::Error> {
                let w = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(2, Duration::from_secs(60))
                    .spawn()
                    .await;
                assert!(LIMITED.set(w).is_ok());
                Ok(Sup)
            }
        }
        static LIMITED: std::sync::OnceLock<ActorRef<CounterWorker>> = std::sync::OnceLock::new();

        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let w = LIMITED.get().expect("child").clone();
        for _ in 0..5 {
            let _ = w.tell(Boom).send().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !w.is_alive() {
                break;
            }
        }
        poll_until(
            || {
                let w = w.clone();
                async move { !w.is_alive() }
            },
            Duration::from_secs(10),
        )
        .await;
        let _ = sup.stop_gracefully().await;
        sup.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn graceful_shutdown_drains_children() {
        let sup = TestSup::spawn(());
        sup.wait_for_startup().await;
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(10), sup.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }

    #[tokio::test]
    async fn graceful_stop_does_not_restart_transient_child() {
        use std::sync::atomic::AtomicU32;

        struct Sup;
        impl Actor for Sup {
            type Args = ();
            type Error = Infallible;
            async fn on_start(
                _args: Self::Args,
                actor_ref: ActorRef<Self>,
            ) -> Result<Self, Self::Error> {
                let count = Arc::new(AtomicU32::new(0));
                let w = CounterWorker::supervise(&actor_ref, CounterWorker::default())
                    .restart_policy(RestartPolicy::Transient)
                    .restart_limit(5, Duration::from_secs(60))
                    .spawn()
                    .await;
                assert!(GRACEFUL.set((w, count)).is_ok());
                Ok(Sup)
            }
        }
        static GRACEFUL: std::sync::OnceLock<(ActorRef<CounterWorker>, Arc<AtomicU32>)> =
            std::sync::OnceLock::new();

        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let (w, _count) = GRACEFUL.get().expect("child").clone();
        // Prove liveness first: state transitions serialize through the child.
        w.ask(Incr).await.expect("incr");
        assert_eq!(w.ask(GetCount).await.expect("get"), 1);
        // Intentional shutdown (Normal exit) must not restart Transient actors.
        let _ = w.stop_gracefully().await;
        w.wait_for_shutdown().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!w.is_alive(), "stopped child must stay stopped");
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(10), sup.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }

    /// Full root shutdown without TUN or network: supervisor stops, children
    /// stop, owned tasks cancel, dataplane stays down with nothing published,
    /// and nothing restarts after intentional shutdown.
    #[tokio::test]
    async fn root_shutdown_drains_tree_without_restart() {
        use crate::actors::dataplane::{
            ActorDataPlaneControl, DataPlaneActorConfig, GetStatus, new_published_plane,
        };
        use crate::actors::routes::RouteActorArgs;
        use crate::actors::test_support::{test_metrics, test_node};
        use crate::actors::update::{UpdateActorArgs, UpdateState};
        use tunnet_core::local_api::{DataPlaneControl, DataPlaneStatusSnapshot};

        let (node, tmp) = test_node().await;
        let paths = node.paths.clone();
        let (events_tx, _) = tokio::sync::broadcast::channel(8);
        let published = new_published_plane();
        let status = DataPlaneStatusSnapshot::new(false);
        let updater = crate::core_update::CoreUpdater::shared(paths.clone(), events_tx.clone());
        let _ = tmp;
        let args = AgentSupervisorArgs {
            dataplane: DataPlaneSupervisorArgs {
                route_args: RouteActorArgs,
                dataplane_config: DataPlaneActorConfig {
                    ifname: "tunnet-test-down".into(),
                    local_addrs: vec!["10.9.0.1".parse().unwrap()],
                    mtu: 1280,
                    dns_cfg: tunnet_common::DnsConfig::default(),
                    dns: None,
                    is_direct: true,
                    network_id: uuid::Uuid::nil(),
                    underlay_hosts: vec![],
                },
                node,
                metrics: test_metrics(),
                peer_dns_active: Arc::new(AtomicBool::new(false)),
                events: events_tx,
                published: published.clone(),
                status: status.clone(),
                ingress: crate::ingress::IngressRegistry::new(),
                initially_up: false,
                initial_generation: 0,
                auto_up: false,
            },
            control: None,
            posture: None,
            presence: vec![],
            update: Some(UpdateActorArgs {
                paths,
                store: None,
                updater,
                state: Arc::new(arc_swap::ArcSwap::from_pointee(UpdateState::Idle)),
            }),
        };
        let sup = AgentSupervisor::spawn_with_mailbox(
            args,
            kameo::mailbox::bounded(super::super::SUPERVISOR_MAILBOX),
        );
        sup.wait_for_startup().await;
        let children: AgentChildren = sup.ask(GetAgentChildren).await.expect("children");
        let dp_sup = children.dataplane_sup.expect("dataplane supervisor");
        let dp_children: DataPlaneChildren =
            dp_sup.ask(GetDataPlaneChildren).await.expect("children");
        let dp = dp_children.dataplane_actor.expect("dataplane");
        let ssh = children.ssh_registry.expect("ssh registry");
        assert!(ssh.is_alive());
        let plane: crate::actors::dataplane::DataPlaneStatus =
            dp.ask(GetStatus).await.expect("status");
        assert!(!plane.up);
        // Real root shutdown path: children stop, owned tasks cancel,
        // dataplane stays down, nothing restarts.
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(30), sup.wait_for_shutdown())
            .await
            .expect("root shutdown drain");
        assert!(!sup.is_alive());
        assert!(!dp_sup.is_alive());
        assert!(!dp.is_alive(), "dataplane must stay stopped (no restart)");
        assert!(!ssh.is_alive());
        assert!(published.load_full().is_none(), "TUN generation withdrawn");
        assert!(!status.is_up(), "status read-model down");
        // Control surface observes the same down state without an actor hop.
        let control = ActorDataPlaneControl::new(status.clone(), dp);
        assert!(!control.is_up());
    }
}
