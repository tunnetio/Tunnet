//! `DataPlaneActor`: single owner of TUN/dataplane lifecycle.
//!
//! The actor is the only writer of [`PublishedDataPlane`]; packet hot paths
//! load an immutable generation once and never touch an async mutex.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwapOption;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use tun_rs::AsyncDevice;
use tunnet_common::DnsConfig;
use tunnet_common::local_api::LocalEvent;
use tunnet_core::CoreNode;
use tunnet_core::local_api::{DataPlaneControl, DataPlaneStatusSnapshot};
use uuid::Uuid;

use super::routes::{ApplyDesiredRoutes, ClearRoutes, RouteActor};
use crate::metrics::AgentMetrics;
use crate::system_dns::DnsController;
use crate::system_routes::desired_from_membership;

// ---------------------------------------------------------------------------
// Published hot-path view
// ---------------------------------------------------------------------------

/// Immutable generation published by `DataPlaneActor`.
///
/// Readers load once, retain `device`, and exit when `cancel` fires.
/// A new TUN publishes a fresh generation; an old reader can never observe a
/// new device because it holds the old `Arc` + old token only.
pub struct PublishedDataPlane {
    /// Monotonic generation: readers pin the generation loaded at start and
    /// never observe a newer device.
    pub generation: u64,
    pub device: Arc<AsyncDevice>,
    pub cancel: tokio_util::sync::CancellationToken,
}

pub type PublishedPlane = Arc<ArcSwapOption<PublishedDataPlane>>;

pub fn new_published_plane() -> PublishedPlane {
    Arc::new(ArcSwapOption::empty())
}

// ---------------------------------------------------------------------------
// Config / errors
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DataPlaneActorConfig {
    pub ifname: String,
    pub assigned_ipv4: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    pub dns_cfg: DnsConfig,
    pub dns: Option<Arc<DnsController>>,
    pub is_direct: bool,
    pub network_id: Uuid,
    pub underlay_hosts: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DataPlaneError {
    #[error("TUN build failed: {0}")]
    Tun(String),
    #[error("route reconcile failed: {0}")]
    Routes(String),
}

#[derive(Clone)]
pub struct DataPlaneActorArgs {
    pub config: DataPlaneActorConfig,
    pub node: CoreNode,
    pub metrics: AgentMetrics,
    pub peer_dns_active: Arc<AtomicBool>,
    pub events: tokio::sync::broadcast::Sender<LocalEvent>,
    pub route_actor: ActorRef<RouteActor>,
    pub published: PublishedPlane,
    pub status: DataPlaneStatusSnapshot,
    /// Ingress reader registry: aborted on BringDown alongside generation
    /// cancellation (defense in depth; readers also observe the token).
    pub ingress: crate::ingress::IngressRegistry,
    /// Start in up state (initial plane already published by bootstrap).
    pub initially_up: bool,
    pub initial_generation: u64,
    /// Reconstruct the up state after a supervised restart: `on_start` issues
    /// an internal BringUp rebuilt from durable state (snapshot cache), so a
    /// restarted incarnation never inherits leaked state yet recovers service.
    /// BringUp failure is logged, never a crash (no restart storm).
    pub auto_up: bool,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

pub struct DataPlaneActor {
    cfg: DataPlaneActorConfig,
    node: CoreNode,
    metrics: AgentMetrics,
    peer_dns_active: Arc<AtomicBool>,
    events: tokio::sync::broadcast::Sender<LocalEvent>,
    route_actor: ActorRef<RouteActor>,
    published: PublishedPlane,
    status: DataPlaneStatusSnapshot,
    ingress: crate::ingress::IngressRegistry,
    up: bool,
    generation: u64,
    outbound: Option<tokio::task::JoinHandle<()>>,
    generation_cancel: Option<tokio_util::sync::CancellationToken>,
}

impl Actor for DataPlaneActor {
    type Args = DataPlaneActorArgs;
    type Error = Infallible;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let auto_up = args.auto_up;
        let this = Self {
            up: args.initially_up,
            generation: args.initial_generation,
            cfg: args.config,
            node: args.node,
            metrics: args.metrics,
            peer_dns_active: args.peer_dns_active,
            events: args.events,
            route_actor: args.route_actor,
            published: args.published,
            status: args.status,
            ingress: args.ingress,
            outbound: None,
            generation_cancel: None,
        };
        if auto_up {
            // Reconstruct service after (re)start from durable state.
            // Prioritized by Kameo ahead of external messages.
            let _ = actor_ref.tell(BringUpSelf).send().await;
        }
        Ok(this)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Best-effort deterministic teardown; never hang shutdown. Runs after
        // failure too, so a restarted incarnation never inherits leaked
        // external state (all teardown steps are idempotent).
        let _ = self.teardown().await;
        Ok(())
    }
}

impl DataPlaneActor {
    async fn teardown(&mut self) {
        // Withdraw published generation first so new readers stop.
        self.published.store(None);
        if let Some(cancel) = self.generation_cancel.take() {
            cancel.cancel();
        }
        if let Some(outbound) = self.outbound.take() {
            outbound.abort();
        }
        // Close tunnel connections so old ingress readers exit.
        self.node.tunnel_pool.close_all().await;
        // Best-effort route/DNS cleanup; never fail shutdown.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.route_actor.ask(ClearRoutes),
        )
        .await;
        crate::forward::teardown_exit_nat();
        if let Some(dns) = self.cfg.dns.clone() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let _ = tokio::task::spawn_blocking(move || dns.restore()).await;
            })
            .await;
        }
        self.peer_dns_active.store(false, Ordering::SeqCst);
        self.up = false;
        self.status.set_up(false);
        self.status.set_outbound_alive(false);
        // NOTE: `restarting` is deliberately left alone here: teardown runs
        // on every stop including crashes, and a crash must keep reporting
        // `restarting` until the next successful bring-up clears it.
        // `do_bring_down` clears it for intentional shutdowns.
    }

    async fn do_bring_up(
        &mut self,
        self_ref: kameo::actor::WeakActorRef<Self>,
    ) -> Result<(), DataPlaneError> {
        if self.up {
            return Ok(());
        }
        let tun = Arc::new(
            crate::tun_io::build_tun(
                &self.cfg.ifname,
                self.cfg.assigned_ipv4,
                self.cfg.prefix,
                self.cfg.mtu,
            )
            .map_err(|e| DataPlaneError::Tun(format!("{e:#}")))?,
        );
        crate::system_firewall::configure(&self.cfg.ifname);
        let _ =
            crate::magic_dns::ensure_magic_dns_addr(&self.cfg.ifname, self.cfg.dns_cfg.magic_ip);

        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let cancel = tokio_util::sync::CancellationToken::new();
        self.published.store(Some(Arc::new(PublishedDataPlane {
            generation,
            device: tun.clone(),
            cancel: cancel.clone(),
        })));
        self.generation_cancel = Some(cancel);

        // OS DNS work stays off the actor executor thread.
        let dns_active = match self.cfg.dns.clone() {
            Some(dns) => {
                let ifname = self.cfg.ifname.clone();
                let magic_ip = self.cfg.dns_cfg.magic_ip;
                let suffix = self.cfg.dns_cfg.suffix.clone();
                let worker = dns.clone();
                match tokio::task::spawn_blocking(move || worker.apply(&ifname, magic_ip, &suffix))
                    .await
                {
                    Ok(Ok(())) => dns.is_active(),
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "PeerDNS OS configuration failed");
                        false
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "PeerDNS configuration task failed");
                        false
                    }
                }
            }
            None => false,
        };
        self.peer_dns_active.store(dns_active, Ordering::SeqCst);

        // Reconcile routes via RouteActor (one-way ask, bounded timeout).
        if !self.cfg.is_direct {
            let (remote_subnets, profile, has_exit) =
                route_snapshot(&self.node, self.cfg.is_direct, self.cfg.network_id);
            let desired = desired_from_membership(
                &self.cfg.ifname,
                &profile,
                self.cfg.assigned_ipv4,
                self.cfg.prefix,
                &remote_subnets,
                has_exit,
                &self.cfg.underlay_hosts,
            );
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                self.route_actor.ask(ApplyDesiredRoutes {
                    desired,
                    // Local lifecycle intent: always applies, never versioned.
                    version: crate::actors::ControlVersion::Local,
                }),
            )
            .await
            .map_err(|_| DataPlaneError::Routes("route apply timed out".into()));
            // Kameo flattens `Result` replies: `ask` yields
            // `Result<(), SendError<RouteError>>` here.
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "route reconcile on dataplane up failed");
                }
                Err(e) => return Err(e),
            }
        }
        crate::forward::ensure_exit_nat(self.node.routes.is_exit_node());

        // The outbound loop's unexpected end is abnormal: report it so
        // supervision restarts us. Shutdown ends it via abort (the
        // generation token is already cancelled then, so no report fires).
        let exit_gen = self
            .generation_cancel
            .clone()
            .expect("generation token published above");
        // Shared tunnel packet resources for this generation: pooled buffers and
        // the runtime sweeper (tied to the generation token — no leaked tasks
        // across bring-up cycles).
        let packet_pool = tunnet_common::packet::PacketPool::new(128);
        self.node.policy.spawn_sweeper(exit_gen.clone());
        let exit_weak = self_ref.clone();
        let outbound = crate::dataplane::spawn_outbound(crate::dataplane::OutboundSpawn {
            tun,
            routes: self.node.routes.clone(),
            pool: self.node.tunnel_pool.clone(),
            runtime: self.node.policy.clone(),
            metrics: self.metrics.clone(),
            bufs: packet_pool,
            meter: self.node.tunnel_pool.cloud_relay_meter(),
            mtu: self.cfg.mtu,
            on_unexpected_end: Box::new(move || {
                if !exit_gen.is_cancelled()
                    && let Some(actor) = exit_weak.upgrade()
                {
                    let _ = actor.tell(OutboundExited).try_send();
                }
            }),
        });
        self.outbound = Some(outbound);
        self.up = true;
        self.status.set_up(true);
        self.status.set_restarting(false);
        self.status.set_outbound_alive(true);
        self.status.set_generation(generation);
        // Eager preconnect (keep-alive): dial every known peer NOW so the
        // first real packet doesn't pay connection setup (the classic
        // first-ping-timeout). Best-effort and bounded: skipped peers are
        // still dialed on demand by the pump. Skipped entirely without
        // keep-alive.
        if self.node.tunnel_pool.keep_alive() {
            let pool = self.node.tunnel_pool.clone();
            let routes = self.node.routes.clone();
            let local = pool.endpoint().id();
            tokio::spawn(async move {
                let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
                let mut set = tokio::task::JoinSet::new();
                for peer in routes.peers() {
                    if peer.endpoint == local {
                        continue;
                    }
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        continue;
                    };
                    let pool = pool.clone();
                    let ep = peer.endpoint;
                    set.spawn(async move {
                        let _permit = permit;
                        let _ = pool.get(ep).await;
                    });
                }
                while set.join_next().await.is_some() {}
            });
        }
        let _ = self.events.send(LocalEvent::DataPlaneChanged { up: true });
        tracing::info!("data plane up");
        Ok(())
    }

    async fn do_bring_down(&mut self) -> Result<(), DataPlaneError> {
        if !self.up {
            return Ok(());
        }
        // Stop ingress readers first (registry abort), then withdraw the
        // generation (token cancellation) in teardown. Both are idempotent;
        // readers also self-remove from the registry on exit.
        self.ingress.abort_all();
        self.teardown().await;
        self.status.set_restarting(false);
        let _ = self.events.send(LocalEvent::DataPlaneChanged { up: false });
        tracing::info!("data plane down");
        Ok(())
    }
}

fn route_snapshot(
    node: &CoreNode,
    is_direct: bool,
    network_id: Uuid,
) -> (Vec<ipnet::Ipv4Net>, tunnet_common::DeviceProfile, bool) {
    if is_direct {
        return (vec![], tunnet_common::DeviceProfile::default(), false);
    }
    if let Some(snap) = tunnet_core::state::load_snapshot_cache(&node.paths)
        && let Some(m) = snap.memberships.iter().find(|m| m.network_id == network_id)
    {
        let remote_subnets: Vec<ipnet::Ipv4Net> = m
            .subnet_routes
            .iter()
            .filter(|r| r.via_endpoint_id != node.identity.endpoint_id_hex())
            .map(|r| r.cidr)
            .collect();
        let has_exit = m.device_profile.exit_node_endpoint_id.is_some();
        return (remote_subnets, m.device_profile.clone(), has_exit);
    }
    (vec![], tunnet_common::DeviceProfile::default(), false)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub struct BringUp;
pub struct BringDown;
pub struct GetStatus;
pub struct ShutdownPlane;

#[derive(Debug, Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct DataPlaneStatus {
    pub up: bool,
    pub generation: u64,
}

impl Message<BringUp> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(&mut self, _msg: BringUp, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let weak = ctx.actor_ref().downgrade();
        let res = self.do_bring_up(weak).await;
        if let Err(e) = &res {
            // Failed bring-up is Down, not restarting: record the cause.
            self.status.set_restarting(false);
            self.status.set_last_error(format!("bring-up failed: {e}"));
        }
        res
    }
}

/// Internal reconstruction after (re)start. Failure is logged, never a crash:
/// a broken TUN at boot must not spin the supervision restart budget.
struct BringUpSelf;

impl Message<BringUpSelf> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, _msg: BringUpSelf, ctx: &mut Context<Self, Self::Reply>) {
        let weak = ctx.actor_ref().downgrade();
        if let Err(e) = self.do_bring_up(weak).await {
            tracing::error!(error = %e, "automatic dataplane bring-up failed; awaiting explicit BringUp");
        }
    }
}

/// The owned outbound loop ended without generation cancellation. Abnormal:
/// supervision must restart us (fresh generation is published on BringUp).
struct OutboundExited;

impl Message<OutboundExited> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, _msg: OutboundExited, _ctx: &mut Context<Self, Self::Reply>) {
        // Publish degraded state BEFORE supervision restarts us, so status
        // readers see `restarting` (with the error and restart count)
        // instead of a stale healthy `up`.
        self.status
            .note_restart("outbound TUN loop unexpectedly terminated".into());
        self.status.set_outbound_alive(false);
        self.status.set_restarting(true);
        panic!("outbound TUN loop unexpectedly terminated");
    }
}

impl Message<BringDown> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(
        &mut self,
        _msg: BringDown,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Ingress readers stop via the generation token (they hold that exact
        // generation's cancellation) plus pool close; the registry self-cleans
        // finished readers.
        self.do_bring_down().await
    }
}

impl Message<GetStatus> for DataPlaneActor {
    type Reply = DataPlaneStatus;

    async fn handle(
        &mut self,
        _msg: GetStatus,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        DataPlaneStatus {
            up: self.up,
            generation: self.generation,
        }
    }
}

impl Message<ShutdownPlane> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, _msg: ShutdownPlane, ctx: &mut Context<Self, Self::Reply>) {
        let _ = self.do_bring_down().await;
        ctx.stop();
    }
}

/// Test-only failure injection: panics inside the handler so supervision
/// restarts the actor (proves panic isolation without killing the process).
#[cfg(test)]
pub struct FailNow;

#[cfg(test)]
impl Message<FailNow> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, _msg: FailNow, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("injected test failure");
    }
}

// ---------------------------------------------------------------------------
// Kameo-free Local API control (agent side)
// ---------------------------------------------------------------------------

/// `DataPlaneControl` implemented with a Kameo actor. Lives in the agent so
/// `tunnet-core` never depends on Kameo. Reads use the atomic snapshot.
#[derive(Clone)]
pub struct ActorDataPlaneControl {
    status: DataPlaneStatusSnapshot,
    actor: ActorRef<DataPlaneActor>,
}

impl ActorDataPlaneControl {
    pub fn new(status: DataPlaneStatusSnapshot, actor: ActorRef<DataPlaneActor>) -> Self {
        Self { status, actor }
    }
}

#[async_trait::async_trait]
impl DataPlaneControl for ActorDataPlaneControl {
    fn is_up(&self) -> bool {
        self.status.is_up()
    }

    fn data_plane_info(&self) -> tunnet_common::local_api::DataPlaneInfo {
        tunnet_common::local_api::DataPlaneInfo {
            state: self.status.state().to_string(),
            outbound_alive: self.status.outbound_alive(),
            restart_count: self.status.restart_count(),
            generation: self.status.generation(),
            last_error: self.status.last_error(),
        }
    }

    async fn bring_up(&self) -> Result<(), String> {
        // Kameo flattens `Result` replies into the `ask` error channel.
        tokio::time::timeout(std::time::Duration::from_secs(30), self.actor.ask(BringUp))
            .await
            .map_err(|_| "data plane bring-up timed out".to_string())?
            .map_err(|e| format!("data plane bring-up failed: {e}"))
    }

    async fn bring_down(&self) -> Result<(), String> {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.actor.ask(BringDown),
        )
        .await
        .map_err(|_| "data plane bring-down timed out".to_string())?
        .map_err(|e| format!("data plane bring-down failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::routes::{RouteActor, RouteActorArgs};
    use crate::actors::supervisor::GetDataPlaneChildren;
    use crate::actors::test_support::{test_metrics, test_node};
    use kameo::actor::Spawn;

    fn test_args(node: CoreNode) -> DataPlaneActorArgs {
        let (events_tx, _) = tokio::sync::broadcast::channel(4);
        // Route actor ref unused on the down-path; wire a real one lazily.
        let route = RouteActor::spawn_with_mailbox(
            RouteActorArgs,
            kameo::mailbox::bounded(crate::actors::ROUTE_MAILBOX),
        );
        DataPlaneActorArgs {
            config: DataPlaneActorConfig {
                ifname: "tunnet-test-down".into(),
                assigned_ipv4: "10.9.0.1".parse().unwrap(),
                prefix: 24,
                mtu: 1280,
                dns_cfg: tunnet_common::DnsConfig::default(),
                dns: None,
                is_direct: true,
                network_id: Uuid::nil(),
                underlay_hosts: vec![],
            },
            node,
            metrics: test_metrics(),
            peer_dns_active: Arc::new(AtomicBool::new(false)),
            events: events_tx,
            route_actor: route,
            published: new_published_plane(),
            status: DataPlaneStatusSnapshot::new(false),
            ingress: crate::ingress::IngressRegistry::new(),
            initially_up: false,
            initial_generation: 0,
            // Tests drive BringUp explicitly; no background reconstruction.
            auto_up: false,
        }
    }

    #[tokio::test]
    async fn bring_down_is_idempotent() {
        let (node, _tmp) = test_node().await;
        let actor = DataPlaneActor::spawn_with_mailbox(
            test_args(node),
            kameo::mailbox::bounded(crate::actors::DATAPLANE_MAILBOX),
        );
        actor.wait_for_startup().await;
        // Kameo flattens `Result` replies: `ask` yields a single `Result`.
        actor.ask(BringDown).await.expect("down");
        actor.ask(BringDown).await.expect("down");
        let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
        assert!(!status.up);
        assert_eq!(status.generation, 0);
        actor.stop_gracefully().await.expect("stop");
        actor.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_bring_down_calls_serialize() {
        let (node, _tmp) = test_node().await;
        let actor = DataPlaneActor::spawn_with_mailbox(
            test_args(node),
            kameo::mailbox::bounded(crate::actors::DATAPLANE_MAILBOX),
        );
        actor.wait_for_startup().await;
        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = actor.clone();
            handles.push(tokio::spawn(async move {
                a.ask(BringDown).await.expect("down");
            }));
        }
        for h in handles {
            tokio::time::timeout(std::time::Duration::from_secs(10), h)
                .await
                .expect("join")
                .expect("task");
        }
        let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
        assert!(!status.up);
        actor.stop_gracefully().await.expect("stop");
        actor.wait_for_shutdown().await;
    }

    #[tokio::test]
    async fn bring_up_failure_or_cycle_leaves_no_residue() {
        use crate::actors::routes::GetRouteStatus;
        use std::sync::atomic::Ordering;

        let (node, _tmp) = test_node().await;
        let mut args = test_args(node);
        args.config.ifname = "tunnet-test-ifname-that-cannot-exist-0123456789-abcdef".into();
        let published = args.published.clone();
        let status_snapshot = args.status.clone();
        let peer_dns = args.peer_dns_active.clone();
        let route = args.route_actor.clone();
        let actor = DataPlaneActor::spawn_with_mailbox(
            args,
            kameo::mailbox::bounded(crate::actors::DATAPLANE_MAILBOX),
        );
        actor.wait_for_startup().await;
        let res = tokio::time::timeout(std::time::Duration::from_secs(120), actor.ask(BringUp))
            .await
            .expect("BringUp must not hang");
        if res.is_err() {
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(!status.up);
            assert_eq!(status.generation, 0);
            assert!(published.load_full().is_none());
            assert!(!status_snapshot.is_up());
            assert!(!peer_dns.load(Ordering::SeqCst));
        } else {
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(status.up);
            assert_eq!(status.generation, 1);
            assert!(published.load_full().is_some());
            assert!(status_snapshot.is_up());
            actor.ask(BringDown).await.expect("down");
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(!status.up);
            assert!(published.load_full().is_none());
            assert!(!status_snapshot.is_up());
            assert!(!peer_dns.load(Ordering::SeqCst));
        }
        let routes: crate::actors::routes::RouteStatus =
            route.ask(GetRouteStatus).await.expect("routes");
        assert!(routes.owned.is_empty());
        actor.ask(BringDown).await.expect("down");
        actor.stop_gracefully().await.expect("stop");
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            actor.wait_for_shutdown(),
        )
        .await
        .expect("shutdown drain");
    }

    #[tokio::test]
    async fn supervised_restart_reconstructs_valid_state() {
        use crate::actors::supervisor::{DataPlaneSupervisor, DataPlaneSupervisorArgs};
        use kameo::supervision::{RestartPolicy, SupervisionStrategy};

        struct Parent;
        impl Actor for Parent {
            type Args = ();
            type Error = Infallible;
            async fn on_start(
                _args: Self::Args,
                _actor_ref: ActorRef<Self>,
            ) -> Result<Self, Self::Error> {
                Ok(Parent)
            }
            fn supervision_strategy() -> SupervisionStrategy {
                SupervisionStrategy::OneForOne
            }
        }

        let (node, _tmp) = test_node().await;
        let (events_tx, _) = tokio::sync::broadcast::channel(4);
        let dp_args = DataPlaneSupervisorArgs {
            route_args: RouteActorArgs,
            dataplane_config: DataPlaneActorConfig {
                ifname: "tunnet-test-down".into(),
                assigned_ipv4: "10.9.0.1".parse().unwrap(),
                prefix: 24,
                mtu: 1280,
                dns_cfg: tunnet_common::DnsConfig::default(),
                dns: None,
                is_direct: true,
                network_id: Uuid::nil(),
                underlay_hosts: vec![],
            },
            node,
            metrics: test_metrics(),
            peer_dns_active: Arc::new(AtomicBool::new(false)),
            events: events_tx,
            published: new_published_plane(),
            status: DataPlaneStatusSnapshot::new(false),
            ingress: crate::ingress::IngressRegistry::new(),
            initially_up: false,
            initial_generation: 0,
            // Tests drive BringUp explicitly; no background reconstruction.
            auto_up: false,
        };
        let parent = Parent::spawn(());
        parent.wait_for_startup().await;
        // NOTE: Transient, not Permanent. Permanent restarts on Normal exits
        // too (kameo links.rs should_restart), so stop_gracefully() below
        // would restart instead of stopping and wait_for_shutdown() would
        // hang forever. Production uses Transient for the same reason.
        let sup = DataPlaneSupervisor::supervise(&parent, dp_args)
            .restart_policy(RestartPolicy::Transient)
            .spawn()
            .await;
        sup.wait_for_startup().await;
        let children: crate::actors::supervisor::DataPlaneChildren =
            sup.ask(GetDataPlaneChildren).await.expect("children");
        let dp = children.dataplane_actor.expect("dataplane");
        // Injected panic: supervisor must restart the child in place and the
        // fresh incarnation must answer with valid (down) state. The test
        // process itself must survive (panic isolation).
        let _ = dp.tell(FailNow).send().await;
        let restarted = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Ok(status) = dp.ask(GetStatus).await
                    && !status.up
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await;
        restarted.expect("dataplane did not restart after injected panic");
        // Bounded shutdown waits: a hang here must fail the test, never
        // block CI forever.
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(std::time::Duration::from_secs(15), sup.wait_for_shutdown())
            .await
            .expect("supervisor shutdown drain");
        let _ = parent.stop_gracefully().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            parent.wait_for_shutdown(),
        )
        .await
        .expect("parent shutdown drain");
    }
}
