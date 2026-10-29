//! `DataPlaneActor`: single owner of TUN/dataplane lifecycle.
//!
//! The actor is the only writer of [`PublishedDataPlane`]; packet hot paths
//! load an immutable generation once and never touch an async mutex.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwapOption;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use tunnet_common::DnsConfig;
use tunnet_common::local_api::LocalEvent;
use tunnet_core::CoreNode;
use tunnet_core::local_api::{DataPlaneControl, DataPlaneStatusSnapshot};
#[cfg(not(target_os = "android"))]
use uuid::Uuid;

use super::routes::RouteActor;
#[cfg(not(target_os = "android"))]
use super::routes::{ApplyDesiredRoutes, ClearRoutes, GetKernelRoutes};
use crate::metrics::AgentMetrics;
use crate::system_dns::DnsController;
#[cfg(not(target_os = "android"))]
use crate::system_routes::desired_from_membership;

/// Immutable generation published by `DataPlaneActor`.
///
/// Readers load once, retain `device`, and exit when `cancel` fires.
/// A new TUN publishes a fresh generation; an old reader can never observe a
/// new device because it holds the old `Arc` + old token only.
pub struct PublishedDataPlane {
    /// Monotonic generation: readers pin the generation loaded at start and
    /// never observe a newer device.
    pub generation: u64,
    pub writer: crate::tun_io::TunWriter,
    pub cancel: tokio_util::sync::CancellationToken,
}

pub struct PlanePublication {
    pub current: ArcSwapOption<PublishedDataPlane>,
    next_generation: AtomicU64,
}

pub type PublishedPlane = Arc<PlanePublication>;

pub fn new_published_plane() -> PublishedPlane {
    Arc::new(PlanePublication {
        current: ArcSwapOption::empty(),
        next_generation: AtomicU64::new(0),
    })
}

// ---------------------------------------------------------------------------
// Config / errors
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DataPlaneActorConfig {
    pub desired_up: Arc<AtomicBool>,
    pub ifname: String,
    pub local_addrs: Vec<Ipv4Addr>,
    /// Peer ranges of the joined networks. Android must declare the traffic it
    /// captures when the tunnel is established; desktop routes peers itself.
    pub peer_cidrs: Vec<ipnet::Ipv4Net>,
    pub mtu: u16,
    pub dns_cfg: DnsConfig,
    pub dns: Option<Arc<DnsController>>,
    pub is_direct: bool,
    #[cfg(not(target_os = "android"))]
    pub network_id: Uuid,
    #[cfg(not(target_os = "android"))]
    pub underlay_hosts: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DataPlaneError {
    #[error("TUN build failed: {0}")]
    Tun(String),
    #[cfg(not(target_os = "android"))]
    #[error("route reconcile failed: {0}")]
    Routes(String),
    #[error("PeerDNS failed: {0}")]
    Dns(String),
    #[error("Direct network conflict: {0}")]
    Conflict(String),
    #[error("OS dataplane configuration failed: {0}")]
    Platform(String),
    #[error("dataplane cleanup failed: {0}")]
    Cleanup(String),
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
    #[cfg_attr(target_os = "android", allow(dead_code))]
    route_actor: ActorRef<RouteActor>,
    published: PublishedPlane,
    status: DataPlaneStatusSnapshot,
    up: bool,
    generation: u64,
    outbound: Option<tokio::task::JoinHandle<()>>,
    writer_task: Option<tokio::task::JoinHandle<()>>,
    generation_cancel: Option<tokio_util::sync::CancellationToken>,
    dns_task: Option<tokio::task::JoinHandle<()>>,
    dns_pool: Option<crate::tun_io::DnsPool>,
    resolver: Option<Arc<tunnet_core::dns::Resolver>>,
    tun_if_index: Option<u32>,
    gateway: Option<crate::forward::GatewayGuard>,
    firewall_ifname: Option<String>,
    startup_retry: Option<(tokio::time::Instant, std::time::Duration)>,
}

impl Actor for DataPlaneActor {
    type Args = DataPlaneActorArgs;
    type Error = Infallible;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let auto_up = args.auto_up && args.config.desired_up.load(Ordering::Acquire);
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
            outbound: None,
            writer_task: None,
            generation_cancel: None,
            dns_task: None,
            dns_pool: None,
            resolver: None,
            tun_if_index: None,
            gateway: None,
            firewall_ifname: None,
            startup_retry: None,
        };
        if auto_up {
            // Reconstruct service after (re)start from durable state.
            // try_send avoids a bounded self-tell deadlock during on_start.
            let _ = actor_ref.tell(BringUpSelf).try_send();
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
        if let Err(error) = self.teardown().await {
            tracing::error!(%error, "dataplane shutdown cleanup failed");
        }
        Ok(())
    }
}

impl DataPlaneActor {
    async fn direct_conflicts(&self) -> Vec<tunnet_core::direct::NetworkConflict> {
        #[cfg(target_os = "android")]
        {
            crate::conflict::check_direct_conflicts_with_routes(&self.node, &self.metrics, &[], &[])
        }
        #[cfg(not(target_os = "android"))]
        {
            let (kernel, owned) = self
                .route_actor
                .ask(GetKernelRoutes)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "kernel route snapshot unavailable; checking interfaces only");
                    (Vec::new(), Vec::new())
                });
            crate::conflict::check_direct_conflicts_with_routes(
                &self.node,
                &self.metrics,
                &kernel,
                &owned,
            )
        }
    }

    #[cfg(not(target_os = "android"))]
    fn desired_routes(&self) -> crate::system_routes::DesiredRoutes {
        let snap = self.node.forwarding.load();
        let mut desired = if self.cfg.is_direct {
            let peer_ips: Vec<Ipv4Addr> = snap.bindings.values().map(|p| p.ip).collect();
            crate::system_routes::desired_direct(
                &self.cfg.ifname,
                &peer_ips,
                &self.cfg.underlay_hosts,
            )
        } else {
            let profile = snap
                .tables
                .profiles
                .get(&self.cfg.network_id)
                .cloned()
                .unwrap_or_default();
            let remote_subnets: Vec<_> = snap
                .tables
                .claims
                .iter()
                .filter(|claim| {
                    claim.network == self.cfg.network_id
                        && !claim.local
                        && claim.cidr.prefix_len() < 32
                })
                .map(|claim| claim.cidr)
                .collect();
            let has_exit = profile.exit_node_endpoint_id.is_some();
            let first = snap
                .local_ip(self.cfg.network_id)
                .unwrap_or(self.node.self_ipv4);
            desired_from_membership(
                &self.cfg.ifname,
                &profile,
                first,
                32,
                &remote_subnets,
                has_exit,
                &self.cfg.underlay_hosts,
            )
        };
        if let Some(index) = self.tun_if_index {
            desired.tun_if_index = Some(index);
        }
        desired
    }

    #[cfg(not(target_os = "android"))]
    async fn reconcile_routes(&self) -> Result<(), DataPlaneError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.route_actor.ask(ApplyDesiredRoutes {
                desired: self.desired_routes(),
                version: crate::actors::ControlVersion::Local,
            }),
        )
        .await
        .map_err(|_| DataPlaneError::Routes("route apply timed out".into()))?
        .map_err(|error| DataPlaneError::Routes(error.to_string()))
    }

    async fn teardown(&mut self) -> Result<(), DataPlaneError> {
        let mut failures = Vec::new();
        self.node.peers.deactivate().await;
        self.published.current.store(None);
        if let Some(cancel) = self.generation_cancel.take() {
            cancel.cancel();
        }
        if let Some(mut outbound) = self.outbound.take()
            && tokio::time::timeout(std::time::Duration::from_secs(3), &mut outbound)
                .await
                .is_err()
        {
            outbound.abort();
            let _ = outbound.await;
        }
        if let Some(dns_task) = self.dns_task.take() {
            dns_task.abort();
            let _ = dns_task.await;
        }
        if let Some(pool) = self.dns_pool.take() {
            pool.shutdown().await;
        }
        if let Some(mut writer) = self.writer_task.take()
            && tokio::time::timeout(std::time::Duration::from_secs(3), &mut writer)
                .await
                .is_err()
        {
            writer.abort();
            let _ = writer.await;
        }
        self.resolver = None;
        #[cfg(not(target_os = "android"))]
        {
            if let Err(error) = self.route_actor.ask(ClearRoutes).await {
                failures.push(format!("routes: {error}"));
            }
        }
        if let Some(gateway) = &mut self.gateway {
            match gateway.teardown() {
                Ok(()) => self.gateway = None,
                Err(error) => failures.push(format!("gateway: {error:#}")),
            }
        }
        if let Some(ifname) = &self.firewall_ifname {
            match crate::system_firewall::teardown(ifname) {
                Ok(()) => self.firewall_ifname = None,
                Err(error) => failures.push(format!("firewall: {error:#}")),
            }
        }
        if let Some(dns) = self.cfg.dns.clone() {
            match tokio::task::spawn_blocking(move || dns.restore()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("DNS: {error}")),
                Err(error) => failures.push(format!("DNS worker: {error}")),
            }
        }
        self.peer_dns_active.store(false, Ordering::SeqCst);
        self.tun_if_index = None;
        self.up = false;
        self.status.set_up(false);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DataPlaneError::Cleanup(failures.join("; ")))
        }
    }

    async fn do_bring_up(
        &mut self,
        self_ref: kameo::actor::WeakActorRef<Self>,
    ) -> Result<(), DataPlaneError> {
        if self.up {
            let snap = self.node.forwarding.load();
            let mut addresses: Vec<_> = snap.tables.local_ips.values().copied().collect();
            let mut installed = self.cfg.local_addrs.clone();
            addresses.sort();
            addresses.dedup();
            installed.sort();
            installed.dedup();
            if !addresses.is_empty() && addresses != installed {
                self.teardown().await?;
                self.cfg.local_addrs = addresses;
            } else {
                #[cfg(not(target_os = "android"))]
                if let Err(error) = self.reconcile_routes().await {
                    self.teardown().await?;
                    return Err(error);
                }
                let advertised = snap
                    .tables
                    .claims
                    .iter()
                    .any(|claim| claim.local && claim.cidr.prefix_len() < 32);
                if advertised && self.gateway.is_none() {
                    match crate::forward::prepare(&self.cfg.ifname, &self.cfg.peer_cidrs, true) {
                        Ok(gateway) => self.gateway = gateway,
                        Err(error) => {
                            self.teardown().await?;
                            return Err(DataPlaneError::Platform(format!("gateway: {error:#}")));
                        }
                    }
                } else if !advertised && let Some(gateway) = &mut self.gateway {
                    gateway
                        .teardown()
                        .map_err(|error| DataPlaneError::Cleanup(format!("gateway: {error:#}")))?;
                    self.gateway = None;
                }
                return Ok(());
            }
        }
        if self.gateway.is_some() || self.firewall_ifname.is_some() {
            self.teardown().await?;
        }
        let conflicts = self.direct_conflicts().await;
        if !conflicts.is_empty() {
            return Err(DataPlaneError::Conflict(format!(
                "{} conflict(s)",
                conflicts.len()
            )));
        }
        let external = self
            .node
            .external_dns
            .as_ref()
            .ok_or_else(|| {
                DataPlaneError::Dns("agent DNS requires captured native authority".into())
            })?
            .for_dns_config(&self.cfg.dns_cfg)
            .map_err(|error| DataPlaneError::Dns(format!("{error:#}")))?;
        let resolver = tunnet_core::dns::Resolver::with_external(
            self.node.routes.clone(),
            &self.cfg.dns_cfg,
            external,
        );
        self.resolver = Some(resolver.clone());
        if self.cfg.dns.is_some() {
            match tunnet_core::dns::listen_udp(tunnet_core::dns::bind_addr(), resolver).await {
                Ok(task) => self.dns_task = Some(task),
                Err(error) => {
                    self.teardown().await?;
                    return Err(DataPlaneError::Dns(format!("{error:#}")));
                }
            }
        }
        let result = self.do_bring_up_mutating(self_ref).await;
        if result.is_err() {
            self.teardown().await?;
        }
        result
    }

    async fn do_bring_up_mutating(
        &mut self,
        self_ref: kameo::actor::WeakActorRef<Self>,
    ) -> Result<(), DataPlaneError> {
        let tun = Arc::new(
            crate::tun_io::build_tun_multi(
                &self.cfg.ifname,
                &self.cfg.local_addrs,
                &self.cfg.peer_cidrs,
                32,
                self.cfg.mtu,
            )
            .map_err(|e| DataPlaneError::Tun(format!("{e:#}")))?,
        );
        #[cfg(not(target_os = "android"))]
        {
            self.tun_if_index = tun.if_index().ok();
        }
        crate::system_firewall::configure(&self.cfg.ifname)
            .map_err(|error| DataPlaneError::Platform(format!("firewall: {error:#}")))?;
        self.firewall_ifname = Some(self.cfg.ifname.clone());

        let generation = self
            .published
            .next_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| DataPlaneError::Tun("generation space exhausted".into()))?
            + 1;
        let cancel = tokio_util::sync::CancellationToken::new();

        let dns_active = match self.cfg.dns.clone() {
            Some(dns) => {
                let ifname = self.cfg.ifname.clone();
                let endpoint = tunnet_common::LocalResolverEndpoint::default();
                let resolver_ip = endpoint.ip;
                let suffix = self.cfg.dns_cfg.suffix.clone();
                let worker = dns.clone();
                match tokio::task::spawn_blocking(move || {
                    worker.apply(&ifname, resolver_ip, &suffix)
                })
                .await
                {
                    Ok(Ok(())) => dns.is_active(),
                    Ok(Err(e)) => {
                        return Err(DataPlaneError::Dns(format!("OS configuration: {e}")));
                    }
                    Err(e) => return Err(DataPlaneError::Dns(format!("configuration task: {e}"))),
                }
            }
            None => true,
        };
        self.peer_dns_active.store(dns_active, Ordering::SeqCst);

        #[cfg(not(target_os = "android"))]
        self.reconcile_routes().await?;
        let advertised = self
            .node
            .forwarding
            .load()
            .tables
            .claims
            .iter()
            .any(|claim| claim.local && claim.cidr.prefix_len() < 32);
        self.gateway = crate::forward::prepare(&self.cfg.ifname, &self.cfg.peer_cidrs, advertised)
            .map_err(|error| DataPlaneError::Platform(format!("gateway: {error:#}")))?;

        self.generation_cancel = Some(cancel.clone());
        self.node
            .forwarding
            .set_mtu(&self.node.routes, self.cfg.mtu);
        let writer_cancel = cancel.clone();
        let writer_weak = self_ref.clone();
        let (writer, writer_task) = crate::tun_io::TunWriter::spawn(
            tun.clone(),
            cancel.clone(),
            self.metrics.clone(),
            self.node.forwarding.clone(),
            Box::new(move || {
                if !writer_cancel.is_cancelled()
                    && let Some(actor) = writer_weak.upgrade()
                {
                    let _ = actor.tell(OutboundExited(generation)).try_send();
                }
            }),
        );
        self.writer_task = Some(writer_task);
        let dns_pool = match self.resolver.clone() {
            Some(resolver) => {
                let pool = crate::tun_io::DnsPool::new(
                    writer.clone(),
                    tunnet_core::dns::InTun::new(resolver),
                    cancel.clone(),
                );
                self.dns_pool = Some(pool.clone());
                pool
            }
            None => {
                return Err(DataPlaneError::Dns("resolver not prepared".into()));
            }
        };
        let plane = Arc::new(PublishedDataPlane {
            generation,
            writer: writer.clone(),
            cancel: cancel.clone(),
        });
        let recv_hook = {
            let inbound = crate::tun_io::SessionInbound {
                plane: plane.clone(),
                peers: self.node.peers.downgrade(),
                policy: self.node.policy.clone(),
                forwarding: self.node.forwarding.clone(),
                metrics: self.metrics.clone(),
            };
            std::sync::Arc::new(move |peer, conn, ctl| {
                let inbound = inbound.clone();
                tokio::spawn(async move {
                    crate::tun_io::serve_tunnel_connection(peer, conn, ctl, inbound).await;
                })
            }) as tunnet_core::peer::RecvHook
        };

        self.published.current.store(Some(plane));
        let feedback_writer = writer.clone();
        self.node
            .peers
            .activate(
                generation,
                cancel.clone(),
                recv_hook,
                Arc::new(move |packet| feedback_writer.try_send(packet)),
            )
            .map_err(|error| DataPlaneError::Tun(format!("activate peer sessions: {error:#}")))?;

        let exit_gen = cancel.clone();
        let exit_weak = self_ref.clone();
        let outbound = crate::dataplane::spawn_outbound(crate::dataplane::OutboundSpawn {
            tun: tun.clone(),
            writer,
            cancel: cancel.clone(),
            peers: self.node.peers.clone(),
            policy: self.node.policy.clone(),
            forwarding: self.node.forwarding.clone(),
            metrics: self.metrics.clone(),
            dns: dns_pool,
            on_unexpected_end: Box::new(move || {
                if !exit_gen.is_cancelled()
                    && let Some(actor) = exit_weak.upgrade()
                {
                    let _ = actor.tell(OutboundExited(generation)).try_send();
                }
            }),
        });
        self.outbound = Some(outbound);
        self.generation = generation;
        self.up = true;
        self.status.set_up(true);
        let _ = self.events.send(LocalEvent::DataPlaneChanged { up: true });
        tracing::info!("data plane up");
        Ok(())
    }

    async fn do_bring_down(&mut self) -> Result<(), DataPlaneError> {
        if !self.up
            && self.published.current.load().is_none()
            && self.dns_task.is_none()
            && self.dns_pool.is_none()
            && self.gateway.is_none()
            && self.firewall_ifname.is_none()
        {
            return Ok(());
        }
        self.teardown().await?;
        let _ = self.events.send(LocalEvent::DataPlaneChanged { up: false });
        tracing::info!("data plane down");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub struct BringUp;
pub struct BringDown;
pub struct WithdrawPlane;
pub struct GetStatus;
pub struct ShutdownPlane;
pub struct ReconcileState;

#[derive(Debug, Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct DataPlaneStatus {
    pub up: bool,
    pub generation: u64,
}

impl Message<BringUp> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(&mut self, _msg: BringUp, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.cfg.desired_up.store(true, Ordering::Release);
        let weak = ctx.actor_ref().downgrade();
        self.do_bring_up(weak).await
    }
}

/// Internal reconstruction after (re)start. Failure is logged, never a crash:
/// a broken TUN at boot must not spin the supervision restart budget.
struct BringUpSelf;

impl Message<BringUpSelf> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, _msg: BringUpSelf, ctx: &mut Context<Self, Self::Reply>) {
        if !self.cfg.desired_up.load(Ordering::Acquire) {
            return;
        }
        let weak = ctx.actor_ref().downgrade();
        if let Err(e) = self.do_bring_up(weak).await {
            tracing::error!(error = %e, "automatic dataplane bring-up failed; awaiting explicit BringUp");
        }
    }
}

/// The owned outbound loop ended without generation cancellation. Abnormal:
/// supervision must restart us (fresh generation is published on BringUp).
struct OutboundExited(u64);

impl Message<OutboundExited> for DataPlaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: OutboundExited, _ctx: &mut Context<Self, Self::Reply>) {
        if self.up && self.generation == msg.0 {
            panic!("TUN task unexpectedly terminated");
        }
    }
}

impl Message<BringDown> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(
        &mut self,
        _msg: BringDown,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.cfg.desired_up.store(false, Ordering::Release);
        self.do_bring_down().await
    }
}

impl Message<WithdrawPlane> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(
        &mut self,
        _msg: WithdrawPlane,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.do_bring_down().await
    }
}

impl Message<ReconcileState> for DataPlaneActor {
    type Reply = Result<(), DataPlaneError>;

    async fn handle(
        &mut self,
        _msg: ReconcileState,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self
            .dns_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
        {
            tracing::error!("PeerDNS exited; withdrawing dataplane and DNS lease");
            self.do_bring_down().await?;
        }
        if !self.cfg.desired_up.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.cfg.is_direct && self.node.forwarding.load().managed.is_none() {
            return self.do_bring_down().await;
        }
        let conflicts = self.direct_conflicts().await;
        if !conflicts.is_empty() {
            if self.up {
                self.do_bring_down().await?;
            }
            return Err(DataPlaneError::Conflict(format!(
                "{} conflict(s)",
                conflicts.len()
            )));
        }
        if self.up {
            self.do_bring_up(ctx.actor_ref().downgrade()).await
        } else {
            if self
                .startup_retry
                .is_some_and(|(at, _)| tokio::time::Instant::now() < at)
            {
                return Ok(());
            }
            let result = self.do_bring_up(ctx.actor_ref().downgrade()).await;
            self.startup_retry = if result.is_err() {
                let delay = self
                    .startup_retry
                    .map_or(std::time::Duration::from_secs(5), |(_, delay)| {
                        (delay * 2).min(std::time::Duration::from_secs(300))
                    });
                Some((tokio::time::Instant::now() + delay, delay))
            } else {
                None
            };
            result
        }
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
                desired_up: Arc::new(AtomicBool::new(false)),
                ifname: "tunnet-test-down".into(),
                local_addrs: vec!["10.9.0.1".parse().unwrap()],
                peer_cidrs: vec!["10.9.0.0/16".parse().unwrap()],
                mtu: 1280,
                dns_cfg: tunnet_common::DnsConfig::default(),
                dns: None,
                is_direct: true,
                #[cfg(not(target_os = "android"))]
                network_id: Uuid::nil(),
                #[cfg(not(target_os = "android"))]
                underlay_hosts: vec![],
            },
            node,
            metrics: test_metrics(),
            peer_dns_active: Arc::new(AtomicBool::new(false)),
            events: events_tx,
            route_actor: route,
            published: new_published_plane(),
            status: DataPlaneStatusSnapshot::new(false),
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
        actor
            .ask(ReconcileState)
            .await
            .expect("paused reconciliation");
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

    struct InstallExitedDns;

    impl Message<InstallExitedDns> for DataPlaneActor {
        type Reply = ();

        async fn handle(&mut self, _: InstallExitedDns, _: &mut Context<Self, Self::Reply>) {
            let task = tokio::spawn(async {});
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            self.dns_task = Some(task);
        }
    }

    #[tokio::test]
    async fn managed_dns_exit_withdraws_dataplane() {
        let (node, _tmp) = test_node().await;
        let mut args = test_args(node);
        args.config.is_direct = false;
        args.initially_up = true;
        let actor = DataPlaneActor::spawn_with_mailbox(
            args,
            kameo::mailbox::bounded(crate::actors::DATAPLANE_MAILBOX),
        );
        actor.wait_for_startup().await;
        actor.ask(InstallExitedDns).await.unwrap();
        actor.ask(ReconcileState).await.unwrap();
        assert!(!actor.ask(GetStatus).await.unwrap().up);
        actor.stop_gracefully().await.unwrap();
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
            assert!(actor.ask(ReconcileState).await.is_err());
            actor
                .ask(ReconcileState)
                .await
                .expect("startup retry deferred");
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(!status.up);
            assert_eq!(status.generation, 0);
            assert!(published.current.load_full().is_none());
            assert!(!status_snapshot.is_up());
            assert!(!peer_dns.load(Ordering::SeqCst));
        } else {
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(status.up);
            assert_eq!(status.generation, 1);
            assert!(published.current.load_full().is_some());
            assert!(status_snapshot.is_up());
            actor.ask(BringDown).await.expect("down");
            let status: DataPlaneStatus = actor.ask(GetStatus).await.expect("status");
            assert!(!status.up);
            assert!(published.current.load_full().is_none());
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
                desired_up: Arc::new(AtomicBool::new(false)),
                ifname: "tunnet-test-down".into(),
                local_addrs: vec!["10.9.0.1".parse().unwrap()],
                peer_cidrs: vec!["10.9.0.0/16".parse().unwrap()],
                mtu: 1280,
                dns_cfg: tunnet_common::DnsConfig::default(),
                dns: None,
                is_direct: true,
                #[cfg(not(target_os = "android"))]
                network_id: Uuid::nil(),
                #[cfg(not(target_os = "android"))]
                underlay_hosts: vec![],
            },
            node,
            metrics: test_metrics(),
            peer_dns_active: Arc::new(AtomicBool::new(false)),
            events: events_tx,
            published: new_published_plane(),
            status: DataPlaneStatusSnapshot::new(false),
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
