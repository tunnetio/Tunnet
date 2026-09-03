//! Desired-state OS route reconciliation via native routing APIs

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use ipnet::Ipv4Net;
// Android has no `route_manager` backend, and needs none: routes there are
// declared on `VpnService.Builder` before the tunnel is established, so the
// framework owns the table. Only the kernel-facing backend below is
// platform-specific; the desired-state logic in this file is shared.
#[cfg(not(target_os = "android"))]
use route_manager::{AsyncRouteManager, Route};
use thiserror::Error;
use tunnet_common::{DeviceProfile, SplitTunnelMode};

use crate::underlay::UnderlayInfo;

fn rfc1918_nets() -> [Ipv4Net; 3] {
    [
        "10.0.0.0/8".parse().expect("rfc1918"),
        "172.16.0.0/12".parse().expect("rfc1918"),
        "192.168.0.0/16".parse().expect("rfc1918"),
    ]
}

fn mesh_cidr(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Net> {
    Ipv4Net::new(ip, prefix).ok().map(|n| n.trunc())
}

fn dest_is_mesh_local(mesh: Option<Ipv4Net>, dest: Ipv4Net) -> bool {
    let Some(mesh) = mesh else {
        return false;
    };
    dest == mesh || mesh.contains(&dest.network()) || dest.contains(&mesh.network())
}

/// Logical desired route: TUN on-link vs underlay next-hop.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RouteKind {
    ViaTun(Ipv4Net),
    ViaGw { cidr: Ipv4Net, gw: Ipv4Addr },
}

/// Identity used to match kernel routes Tunnet owns or intends to install.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec {
    pub dest: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub if_index: u32,
    pub if_name: String,
}

impl RouteSpec {
    fn identity(&self) -> (Ipv4Net, Option<Ipv4Addr>, u32) {
        (self.dest, self.gateway, self.if_index)
    }

    fn add_rank(&self) -> u8 {
        match (self.gateway, self.dest.prefix_len()) {
            (Some(_), 32) => 0,
            (Some(_), _) => 1,
            (None, 0) => 3,
            (None, _) => 2,
        }
    }

    fn del_rank(&self) -> u8 {
        3 - self.add_rank()
    }

    fn is_default_tun(&self) -> bool {
        self.gateway.is_none() && self.dest.prefix_len() == 0
    }

    fn is_host_escape(&self) -> bool {
        self.gateway.is_some() && self.dest.prefix_len() == 32
    }
}

impl std::fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.gateway {
            Some(gw) => write!(
                f,
                "{}/{} via {} ifindex={} ({})",
                self.dest.network(),
                self.dest.prefix_len(),
                gw,
                self.if_index,
                self.if_name
            ),
            None => write!(
                f,
                "{}/{} dev {} ifindex={}",
                self.dest.network(),
                self.dest.prefix_len(),
                self.if_name,
                self.if_index
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Delete,
    List,
}

impl RouteOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "delete",
            Self::List => "list",
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum RouteError {
    #[error("route already exists")]
    AlreadyExists,
    #[error("route not found")]
    NotFound,
    #[error("permission denied for route {op}: {route}")]
    PermissionDenied { op: &'static str, route: String },
    #[error("invalid interface for route {route}")]
    InvalidInterface { route: String },
    #[error("invalid gateway for route {route}")]
    InvalidGateway { route: String },
    #[error("{op} {route}: {detail}")]
    Native {
        op: &'static str,
        route: String,
        detail: String,
    },
    #[error("failed to list kernel routes: {0}")]
    List(String),
    #[error("{} route operation(s) failed", .0.len())]
    Multiple(Vec<RouteError>),
}

impl RouteError {
    fn is_idempotent_add(&self) -> bool {
        matches!(self, Self::AlreadyExists)
    }

    fn is_idempotent_delete(&self) -> bool {
        matches!(self, Self::NotFound)
    }

    fn from_io(op: RouteOp, spec: Option<&RouteSpec>, err: io::Error) -> Self {
        let route = spec.map(ToString::to_string).unwrap_or_default();
        match err.kind() {
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied {
                op: op.as_str(),
                route,
            },
            _ => {
                let msg = err.to_string();
                if msg.contains("gateway") {
                    Self::InvalidGateway { route }
                } else if msg.contains("if_index")
                    || msg.contains("if_name")
                    || msg.contains("prefix")
                {
                    Self::InvalidInterface { route }
                } else if op == RouteOp::List {
                    Self::List(msg)
                } else {
                    Self::Native {
                        op: op.as_str(),
                        route,
                        detail: msg,
                    }
                }
            }
        }
    }
}

#[async_trait]
pub(crate) trait RouteBackend: Send {
    async fn list(&mut self) -> Result<Vec<RouteSpec>, RouteError>;
    async fn add(&mut self, route: &RouteSpec) -> Result<(), RouteError>;
    async fn delete(&mut self, route: &RouteSpec) -> Result<(), RouteError>;
}

#[cfg(not(target_os = "android"))]
struct NativeBackend {
    manager: AsyncRouteManager,
}

#[cfg(not(target_os = "android"))]
impl NativeBackend {
    fn new() -> io::Result<Self> {
        Ok(Self {
            manager: AsyncRouteManager::new()?,
        })
    }
}

/// Android backend: the framework installed the routes, so reconciliation has
/// nothing to do and must not claim otherwise.
///
/// Reporting an empty table is truthful from this process's point of view: it
/// owns no routes, so it has none to add or remove. The engine then computes an
/// empty diff rather than repeatedly trying to install routes it cannot.
#[cfg(target_os = "android")]
struct FrameworkOwnedBackend;

#[cfg(target_os = "android")]
#[async_trait]
impl RouteBackend for FrameworkOwnedBackend {
    async fn list(&mut self) -> Result<Vec<RouteSpec>, RouteError> {
        Ok(Vec::new())
    }

    async fn add(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
        tracing::debug!(
            ?route,
            "route add skipped; VpnService.Builder owns the table"
        );
        Ok(())
    }

    async fn delete(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
        tracing::debug!(
            ?route,
            "route delete skipped; VpnService.Builder owns the table"
        );
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
fn spec_to_route(spec: &RouteSpec) -> Route {
    let mut route = Route::new(IpAddr::V4(spec.dest.network()), spec.dest.prefix_len())
        .with_if_index(spec.if_index);
    if !spec.if_name.is_empty() {
        route = route.with_if_name(spec.if_name.clone());
    }
    if let Some(gw) = spec.gateway {
        route = route.with_gateway(IpAddr::V4(gw));
    }
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if spec.gateway.is_none() {
        // Prefer TUN over a competing underlay default of equal prefix length.
        route = route.with_metric(1);
    }
    route
}

#[cfg(not(target_os = "android"))]
fn spec_from_route(route: &Route) -> Option<RouteSpec> {
    let IpAddr::V4(dest) = route.destination() else {
        return None;
    };
    let dest = Ipv4Net::new(dest, route.prefix()).ok()?;
    let gateway = match route.gateway() {
        Some(IpAddr::V4(ip)) => Some(ip),
        None => None,
        Some(_) => return None,
    };
    let if_index = route.if_index()?;
    Some(RouteSpec {
        dest,
        gateway,
        if_index,
        if_name: route.if_name().cloned().unwrap_or_default(),
    })
}

#[cfg(not(target_os = "android"))]
#[async_trait]
impl RouteBackend for NativeBackend {
    async fn list(&mut self) -> Result<Vec<RouteSpec>, RouteError> {
        let routes = self
            .manager
            .list()
            .await
            .map_err(|e| RouteError::from_io(RouteOp::List, None, e))?;
        Ok(routes.iter().filter_map(spec_from_route).collect())
    }

    async fn add(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
        let native = spec_to_route(route);
        self.manager
            .add(&native)
            .await
            .map_err(|e| RouteError::from_io(RouteOp::Add, Some(route), e))
    }

    async fn delete(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
        let native = spec_to_route(route);
        self.manager
            .delete(&native)
            .await
            .map_err(|e| RouteError::from_io(RouteOp::Delete, Some(route), e))
    }
}

/// Desired OS routing state for the agent dataplane.
#[derive(Debug, Clone)]
pub struct DesiredRoutes {
    pub ifname: String,
    pub tun_if_index: Option<u32>,
    pub profile: DeviceProfile,
    /// Interface prefix (e.g. 10.7.0.0/24). Must stay on TUN; the OS often
    /// installs this as a connected route that is not in `remote_subnets`.
    pub mesh_cidr: Option<Ipv4Net>,
    pub remote_subnets: Vec<Ipv4Net>,
    pub has_exit: bool,
    pub underlay_hosts: Vec<Ipv4Addr>,
    /// When set, tests and callers skip live underlay discovery.
    pub underlay: Option<UnderlayInfo>,
}

impl DesiredRoutes {
    fn exit_exclude(&self) -> bool {
        (self.has_exit || self.profile.exit_node_endpoint_id.is_some())
            && self.profile.split_tunnel_mode == SplitTunnelMode::Exclude
    }

    fn kinds(&self, gateway: Option<Ipv4Addr>, allow_default: bool) -> BTreeSet<RouteKind> {
        let mut set = BTreeSet::new();
        if let Some(mesh) = self.mesh_cidr {
            set.insert(RouteKind::ViaTun(mesh));
        }
        for cidr in &self.remote_subnets {
            set.insert(RouteKind::ViaTun(*cidr));
        }

        match self.profile.split_tunnel_mode {
            SplitTunnelMode::Include => {
                for cidr in &self.profile.split_tunnel_cidrs {
                    set.insert(RouteKind::ViaTun(*cidr));
                }
            }
            SplitTunnelMode::Exclude => {
                if self.has_exit || self.profile.exit_node_endpoint_id.is_some() {
                    if allow_default {
                        set.insert(RouteKind::ViaTun("0.0.0.0/0".parse().expect("default")));
                    }
                    if let Some(gw) = gateway {
                        for cidr in &self.profile.split_tunnel_cidrs {
                            set.insert(RouteKind::ViaGw { cidr: *cidr, gw });
                        }
                        if self.profile.allow_local_lan {
                            for c in rfc1918_nets() {
                                set.insert(RouteKind::ViaGw { cidr: c, gw });
                            }
                        }
                        for host in &self.underlay_hosts {
                            set.insert(RouteKind::ViaGw {
                                cidr: Ipv4Net::from(*host),
                                gw,
                            });
                        }
                    }
                }
            }
        }
        set
    }

    fn to_specs(
        &self,
        gateway: Option<Ipv4Addr>,
        underlay_if: Option<(u32, &str)>,
        tun_if: (u32, &str),
        allow_default: bool,
    ) -> BTreeSet<RouteSpec> {
        self.kinds(gateway, allow_default)
            .into_iter()
            .filter_map(|kind| match kind {
                RouteKind::ViaTun(cidr) => Some(RouteSpec {
                    dest: cidr,
                    gateway: None,
                    if_index: tun_if.0,
                    if_name: tun_if.1.to_string(),
                }),
                RouteKind::ViaGw { cidr, gw } => {
                    let (if_index, if_name) = underlay_if?;
                    Some(RouteSpec {
                        dest: cidr,
                        gateway: Some(gw),
                        if_index,
                        if_name: if_name.to_string(),
                    })
                }
            })
            .collect()
    }
}

/// Single-owner route state. Owned directly by `RouteActor`; no shared mutex.
pub(crate) struct RouteEngine {
    backend: Box<dyn RouteBackend>,
    pub(crate) owned: BTreeSet<RouteSpec>,
    last_desired: Option<DesiredRoutes>,
}

impl RouteEngine {
    pub(crate) fn new() -> anyhow::Result<Self> {
        #[cfg(not(target_os = "android"))]
        let backend: Box<dyn RouteBackend> =
            Box::new(NativeBackend::new().map_err(|e| anyhow::anyhow!("route manager: {e}"))?);
        #[cfg(target_os = "android")]
        let backend: Box<dyn RouteBackend> = Box::new(FrameworkOwnedBackend);
        Ok(Self::with_backend(backend))
    }

    pub(crate) fn with_backend(backend: Box<dyn RouteBackend>) -> Self {
        Self {
            backend,
            owned: BTreeSet::new(),
            last_desired: None,
        }
    }

    pub(crate) fn owned_routes(&self) -> Vec<RouteSpec> {
        self.owned.iter().cloned().collect()
    }

    pub(crate) async fn reconcile_last(&mut self) -> Result<(), RouteError> {
        let Some(desired) = self.last_desired.clone() else {
            return Ok(());
        };
        self.reconcile(&desired).await
    }

    pub(crate) async fn reconcile(&mut self, desired: &DesiredRoutes) -> Result<(), RouteError> {
        self.last_desired = Some(desired.clone());

        let underlay = desired.underlay.clone().or_else(UnderlayInfo::discover);
        let gateway = underlay.as_ref().and_then(UnderlayInfo::gateway_v4);
        let underlay_if = underlay
            .as_ref()
            .map(|u| (u.interface_index, u.interface_name.as_str()));

        let tun_index = desired
            .tun_if_index
            .or_else(|| resolve_if_index(&desired.ifname));
        let Some(tun_index) = tun_index else {
            return Err(RouteError::InvalidInterface {
                route: desired.ifname.clone(),
            });
        };
        let tun_if = (tun_index, desired.ifname.as_str());

        let allow_default = if desired.exit_exclude() {
            if gateway.is_none() || underlay_if.is_none() {
                tracing::warn!(
                    "exit node enabled but underlay default gateway/interface unknown; refusing default via TUN"
                );
                false
            } else {
                true
            }
        } else {
            true
        };

        if allow_default
            && desired.exit_exclude()
            && gateway.is_some()
            && desired.underlay_hosts.is_empty()
        {
            tracing::warn!("exit enabled with empty underlay host list; control plane may loop");
        }

        let want = desired.to_specs(gateway, underlay_if, tun_if, allow_default);

        let kernel = self.backend.list().await?;
        let kernel_by_id: BTreeSet<_> = kernel.iter().map(RouteSpec::identity).collect();

        self.owned
            .retain(|owned| kernel.iter().any(|k| k.identity() == owned.identity()));
        for spec in &want {
            if kernel_by_id.contains(&spec.identity()) {
                self.owned.insert(spec.clone());
            }
        }

        let mut to_del: Vec<RouteSpec> = self
            .owned
            .iter()
            .filter(|owned| !want.iter().any(|w| w.identity() == owned.identity()))
            .cloned()
            .collect();

        for k in &kernel {
            let desired_dest = want.iter().any(|w| w.dest == k.dest);
            let tun_owned = k.if_index == tun_index && k.gateway.is_none();
            let matches_want = want.iter().any(|w| w.identity() == k.identity());
            if matches_want {
                continue;
            }
            if tun_owned && !want.iter().any(|w| w.dest == k.dest && w.gateway.is_none()) {
                if dest_is_mesh_local(desired.mesh_cidr, k.dest) {
                    continue;
                }
                if !to_del.iter().any(|d| d.identity() == k.identity()) {
                    to_del.push(k.clone());
                }
                continue;
            }
            if desired_dest && !to_del.iter().any(|d| d.identity() == k.identity()) {
                to_del.push(k.clone());
            }
        }

        to_del.sort_by_key(RouteSpec::del_rank);
        let mut errors = Vec::new();
        for spec in to_del {
            match self.backend.delete(&spec).await {
                Ok(()) => {
                    self.owned.retain(|o| o.identity() != spec.identity());
                    tracing::debug!(route = %spec, "removed OS route");
                }
                Err(e) if e.is_idempotent_delete() => {
                    self.owned.retain(|o| o.identity() != spec.identity());
                }
                Err(e) => {
                    let still_there = match self.backend.list().await {
                        Ok(list) => list.iter().any(|k| k.identity() == spec.identity()),
                        Err(_) => true,
                    };
                    if !still_there {
                        self.owned.retain(|o| o.identity() != spec.identity());
                    } else {
                        tracing::warn!(error = %e, route = %spec, "failed to delete OS route");
                        errors.push(e);
                    }
                }
            }
        }

        let kernel = self.backend.list().await?;
        let kernel_by_id: BTreeSet<_> = kernel.iter().map(RouteSpec::identity).collect();
        let mut to_add: Vec<_> = want
            .iter()
            .filter(|w| !kernel_by_id.contains(&w.identity()))
            .cloned()
            .collect();
        to_add.sort_by_key(RouteSpec::add_rank);

        let mut escape_failed = false;
        for spec in to_add {
            if spec.is_default_tun() && escape_failed {
                tracing::warn!(
                    route = %spec,
                    "skipping TUN default route because an underlay escape route failed"
                );
                continue;
            }
            match self.backend.add(&spec).await {
                Ok(()) => {
                    self.owned.insert(spec.clone());
                    tracing::debug!(route = %spec, "installed OS route");
                }
                Err(e) if e.is_idempotent_add() => {
                    let kernel = self.backend.list().await.unwrap_or_default();
                    if kernel.iter().any(|k| k.identity() == spec.identity()) {
                        self.owned.insert(spec.clone());
                    } else {
                        tracing::warn!(error = %e, route = %spec, "add reported exists without matching kernel route");
                        errors.push(e);
                        if spec.is_host_escape() {
                            escape_failed = true;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, route = %spec, "failed to install OS route");
                    if spec.is_host_escape() {
                        escape_failed = true;
                    }
                    errors.push(e);
                }
            }
        }

        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(RouteError::Multiple(errors)),
        }
    }

    pub(crate) async fn clear(&mut self) -> Result<(), RouteError> {
        let mut routes: Vec<_> = self.owned.iter().cloned().collect();
        routes.sort_by_key(RouteSpec::del_rank);
        let mut errors = Vec::new();
        for spec in routes {
            match self.backend.delete(&spec).await {
                Ok(()) | Err(RouteError::NotFound) => {
                    self.owned.retain(|o| o.identity() != spec.identity());
                }
                Err(e) => {
                    let still_there = match self.backend.list().await {
                        Ok(list) => list.iter().any(|k| k.identity() == spec.identity()),
                        Err(_) => true,
                    };
                    if still_there {
                        errors.push(e);
                    } else {
                        self.owned.retain(|o| o.identity() != spec.identity());
                    }
                }
            }
        }
        self.last_desired = None;
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(RouteError::Multiple(errors)),
        }
    }
}

fn resolve_if_index(name: &str) -> Option<u32> {
    netdev::get_interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.index)
}

/// Build a [`DesiredRoutes`] from high-level membership inputs (pure, testable).
#[allow(clippy::too_many_arguments)]
pub fn desired_from_membership(
    ifname: &str,
    profile: &DeviceProfile,
    assigned_ipv4: Ipv4Addr,
    prefix: u8,
    remote_subnets: &[Ipv4Net],
    has_exit: bool,
    underlay_hosts: &[Ipv4Addr],
) -> DesiredRoutes {
    DesiredRoutes {
        ifname: ifname.to_string(),
        tun_if_index: resolve_if_index(ifname),
        profile: profile.clone(),
        mesh_cidr: mesh_cidr(assigned_ipv4, prefix),
        remote_subnets: remote_subnets.to_vec(),
        has_exit,
        underlay_hosts: underlay_hosts.to_vec(),
        underlay: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockState {
        kernel: BTreeSet<RouteSpec>,
        fail_add: BTreeSet<(Ipv4Net, Option<Ipv4Addr>, u32)>,
        fail_delete: BTreeSet<(Ipv4Net, Option<Ipv4Addr>, u32)>,
        add_calls: Vec<RouteSpec>,
        delete_calls: Vec<RouteSpec>,
    }

    struct MockBackend {
        state: Arc<Mutex<MockState>>,
    }

    #[async_trait]
    impl RouteBackend for MockBackend {
        async fn list(&mut self) -> Result<Vec<RouteSpec>, RouteError> {
            Ok(self.state.lock().unwrap().kernel.iter().cloned().collect())
        }

        async fn add(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
            let mut s = self.state.lock().unwrap();
            s.add_calls.push(route.clone());
            if s.fail_add.contains(&route.identity()) {
                return Err(RouteError::Native {
                    op: "add",
                    route: route.to_string(),
                    detail: "mock".into(),
                });
            }
            s.kernel.insert(route.clone());
            Ok(())
        }

        async fn delete(&mut self, route: &RouteSpec) -> Result<(), RouteError> {
            let mut s = self.state.lock().unwrap();
            s.delete_calls.push(route.clone());
            if s.fail_delete.contains(&route.identity()) {
                return Err(RouteError::Native {
                    op: "delete",
                    route: route.to_string(),
                    detail: "mock".into(),
                });
            }
            s.kernel.retain(|k| k.identity() != route.identity());
            Ok(())
        }
    }

    fn gw() -> Ipv4Addr {
        "192.168.1.1".parse().unwrap()
    }

    fn underlay() -> UnderlayInfo {
        UnderlayInfo {
            interface_index: 2,
            interface_name: "eth0".into(),
            gateway: Some(IpAddr::V4(gw())),
            ..Default::default()
        }
    }

    fn spec_tun(cidr: &str, idx: u32) -> RouteSpec {
        RouteSpec {
            dest: cidr.parse().unwrap(),
            gateway: None,
            if_index: idx,
            if_name: "tun0".into(),
        }
    }

    fn spec_gw(cidr: &str, gateway: Ipv4Addr, idx: u32) -> RouteSpec {
        RouteSpec {
            dest: cidr.parse().unwrap(),
            gateway: Some(gateway),
            if_index: idx,
            if_name: "eth0".into(),
        }
    }

    fn mesh_desired() -> DesiredRoutes {
        DesiredRoutes {
            ifname: "tun0".into(),
            tun_if_index: Some(9),
            profile: DeviceProfile::default(),
            mesh_cidr: Some("10.99.0.0/24".parse().unwrap()),
            remote_subnets: vec!["10.99.0.0/24".parse().unwrap()],
            has_exit: false,
            underlay_hosts: vec![],
            underlay: Some(underlay()),
        }
    }

    fn exit_desired() -> DesiredRoutes {
        let profile = DeviceProfile {
            exit_node_endpoint_id: Some("abc".into()),
            allow_local_lan: true,
            split_tunnel_mode: SplitTunnelMode::Exclude,
            ..Default::default()
        };
        DesiredRoutes {
            ifname: "tun0".into(),
            tun_if_index: Some(9),
            profile,
            mesh_cidr: None,
            remote_subnets: vec![],
            has_exit: true,
            underlay_hosts: vec!["1.2.3.4".parse().unwrap()],
            underlay: Some(underlay()),
        }
    }

    fn reconciler(mock: MockBackend) -> RouteEngine {
        RouteEngine::with_backend(Box::new(mock))
    }

    #[tokio::test]
    async fn successful_add_updates_tracked_state() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        assert!(
            r.owned
                .iter()
                .any(|s| s.dest == "10.99.0.0/24".parse().unwrap())
        );
        assert!(
            state
                .lock()
                .unwrap()
                .kernel
                .iter()
                .any(|s| s.dest == "10.99.0.0/24".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn failed_add_does_not_update_tracked_state() {
        let dest: Ipv4Net = "10.99.0.0/24".parse().unwrap();
        let state = Arc::new(Mutex::new(MockState {
            fail_add: [spec_tun("10.99.0.0/24", 9).identity()].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        assert!(r.reconcile(&mesh_desired()).await.is_err());
        assert!(!r.owned.iter().any(|s| s.dest == dest));
        assert!(state.lock().unwrap().kernel.is_empty());
    }

    #[tokio::test]
    async fn failed_add_is_retried_on_next_reconcile() {
        let dest: Ipv4Net = "10.99.0.0/24".parse().unwrap();
        let ident = spec_tun("10.99.0.0/24", 9).identity();
        let state = Arc::new(Mutex::new(MockState {
            fail_add: [ident].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        assert!(r.reconcile(&mesh_desired()).await.is_err());
        state.lock().unwrap().fail_add.clear();
        r.reconcile(&mesh_desired()).await.unwrap();
        assert_eq!(state.lock().unwrap().add_calls.len(), 2);
        assert!(r.owned.iter().any(|s| s.dest == dest));
    }

    #[tokio::test]
    async fn successful_delete_removes_tracked_state() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        r.clear().await.unwrap();
        assert!(r.owned.is_empty());
        assert!(state.lock().unwrap().kernel.is_empty());
    }

    #[tokio::test]
    async fn failed_delete_does_not_falsely_mark_absent() {
        let ident = spec_tun("10.99.0.0/24", 9).identity();
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        state.lock().unwrap().fail_delete.insert(ident);
        assert!(r.clear().await.is_err());
        assert!(r.owned.iter().any(|s| s.identity() == ident));
        assert!(!state.lock().unwrap().kernel.is_empty());
    }

    #[tokio::test]
    async fn external_kernel_removal_is_restored() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        state.lock().unwrap().kernel.clear();
        r.reconcile(&mesh_desired()).await.unwrap();
        assert_eq!(state.lock().unwrap().add_calls.len(), 2);
        assert!(!state.lock().unwrap().kernel.is_empty());
    }

    #[tokio::test]
    async fn stale_in_memory_state_is_corrected_from_kernel() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        state.lock().unwrap().kernel.clear();
        r.reconcile(&mesh_desired()).await.unwrap();
        let owned = r.owned.clone();
        let kernel = state.lock().unwrap().kernel.clone();
        assert_eq!(owned.len(), kernel.len());
    }

    #[tokio::test]
    async fn restart_with_existing_routes_does_not_duplicate() {
        let existing = spec_tun("10.99.0.0/24", 9);
        let state = Arc::new(Mutex::new(MockState {
            kernel: [existing].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        assert!(state.lock().unwrap().add_calls.is_empty());
        assert_eq!(r.owned.len(), 1);
    }

    #[tokio::test]
    async fn wrong_gateway_is_corrected() {
        let old = spec_gw("1.2.3.4/32", "10.0.0.1".parse().unwrap(), 2);
        let state = Arc::new(Mutex::new(MockState {
            kernel: [old.clone()].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.owned.insert(old);
        r.reconcile(&exit_desired()).await.unwrap();
        let kernel = state.lock().unwrap().kernel.clone();
        assert!(
            kernel
                .iter()
                .any(|s| s.gateway == Some(gw()) && s.dest.prefix_len() == 32)
        );
        assert!(
            !kernel
                .iter()
                .any(|s| s.gateway == Some("10.0.0.1".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn wrong_interface_is_corrected() {
        let wrong = spec_tun("10.99.0.0/24", 99);
        let state = Arc::new(Mutex::new(MockState {
            kernel: [wrong.clone()].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.owned.insert(wrong);
        r.reconcile(&mesh_desired()).await.unwrap();
        let kernel = state.lock().unwrap().kernel.clone();
        assert!(kernel.iter().all(|s| s.if_index == 9));
    }

    #[tokio::test]
    async fn gateway_change_replaces_escape_routes() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&exit_desired()).await.unwrap();
        let mut next = exit_desired();
        let mut u = underlay();
        u.gateway = Some(IpAddr::V4("192.168.2.1".parse().unwrap()));
        next.underlay = Some(u);
        r.reconcile(&next).await.unwrap();
        let kernel = state.lock().unwrap().kernel.clone();
        assert!(
            kernel
                .iter()
                .any(|s| s.gateway == Some("192.168.2.1".parse().unwrap()))
        );
        assert!(
            !kernel
                .iter()
                .any(|s| s.gateway == Some(gw()) && s.dest.prefix_len() == 32)
        );
    }

    #[tokio::test]
    async fn underlay_interface_change_is_handled() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&exit_desired()).await.unwrap();
        let mut next = exit_desired();
        let mut u = underlay();
        u.interface_index = 7;
        u.interface_name = "wlan0".into();
        next.underlay = Some(u);
        r.reconcile(&next).await.unwrap();
        let kernel = state.lock().unwrap().kernel.clone();
        assert!(
            kernel
                .iter()
                .filter(|s| s.gateway.is_some())
                .all(|s| s.if_index == 7)
        );
    }

    #[tokio::test]
    async fn default_tun_installed_after_escape_routes() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&exit_desired()).await.unwrap();
        let adds = state.lock().unwrap().add_calls.clone();
        let default_pos = adds
            .iter()
            .position(|s| s.is_default_tun())
            .expect("default");
        let escape_pos = adds
            .iter()
            .position(|s| s.is_host_escape())
            .expect("escape");
        assert!(escape_pos < default_pos);
    }

    #[tokio::test]
    async fn default_route_refused_without_underlay() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        let mut d = exit_desired();
        d.underlay = Some(UnderlayInfo {
            interface_index: 2,
            interface_name: "eth0".into(),
            gateway: None,
            ..Default::default()
        });
        r.reconcile(&d).await.unwrap();
        assert!(
            !state
                .lock()
                .unwrap()
                .kernel
                .iter()
                .any(|s| s.is_default_tun())
        );
    }

    #[tokio::test]
    async fn cleanup_does_not_remove_unrelated_routes() {
        let unrelated = spec_gw("8.8.8.8/32", gw(), 2);
        let state = Arc::new(Mutex::new(MockState {
            kernel: [unrelated.clone()].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&mesh_desired()).await.unwrap();
        assert!(state.lock().unwrap().kernel.contains(&unrelated));
        r.clear().await.unwrap();
        assert!(state.lock().unwrap().kernel.contains(&unrelated));
    }

    #[tokio::test]
    async fn empty_advertised_preserves_os_mesh_connected_route() {
        let mesh = spec_tun("10.7.0.0/24", 9);
        let host = spec_tun("10.7.0.2/32", 9);
        let state = Arc::new(Mutex::new(MockState {
            kernel: [mesh.clone(), host.clone()].into(),
            ..Default::default()
        }));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&DesiredRoutes {
            ifname: "tun0".into(),
            tun_if_index: Some(9),
            profile: DeviceProfile::default(),
            mesh_cidr: Some("10.7.0.0/24".parse().unwrap()),
            remote_subnets: vec![],
            has_exit: false,
            underlay_hosts: vec![],
            underlay: Some(underlay()),
        })
        .await
        .unwrap();
        let kernel = state.lock().unwrap().kernel.clone();
        assert!(kernel.contains(&mesh));
        assert!(kernel.contains(&host));
        assert!(state.lock().unwrap().delete_calls.is_empty());
    }

    #[tokio::test]
    async fn mesh_cidr_is_installed_when_kernel_has_no_connected_route() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut r = reconciler(MockBackend {
            state: state.clone(),
        });
        r.reconcile(&DesiredRoutes {
            ifname: "tun0".into(),
            tun_if_index: Some(9),
            profile: DeviceProfile::default(),
            mesh_cidr: Some("10.7.0.0/24".parse().unwrap()),
            remote_subnets: vec![],
            has_exit: false,
            underlay_hosts: vec![],
            underlay: Some(underlay()),
        })
        .await
        .unwrap();
        assert!(
            state
                .lock()
                .unwrap()
                .kernel
                .iter()
                .any(|s| s.dest == "10.7.0.0/24".parse().unwrap())
        );
    }

    #[test]
    fn desired_includes_rfc1918_when_allow_local_lan() {
        let d = exit_desired();
        let set = d.kinds(Some(gw()), true);
        assert!(set.contains(&RouteKind::ViaTun("0.0.0.0/0".parse().unwrap())));
        assert!(set.contains(&RouteKind::ViaGw {
            cidr: "10.0.0.0/8".parse().unwrap(),
            gw: gw(),
        }));
        assert!(set.contains(&RouteKind::ViaGw {
            cidr: Ipv4Net::from("1.2.3.4".parse::<Ipv4Addr>().unwrap()),
            gw: gw(),
        }));
    }
}
