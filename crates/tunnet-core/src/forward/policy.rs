use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use iroh::EndpointId;
use parking_lot::Mutex;
use serde::Serialize;
use tunnet_common::PeerPosture;
use tunnet_common::packet::{
    CachedTransport, FragKey, Fragmentation, Packet, ResolvedL4, TcpFlags, frag_key,
    synthesize_reject,
};
use tunnet_common::policy::{
    Action, Direction, EvalReason, FlowContext, Protocol, RuleScope,
    evaluate_flow as evaluate_flow_policy,
};
use uuid::Uuid;

use super::PostureAuthorization;
use super::snapshot::{AuthorizationEpoch, ForwardingSnapshot, NetworkPolicy};
use crate::direct::firewall::{FirewallAction, FirewallRule, PeerFilter};

const DENY_LOG_CAP: usize = 64;
const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);
const FLOW_CAP: usize = 4096;
const FRAG_TTL: Duration = Duration::from_secs(2);
const FRAG_CAP: usize = 4096;
const SPOOF_WINDOW: Duration = Duration::from_secs(60);

const TCP_FIN: u8 = TcpFlags::FIN;
const TCP_SYN: u8 = TcpFlags::SYN;
const TCP_RST: u8 = TcpFlags::RST;
const TCP_ACK: u8 = TcpFlags::ACK;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        posture: Option<PostureAuthorization>,
    },
    Deny,
    Reject {
        reply: Bytes,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct DenyRecord {
    pub peer_endpoint: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub reason: String,
    pub rule_slug: Option<String>,
    pub scope: Option<String>,
    pub at_unix: i64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NetStats {
    pub allowed: u64,
    pub denied: u64,
    pub rejected: u64,
    pub flows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    network: Uuid,
    peer: EndpointId,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    transport: FlowTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowTransport {
    Tcp {
        source: u16,
        destination: u16,
    },
    Udp {
        source: u16,
        destination: u16,
    },
    Echo {
        identifier: u16,
        sequence: u16,
        request: bool,
    },
}

impl FlowKey {
    fn reverse(self) -> Self {
        Self {
            network: self.network,
            peer: self.peer,
            src: self.dst,
            dst: self.src,
            transport: match self.transport {
                FlowTransport::Tcp {
                    source,
                    destination,
                } => FlowTransport::Tcp {
                    source: destination,
                    destination: source,
                },
                FlowTransport::Udp {
                    source,
                    destination,
                } => FlowTransport::Udp {
                    source: destination,
                    destination: source,
                },
                FlowTransport::Echo {
                    identifier,
                    sequence,
                    request,
                } => FlowTransport::Echo {
                    identifier,
                    sequence,
                    request: !request,
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPhase {
    SynSent,
    Established,
    TimeWait,
}

#[derive(Debug, Clone, Copy)]
enum FlowPhase {
    Tcp(TcpPhase),
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
struct FlowEntry {
    phase: FlowPhase,
    last_seen: Instant,
    auth: AuthorizationEpoch,
    posture_ok: Arc<bool>,
    posture: Option<PostureAuthorization>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentIdentity {
    network: Uuid,
    peer: EndpointId,
    direction: Direction,
    fragment: FragKey,
}

#[derive(Debug, Clone)]
struct FragEntry {
    transport: CachedTransport,
    expires: Instant,
    auth: AuthorizationEpoch,
    posture_ok: Arc<bool>,
    posture: Option<PostureAuthorization>,
}

struct SpoofState {
    by_peer: HashMap<String, u64>,
    total: u64,
    window_start: Instant,
}

impl Default for SpoofState {
    fn default() -> Self {
        Self {
            by_peer: HashMap::new(),
            total: 0,
            window_start: Instant::now(),
        }
    }
}

pub struct PeerCtx<'a> {
    pub endpoint: EndpointId,
    pub hex: &'a str,
    pub hostname: &'a str,
    pub tags: &'a [String],
    pub network_name: &'a str,
}

#[derive(Debug, Clone)]
struct AuthCtx {
    epoch: AuthorizationEpoch,
    posture_ok: Arc<bool>,
}

impl AuthCtx {
    fn of(snap: &ForwardingSnapshot, net: Uuid) -> Self {
        Self {
            epoch: snap.auth_epoch(net),
            posture_ok: snap.posture_ok.load_full(),
        }
    }

    fn matches(&self, auth: AuthorizationEpoch, posture_ok: &Arc<bool>) -> bool {
        self.epoch == auth && Arc::ptr_eq(&self.posture_ok, posture_ok)
    }
}

#[derive(Default)]
struct Counters {
    allowed: AtomicU64,
    denied: AtomicU64,
    rejected: AtomicU64,
}

#[derive(Clone, Default)]
pub struct PolicyEngine {
    inner: Arc<PolicyInner>,
}

struct PolicyInner {
    flows: Mutex<HashMap<FlowKey, FlowEntry>>,
    frags: Mutex<HashMap<FragmentIdentity, FragEntry>>,
    spoof: DashMap<Uuid, SpoofState>,
    global: Counters,
    nets: DashMap<Uuid, Counters>,
    denies: Mutex<VecDeque<DenyRecord>>,
}

impl Default for PolicyInner {
    fn default() -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            frags: Mutex::new(HashMap::new()),
            spoof: DashMap::new(),
            global: Counters::default(),
            nets: DashMap::new(),
            denies: Mutex::new(VecDeque::with_capacity(DENY_LOG_CAP)),
        }
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate(
        &self,
        snap: &ForwardingSnapshot,
        net: Uuid,
        peer: &PeerCtx<'_>,
        direction: Direction,
        pkt: &Packet<'_>,
    ) -> Decision {
        let ctx = AuthCtx::of(snap, net);
        let Some(src) = pkt.ip.v4_src() else {
            self.count(net, false, false);
            return Decision::Deny;
        };
        let Some(dst) = pkt.ip.v4_dst() else {
            self.count(net, false, false);
            return Decision::Deny;
        };
        let Some(l4) = self.resolve(&ctx, snap, net, peer.endpoint, direction, pkt) else {
            self.count(net, false, false);
            return Decision::Deny;
        };
        let decision = match snap.policy_for(net) {
            None => {
                self.count(net, false, false);
                Decision::Deny
            }
            Some(NetworkPolicy::Managed { bundle }) => {
                self.managed(&ctx, snap, net, peer, direction, src, dst, l4, bundle)
            }
            Some(NetworkPolicy::Direct {
                enabled,
                local,
                suggested,
                ..
            }) => self.direct(
                &ctx, net, peer, direction, pkt, src, dst, l4, *enabled, local, suggested,
            ),
        };
        if let Decision::Allow { posture } = decision {
            self.remember_fragment(&ctx, net, peer.endpoint, direction, pkt, posture);
        } else if matches!(pkt.fragmentation, Fragmentation::First { .. })
            && let Some(key) = frag_key(pkt)
        {
            self.inner.frags.lock().remove(&FragmentIdentity {
                network: net,
                peer: peer.endpoint,
                direction,
                fragment: key,
            });
        }
        decision
    }

    pub fn evaluate_flow(&self, snap: &ForwardingSnapshot, flow: &FlowContext) -> Decision {
        let Some(NetworkPolicy::Managed { bundle }) = snap.managed.and_then(|n| snap.policy_for(n))
        else {
            return Decision::Deny;
        };
        self.evaluate_managed_flow(bundle, flow, Direction::Outbound)
    }

    pub fn evaluate_network_flow(
        &self,
        snap: &ForwardingSnapshot,
        network: Uuid,
        peer: &PeerCtx<'_>,
        direction: Direction,
        flow: &FlowContext,
    ) -> Decision {
        match snap.policy_for(network) {
            Some(NetworkPolicy::Managed { bundle }) => {
                self.evaluate_managed_flow(bundle, flow, direction)
            }
            Some(NetworkPolicy::Direct {
                enabled,
                local,
                suggested,
                ..
            }) => {
                if !enabled {
                    return Decision::Allow { posture: None };
                }
                let l4 = ResolvedL4 {
                    protocol: flow.protocol,
                    src_port: None,
                    dst_port: flow.dst_port,
                    tcp_flags: None,
                    icmp_type: None,
                    icmp_id: None,
                    icmp_seq: None,
                };
                match match_rules(local, direction, l4, peer, network)
                    .or_else(|| match_rules(suggested, direction, l4, peer, network))
                    .unwrap_or(FirewallAction::Allow)
                {
                    FirewallAction::Allow => Decision::Allow { posture: None },
                    FirewallAction::Deny | FirewallAction::Reject => Decision::Deny,
                }
            }
            None => Decision::Deny,
        }
    }

    fn evaluate_managed_flow(
        &self,
        bundle: &tunnet_common::policy::PolicyBundle,
        flow: &FlowContext,
        direction: Direction,
    ) -> Decision {
        let verdict = evaluate_flow_policy(bundle, flow);
        if verdict.action == Action::Deny {
            self.record_deny(
                &flow.src.endpoint_hex,
                flow.dst_port,
                flow.protocol,
                &verdict,
            );
            return Decision::Deny;
        }
        Decision::Allow {
            posture: verdict
                .posture_required
                .then_some(PostureAuthorization { source: direction }),
        }
    }

    pub fn record_spoof(&self, net: Uuid, peer_hex: &str) -> bool {
        let mut entry = self.inner.spoof.entry(net).or_default();
        let now = Instant::now();
        if now.duration_since(entry.window_start) > SPOOF_WINDOW {
            entry.by_peer.clear();
            entry.total = 0;
            entry.window_start = now;
        }
        *entry.by_peer.entry(peer_hex.to_string()).or_insert(0) += 1;
        entry.total += 1;
        entry.total == 1
    }

    pub fn drain_spoof(&self, net: Uuid) -> Vec<(String, u64)> {
        let Some(mut entry) = self.inner.spoof.get_mut(&net) else {
            return Vec::new();
        };
        let out: Vec<(String, u64)> = entry
            .by_peer
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(p, n)| (p.clone(), *n))
            .collect();
        entry.by_peer.clear();
        entry.total = 0;
        entry.window_start = Instant::now();
        out
    }

    pub fn net_stats(&self, net: Uuid) -> Option<NetStats> {
        let counters = self.inner.nets.get(&net)?;
        Some(NetStats {
            allowed: counters.allowed.load(Ordering::Relaxed),
            denied: counters.denied.load(Ordering::Relaxed),
            rejected: counters.rejected.load(Ordering::Relaxed),
            flows: self
                .inner
                .flows
                .lock()
                .iter()
                .filter(|(k, _)| k.network == net)
                .count(),
        })
    }

    pub fn recent_denies(&self) -> Vec<DenyRecord> {
        self.inner.denies.lock().iter().cloned().collect()
    }

    pub fn flush(&self) {
        self.inner.flows.lock().clear();
        self.inner.frags.lock().clear();
    }

    pub fn flush_network(&self, net: Uuid) {
        self.inner.nets.remove(&net);
        self.inner.spoof.remove(&net);
        self.inner.flows.lock().retain(|k, _| k.network != net);
        self.inner.frags.lock().retain(|key, _| key.network != net);
    }

    fn resolve(
        &self,
        ctx: &AuthCtx,
        snap: &ForwardingSnapshot,
        net: Uuid,
        peer: EndpointId,
        direction: Direction,
        pkt: &Packet<'_>,
    ) -> Option<ResolvedL4> {
        if pkt.transport.is_later_fragment() {
            let key = FragKey {
                src: pkt.ip.src(),
                dst: pkt.ip.dst(),
                protocol: pkt.ip.ip_protocol(),
                identification: pkt.fragmentation.identification()?,
            };
            let mut frags = self.inner.frags.lock();
            let entry = frags.get(&FragmentIdentity {
                network: net,
                peer,
                direction,
                fragment: key,
            })?;
            if !ctx.matches(entry.auth, &entry.posture_ok)
                || entry
                    .posture
                    .is_some_and(|posture| !posture.allows(snap, net, peer))
                || Instant::now() >= entry.expires
            {
                frags.remove(&FragmentIdentity {
                    network: net,
                    peer,
                    direction,
                    fragment: key,
                });
                return None;
            }
            return Some(entry.transport.to_resolved());
        }
        ResolvedL4::from_transport(pkt.transport)
    }

    #[allow(clippy::too_many_arguments)]
    fn remember_fragment(
        &self,
        ctx: &AuthCtx,
        net: Uuid,
        peer: EndpointId,
        direction: Direction,
        pkt: &Packet<'_>,
        posture: Option<PostureAuthorization>,
    ) {
        if matches!(pkt.fragmentation, Fragmentation::First { .. })
            && let (Some(key), Some(transport)) = (
                frag_key(pkt),
                CachedTransport::from_transport(pkt.transport),
            )
        {
            let mut frags = self.inner.frags.lock();
            frags.retain(|_, entry| entry.expires > Instant::now());
            if frags.len() >= FRAG_CAP
                && !frags.contains_key(&FragmentIdentity {
                    network: net,
                    peer,
                    direction,
                    fragment: key,
                })
                && let Some(oldest) = frags.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k)
            {
                frags.remove(&oldest);
            }
            frags.insert(
                FragmentIdentity {
                    network: net,
                    peer,
                    direction,
                    fragment: key,
                },
                FragEntry {
                    transport,
                    expires: Instant::now() + FRAG_TTL,
                    auth: ctx.epoch,
                    posture_ok: ctx.posture_ok.clone(),
                    posture,
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn managed(
        &self,
        ctx: &AuthCtx,
        snap: &ForwardingSnapshot,
        net: Uuid,
        peer: &PeerCtx<'_>,
        direction: Direction,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
        bundle: &tunnet_common::policy::PolicyBundle,
    ) -> Decision {
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
        if let Some(key) = flow_key(net, peer.endpoint, src, dst, l4)
            && let Some(posture) = self.flow_allows(ctx, Some(snap), direction, key, tcp_flags)
        {
            self.count(net, true, false);
            return Decision::Allow { posture };
        }
        let peer_posture = snap
            .binding(net, peer.endpoint)
            .map(|binding| binding.posture.clone())
            .unwrap_or(PeerPosture::Unknown);
        let self_posture = if *ctx.posture_ok {
            snap.source_posture(net, peer.endpoint, Direction::Outbound)
        } else {
            PeerPosture::Unknown
        };
        let mut peer_side = tunnet_common::policy::FlowEndpoint::member(
            peer.hex.to_owned(),
            peer.tags.to_vec(),
            peer.network_name.to_owned(),
            None,
            peer_posture.clone(),
        );
        let mut self_side = snap.self_endpoint();
        self_side.posture = self_posture.clone();
        let (src_side, dst_side) = match direction {
            Direction::Outbound => {
                self_side.ip = Some(src);
                peer_side.ip = Some(dst);
                (self_side, peer_side)
            }
            Direction::Inbound => {
                self_side.ip = Some(dst);
                peer_side.ip = Some(src);
                (peer_side, self_side)
            }
        };
        let flow = FlowContext {
            src: src_side,
            dst: dst_side,
            protocol: l4.protocol,
            dst_port: l4.dst_port,
        };
        let verdict = evaluate_flow_policy(bundle, &flow);
        if verdict.action == Action::Deny {
            self.record_deny(peer.hex, flow.dst_port, flow.protocol, &verdict);
            self.count(net, false, false);
            return Decision::Deny;
        }
        let posture = verdict
            .posture_required
            .then_some(PostureAuthorization { source: direction });
        if let Some(key) = flow_key(net, peer.endpoint, src, dst, l4) {
            self.open_flow(ctx, key, l4.protocol, tcp_flags, posture);
        }
        self.count(net, true, false);
        Decision::Allow { posture }
    }

    #[allow(clippy::too_many_arguments)]
    fn direct(
        &self,
        ctx: &AuthCtx,
        net: Uuid,
        peer: &PeerCtx<'_>,
        direction: Direction,
        pkt: &Packet<'_>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
        enabled: bool,
        local: &[FirewallRule],
        suggested: &[FirewallRule],
    ) -> Decision {
        if !enabled {
            self.count(net, true, false);
            return Decision::Allow { posture: None };
        }
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
        if let Some(key) = flow_key(net, peer.endpoint, src, dst, l4)
            && let Some(posture) = self.flow_allows(ctx, None, direction, key, tcp_flags)
        {
            self.count(net, true, false);
            return Decision::Allow { posture };
        }
        if let Some(action) = match_rules(local, direction, l4, peer, net) {
            return self.apply(
                ctx,
                net,
                peer.endpoint,
                action,
                direction,
                pkt,
                src,
                dst,
                l4,
            );
        }
        if let Some(action) = match_rules(suggested, direction, l4, peer, net) {
            return self.apply(
                ctx,
                net,
                peer.endpoint,
                action,
                direction,
                pkt,
                src,
                dst,
                l4,
            );
        }
        self.apply(
            ctx,
            net,
            peer.endpoint,
            FirewallAction::Allow,
            direction,
            pkt,
            src,
            dst,
            l4,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &self,
        ctx: &AuthCtx,
        net: Uuid,
        peer: EndpointId,
        action: FirewallAction,
        _direction: Direction,
        pkt: &Packet<'_>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
    ) -> Decision {
        match action {
            FirewallAction::Allow => {
                if let Some(key) = flow_key(net, peer, src, dst, l4) {
                    let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
                    self.open_flow(ctx, key, l4.protocol, tcp_flags, None);
                }
                self.count(net, true, false);
                Decision::Allow { posture: None }
            }
            FirewallAction::Deny => {
                self.count(net, false, false);
                Decision::Deny
            }
            FirewallAction::Reject => {
                self.count(net, false, true);
                Decision::Reject {
                    reply: synthesize_reject(pkt).unwrap_or_default(),
                }
            }
        }
    }

    fn flow_allows(
        &self,
        ctx: &AuthCtx,
        snap: Option<&ForwardingSnapshot>,
        direction: Direction,
        fwd: FlowKey,
        tcp_flags: u8,
    ) -> Option<Option<PostureAuthorization>> {
        let now = Instant::now();
        let rev = fwd.reverse();
        let mut flows = self.inner.flows.lock();
        let key = if flows.contains_key(&fwd) { fwd } else { rev };
        let entry = flows.get_mut(&key)?;
        if !ctx.matches(entry.auth, &entry.posture_ok)
            || entry.posture.is_some_and(|posture| {
                snap.is_none_or(|snap| !posture.allows(snap, fwd.network, fwd.peer))
            })
            || flow_expired(entry, now)
        {
            flows.remove(&key);
            return None;
        }
        let inbound = matches!(direction, Direction::Inbound);
        match entry.phase {
            FlowPhase::Tcp(phase) => match phase {
                TcpPhase::SynSent => {
                    if inbound || (tcp_flags & TCP_ACK) != 0 || (tcp_flags & TCP_RST) != 0 {
                        if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                            entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                        } else {
                            entry.phase = FlowPhase::Tcp(TcpPhase::Established);
                        }
                        entry.last_seen = now;
                        return Some(entry.posture);
                    }
                    if !inbound {
                        entry.last_seen = now;
                        return Some(entry.posture);
                    }
                    None
                }
                TcpPhase::Established => {
                    if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                        entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                    }
                    entry.last_seen = now;
                    Some(entry.posture)
                }
                TcpPhase::TimeWait => {
                    entry.last_seen = now;
                    Some(entry.posture)
                }
            },
            FlowPhase::Udp | FlowPhase::Icmp => {
                entry.last_seen = now;
                Some(entry.posture)
            }
        }
    }

    fn open_flow(
        &self,
        ctx: &AuthCtx,
        key: FlowKey,
        proto: Protocol,
        tcp_flags: u8,
        posture: Option<PostureAuthorization>,
    ) {
        if matches!(key.transport, FlowTransport::Echo { request: false, .. }) {
            return;
        }
        let now = Instant::now();
        let phase = match proto {
            Protocol::Tcp => {
                if (tcp_flags & TCP_SYN) != 0 && (tcp_flags & TCP_ACK) == 0 {
                    FlowPhase::Tcp(TcpPhase::SynSent)
                } else if (tcp_flags & TCP_FIN) != 0 || (tcp_flags & TCP_RST) != 0 {
                    FlowPhase::Tcp(TcpPhase::TimeWait)
                } else {
                    FlowPhase::Tcp(TcpPhase::Established)
                }
            }
            Protocol::Udp => FlowPhase::Udp,
            Protocol::Icmp | Protocol::Icmpv6 => FlowPhase::Icmp,
            Protocol::Any | Protocol::Other(_) => return,
        };
        let mut flows = self.inner.flows.lock();
        if flows.len() >= FLOW_CAP && !flows.contains_key(&key) {
            flows.retain(|_, entry| !flow_expired(entry, now));
            if flows.len() >= FLOW_CAP {
                return;
            }
        }
        flows
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                st.auth = ctx.epoch;
                st.posture_ok = ctx.posture_ok.clone();
                st.posture = posture;
                if matches!(st.phase, FlowPhase::Tcp(TcpPhase::SynSent))
                    && matches!(phase, FlowPhase::Tcp(TcpPhase::Established))
                {
                    st.phase = phase;
                }
                if matches!(phase, FlowPhase::Tcp(TcpPhase::TimeWait)) {
                    st.phase = phase;
                }
            })
            .or_insert(FlowEntry {
                phase,
                last_seen: now,
                auth: ctx.epoch,
                posture_ok: ctx.posture_ok.clone(),
                posture,
            });
    }

    fn count(&self, net: Uuid, allowed: bool, rejected: bool) {
        if allowed {
            self.inner.global.allowed.fetch_add(1, Ordering::Relaxed);
        } else if rejected {
            self.inner.global.rejected.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.global.denied.fetch_add(1, Ordering::Relaxed);
        }
        let counters = self.inner.nets.entry(net).or_default();
        if allowed {
            counters.allowed.fetch_add(1, Ordering::Relaxed);
        } else if rejected {
            counters.rejected.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_deny(
        &self,
        peer_hex: &str,
        dst_port: Option<u16>,
        proto: Protocol,
        verdict: &tunnet_common::policy::EvalVerdict,
    ) {
        let reason = match verdict.reason {
            EvalReason::OrgDeny => "org_deny",
            EvalReason::NetworkDeny => "network_deny",
            EvalReason::NetworkAllow => "network_allow",
            EvalReason::DefaultAllow => "default_allow",
            EvalReason::DefaultDeny => "default_deny",
            EvalReason::IcmpPolicy => "icmp_policy",
            EvalReason::PostureSkip => "posture_skip",
        };
        let scope = verdict.scope.map(|s| match s {
            RuleScope::Organization => "organization".to_string(),
            RuleScope::Network => "network".to_string(),
        });
        let record = DenyRecord {
            peer_endpoint: peer_hex.to_string(),
            dst_port,
            protocol: format!("{proto:?}").to_lowercase(),
            reason: reason.to_string(),
            rule_slug: verdict.rule_slug.clone(),
            scope,
            at_unix: jiff::Timestamp::now().as_second(),
        };
        let mut log = self.inner.denies.lock();
        if log.len() >= DENY_LOG_CAP {
            log.pop_front();
        }
        log.push_back(record);
    }
}

fn flow_key(
    network: Uuid,
    peer: EndpointId,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    l4: ResolvedL4,
) -> Option<FlowKey> {
    let transport = match l4.protocol {
        Protocol::Tcp => FlowTransport::Tcp {
            source: l4.src_port?,
            destination: l4.dst_port?,
        },
        Protocol::Udp => FlowTransport::Udp {
            source: l4.src_port?,
            destination: l4.dst_port?,
        },
        Protocol::Icmp => FlowTransport::Echo {
            identifier: l4.icmp_id?,
            sequence: l4.icmp_seq?,
            request: match l4.icmp_type? {
                8 => true,
                0 => false,
                _ => return None,
            },
        },
        _ => return None,
    };
    Some(FlowKey {
        network,
        peer,
        src,
        dst,
        transport,
    })
}

fn flow_expired(st: &FlowEntry, now: Instant) -> bool {
    let ttl = match st.phase {
        FlowPhase::Tcp(TcpPhase::TimeWait) => TCP_TIME_WAIT_TTL,
        FlowPhase::Tcp(_) => TCP_ACTIVE_TTL,
        FlowPhase::Udp => UDP_TTL,
        FlowPhase::Icmp => ICMP_TTL,
    };
    now.duration_since(st.last_seen) > ttl
}

fn match_rules(
    rules: &[FirewallRule],
    direction: Direction,
    l4: ResolvedL4,
    peer: &PeerCtx<'_>,
    net: Uuid,
) -> Option<FirewallAction> {
    let want_dir = match direction {
        Direction::Inbound => crate::direct::firewall::FirewallDirection::In,
        Direction::Outbound => crate::direct::firewall::FirewallDirection::Out,
    };
    for rule in rules {
        if rule.direction != want_dir {
            continue;
        }
        if !l4.protocol.matches_rule(Some(rule.protocol)) {
            continue;
        }
        if !rule.ports.is_empty() && !l4.protocol.is_icmp() {
            let Some(port) = l4.dst_port else {
                continue;
            };
            if !rule.ports.iter().any(|p| p.contains(port)) {
                continue;
            }
        }
        if !peer_matches(&rule.peer, peer, net) {
            continue;
        }
        return Some(rule.action);
    }
    None
}

fn peer_matches(filter: &PeerFilter, peer: &PeerCtx<'_>, net: Uuid) -> bool {
    match filter {
        PeerFilter::Any => true,
        PeerFilter::Endpoint(id) => peer.hex.eq_ignore_ascii_case(id),
        PeerFilter::Hostname(h) => peer.hostname.eq_ignore_ascii_case(h),
        PeerFilter::NetworkId(n) => {
            net.to_string().eq_ignore_ascii_case(n)
                || n.parse::<Uuid>().ok().is_some_and(|parsed| parsed == net)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::snapshot::{ForwardingStore, SelfIdentity};
    use crate::routing::RoutingTable;
    use rstest::rstest;
    use tunnet_common::policy::{
        Action, DefaultAction, IcmpPolicy, PolicyBundle, PolicyRule, PortRange,
        Protocol as PolProto, RuleScope, Selector,
    };

    const NET: Uuid = Uuid::from_u128(1);
    const SELF_HEX: &str = "aa";
    const PEER_HEX: &str = "bb";

    fn hex(c: &str) -> String {
        c.repeat(32)
    }

    fn tcp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, 1, 1000);
        if flags & TCP_SYN != 0 {
            b = b.syn();
        }
        if flags & TCP_ACK != 0 {
            b = b.ack(1);
        }
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn udp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(sport, dport);
        let mut out = Vec::new();
        b.write(&mut out, &[0u8; 32]).unwrap();
        out
    }

    fn managed_setup(bundle: PolicyBundle) -> (ForwardingStore, PolicyEngine, RoutingTable) {
        let routes = RoutingTable::new();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint_id: hex(PEER_HEX),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: PeerPosture::verified(
                    ["disk-encryption"],
                    jiff::Timestamp::now() + jiff::SignedDuration::from_secs(600),
                ),
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            NET,
            &hex(SELF_HEX),
            1,
        );
        let store = ForwardingStore::new();
        store.set_managed_bundle(
            &routes,
            NET,
            bundle,
            SelfIdentity {
                endpoint_hex: hex(SELF_HEX),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
                posture: PeerPosture::verified(
                    ["disk-encryption"],
                    jiff::Timestamp::now() + jiff::SignedDuration::from_secs(600),
                ),
            },
        );
        (store, PolicyEngine::new(), routes)
    }

    fn allow_tcp_80_bundle() -> PolicyBundle {
        PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Allow,
                ports: vec![PortRange { start: 80, end: 80 }],
                protocol: Some(PolProto::Tcp),
                priority: 100,
                order_index: 0,
                scope: RuleScope::Network,
                enabled: true,
                slug: Some("allow-http".into()),
                src_posture: vec![],
            }],
            ssh_rules: vec![],
            version: 1,
            signature: String::new(),
            default_action: DefaultAction::Deny,
            icmp_policy: IcmpPolicy::Deny,
            postures: Default::default(),
            default_src_posture: vec![],
            posture_enforcement: None,
        }
    }

    fn eval_as(
        policy: &PolicyEngine,
        snap: &ForwardingSnapshot,
        net: Uuid,
        hex: &str,
        hostname: &str,
        dir: Direction,
        raw: &[u8],
    ) -> Decision {
        let tags: Vec<String> = vec![];
        let pkt = tunnet_common::packet::parse(raw).unwrap();
        policy.evaluate(
            snap,
            net,
            &PeerCtx {
                endpoint: hex.parse().unwrap(),
                hex,
                hostname,
                tags: &tags,
                network_name: "net",
            },
            dir,
            &pkt,
        )
    }

    fn eval(
        policy: &PolicyEngine,
        snap: &ForwardingSnapshot,
        net: Uuid,
        dir: Direction,
        raw: &[u8],
    ) -> Decision {
        eval_as(policy, snap, net, &hex(PEER_HEX), "peer", dir, raw)
    }

    fn publish_claims(
        store: &ForwardingStore,
        routes: &RoutingTable,
        bundle: &PolicyBundle,
        self_until: jiff::Timestamp,
        peer_until: jiff::Timestamp,
    ) {
        store.update_managed(
            routes,
            NET,
            bundle.clone(),
            SelfIdentity {
                endpoint_hex: hex(SELF_HEX),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
                posture: PeerPosture::verified(["disk-encryption"], self_until),
            },
            || {
                routes.apply_peer_delta(
                    NET,
                    &[tunnet_common::PeerEntry {
                        ip: Ipv4Addr::new(100, 64, 0, 2),
                        endpoint_id: hex(PEER_HEX),
                        hostname: "peer".into(),
                        tags: vec![],
                        ssh_host_key: None,
                        posture: PeerPosture::verified(["disk-encryption"], peer_until),
                    }],
                    &[],
                    2,
                    &hex(SELF_HEX),
                    "net",
                )
            },
        );
    }

    #[rstest::rstest]
    #[case(Direction::Outbound)]
    #[case(Direction::Inbound)]
    fn proof_continuity_and_origin_expiry_control_both_flow_directions(#[case] origin: Direction) {
        let mut bundle = allow_tcp_80_bundle();
        bundle.rules[0].src_posture = vec!["disk-encryption".into()];
        let (store, policy, routes) = managed_setup(bundle.clone());
        let local = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        let (source, destination, return_direction) = match origin {
            Direction::Outbound => (local, peer, Direction::Inbound),
            Direction::Inbound => (peer, local, Direction::Outbound),
        };
        let request = tcp_pkt(source, destination, 52_000, 80, TCP_SYN);
        let response = tcp_pkt(destination, source, 80, 52_000, TCP_SYN | TCP_ACK);
        assert!(
            matches!(eval(&policy,&store.load(),NET,origin,&request), Decision::Allow { posture: Some(PostureAuthorization { source }) } if source == origin)
        );
        let epoch = store.load().auth_epoch(NET);
        let now = jiff::Timestamp::now();
        let live = now + jiff::SignedDuration::from_secs(1200);
        publish_claims(&store, &routes, &bundle, live, live);
        assert_eq!(store.load().auth_epoch(NET), epoch);
        assert!(matches!(
            eval(&policy, &store.load(), NET, return_direction, &response),
            Decision::Allow { .. }
        ));
        let expired = now - jiff::SignedDuration::from_secs(1);
        let (self_until, peer_until) = match origin {
            Direction::Outbound => (expired, live),
            Direction::Inbound => (live, expired),
        };
        publish_claims(&store, &routes, &bundle, self_until, peer_until);
        assert!(matches!(
            eval(&policy, &store.load(), NET, return_direction, &response),
            Decision::Deny
        ));
        publish_claims(&store, &routes, &bundle, live, live);
        assert_ne!(store.load().auth_epoch(NET), epoch);
        assert!(matches!(
            eval(&policy, &store.load(), NET, return_direction, &response),
            Decision::Deny
        ));
        assert!(matches!(
            eval(&policy, &store.load(), NET, origin, &request),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            eval(&policy, &store.load(), NET, return_direction, &response),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn unrelated_posture_rule_does_not_attach_expiry_to_allowed_flow() {
        let mut bundle = allow_tcp_80_bundle();
        let mut restricted = bundle.rules[0].clone();
        restricted.ports = vec![PortRange { start: 22, end: 22 }];
        restricted.src_posture = vec!["disk-encryption".into()];
        bundle.rules.push(restricted);
        let (store, policy, routes) = managed_setup(bundle.clone());
        let expired = jiff::Timestamp::now() - jiff::SignedDuration::from_secs(1);
        publish_claims(&store, &routes, &bundle, expired, expired);
        let raw = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            52_000,
            80,
            TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &store.load(), NET, Direction::Outbound, &raw),
            Decision::Allow { posture: None }
        ));
    }

    #[test]
    fn managed_allow_opens_flow_for_return() {
        let (store, policy, _routes) = managed_setup(allow_tcp_80_bundle());
        let snap = store.load();
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let out = tcp_pkt(self_ip, peer_ip, 52_000, 80, TCP_SYN);
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &out),
            Decision::Allow { .. }
        ));
        let ret = tcp_pkt(peer_ip, self_ip, 80, 52_000, TCP_ACK | TCP_SYN);
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &ret),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn managed_inbound_denied_without_prior_outbound() {
        let (store, policy, _routes) = managed_setup(allow_tcp_80_bundle());
        let snap = store.load();
        let p = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            80,
            52_000,
            TCP_ACK | TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &p),
            Decision::Deny
        ));
        assert_eq!(policy.recent_denies().len(), 1);
    }

    fn open_managed_flow(policy: &PolicyEngine, store: &ForwardingStore) {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let out = tcp_pkt(self_ip, peer_ip, 52_000, 80, TCP_SYN);
        assert!(matches!(
            eval(policy, &store.load(), NET, Direction::Outbound, &out),
            Decision::Allow { .. }
        ));
    }

    fn return_packet() -> Vec<u8> {
        tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            80,
            52_000,
            TCP_ACK,
        )
    }

    #[test]
    fn republish_without_changes_preserves_flows() {
        let (store, policy, routes) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        store.republish(&routes);
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn non_security_updates_preserve_flows(#[case] mtu: bool) {
        let (store, policy, routes) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        if mtu {
            store.set_mtu(&routes, 1400);
        } else {
            store.set_ssh_addrs(&routes, ["10.7.0.1".parse().unwrap()].into_iter().collect());
        }
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn policy_change_invalidates_flows() {
        let (store, policy, routes) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        let mut denied = allow_tcp_80_bundle();
        denied.default_action = DefaultAction::Deny;
        denied.rules.clear();
        store.set_managed_bundle(
            &routes,
            NET,
            denied,
            SelfIdentity {
                endpoint_hex: hex(SELF_HEX),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
                posture: tunnet_common::PeerPosture::Unknown,
            },
        );
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Deny
        ));
    }

    #[test]
    fn posture_flip_invalidates_and_revalidates() {
        let mut bundle = allow_tcp_80_bundle();
        bundle.rules[0].src_posture = vec!["disk-encryption".into()];
        let (store, policy, _) = managed_setup(bundle);
        open_managed_flow(&policy, &store);
        store.posture_source().store(Arc::new(false));
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Deny
        ));
        store.posture_source().store(Arc::new(true));
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Deny
        ));
        open_managed_flow(&policy, &store);
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn stale_flip_preserves_allowed_flows() {
        let (store, policy, _) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        store.set_stale(true);
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn fragment_state_invalidated_by_policy_change() {
        let (store, policy, routes) = managed_setup(allow_tcp_80_bundle());
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let mut first = tcp_pkt(self_ip, peer_ip, 52_000, 80, TCP_SYN);
        first[6] = 0x20;
        first[7] = 0;
        assert!(matches!(
            eval(&policy, &store.load(), NET, Direction::Outbound, &first),
            Decision::Allow { .. }
        ));
        let mut denied = allow_tcp_80_bundle();
        denied.default_action = DefaultAction::Deny;
        denied.rules.clear();
        store.set_managed_bundle(
            &routes,
            NET,
            denied,
            SelfIdentity {
                endpoint_hex: hex(SELF_HEX),
                ip: self_ip,
                tags: vec![],
                network: "net".into(),
                posture: tunnet_common::PeerPosture::Unknown,
            },
        );
        let mut later = tcp_pkt(self_ip, peer_ip, 52_000, 80, TCP_SYN);
        later[6] = 0;
        later[7] = 8;
        assert!(matches!(
            eval(&policy, &store.load(), NET, Direction::Outbound, &later),
            Decision::Deny
        ));
    }

    #[test]
    fn stale_policy_preserves_explicit_decisions() {
        let (store, policy, _routes) = managed_setup(PolicyBundle {
            rules: vec![],
            default_action: DefaultAction::Allow,
            icmp_policy: IcmpPolicy::Deny,
            ..PolicyBundle::default()
        });
        store.set_stale(true);
        let snap = store.load();
        let p = udp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            40000,
            5000,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &p),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn posture_gated_rule_denies_when_unhealthy() {
        let mut bundle = allow_tcp_80_bundle();
        bundle.rules[0].src_posture = vec!["disk-encryption".into()];
        let (store, policy, _routes) = managed_setup(bundle);
        store.posture_source().store(Arc::new(false));
        let snap = store.load();
        let out = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            52_000,
            80,
            TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &out),
            Decision::Deny
        ));
    }

    fn direct_setup(
        local: Vec<crate::direct::firewall::FirewallRule>,
    ) -> (ForwardingStore, PolicyEngine, RoutingTable) {
        let routes = RoutingTable::new();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint_id: hex(PEER_HEX),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "net",
            NET,
            &hex(SELF_HEX),
            1,
        );
        let store = ForwardingStore::new();
        store.set_firewall(
            &routes,
            NET,
            crate::forward::FirewallRules {
                enabled: true,
                version: 2,
                local,
                suggested: vec![],
            },
        );
        (store, PolicyEngine::new(), routes)
    }

    #[rstest]
    #[case(Direction::Outbound)]
    #[case(Direction::Inbound)]
    fn direct_default_allows_known_peer(#[case] dir: Direction) {
        let (store, policy, _routes) = direct_setup(vec![]);
        let snap = store.load();
        let (src, dst) = match dir {
            Direction::Outbound => (Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2)),
            Direction::Inbound => (Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 1)),
        };
        let p = tcp_pkt(src, dst, 12345, 443, TCP_SYN);
        assert!(matches!(
            eval(&policy, &snap, NET, dir, &p),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn direct_return_traffic_allowed_via_conntrack() {
        let (store, policy, _routes) = direct_setup(vec![]);
        let snap = store.load();
        let out = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
            TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &out),
            Decision::Allow { .. }
        ));
        let ret = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
            TCP_ACK,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &ret),
            Decision::Allow { .. }
        ));
    }

    #[rstest]
    #[case(0, 0, 7, true)]
    #[case(0, 0, 8, false)]
    #[case(0, 1, 7, false)]
    #[case(8, 0, 7, false)]
    #[case(3, 0, 7, false)]
    #[case(5, 0, 7, false)]
    fn echo_conntrack_only_authorizes_matching_reply(
        #[case] message_type: u8,
        #[case] identifier: u16,
        #[case] sequence: u16,
        #[case] allowed: bool,
        #[values(false, true)] managed: bool,
    ) {
        use crate::direct::firewall::{FirewallDirection, PeerFilter};
        let (store, policy, _routes) = if managed {
            let mut bundle = allow_tcp_80_bundle();
            bundle.icmp_policy = IcmpPolicy::Acl;
            bundle.rules[0].src = Selector::Endpoint(hex(SELF_HEX));
            bundle.rules[0].protocol = Some(Protocol::Icmp);
            bundle.rules[0].ports.clear();
            managed_setup(bundle)
        } else {
            direct_setup(vec![FirewallRule {
                direction: FirewallDirection::In,
                action: FirewallAction::Deny,
                protocol: Protocol::Icmp,
                ports: vec![],
                peer: PeerFilter::Any,
            }])
        };
        let make = |src, dst, identifier, sequence| {
            let builder = etherparse::PacketBuilder::ipv4(src, dst, 64)
                .icmpv4_echo_request(identifier, sequence);
            let mut packet = Vec::new();
            builder.write(&mut packet, &[0; 20]).unwrap();
            packet
        };
        let snap = store.load();
        let request = make([100, 64, 0, 1], [100, 64, 0, 2], 0, 7);
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &request),
            Decision::Allow { .. }
        ));
        let mut incoming = make([100, 64, 0, 2], [100, 64, 0, 1], identifier, sequence);
        incoming[20] = message_type;
        incoming[22..24].fill(0);
        let checksum = etherparse::checksum::Sum16BitWords::new()
            .add_slice(&incoming[20..])
            .ones_complement();
        incoming[22..24].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            matches!(
                eval(&policy, &snap, NET, Direction::Inbound, &incoming),
                Decision::Allow { .. }
            ),
            allowed
        );
    }

    #[test]
    fn firewall_change_is_network_scoped() {
        use crate::direct::firewall::{FirewallAction, FirewallDirection, FirewallRule};
        const NET_A: Uuid = Uuid::from_u128(10);
        const NET_B: Uuid = Uuid::from_u128(20);
        let routes = RoutingTable::new();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint_id: hex("bb"),
                hostname: "peer-a".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "a",
            NET_A,
            &hex(SELF_HEX),
            1,
        );
        routes.replace_network(
            NET_B,
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::new(100, 64, 0, 3),
                endpoint_id: hex("cc"),
                hostname: "peer-b".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &tunnet_common::DnsConfig::default(),
            "b",
            &hex(SELF_HEX),
            1,
        );
        let store = ForwardingStore::new();
        let policy = PolicyEngine::new();
        for net in [NET_A, NET_B] {
            store.set_firewall(
                &routes,
                net,
                crate::forward::FirewallRules {
                    enabled: true,
                    version: 1,
                    local: vec![],
                    suggested: vec![],
                },
            );
        }
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let out_a = tcp_pkt(self_ip, Ipv4Addr::new(100, 64, 0, 2), 10000, 443, TCP_SYN);
        let out_b = tcp_pkt(self_ip, Ipv4Addr::new(100, 64, 0, 3), 10000, 443, TCP_SYN);
        assert!(matches!(
            eval_as(
                &policy,
                &store.load(),
                NET_A,
                &hex("bb"),
                "peer-a",
                Direction::Outbound,
                &out_a
            ),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            eval_as(
                &policy,
                &store.load(),
                NET_B,
                &hex("cc"),
                "peer-b",
                Direction::Outbound,
                &out_b
            ),
            Decision::Allow { .. }
        ));
        store.set_firewall(
            &routes,
            NET_A,
            crate::forward::FirewallRules {
                enabled: true,
                version: 2,
                local: vec![FirewallRule {
                    direction: FirewallDirection::In,
                    action: FirewallAction::Deny,
                    protocol: PolProto::Tcp,
                    ports: vec![],
                    peer: crate::direct::firewall::PeerFilter::Any,
                }],
                suggested: vec![],
            },
        );
        let ret_a = tcp_pkt(Ipv4Addr::new(100, 64, 0, 2), self_ip, 443, 10000, TCP_ACK);
        let ret_b = tcp_pkt(Ipv4Addr::new(100, 64, 0, 3), self_ip, 443, 10000, TCP_ACK);
        assert!(matches!(
            eval_as(
                &policy,
                &store.load(),
                NET_A,
                &hex("bb"),
                "peer-a",
                Direction::Inbound,
                &ret_a
            ),
            Decision::Deny
        ));
        assert!(matches!(
            eval_as(
                &policy,
                &store.load(),
                NET_B,
                &hex("cc"),
                "peer-b",
                Direction::Inbound,
                &ret_b
            ),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn direct_local_deny_with_later_fragment_bypass() {
        use crate::direct::firewall::{FirewallAction, FirewallDirection, FirewallRule};
        use tunnet_common::policy::PortRange;
        let (store, policy, _routes) = direct_setup(vec![FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: PolProto::Tcp,
            ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            peer: crate::direct::firewall::PeerFilter::Any,
        }]);
        let snap = store.load();
        let p = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
            TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &p),
            Decision::Deny
        ));
        let mut later = p.clone();
        later[6] = 0;
        later[7] = 8;
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &later),
            Decision::Deny
        ));
    }

    #[test]
    fn direct_reject_synthesizes_reply() {
        use crate::direct::firewall::{FirewallAction, FirewallDirection, FirewallRule};
        let (store, policy, _routes) = direct_setup(vec![FirewallRule {
            direction: FirewallDirection::In,
            action: FirewallAction::Reject,
            protocol: PolProto::Tcp,
            ports: vec![],
            peer: crate::direct::firewall::PeerFilter::Any,
        }]);
        let snap = store.load();
        let p = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            9999,
            22,
            TCP_SYN,
        );
        match eval(&policy, &snap, NET, Direction::Inbound, &p) {
            Decision::Reject { reply } => {
                assert!(reply.len() >= 40);
                assert_eq!(reply[9], 6);
            }
            d => panic!("unexpected {d:?}"),
        }
    }

    #[test]
    fn orphan_later_fragment_is_dropped() {
        let (store, policy, _routes) = managed_setup(allow_tcp_80_bundle());
        let snap = store.load();
        let mut later = tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            80,
            TCP_SYN,
        );
        later[6] = 0;
        later[7] = 8;
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &later),
            Decision::Deny
        ));
    }
    #[test]
    fn missing_policy_denies_packets_and_streams() {
        let (store, policy, routes) = managed_setup(allow_tcp_80_bundle());
        let raw = tcp_pkt(
            "100.64.0.1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            52000,
            80,
            TCP_SYN,
        );
        assert!(matches!(
            eval(&policy, &store.load(), NET, Direction::Outbound, &raw),
            Decision::Allow { .. }
        ));
        store.clear_managed(&routes, NET);
        let snap = store.load();
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &raw),
            Decision::Deny
        ));
        let flow = FlowContext {
            src: snap.self_endpoint(),
            dst: tunnet_common::policy::FlowEndpoint::external(Some("10.0.0.1".parse().unwrap())),
            protocol: Protocol::Tcp,
            dst_port: Some(80),
        };
        assert!(matches!(policy.evaluate_flow(&snap, &flow), Decision::Deny));
    }

    #[test]
    fn posture_transition_without_packets_invalidates_return_flow() {
        let (store, policy, _) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
        let source = store.posture_source();
        source.store(Arc::new(false));
        source.store(Arc::new(true));
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Deny
        ));
        open_managed_flow(&policy, &store);
        assert!(matches!(
            eval(
                &policy,
                &store.load(),
                NET,
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn tracked_flow_and_fragment_metadata_are_peer_and_direction_scoped() {
        let (store, policy, _) = managed_setup(allow_tcp_80_bundle());
        open_managed_flow(&policy, &store);
        let snap = store.load();
        assert!(matches!(
            eval_as(
                &policy,
                &snap,
                NET,
                &hex("cc"),
                "other",
                Direction::Inbound,
                &return_packet()
            ),
            Decision::Deny
        ));
        let mut first = tcp_pkt(
            "100.64.0.1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            52000,
            80,
            TCP_SYN,
        );
        first[6] = 0x20;
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &first),
            Decision::Allow { .. }
        ));
        let mut later = first.clone();
        later[6] = 0;
        later[7] = 8;
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &later),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            eval_as(
                &policy,
                &snap,
                NET,
                &hex("cc"),
                "other",
                Direction::Outbound,
                &later
            ),
            Decision::Deny
        ));
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &later),
            Decision::Deny
        ));
        first[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &first),
            Decision::Deny
        ));
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &later),
            Decision::Deny
        ));
    }

    #[test]
    fn stale_control_plane_does_not_override_icmp_deny() {
        let (store, policy, _) = managed_setup(PolicyBundle {
            icmp_policy: IcmpPolicy::Deny,
            ..PolicyBundle::default()
        });
        let builder = etherparse::PacketBuilder::ipv4([100, 64, 0, 1], [100, 64, 0, 2], 64)
            .icmpv4_echo_request(1, 2);
        let mut raw = Vec::new();
        builder.write(&mut raw, &[]).unwrap();
        for stale in [false, true, false] {
            store.set_stale(stale);
            assert!(matches!(
                eval(&policy, &store.load(), NET, Direction::Outbound, &raw),
                Decision::Deny
            ));
        }
    }

    #[test]
    fn flow_pressure_has_bounded_return_authorization() {
        use crate::direct::firewall::{FirewallAction, FirewallDirection, FirewallRule};
        let (store, policy, _) = direct_setup(vec![FirewallRule {
            direction: FirewallDirection::In,
            action: FirewallAction::Deny,
            protocol: PolProto::Tcp,
            ports: vec![],
            peer: PeerFilter::Any,
        }]);
        let snap = store.load();
        for port in 10000..=14096 {
            let raw = tcp_pkt(
                "100.64.0.1".parse().unwrap(),
                "100.64.0.2".parse().unwrap(),
                port,
                443,
                TCP_SYN,
            );
            assert!(matches!(
                eval(&policy, &snap, NET, Direction::Outbound, &raw),
                Decision::Allow { .. }
            ));
        }
        let return_to = |port| {
            tcp_pkt(
                "100.64.0.2".parse().unwrap(),
                "100.64.0.1".parse().unwrap(),
                443,
                port,
                TCP_ACK,
            )
        };
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &return_to(10000)),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &return_to(14096)),
            Decision::Deny
        ));
        assert_eq!(policy.net_stats(NET).unwrap().flows, 4096);
    }
}
