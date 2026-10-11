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
use tunnet_common::packet::{
    CachedTransport, FragKey, Fragmentation, Packet, ResolvedL4, TcpFlags, frag_key,
    synthesize_reject,
};
use tunnet_common::policy::{
    Action, Direction, EvalReason, FlowContext, Protocol, RuleScope,
    evaluate_flow as evaluate_flow_policy,
};
use uuid::Uuid;

use super::snapshot::{ForwardingSnapshot, NetworkPolicy};
use crate::direct::firewall::{FirewallAction, FirewallRule, PeerFilter};

const DENY_LOG_CAP: usize = 64;
const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);
const GC_INTERVAL: Duration = Duration::from_secs(10);
const FRAG_TTL: Duration = Duration::from_secs(2);
const FRAG_CAP: usize = 4096;
const SPOOF_WINDOW: Duration = Duration::from_secs(60);

const TCP_FIN: u8 = TcpFlags::FIN;
const TCP_SYN: u8 = TcpFlags::SYN;
const TCP_RST: u8 = TcpFlags::RST;
const TCP_ACK: u8 = TcpFlags::ACK;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Deny,
    Reject { reply: Bytes },
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
    proto: u8,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

impl FlowKey {
    fn reverse(self) -> Self {
        Self {
            network: self.network,
            proto: self.proto,
            src: self.dst,
            sport: self.dport,
            dst: self.src,
            dport: self.sport,
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
    auth: u64,
    posture_ok: bool,
    stale: bool,
}

#[derive(Debug, Clone)]
struct FragEntry {
    transport: CachedTransport,
    expires: Instant,
    auth: u64,
    posture_ok: bool,
    stale: bool,
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

#[derive(Debug, Clone, Copy)]
struct AuthCtx {
    epoch: u64,
    posture_ok: bool,
    stale: bool,
}

impl AuthCtx {
    fn of(snap: &ForwardingSnapshot, net: Uuid) -> Self {
        Self {
            epoch: snap.auth_epoch(net),
            posture_ok: **snap.posture_ok.load(),
            stale: **snap.stale.load(),
        }
    }

    fn matches(&self, auth: u64, posture_ok: bool, stale: bool) -> bool {
        self.epoch == auth && self.posture_ok == posture_ok && self.stale == stale
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
    flows: DashMap<FlowKey, FlowEntry>,
    frags: Mutex<HashMap<(Uuid, FragKey), FragEntry>>,
    spoof: DashMap<Uuid, SpoofState>,
    global: Counters,
    nets: DashMap<Uuid, Counters>,
    denies: Mutex<VecDeque<DenyRecord>>,
}

impl Default for PolicyInner {
    fn default() -> Self {
        Self {
            flows: DashMap::new(),
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
        let engine = Self {
            inner: Arc::new(PolicyInner::default()),
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inner = engine.inner.clone();
            handle.spawn(async move {
                let mut tick = tokio::time::interval(GC_INTERVAL);
                loop {
                    tick.tick().await;
                    let now = Instant::now();
                    inner.flows.retain(|_, st| !flow_expired(st, now));
                    let mut frags = inner.frags.lock();
                    frags.retain(|_, e| e.expires > now);
                }
            });
        }
        engine
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
        let Some(l4) = self.resolve(&ctx, net, pkt) else {
            self.count(net, false, false);
            return Decision::Deny;
        };
        match snap.policy_for(net) {
            None => {
                self.count(net, true, false);
                Decision::Allow
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
        }
    }

    pub fn evaluate_flow(&self, snap: &ForwardingSnapshot, flow: &FlowContext) -> Decision {
        let Some(NetworkPolicy::Managed { bundle }) = snap.managed.and_then(|n| snap.policy_for(n))
        else {
            return Decision::Allow;
        };
        let posture_required = !bundle.default_src_posture.is_empty()
            || bundle.rules.iter().any(|r| !r.src_posture.is_empty());
        let flow = FlowContext {
            src_posture_ok: if posture_required {
                flow.src_posture_ok
            } else {
                true
            },
            ..flow.clone()
        };
        let verdict = evaluate_flow_policy(bundle, &flow);
        if verdict.action == Action::Deny {
            if **snap.stale.load()
                && bundle.rules.is_empty()
                && bundle.default_action == tunnet_common::policy::DefaultAction::Allow
            {
                return Decision::Allow;
            }
            self.record_deny(
                &flow.src.endpoint_hex,
                flow.dst_port,
                flow.protocol,
                &verdict,
            );
            return Decision::Deny;
        }
        Decision::Allow
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
                .iter()
                .filter(|e| e.key().network == net)
                .count(),
        })
    }

    pub fn recent_denies(&self) -> Vec<DenyRecord> {
        self.inner.denies.lock().iter().cloned().collect()
    }

    pub fn flush(&self) {
        self.inner.flows.clear();
        self.inner.frags.lock().clear();
    }

    pub fn flush_network(&self, net: Uuid) {
        self.inner.flows.retain(|k, _| k.network != net);
        self.inner.frags.lock().retain(|(n, _), _| *n != net);
    }

    fn resolve(&self, ctx: &AuthCtx, net: Uuid, pkt: &Packet<'_>) -> Option<ResolvedL4> {
        if pkt.transport.is_later_fragment() {
            let key = FragKey {
                src: pkt.ip.src(),
                dst: pkt.ip.dst(),
                protocol: pkt.ip.ip_protocol(),
                identification: pkt.fragmentation.identification()?,
            };
            let mut frags = self.inner.frags.lock();
            let entry = frags.get(&(net, key))?;
            if !ctx.matches(entry.auth, entry.posture_ok, entry.stale)
                || Instant::now() >= entry.expires
            {
                frags.remove(&(net, key));
                return None;
            }
            return Some(entry.transport.to_resolved());
        }
        if matches!(pkt.fragmentation, Fragmentation::First { .. })
            && let (Some(key), Some(transport)) = (
                frag_key(pkt),
                CachedTransport::from_transport(pkt.transport),
            )
        {
            let mut frags = self.inner.frags.lock();
            if frags.len() >= FRAG_CAP
                && !frags.contains_key(&(net, key))
                && let Some(oldest) = frags.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k)
            {
                frags.remove(&oldest);
            }
            frags.insert(
                (net, key),
                FragEntry {
                    transport,
                    expires: Instant::now() + FRAG_TTL,
                    auth: ctx.epoch,
                    posture_ok: ctx.posture_ok,
                    stale: ctx.stale,
                },
            );
        }
        ResolvedL4::from_transport(pkt.transport)
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
        if let Some(key) = managed_key(net, l4.protocol, src, dst, l4.src_port, l4.dst_port)
            && self.flow_allows(ctx, direction, key, tcp_flags)
        {
            self.count(net, true, false);
            return Decision::Allow;
        }
        let mut peer_side = snap.peer_endpoint(peer.endpoint);
        let self_side = snap.self_endpoint();
        let (src_side, dst_side) = match direction {
            Direction::Outbound => {
                peer_side.ip = Some(dst);
                (self_side, peer_side)
            }
            Direction::Inbound => {
                peer_side.ip = Some(src);
                (peer_side, self_side)
            }
        };
        let posture_required = !bundle.default_src_posture.is_empty()
            || bundle.rules.iter().any(|r| !r.src_posture.is_empty());
        let flow = FlowContext {
            src: src_side,
            dst: dst_side,
            protocol: l4.protocol,
            dst_port: l4.dst_port,
            src_posture_ok: if posture_required {
                **snap.posture_ok.load()
            } else {
                true
            },
        };
        let verdict = evaluate_flow_policy(bundle, &flow);
        if verdict.action == Action::Deny {
            if **snap.stale.load()
                && bundle.rules.is_empty()
                && bundle.default_action == tunnet_common::policy::DefaultAction::Allow
            {
                self.count(net, true, false);
                return Decision::Allow;
            }
            self.record_deny(peer.hex, flow.dst_port, flow.protocol, &verdict);
            self.count(net, false, false);
            return Decision::Deny;
        }
        if let Some(key) = managed_key(net, l4.protocol, src, dst, l4.src_port, l4.dst_port) {
            self.open_flow(ctx, key, l4.protocol, tcp_flags);
        }
        self.count(net, true, false);
        Decision::Allow
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
            return Decision::Allow;
        }
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
        if let Some(key) = direct_key(net, l4.protocol, src, dst, l4)
            && self.flow_allows(ctx, direction, key, tcp_flags)
        {
            self.count(net, true, false);
            return Decision::Allow;
        }
        if let Some(action) = match_rules(local, direction, l4, peer, net) {
            return self.apply(ctx, net, action, direction, pkt, src, dst, l4);
        }
        if let Some(action) = match_rules(suggested, direction, l4, peer, net) {
            return self.apply(ctx, net, action, direction, pkt, src, dst, l4);
        }
        self.apply(
            ctx,
            net,
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
        action: FirewallAction,
        _direction: Direction,
        pkt: &Packet<'_>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        l4: ResolvedL4,
    ) -> Decision {
        match action {
            FirewallAction::Allow => {
                if let Some(key) = direct_key(net, l4.protocol, src, dst, l4) {
                    let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
                    self.open_flow(ctx, key, l4.protocol, tcp_flags);
                }
                self.count(net, true, false);
                Decision::Allow
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
        direction: Direction,
        fwd: FlowKey,
        tcp_flags: u8,
    ) -> bool {
        let now = Instant::now();
        let rev = fwd.reverse();
        let mut entry = match self.inner.flows.get_mut(&fwd) {
            Some(e) => e,
            None => match self.inner.flows.get_mut(&rev) {
                Some(e) => e,
                None => return false,
            },
        };
        let key = *entry.key();
        if !ctx.matches(entry.auth, entry.posture_ok, entry.stale) || flow_expired(&entry, now) {
            drop(entry);
            self.inner.flows.remove(&key);
            return false;
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
                        return true;
                    }
                    if !inbound {
                        entry.last_seen = now;
                        return true;
                    }
                    false
                }
                TcpPhase::Established => {
                    if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                        entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                    }
                    entry.last_seen = now;
                    true
                }
                TcpPhase::TimeWait => {
                    entry.last_seen = now;
                    true
                }
            },
            FlowPhase::Udp | FlowPhase::Icmp => {
                entry.last_seen = now;
                true
            }
        }
    }

    fn open_flow(&self, ctx: &AuthCtx, key: FlowKey, proto: Protocol, tcp_flags: u8) {
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
        self.inner
            .flows
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                st.auth = ctx.epoch;
                st.posture_ok = ctx.posture_ok;
                st.stale = ctx.stale;
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
                posture_ok: ctx.posture_ok,
                stale: ctx.stale,
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

fn proto_num(proto: Protocol) -> Option<u8> {
    match proto {
        Protocol::Tcp => Some(6),
        Protocol::Udp => Some(17),
        Protocol::Icmp => Some(1),
        Protocol::Icmpv6 => Some(58),
        Protocol::Other(n) => Some(n),
        Protocol::Any => None,
    }
}

fn managed_key(
    network: Uuid,
    proto: Protocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<FlowKey> {
    let num = proto_num(proto)?;
    if num == 1 {
        return Some(FlowKey {
            network,
            proto: num,
            src: src.min(dst),
            sport: src_port.unwrap_or(0),
            dst: src.max(dst),
            dport: 0,
        });
    }
    Some(FlowKey {
        network,
        proto: num,
        src,
        sport: src_port.unwrap_or(0),
        dst,
        dport: dst_port.unwrap_or(0),
    })
}

fn direct_key(
    network: Uuid,
    proto: Protocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    l4: ResolvedL4,
) -> Option<FlowKey> {
    let num = proto.ip_number()?;
    if proto.is_icmp() {
        return Some(FlowKey {
            network,
            proto: num,
            src: src.min(dst),
            sport: l4.icmp_id.unwrap_or(0),
            dst: src.max(dst),
            dport: 0,
        });
    }
    Some(FlowKey {
        network,
        proto: num,
        src,
        sport: l4.src_port.unwrap_or(0),
        dst,
        dport: l4.dst_port.unwrap_or(0),
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

    #[test]
    fn managed_allow_opens_flow_for_return() {
        let (store, policy, _routes) = managed_setup(allow_tcp_80_bundle());
        let snap = store.load();
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let out = tcp_pkt(self_ip, peer_ip, 52_000, 80, TCP_SYN);
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Outbound, &out),
            Decision::Allow
        ));
        let ret = tcp_pkt(peer_ip, self_ip, 80, 52_000, TCP_ACK | TCP_SYN);
        assert!(matches!(
            eval(&policy, &snap, NET, Direction::Inbound, &ret),
            Decision::Allow
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
            Decision::Allow
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

    fn return_covered() -> Vec<u8> {
        tcp_pkt(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            80,
            80,
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
            Decision::Allow
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
            Decision::Allow
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
                &return_covered()
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
                &return_covered()
            ),
            Decision::Allow
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
                &return_covered()
            ),
            Decision::Allow
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
            Decision::Allow
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
    fn stale_open_network_fails_open() {
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
            Decision::Allow
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
            Decision::Allow
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
            Decision::Allow
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
            Decision::Allow
        ));
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
            Decision::Allow
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
            Decision::Allow
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
            Decision::Allow
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
}
