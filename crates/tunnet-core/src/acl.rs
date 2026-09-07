use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::Serialize;
use tunnet_common::packet::{FragmentTable, Packet, ResolvedL4, TcpFlags};
use tunnet_common::policy::{
    Action, Direction, EvalCtx, EvalReason, EvalVerdict, PolicyBundle, Protocol, evaluate_detailed,
};

use crate::routing::{PeerInfo, RoutingTable};

const DENY_LOG_CAP: usize = 64;

// Match `direct/firewall.rs` conntrack TTLs.
const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);
const GC_INTERVAL: Duration = Duration::from_secs(10);

const TCP_FIN: u8 = TcpFlags::FIN;
const TCP_SYN: u8 = TcpFlags::SYN;
const TCP_RST: u8 = TcpFlags::RST;
const TCP_ACK: u8 = TcpFlags::ACK;

#[derive(Debug, Clone)]
pub struct SelfIdentity {
    pub endpoint_hex: String,
    pub ip: Ipv4Addr,
    pub tags: Vec<String>,
    pub network: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AclDenyRecord {
    pub peer_endpoint: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub reason: String,
    pub rule_slug: Option<String>,
    pub scope: Option<String>,
    pub at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

impl FlowKey {
    fn reverse(self) -> Self {
        Self {
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
struct FlowState {
    phase: FlowPhase,
    last_seen: Instant,
}

#[derive(Clone)]
pub struct AclEngine {
    pub self_id: Arc<ArcSwap<SelfIdentity>>,
    pub routes: RoutingTable,
    pub bundle: Arc<ArcSwap<PolicyBundle>>,
    pub stale: Arc<ArcSwap<bool>>,
    /// When false, ACL rules that require source posture do not match.
    pub src_posture_ok: Arc<ArcSwap<bool>>,
    deny_log: Arc<Mutex<VecDeque<AclDenyRecord>>>,
    conntrack: Arc<DashMap<FlowKey, FlowState>>,
    fragments: Arc<Mutex<FragmentTable>>,
}

impl AclEngine {
    pub fn new(self_id: SelfIdentity, routes: RoutingTable, bundle: PolicyBundle) -> Self {
        Self::with_posture_flag(
            self_id,
            routes,
            bundle,
            Arc::new(ArcSwap::from_pointee(true)),
        )
    }

    pub fn with_posture_flag(
        self_id: SelfIdentity,
        routes: RoutingTable,
        bundle: PolicyBundle,
        src_posture_ok: Arc<ArcSwap<bool>>,
    ) -> Self {
        let engine = Self {
            self_id: Arc::new(ArcSwap::from_pointee(self_id)),
            routes,
            bundle: Arc::new(ArcSwap::from_pointee(bundle)),
            stale: Arc::new(ArcSwap::from_pointee(false)),
            src_posture_ok,
            deny_log: Arc::new(Mutex::new(VecDeque::with_capacity(DENY_LOG_CAP))),
            conntrack: Arc::new(DashMap::new()),
            fragments: Arc::new(Mutex::new(FragmentTable::default())),
        };
        engine.spawn_gc();
        engine
    }

    fn spawn_gc(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let conntrack = self.conntrack.clone();
        handle.spawn(async move {
            let mut tick = tokio::time::interval(GC_INTERVAL);
            loop {
                tick.tick().await;
                let now = Instant::now();
                conntrack.retain(|_, st| !is_expired(st, now));
            }
        });
    }

    pub fn set_src_posture_ok(&self, ok: bool) {
        self.src_posture_ok.store(Arc::new(ok));
    }

    pub fn replace_bundle(&self, b: PolicyBundle) {
        self.bundle.store(Arc::new(b));
        self.stale.store(Arc::new(false));
        self.conntrack.clear();
        self.fragments.lock().clear();
    }

    pub fn flush_conntrack(&self) {
        self.conntrack.clear();
    }

    pub fn replace_self_tags(&self, tags: Vec<String>) {
        let current = self.self_id.load();
        if current.tags == tags {
            return;
        }
        self.self_id.store(Arc::new(SelfIdentity {
            endpoint_hex: current.endpoint_hex.clone(),
            ip: current.ip,
            tags,
            network: current.network.clone(),
        }));
    }

    pub fn mark_stale(&self) {
        self.stale.store(Arc::new(true));
    }

    pub fn recent_denies(&self) -> Vec<AclDenyRecord> {
        self.deny_log.lock().iter().cloned().collect()
    }

    /// Policy for an explicit flow (e.g. a proxied TCP stream) with real
    /// protocol/port context. Stateless: proxied return traffic shares the
    /// originating connection, so no conntrack entry is opened.
    pub fn allow_flow(
        &self,
        peer_endpoint_hex: &str,
        direction: Direction,
        protocol: Protocol,
        dst_port: Option<u16>,
    ) -> bool {
        self.evaluate_flow(peer_endpoint_hex, direction, protocol, dst_port)
            .action
            == Action::Allow
    }

    pub fn evaluate_flow(
        &self,
        peer_endpoint_hex: &str,
        direction: Direction,
        protocol: Protocol,
        dst_port: Option<u16>,
    ) -> EvalVerdict {
        let peer = self.routes.lookup_endpoint(peer_endpoint_hex);
        let peer_ip = peer.as_ref().map(|p| p.ip);
        self.eval_policy(
            peer.as_deref(),
            peer_endpoint_hex,
            peer_ip,
            direction,
            protocol,
            dst_port,
        )
    }

    pub fn allow_packet(
        &self,
        peer_endpoint_hex: &str,
        direction: Direction,
        packet: &Packet<'_>,
    ) -> bool {
        self.evaluate_packet(peer_endpoint_hex, direction, packet)
            .action
            == Action::Allow
    }

    pub fn evaluate_packet(
        &self,
        peer_endpoint_hex: &str,
        direction: Direction,
        packet: &Packet<'_>,
    ) -> EvalVerdict {
        let Some(src) = packet.ip.v4_src() else {
            return EvalVerdict {
                action: Action::Deny,
                reason: EvalReason::DefaultDeny,
                rule_slug: None,
                scope: None,
            };
        };
        let Some(dst) = packet.ip.v4_dst() else {
            return EvalVerdict {
                action: Action::Deny,
                reason: EvalReason::DefaultDeny,
                rule_slug: None,
                scope: None,
            };
        };
        let Some(l4) = self.fragments.lock().resolve(packet) else {
            return EvalVerdict {
                action: Action::Deny,
                reason: EvalReason::DefaultDeny,
                rule_slug: None,
                scope: None,
            };
        };
        let peer = self.routes.lookup_endpoint(peer_endpoint_hex);
        self.check(peer.as_deref(), peer_endpoint_hex, src, dst, direction, l4)
    }

    fn check(
        &self,
        peer: Option<&PeerInfo>,
        peer_hex: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        direction: Direction,
        l4: ResolvedL4,
    ) -> EvalVerdict {
        let proto = l4.protocol;
        let src_port = l4.src_port;
        let dst_port = l4.dst_port;
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
        let peer_ip = match direction {
            Direction::Outbound => Some(dst),
            Direction::Inbound => Some(src),
        };

        // 1) Established / return traffic via conntrack.
        if let Some(key) = flow_key(proto, src, dst, src_port, dst_port)
            && self.conntrack_allows(direction, key, tcp_flags)
        {
            return EvalVerdict {
                action: Action::Allow,
                reason: EvalReason::DefaultAllow,
                rule_slug: None,
                scope: None,
            };
        }

        let verdict = self.eval_policy(peer, peer_hex, peer_ip, direction, proto, dst_port);
        if verdict.action == Action::Deny {
            return verdict;
        }

        // 2) Policy allowed → open / refresh flow for return traffic.
        if let Some(key) = flow_key(proto, src, dst, src_port, dst_port) {
            self.open_or_refresh_flow(key, proto, tcp_flags);
        }
        verdict
    }

    fn eval_policy(
        &self,
        peer: Option<&PeerInfo>,
        peer_hex: &str,
        peer_ip: Option<Ipv4Addr>,
        direction: Direction,
        proto: Protocol,
        dst_port: Option<u16>,
    ) -> EvalVerdict {
        let empty_tags: Vec<String> = Vec::new();
        let self_id = self.self_id.load();
        let bundle = self.bundle.load();
        let posture_required = !bundle.default_src_posture.is_empty()
            || bundle.rules.iter().any(|r| !r.src_posture.is_empty());
        let src_posture_ok = if posture_required {
            **self.src_posture_ok.load()
        } else {
            true
        };
        let ctx = EvalCtx {
            self_endpoint_hex: &self_id.endpoint_hex,
            self_ip: self_id.ip,
            self_tags: &self_id.tags,
            self_network: &self_id.network,
            peer_endpoint_hex: peer_hex,
            peer_ip,
            peer_tags: peer.map(|p| p.tags.as_slice()).unwrap_or(&empty_tags),
            peer_network: &self_id.network,
            dst_port,
            protocol: proto,
            src_posture_ok,
        };
        let verdict = evaluate_detailed(&bundle, &ctx, direction);
        if verdict.action == Action::Deny {
            // Fail-open only for open networks with no rules during poll outage.
            if **self.stale.load()
                && bundle.rules.is_empty()
                && bundle.default_action == tunnet_common::policy::DefaultAction::Allow
            {
                return EvalVerdict {
                    action: Action::Allow,
                    reason: EvalReason::DefaultAllow,
                    rule_slug: None,
                    scope: None,
                };
            }
            self.record_deny(peer_hex, dst_port, proto, &verdict);
            tracing::debug!(
                peer = %peer_hex,
                ?dst_port,
                ?proto,
                reason = ?verdict.reason,
                slug = ?verdict.rule_slug,
                "ACL deny"
            );
        }
        verdict
    }

    fn conntrack_allows(&self, direction: Direction, fwd: FlowKey, tcp_flags: u8) -> bool {
        let now = Instant::now();
        let rev = fwd.reverse();
        let key = if self.conntrack.contains_key(&fwd) {
            fwd
        } else if self.conntrack.contains_key(&rev) {
            rev
        } else {
            return false;
        };

        let mut entry = match self.conntrack.get_mut(&key) {
            Some(e) => e,
            None => return false,
        };
        if is_expired(&entry, now) {
            drop(entry);
            self.conntrack.remove(&key);
            return false;
        }

        match entry.phase {
            FlowPhase::Tcp(phase) => match phase {
                TcpPhase::SynSent => {
                    if matches!(direction, Direction::Inbound)
                        || (tcp_flags & TCP_ACK) != 0
                        || (tcp_flags & TCP_RST) != 0
                    {
                        if (tcp_flags & TCP_RST) != 0 || (tcp_flags & TCP_FIN) != 0 {
                            entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                        } else {
                            entry.phase = FlowPhase::Tcp(TcpPhase::Established);
                        }
                        entry.last_seen = now;
                        return true;
                    }
                    if matches!(direction, Direction::Outbound) {
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

    fn open_or_refresh_flow(&self, key: FlowKey, proto: Protocol, tcp_flags: u8) {
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

        self.conntrack
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                if matches!(st.phase, FlowPhase::Tcp(TcpPhase::SynSent))
                    && matches!(phase, FlowPhase::Tcp(TcpPhase::Established))
                {
                    st.phase = phase;
                }
                if matches!(phase, FlowPhase::Tcp(TcpPhase::TimeWait)) {
                    st.phase = phase;
                }
            })
            .or_insert(FlowState {
                phase,
                last_seen: now,
            });
    }

    fn record_deny(
        &self,
        peer_hex: &str,
        dst_port: Option<u16>,
        proto: Protocol,
        verdict: &EvalVerdict,
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
            tunnet_common::policy::RuleScope::Organization => "organization".to_string(),
            tunnet_common::policy::RuleScope::Network => "network".to_string(),
        });
        let record = AclDenyRecord {
            peer_endpoint: peer_hex.to_string(),
            dst_port,
            protocol: format!("{proto:?}").to_lowercase(),
            reason: reason.to_string(),
            rule_slug: verdict.rule_slug.clone(),
            scope,
            at_unix: jiff::Timestamp::now().as_second(),
        };
        let mut log = self.deny_log.lock();
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

fn flow_key(
    proto: Protocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<FlowKey> {
    let proto = proto_num(proto)?;
    if proto == 1 {
        return Some(FlowKey {
            proto,
            src: src.min(dst),
            sport: src_port.unwrap_or(0),
            dst: src.max(dst),
            dport: 0,
        });
    }
    Some(FlowKey {
        proto,
        src,
        sport: src_port.unwrap_or(0),
        dst,
        dport: dst_port.unwrap_or(0),
    })
}

fn is_expired(st: &FlowState, now: Instant) -> bool {
    let ttl = match st.phase {
        FlowPhase::Tcp(TcpPhase::TimeWait) => TCP_TIME_WAIT_TTL,
        FlowPhase::Tcp(_) => TCP_ACTIVE_TTL,
        FlowPhase::Udp => UDP_TTL,
        FlowPhase::Icmp => ICMP_TTL,
    };
    now.duration_since(st.last_seen) > ttl
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_common::policy::{
        Action, DefaultAction, IcmpPolicy, PolicyRule, PortRange, RuleScope, Selector,
    };

    fn test_engine(bundle: PolicyBundle) -> AclEngine {
        let self_id = SelfIdentity {
            endpoint_hex: "aa".repeat(32),
            ip: Ipv4Addr::new(100, 64, 0, 1),
            tags: vec![],
            network: "net".into(),
        };
        AclEngine::new(self_id, RoutingTable::new(), bundle)
    }

    fn allow_tcp_80_bundle() -> PolicyBundle {
        PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Allow,
                ports: vec![PortRange { start: 80, end: 80 }],
                protocol: Some(Protocol::Tcp),
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

    #[test]
    fn outbound_allow_opens_flow_for_inbound_return() {
        let acl = test_engine(allow_tcp_80_bundle());
        let peer = "bb".repeat(32);
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let ephemeral = 52_000u16;

        let out = tcp_pkt(self_ip, peer_ip, ephemeral, 80, TCP_SYN);
        let pkt = tunnet_common::packet::parse(&out).unwrap();
        assert!(acl.allow_packet(&peer, Direction::Outbound, &pkt));

        let ret = tcp_pkt(peer_ip, self_ip, 80, ephemeral, TCP_ACK | TCP_SYN);
        let pkt = tunnet_common::packet::parse(&ret).unwrap();
        assert!(acl.allow_packet(&peer, Direction::Inbound, &pkt));
    }

    #[test]
    fn inbound_ephemeral_denied_without_prior_outbound() {
        let acl = test_engine(allow_tcp_80_bundle());
        let peer = "bb".repeat(32);
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);

        let p = tcp_pkt(peer_ip, self_ip, 80, 52_000, TCP_ACK | TCP_SYN);
        let pkt = tunnet_common::packet::parse(&p).unwrap();
        assert!(!acl.allow_packet(&peer, Direction::Inbound, &pkt));
    }

    #[test]
    fn replace_bundle_flushes_conntrack() {
        let acl = test_engine(allow_tcp_80_bundle());
        let peer = "bb".repeat(32);
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 2);
        let ephemeral = 52_000u16;

        let out = tcp_pkt(self_ip, peer_ip, ephemeral, 80, TCP_SYN);
        let pkt = tunnet_common::packet::parse(&out).unwrap();
        assert!(acl.allow_packet(&peer, Direction::Outbound, &pkt));

        acl.replace_bundle(allow_tcp_80_bundle());

        let ret = tcp_pkt(peer_ip, self_ip, 80, ephemeral, TCP_ACK);
        let pkt = tunnet_common::packet::parse(&ret).unwrap();
        assert!(!acl.allow_packet(&peer, Direction::Inbound, &pkt));
    }

    fn allow_tcp_443_bundle() -> PolicyBundle {
        let mut b = allow_tcp_80_bundle();
        b.rules[0].ports = vec![PortRange {
            start: 443,
            end: 443,
        }];
        b.rules[0].slug = Some("allow-https".into());
        b
    }

    #[test]
    fn explicit_flow_enforces_real_port_under_default_deny() {
        let acl = test_engine(allow_tcp_443_bundle());
        let peer = "bb".repeat(32);
        assert!(acl.allow_flow(&peer, Direction::Outbound, Protocol::Tcp, Some(443)));
        assert!(!acl.allow_flow(&peer, Direction::Outbound, Protocol::Tcp, Some(22)));
        assert!(!acl.allow_flow(&peer, Direction::Outbound, Protocol::Tcp, None));
        assert!(!acl.allow_flow(&peer, Direction::Outbound, Protocol::Udp, Some(443)));
    }
}
