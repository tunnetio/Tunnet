//! Userspace stateful firewall for Direct mode.
//!
//! Defaults (authenticated mesh peers):
//! - Outbound: allow all (opens flow)
//! - Inbound from a known mesh peer: allow all (QUIC already gated by PSK/AuthCache)
//! - Inbound without a peer identity: ICMP echo only; TCP/UDP deny
//!
//! Restrict further with local ACL rules (`tunnet firewall`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tunnet_common::policy::{Action, PolicyBundle, PolicyRule, PortRange, Protocol, Selector};
use uuid::Uuid;

use crate::state::StatePaths;

// ── Timeouts ──────────────────────────────────────────────────────────────

const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);
const GC_INTERVAL: Duration = Duration::from_secs(10);

// ── Rule types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    Allow,
    Deny,
    /// Silent drop vs. send TCP RST / ICMP unreachable back to the local stack.
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerFilter {
    #[default]
    #[serde(alias = "*")]
    Any,
    Endpoint(String),
    Hostname(String),
    NetworkId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: Protocol,
    /// Empty = any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub peer: PeerFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub version: u64,
}

fn default_true() -> bool {
    true
}

/// Empty config: engine applies built-in default policy.
pub fn default_firewall() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        rules: vec![],
        version: 1,
    }
}

impl FirewallConfig {
    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        Ok(crate::agent_config::load_firewall(paths))
    }

    pub fn save(&self, paths: &StatePaths, network_name: &str) -> anyhow::Result<()> {
        crate::agent_config::save_firewall(paths, network_name, self)
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
        self.version += 1;
    }

    pub fn remove_at(&mut self, index: usize) -> anyhow::Result<()> {
        if index >= self.rules.len() {
            anyhow::bail!("rule index out of range");
        }
        self.rules.remove(index);
        self.version += 1;
        Ok(())
    }

    pub fn reset(&mut self) {
        *self = default_firewall();
    }
}

pub fn parse_port_spec(s: &str) -> anyhow::Result<Vec<PortRange>> {
    if s.is_empty() || s == "*" {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse().context("port range start")?;
            let end: u16 = b.parse().context("port range end")?;
            out.push(PortRange { start, end });
        } else {
            let p: u16 = part.parse().context("port")?;
            out.push(PortRange { start: p, end: p });
        }
    }
    Ok(out)
}

/// Parse peer filter from CLI/IPC: `*`, bare hostname, `endpoint:<hex>`, `host:<name>`, or hex endpoint.
pub fn parse_peer_filter(s: Option<&str>) -> anyhow::Result<PeerFilter> {
    let Some(s) = s.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(PeerFilter::Any);
    };
    if s == "*" || s.eq_ignore_ascii_case("any") {
        return Ok(PeerFilter::Any);
    }
    if let Some(rest) = s.strip_prefix("endpoint:") {
        return Ok(PeerFilter::Endpoint(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("host:") {
        return Ok(PeerFilter::Hostname(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("hostname:") {
        return Ok(PeerFilter::Hostname(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("network:") {
        return Ok(PeerFilter::NetworkId(rest.to_string()));
    }
    // 64-char hex → endpoint id; otherwise treat as hostname.
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PeerFilter::Endpoint(s.to_string()));
    }
    Ok(PeerFilter::Hostname(s.to_string()))
}

pub fn peer_filter_display(peer: &PeerFilter) -> Option<String> {
    match peer {
        PeerFilter::Any => None,
        PeerFilter::Endpoint(e) => Some(format!("endpoint:{e}")),
        PeerFilter::Hostname(h) => Some(format!("host:{h}")),
        PeerFilter::NetworkId(n) => Some(format!("network:{n}")),
    }
}

pub fn action_display(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Deny => "deny",
        FirewallAction::Reject => "reject",
    }
}

pub fn direction_display(d: FirewallDirection) -> &'static str {
    match d {
        FirewallDirection::In => "in",
        FirewallDirection::Out => "out",
    }
}

// ── Packet header view (zero-copy) ────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct PacketView {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: Protocol,
    pub proto_num: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
    pub ihl: usize,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Parse IPv4 headers without copying payload. Returns `None` for non-IPv4/short.
pub fn parse_packet(packet: &[u8]) -> Option<PacketView> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl || ihl < 20 {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
    let proto_num = packet[9];

    let mut view = PacketView {
        src,
        dst,
        protocol: Protocol::Any,
        proto_num,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        icmp_type: 0,
        icmp_code: 0,
        icmp_id: 0,
        icmp_seq: 0,
        ihl,
    };

    match proto_num {
        6 => {
            view.protocol = Protocol::Tcp;
            if packet.len() >= ihl + 14 {
                view.src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                view.dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                view.tcp_flags = packet[ihl + 13];
            }
        }
        17 => {
            view.protocol = Protocol::Udp;
            if packet.len() >= ihl + 4 {
                view.src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                view.dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            }
        }
        1 => {
            view.protocol = Protocol::Icmp;
            if packet.len() >= ihl + 8 {
                view.icmp_type = packet[ihl];
                view.icmp_code = packet[ihl + 1];
                // Echo request/reply: identifier + sequence at offset 4
                view.icmp_id = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]);
                view.icmp_seq = u16::from_be_bytes([packet[ihl + 6], packet[ihl + 7]]);
                // Encode id/seq into "ports" for conntrack key
                view.src_port = view.icmp_id;
                view.dst_port = view.icmp_seq;
            }
        }
        _ => {}
    }
    Some(view)
}

// ── Conntrack ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

impl FlowKey {
    fn forward(v: &PacketView) -> Self {
        if v.protocol == Protocol::Icmp {
            // ICMP: track by echo id; sport=id, dport=0 for both directions keyed by id
            Self {
                proto: v.proto_num,
                src: v.src.min(v.dst),
                sport: v.icmp_id,
                dst: v.src.max(v.dst),
                dport: 0,
            }
        } else {
            Self {
                proto: v.proto_num,
                src: v.src,
                sport: v.src_port,
                dst: v.dst,
                dport: v.dst_port,
            }
        }
    }

    fn reverse(v: &PacketView) -> Self {
        if v.protocol == Protocol::Icmp {
            Self::forward(v)
        } else {
            Self {
                proto: v.proto_num,
                src: v.dst,
                sport: v.dst_port,
                dst: v.src,
                dport: v.src_port,
            }
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

// ── Evaluation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[derive(Debug)]
pub enum EvalResult {
    Allow,
    Deny,
    /// Synthesized RST / ICMP unreachable for the local TUN.
    Reject {
        reply: Bytes,
    },
}

pub struct FirewallStats {
    pub conntrack_entries: usize,
    pub local_rules: usize,
    pub suggested_rules: usize,
    pub enabled: bool,
    pub version: u64,
    pub packets_allowed: u64,
    pub packets_denied: u64,
    pub packets_rejected: u64,
}

// ── Engine ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct FirewallEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    enabled: ArcSwap<bool>,
    local_rules: ArcSwap<Vec<FirewallRule>>,
    suggested_rules: ArcSwap<Vec<FirewallRule>>,
    version: AtomicU64,
    conntrack: DashMap<FlowKey, FlowState>,
    allowed: AtomicU64,
    denied: AtomicU64,
    rejected: AtomicU64,
    /// Self mesh IP for default policy and reject synthesis.
    self_ip: ArcSwap<Ipv4Addr>,
}

impl FirewallEngine {
    pub fn from_config(
        cfg: &FirewallConfig,
        self_ip: Ipv4Addr,
        _self_endpoint_hex: String,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(EngineInner {
                enabled: ArcSwap::from_pointee(cfg.enabled),
                local_rules: ArcSwap::from_pointee(cfg.rules.clone()),
                suggested_rules: ArcSwap::from_pointee(Vec::new()),
                version: AtomicU64::new(cfg.version),
                conntrack: DashMap::new(),
                allowed: AtomicU64::new(0),
                denied: AtomicU64::new(0),
                rejected: AtomicU64::new(0),
                self_ip: ArcSwap::from_pointee(self_ip),
            }),
        };
        engine.spawn_gc();
        engine
    }

    fn spawn_gc(&self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(GC_INTERVAL);
            loop {
                tick.tick().await;
                let now = Instant::now();
                inner.conntrack.retain(|_, st| !is_expired(st, now));
            }
        });
    }

    pub fn reload_local(&self, cfg: &FirewallConfig) {
        self.inner.enabled.store(Arc::new(cfg.enabled));
        self.inner.local_rules.store(Arc::new(cfg.rules.clone()));
        self.inner.version.store(cfg.version, Ordering::Relaxed);
    }

    pub fn set_suggested(&self, rules: Vec<FirewallRule>) {
        self.inner.suggested_rules.store(Arc::new(rules));
    }

    pub fn clear_suggested(&self) {
        self.inner.suggested_rules.store(Arc::new(Vec::new()));
    }

    pub fn flush_conntrack(&self) {
        self.inner.conntrack.clear();
    }

    pub fn set_self_ip(&self, ip: Ipv4Addr) {
        self.inner.self_ip.store(Arc::new(ip));
    }

    pub fn stats(&self) -> FirewallStats {
        FirewallStats {
            conntrack_entries: self.inner.conntrack.len(),
            local_rules: self.inner.local_rules.load().len(),
            suggested_rules: self.inner.suggested_rules.load().len(),
            enabled: **self.inner.enabled.load(),
            version: self.inner.version.load(Ordering::Relaxed),
            packets_allowed: self.inner.allowed.load(Ordering::Relaxed),
            packets_denied: self.inner.denied.load(Ordering::Relaxed),
            packets_rejected: self.inner.rejected.load(Ordering::Relaxed),
        }
    }

    pub fn local_rules_snapshot(&self) -> Vec<FirewallRule> {
        self.inner.local_rules.load().as_ref().clone()
    }

    pub fn suggested_rules_snapshot(&self) -> Vec<FirewallRule> {
        self.inner.suggested_rules.load().as_ref().clone()
    }

    /// Ensure inbound TCP to `port` is allowed (e.g. SSH external port 22).
    /// Merges into local rules in-memory without persisting to disk.
    pub fn ensure_inbound_tcp_allow(&self, port: u16) {
        let mut rules = self.local_rules_snapshot();
        let already = rules.iter().any(|r| {
            r.direction == FirewallDirection::In
                && r.action == FirewallAction::Allow
                && r.protocol == Protocol::Tcp
                && (r.ports.is_empty() || r.ports.iter().any(|p| p.start <= port && port <= p.end))
                && matches!(r.peer, PeerFilter::Any)
        });
        if already {
            return;
        }
        rules.push(FirewallRule {
            direction: FirewallDirection::In,
            action: FirewallAction::Allow,
            protocol: Protocol::Tcp,
            ports: vec![PortRange {
                start: port,
                end: port,
            }],
            peer: PeerFilter::Any,
        });
        let version = self.inner.version.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.local_rules.store(Arc::new(rules));
        self.inner.version.store(version, Ordering::Relaxed);
        tracing::info!(port, "firewall: ensured inbound TCP allow for SSH");
    }

    /// Evaluate a packet. `peer_endpoint_hex` is the remote mesh peer (if known).
    /// `network_id` is the peer's Direct network (for `PeerFilter::NetworkId`).
    pub fn evaluate(
        &self,
        direction: PacketDirection,
        packet: &[u8],
        peer_endpoint_hex: Option<&str>,
        peer_hostname: Option<&str>,
        network_id: Option<Uuid>,
    ) -> EvalResult {
        if !**self.inner.enabled.load() {
            self.inner.allowed.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Allow;
        }

        let Some(view) = parse_packet(packet) else {
            self.inner.denied.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Deny;
        };

        // 1) Conntrack return / established traffic
        if self.conntrack_allows(direction, &view) {
            self.inner.allowed.fetch_add(1, Ordering::Relaxed);
            return EvalResult::Allow;
        }

        // 2) Local rules (override), then suggested (base)
        if let Some(action) = self.match_rules(
            &self.inner.local_rules.load(),
            direction,
            &view,
            peer_endpoint_hex,
            peer_hostname,
            network_id,
        ) {
            return self.apply_action(action, direction, packet, &view);
        }
        if let Some(action) = self.match_rules(
            &self.inner.suggested_rules.load(),
            direction,
            &view,
            peer_endpoint_hex,
            peer_hostname,
            network_id,
        ) {
            return self.apply_action(action, direction, packet, &view);
        }

        // 3) Default policy
        let default = default_policy(direction, &view, peer_endpoint_hex);
        self.apply_action(default, direction, packet, &view)
    }

    fn apply_action(
        &self,
        action: FirewallAction,
        direction: PacketDirection,
        packet: &[u8],
        view: &PacketView,
    ) -> EvalResult {
        match action {
            FirewallAction::Allow => {
                self.open_or_refresh_flow(direction, view);
                self.inner.allowed.fetch_add(1, Ordering::Relaxed);
                EvalResult::Allow
            }
            FirewallAction::Deny => {
                self.inner.denied.fetch_add(1, Ordering::Relaxed);
                EvalResult::Deny
            }
            FirewallAction::Reject => {
                self.inner.rejected.fetch_add(1, Ordering::Relaxed);
                let reply = synthesize_reject(packet, view).unwrap_or_default();
                EvalResult::Reject { reply }
            }
        }
    }

    fn match_rules(
        &self,
        rules: &[FirewallRule],
        direction: PacketDirection,
        view: &PacketView,
        peer_hex: Option<&str>,
        peer_hostname: Option<&str>,
        network_id: Option<Uuid>,
    ) -> Option<FirewallAction> {
        let want_dir = match direction {
            PacketDirection::Inbound => FirewallDirection::In,
            PacketDirection::Outbound => FirewallDirection::Out,
        };
        for rule in rules {
            if rule.direction != want_dir {
                continue;
            }
            if rule.protocol != Protocol::Any && rule.protocol != view.protocol {
                continue;
            }
            if !rule.ports.is_empty() {
                let port = match direction {
                    PacketDirection::Outbound => view.dst_port,
                    PacketDirection::Inbound => view.dst_port,
                };
                if view.protocol == Protocol::Icmp {
                    // ports ignored for ICMP unless empty
                } else if !rule.ports.iter().any(|p| p.contains(port)) {
                    continue;
                }
            }
            if !peer_matches(&rule.peer, peer_hex, peer_hostname, network_id) {
                continue;
            }
            return Some(rule.action);
        }
        None
    }

    fn conntrack_allows(&self, direction: PacketDirection, view: &PacketView) -> bool {
        let now = Instant::now();
        let fwd = FlowKey::forward(view);
        let rev = FlowKey::reverse(view);

        // Look up either orientation
        let key = if self.inner.conntrack.contains_key(&fwd) {
            fwd
        } else if self.inner.conntrack.contains_key(&rev) {
            rev
        } else {
            return false;
        };

        let mut entry = match self.inner.conntrack.get_mut(&key) {
            Some(e) => e,
            None => return false,
        };
        if is_expired(&entry, now) {
            drop(entry);
            self.inner.conntrack.remove(&key);
            return false;
        }

        match entry.phase {
            FlowPhase::Tcp(phase) => {
                match phase {
                    TcpPhase::SynSent => {
                        // Inbound SYN-ACK or any reverse packet establishes
                        if direction == PacketDirection::Inbound
                            || (view.tcp_flags & TCP_ACK) != 0
                            || (view.tcp_flags & TCP_RST) != 0
                        {
                            if (view.tcp_flags & TCP_RST) != 0 || (view.tcp_flags & TCP_FIN) != 0 {
                                entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                            } else {
                                entry.phase = FlowPhase::Tcp(TcpPhase::Established);
                            }
                            entry.last_seen = now;
                            return true;
                        }
                        // More outbound data while waiting
                        if direction == PacketDirection::Outbound {
                            entry.last_seen = now;
                            return true;
                        }
                        false
                    }
                    TcpPhase::Established => {
                        if (view.tcp_flags & TCP_RST) != 0 || (view.tcp_flags & TCP_FIN) != 0 {
                            entry.phase = FlowPhase::Tcp(TcpPhase::TimeWait);
                        }
                        entry.last_seen = now;
                        true
                    }
                    TcpPhase::TimeWait => {
                        entry.last_seen = now;
                        true
                    }
                }
            }
            FlowPhase::Udp | FlowPhase::Icmp => {
                entry.last_seen = now;
                true
            }
        }
    }

    fn open_or_refresh_flow(&self, _direction: PacketDirection, view: &PacketView) {
        let now = Instant::now();
        let key = FlowKey::forward(view);

        let phase = match view.protocol {
            Protocol::Tcp => {
                if (view.tcp_flags & TCP_SYN) != 0 && (view.tcp_flags & TCP_ACK) == 0 {
                    FlowPhase::Tcp(TcpPhase::SynSent)
                } else if (view.tcp_flags & TCP_FIN) != 0 || (view.tcp_flags & TCP_RST) != 0 {
                    FlowPhase::Tcp(TcpPhase::TimeWait)
                } else {
                    FlowPhase::Tcp(TcpPhase::Established)
                }
            }
            Protocol::Udp => FlowPhase::Udp,
            Protocol::Icmp => FlowPhase::Icmp,
            Protocol::Any => return,
        };

        self.inner
            .conntrack
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                // upgrade SYN_SENT → EST on data
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
}

fn peer_matches(
    filter: &PeerFilter,
    peer_hex: Option<&str>,
    peer_hostname: Option<&str>,
    network_id: Option<Uuid>,
) -> bool {
    match filter {
        PeerFilter::Any => true,
        PeerFilter::Endpoint(id) => peer_hex.is_some_and(|h| h.eq_ignore_ascii_case(id)),
        PeerFilter::Hostname(h) => peer_hostname.is_some_and(|n| n.eq_ignore_ascii_case(h)),
        PeerFilter::NetworkId(n) => {
            let Some(id) = network_id else {
                return false;
            };
            id.to_string().eq_ignore_ascii_case(n)
                || n.parse::<Uuid>().ok().is_some_and(|parsed| parsed == id)
        }
    }
}

fn default_policy(
    direction: PacketDirection,
    view: &PacketView,
    peer_endpoint_hex: Option<&str>,
) -> FirewallAction {
    match direction {
        PacketDirection::Outbound => FirewallAction::Allow,
        PacketDirection::Inbound => {
            // Mesh peer identity is only set after QUIC auth (DirectAuthHook /
            // AuthCache). Match Tailscale/ZeroTier: allow all between authenticated
            // peers; lock down with local firewall rules when needed.
            if peer_endpoint_hex.is_some() {
                return FirewallAction::Allow;
            }
            if view.protocol == Protocol::Icmp && (view.icmp_type == 8 || view.icmp_type == 0) {
                FirewallAction::Allow
            } else {
                FirewallAction::Deny
            }
        }
    }
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

// ── Reject synthesis ──────────────────────────────────────────────────────

/// Build a TCP RST or ICMP Destination Unreachable for the local TUN.
pub fn synthesize_reject(packet: &[u8], view: &PacketView) -> Option<Bytes> {
    match view.protocol {
        Protocol::Tcp => synthesize_tcp_rst(packet, view),
        Protocol::Udp | Protocol::Icmp => synthesize_icmp_unreach(packet, view),
        Protocol::Any => None,
    }
}

fn synthesize_tcp_rst(packet: &[u8], view: &PacketView) -> Option<Bytes> {
    let ihl = view.ihl;
    if packet.len() < ihl + 20 {
        return None;
    }
    // Read original seq/ack
    let seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);
    let ack = u32::from_be_bytes([
        packet[ihl + 8],
        packet[ihl + 9],
        packet[ihl + 10],
        packet[ihl + 11],
    ]);

    let mut out = vec![0u8; 40]; // 20 IP + 20 TCP
    // IPv4 header
    out[0] = 0x45;
    out[1] = 0;
    out[2] = 0;
    out[3] = 40; // total length
    out[8] = 64; // TTL
    out[9] = 6; // TCP
    // src = original dst, dst = original src
    out[12..16].copy_from_slice(&view.dst.octets());
    out[16..20].copy_from_slice(&view.src.octets());
    // TCP
    out[20..22].copy_from_slice(&view.dst_port.to_be_bytes());
    out[22..24].copy_from_slice(&view.src_port.to_be_bytes());
    // seq = original ack (or 0), ack = original seq+1
    let new_seq = if (view.tcp_flags & TCP_ACK) != 0 {
        ack
    } else {
        0
    };
    let new_ack = seq.wrapping_add(1);
    out[24..28].copy_from_slice(&new_seq.to_be_bytes());
    out[28..32].copy_from_slice(&new_ack.to_be_bytes());
    out[32] = 0x50; // data offset 5
    out[33] = TCP_RST | TCP_ACK;
    // IP checksum
    let ip_csum = ipv4_checksum(&out[0..20]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP checksum
    let tcp_csum = tcp_checksum(&out, view.dst, view.src);
    out[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    Some(Bytes::from(out))
}

fn synthesize_icmp_unreach(packet: &[u8], view: &PacketView) -> Option<Bytes> {
    // ICMP Destination Unreachable, code 10 (host administratively prohibited)
    // or 3 (port unreachable) for UDP
    let code: u8 = if view.protocol == Protocol::Udp {
        3
    } else {
        10
    };
    let copy_len = packet.len().min(view.ihl + 8).min(28);
    let total = 20 + 8 + copy_len;
    let mut out = vec![0u8; total];
    out[0] = 0x45;
    let tl = total as u16;
    out[2..4].copy_from_slice(&tl.to_be_bytes());
    out[8] = 64;
    out[9] = 1; // ICMP
    out[12..16].copy_from_slice(&view.dst.octets());
    out[16..20].copy_from_slice(&view.src.octets());
    // ICMP header
    out[20] = 3; // dest unreach
    out[21] = code;
    // unused 4 bytes zero
    out[28..28 + copy_len].copy_from_slice(&packet[..copy_len]);
    let ip_csum = ipv4_checksum(&out[0..20]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_csum = icmp_checksum(&out[20..]);
    out[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(Bytes::from(out))
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i == 10 {
            i += 2;
            continue; // skip checksum field
        }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(ip_packet: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let tcp = &ip_packet[20..];
    let mut sum: u32 = 0;
    // pseudo header
    for b in src.octets().chunks(2) {
        sum += u16::from_be_bytes([b[0], b[1]]) as u32;
    }
    for b in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([b[0], b[1]]) as u32;
    }
    sum += 6; // protocol
    sum += tcp.len() as u32;
    let mut i = 0;
    while i + 1 < tcp.len() {
        if i == 16 {
            i += 2; // skip checksum
            continue;
        }
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ── AclEngine bridge (connection-level) ───────────────────────────────────

/// Compile effective Direct rules into a PolicyBundle for connection hooks.
pub fn firewall_to_policy(
    cfg: &FirewallConfig,
    self_endpoint_hex: &str,
    self_ip: Ipv4Addr,
) -> PolicyBundle {
    let _ = self_ip;
    if !cfg.enabled {
        return PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Allow,
                ports: vec![],
                protocol: Some(Protocol::Any),
                priority: 0,
                src_posture: vec![],
            }],
            ssh_rules: vec![],
            version: cfg.version,
            signature: String::new(),
            postures: HashMap::new(),
            default_src_posture: vec![],
            posture_enforcement: None,
        };
    }

    let mut rules = Vec::new();
    let mut priority = 1000i32;
    for fr in &cfg.rules {
        // Reject maps to Deny at connection level (no RST on QUIC accept)
        let action = match fr.action {
            FirewallAction::Allow => Action::Allow,
            FirewallAction::Deny | FirewallAction::Reject => Action::Deny,
        };
        let peer_sel = match &fr.peer {
            PeerFilter::Any | PeerFilter::NetworkId(_) | PeerFilter::Hostname(_) => Selector::Any,
            PeerFilter::Endpoint(e) => Selector::Endpoint(e.clone()),
        };
        let (src, dst) = match fr.direction {
            FirewallDirection::In => (peer_sel, Selector::Endpoint(self_endpoint_hex.to_string())),
            FirewallDirection::Out => (Selector::Endpoint(self_endpoint_hex.to_string()), peer_sel),
        };
        rules.push(PolicyRule {
            src,
            dst,
            action,
            ports: fr.ports.clone(),
            protocol: Some(fr.protocol),
            priority,
            src_posture: vec![],
        });
        priority -= 1;
    }

    // Default: allow outbound any, allow inbound ICMP (via missing deny for icmp only is hard);
    // connection-level: allow any peer that is in AuthCache is separate. Peer-level allow
    // for established mesh: allow any → self at low priority for membership peers handled by hook.
    rules.push(PolicyRule {
        src: Selector::Endpoint(self_endpoint_hex.to_string()),
        dst: Selector::Any,
        action: Action::Allow,
        ports: vec![],
        protocol: Some(Protocol::Any),
        priority: -100,
        src_posture: vec![],
    });
    // Inbound: allow any (packet path enforces via FirewallEngine); connection accept
    // still gated by AuthCache in DirectAuthHook.
    rules.push(PolicyRule {
        src: Selector::Any,
        dst: Selector::Endpoint(self_endpoint_hex.to_string()),
        action: Action::Allow,
        ports: vec![],
        protocol: Some(Protocol::Any),
        priority: -200,
        src_posture: vec![],
    });

    PolicyBundle {
        rules,
        ssh_rules: vec![],
        version: cfg.version,
        signature: String::new(),
        postures: HashMap::new(),
        default_src_posture: vec![],
        posture_enforcement: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> FirewallEngine {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        FirewallEngine::from_config(
            &default_firewall(),
            Ipv4Addr::new(100, 64, 0, 1),
            "aa".repeat(32),
        )
    }

    fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2] = 0;
        p[3] = 40;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = TCP_SYN;
        p
    }

    fn tcp_ack(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = tcp_syn(src, dst, sport, dport);
        p[33] = TCP_ACK;
        p
    }

    #[test]
    fn parse_tcp() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);
        let p = tcp_syn(src, dst, 12345, 80);
        let v = parse_packet(&p).unwrap();
        assert_eq!(v.protocol, Protocol::Tcp);
        assert_eq!(v.src_port, 12345);
        assert_eq!(v.dst_port, 80);
        assert_ne!(v.tcp_flags & TCP_SYN, 0);
    }

    #[test]
    fn outbound_allowed_by_default() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Outbound, &p, Some("peer"), None, None),
            EvalResult::Allow
        ));
    }

    #[test]
    fn inbound_tcp_allowed_from_authenticated_peer() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Inbound, &p, Some("peer"), None, None),
            EvalResult::Allow
        ));
    }

    #[test]
    fn inbound_tcp_denied_without_peer_identity() {
        let e = engine();
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Inbound, &p, None, None, None),
            EvalResult::Deny
        ));
    }

    #[test]
    fn return_traffic_allowed_via_conntrack() {
        let e = engine();
        let out = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Outbound, &out, Some("peer"), None, None),
            EvalResult::Allow
        ));
        let ret = tcp_ack(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            443,
            12345,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Inbound, &ret, Some("peer"), None, None),
            EvalResult::Allow
        ));
    }

    #[test]
    fn local_deny_outbound() {
        let e = engine();
        e.reload_local(&FirewallConfig {
            enabled: true,
            version: 2,
            rules: vec![FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Deny,
                protocol: Protocol::Tcp,
                ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                peer: PeerFilter::Any,
            }],
        });
        let p = tcp_syn(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            12345,
            443,
        );
        assert!(matches!(
            e.evaluate(PacketDirection::Outbound, &p, Some("peer"), None, None),
            EvalResult::Deny
        ));
    }

    #[test]
    fn reject_synthesizes_rst() {
        let src = Ipv4Addr::new(100, 64, 0, 2);
        let dst = Ipv4Addr::new(100, 64, 0, 1);
        let p = tcp_syn(src, dst, 9999, 22);
        let v = parse_packet(&p).unwrap();
        let reply = synthesize_reject(&p, &v).unwrap();
        assert!(reply.len() >= 40);
        assert_eq!(reply[9], 6); // TCP
        assert_ne!(reply[33] & TCP_RST, 0);
    }
}
