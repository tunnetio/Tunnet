//! Userspace stateful firewall configuration for Direct mode.
//!
//! This engine is a control-plane object: it owns firewall configuration
//! (local rules, suggested rules, enabled flag) and publishes compiled
//! snapshots to the shared [`crate::policy_runtime::PolicyRuntime`], which
//! owns all packet evaluation, conntrack, and expiry. Packet verdicts,
//! defaults (outbound allow; inbound from known peers allow; otherwise ICMP
//! echo only) and reject synthesis live in the runtime.
//!
//! Restrict further with local ACL rules (`tunnet firewall`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tunnet_common::policy::{Action, PolicyBundle, PolicyRule, PortRange, Protocol, Selector};
use uuid::Uuid;

use crate::policy_runtime::PolicyRuntime;
use crate::state::StatePaths;

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

// ── Engine (control-plane configuration + runtime publishing) ─────────────

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
    /// Self mesh IP (kept for diagnostics/compat; policy uses runtime state).
    self_ip: ArcSwap<Ipv4Addr>,
    /// Owning Direct network: published snapshots stay network-scoped (§0.2).
    network_id: Uuid,
    /// Attached shared runtime. Every mutation publishes a fresh compiled
    /// snapshot + generation bump (§0.3); packet state lives there, never here.
    runtime: RwLock<Option<PolicyRuntime>>,
}

impl FirewallEngine {
    pub fn from_config(
        cfg: &FirewallConfig,
        self_ip: Ipv4Addr,
        _self_endpoint_hex: String,
        network_id: Uuid,
    ) -> Self {
        Self {
            inner: Arc::new(EngineInner {
                enabled: ArcSwap::from_pointee(cfg.enabled),
                local_rules: ArcSwap::from_pointee(cfg.rules.clone()),
                suggested_rules: ArcSwap::from_pointee(Vec::new()),
                version: AtomicU64::new(cfg.version),
                self_ip: ArcSwap::from_pointee(self_ip),
                network_id,
                runtime: RwLock::new(None),
            }),
        }
    }

    /// Attach the shared runtime (node build / dataplane bring-up). All
    /// subsequent mutations publish to it.
    pub fn attach_runtime(&self, runtime: PolicyRuntime) {
        *self.inner.runtime.write() = Some(runtime);
        self.publish();
    }

    /// Compile this network's rules and publish to the shared runtime.
    fn publish(&self) {
        let Some(rt) = self.inner.runtime.read().clone() else {
            return;
        };
        rt.publish_firewall(
            self.inner.network_id,
            self.local_rules_snapshot(),
            self.suggested_rules_snapshot(),
            **self.inner.enabled.load(),
        );
    }

    fn bump_version(&self) -> u64 {
        self.inner.version.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn reload_local(&self, cfg: &FirewallConfig) {
        self.inner.enabled.store(Arc::new(cfg.enabled));
        self.inner.local_rules.store(Arc::new(cfg.rules.clone()));
        self.inner.version.store(cfg.version, Ordering::Relaxed);
        self.bump_version();
        self.publish();
    }

    pub fn set_suggested(&self, rules: Vec<FirewallRule>) {
        self.inner.suggested_rules.store(Arc::new(rules));
        // Version bump is the reliable generation signal (§0.3): the legacy
        // code never bumped here, so suggested-rule edits were invisible.
        self.bump_version();
        self.publish();
    }

    pub fn clear_suggested(&self) {
        self.inner.suggested_rules.store(Arc::new(Vec::new()));
        self.bump_version();
        self.publish();
    }

    /// Invalidate shared conntrack via the runtime (CLI flush, teardown).
    pub fn flush_conntrack(&self) {
        if let Some(rt) = self.inner.runtime.read().clone() {
            rt.invalidate();
        }
    }

    pub fn set_self_ip(&self, ip: Ipv4Addr) {
        self.inner.self_ip.store(Arc::new(ip));
    }

    pub fn stats(&self) -> FirewallStats {
        // Packet counters live in the shared runtime now (this engine no
        // longer sees packets); conntrack_entries is dataplane-wide.
        let (allowed, denied, rejected, conntrack_entries) = match self.inner.runtime.read().clone()
        {
            Some(rt) => {
                let c = rt.fw_counters_for(self.inner.network_id);
                (
                    c.allowed.load(Ordering::Relaxed),
                    c.denied.load(Ordering::Relaxed),
                    c.rejected.load(Ordering::Relaxed),
                    rt.conntrack_len(),
                )
            }
            None => (0, 0, 0, 0),
        };
        FirewallStats {
            conntrack_entries,
            local_rules: self.inner.local_rules.load().len(),
            suggested_rules: self.inner.suggested_rules.load().len(),
            enabled: **self.inner.enabled.load(),
            version: self.inner.version.load(Ordering::Relaxed),
            packets_allowed: allowed,
            packets_denied: denied,
            packets_rejected: rejected,
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
        self.publish();
    }
}

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
                order_index: 0,
                scope: tunnet_common::policy::RuleScope::Network,
                enabled: true,
                slug: None,
                src_posture: vec![],
            }],
            ssh_rules: vec![],
            version: cfg.version,
            signature: String::new(),
            default_action: tunnet_common::policy::DefaultAction::Allow,
            icmp_policy: tunnet_common::policy::IcmpPolicy::Allow,
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
            order_index: 1000 - priority,
            scope: tunnet_common::policy::RuleScope::Network,
            enabled: true,
            slug: None,
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
        order_index: 10_000,
        scope: tunnet_common::policy::RuleScope::Network,
        enabled: true,
        slug: None,
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
        order_index: 10_001,
        scope: tunnet_common::policy::RuleScope::Network,
        enabled: true,
        slug: None,
        src_posture: vec![],
    });

    PolicyBundle {
        rules,
        ssh_rules: vec![],
        version: cfg.version,
        signature: String::new(),
        default_action: tunnet_common::policy::DefaultAction::Allow,
        icmp_policy: tunnet_common::policy::IcmpPolicy::Allow,
        postures: HashMap::new(),
        default_src_posture: vec![],
        posture_enforcement: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_common::packet::synthesize_reject;

    fn engine() -> FirewallEngine {
        FirewallEngine::from_config(
            &default_firewall(),
            Ipv4Addr::new(100, 64, 0, 1),
            "aa".repeat(32),
            Uuid::nil(),
        )
    }

    fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, 1, 1000)
            .syn();
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    fn tcp_ack(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, 1, 1000)
            .ack(1);
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn parse_tcp() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);
        let p = tcp_syn(src, dst, 12345, 80);
        let v = tunnet_common::packet::parse(&p).unwrap();
        assert_eq!(v.policy_protocol(), Protocol::Tcp);
        assert_eq!(v.transport.src_port(), Some(12345));
        assert_eq!(v.transport.dst_port(), Some(80));
        assert!(v.transport.tcp_flags().unwrap().syn());
        let _ = tcp_ack(src, dst, 80, 12345);
    }

    #[test]
    fn suggested_rules_bump_version() {
        // Regression: legacy set_suggested never bumped the version, so
        // suggested-rule edits were invisible to generation signals.
        let e = engine();
        let v0 = e.stats().version;
        e.set_suggested(vec![FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![],
            peer: PeerFilter::Any,
        }]);
        assert!(e.stats().version > v0);
        assert_eq!(e.suggested_rules_snapshot().len(), 1);
        e.clear_suggested();
        assert!(e.suggested_rules_snapshot().is_empty());
    }

    #[test]
    fn ensure_inbound_tcp_allow_idempotent() {
        let e = engine();
        e.ensure_inbound_tcp_allow(22);
        e.ensure_inbound_tcp_allow(22);
        let rules = e.local_rules_snapshot();
        assert_eq!(
            rules
                .iter()
                .filter(|r| r.direction == FirewallDirection::In)
                .count(),
            1
        );
    }

    #[test]
    fn reject_synthesizes_rst() {
        let src = Ipv4Addr::new(100, 64, 0, 2);
        let dst = Ipv4Addr::new(100, 64, 0, 1);
        let p = tcp_syn(src, dst, 9999, 22);
        let v = tunnet_common::packet::parse(&p).unwrap();
        let reply = synthesize_reject(&v).unwrap();
        assert!(reply.len() >= 40);
        assert_eq!(reply[9], 6);
        let parsed = tunnet_common::packet::parse(&reply).unwrap();
        assert!(parsed.transport.tcp_flags().unwrap().rst());
    }
}
