//! Userspace firewall configuration for Direct mode.
//!
//! Packet evaluation lives in [`crate::forward::PolicyEngine`]; this module
//! owns the rule configuration, its persistence, and its CLI/API parsing.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tunnet_common::policy::{PortRange, Protocol};

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
