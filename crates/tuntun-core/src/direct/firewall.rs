//! Per-device local firewall for Direct mode.
//!
//! Secure-by-default: inbound TCP/UDP denied, inbound ICMP allowed, outbound
//! allowed. Rules compile into a [`PolicyBundle`] for the shared [`AclEngine`].

use std::net::Ipv4Addr;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tuntun_common::policy::{Action, PolicyBundle, PolicyRule, PortRange, Protocol, Selector};

use crate::state::StatePaths;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub direction: FirewallDirection,
    pub action: Action,
    pub protocol: Protocol,
    /// Empty = any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// Optional peer endpoint hex restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub rules: Vec<FirewallRule>,
    pub version: u64,
}

/// Default secure Direct firewall.
pub fn default_firewall() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        rules: vec![
            FirewallRule {
                direction: FirewallDirection::In,
                action: Action::Allow,
                protocol: Protocol::Icmp,
                ports: vec![],
                peer: None,
            },
            FirewallRule {
                direction: FirewallDirection::Out,
                action: Action::Allow,
                protocol: Protocol::Any,
                ports: vec![],
                peer: None,
            },
            // Implicit deny inbound TCP/UDP via missing allow + final deny.
            FirewallRule {
                direction: FirewallDirection::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                ports: vec![],
                peer: None,
            },
            FirewallRule {
                direction: FirewallDirection::In,
                action: Action::Deny,
                protocol: Protocol::Udp,
                ports: vec![],
                peer: None,
            },
        ],
        version: 1,
    }
}

impl FirewallConfig {
    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        if !paths.firewall_file().exists() {
            let cfg = default_firewall();
            cfg.save(paths)?;
            return Ok(cfg);
        }
        let bytes = std::fs::read(paths.firewall_file())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, paths: &StatePaths) -> anyhow::Result<()> {
        paths.ensure()?;
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(paths.firewall_file(), json)?;
        Ok(())
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        // Insert allows before denies for same direction.
        let insert_at = if rule.action == Action::Allow {
            self.rules
                .iter()
                .position(|r| r.action == Action::Deny && r.direction == rule.direction)
                .unwrap_or(self.rules.len())
        } else {
            self.rules.len()
        };
        self.rules.insert(insert_at, rule);
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
}

/// Compile local firewall rules into a PolicyBundle.
///
/// Policy evaluation is src/dst based (not direction-aware). We encode:
/// - inbound rules: src = peer/any, dst = self
/// - outbound rules: src = self, dst = peer/any
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
            }],
            ssh_rules: vec![],
            version: cfg.version,
            signature: String::new(),
        };
    }

    let mut rules = Vec::new();
    let mut priority = 1000i32;
    for fr in &cfg.rules {
        let (src, dst) = match fr.direction {
            FirewallDirection::In => {
                let src = fr
                    .peer
                    .as_ref()
                    .map(|p| Selector::Endpoint(p.clone()))
                    .unwrap_or(Selector::Any);
                let dst = Selector::Endpoint(self_endpoint_hex.to_string());
                (src, dst)
            }
            FirewallDirection::Out => {
                let src = Selector::Endpoint(self_endpoint_hex.to_string());
                let dst = fr
                    .peer
                    .as_ref()
                    .map(|p| Selector::Endpoint(p.clone()))
                    .unwrap_or(Selector::Any);
                (src, dst)
            }
        };
        rules.push(PolicyRule {
            src,
            dst,
            action: fr.action,
            ports: fr.ports.clone(),
            protocol: Some(fr.protocol),
            priority,
        });
        priority -= 1;
    }

    // Allow established-style peer membership traffic at L3 by allowing any
    // to self for ICMP already covered; final catch-all deny.
    rules.push(PolicyRule {
        src: Selector::Any,
        dst: Selector::Endpoint(self_endpoint_hex.to_string()),
        action: Action::Deny,
        ports: vec![],
        protocol: Some(Protocol::Any),
        priority: -1000,
    });

    PolicyBundle {
        rules,
        ssh_rules: vec![],
        version: cfg.version,
        signature: String::new(),
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
