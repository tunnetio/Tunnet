//! Unified agent configuration (`tuntun.toml`) - single source of truth for
//! node, Direct networks, firewall, DNS, connect allowlist, logging, mDNS, and updates.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tuntun_common::DnsConfig;
use tuntun_common::policy::{PortRange, Protocol};

use crate::direct::contact::parse_contact_id;
use crate::direct::firewall::{
    FirewallAction, FirewallConfig, FirewallDirection, FirewallRule, PeerFilter, default_firewall,
};
use crate::state::{PersistedState, StatePaths};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunTunConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub direct: BTreeMap<String, DirectNetworkSection>,
    #[serde(default)]
    pub connect: ConnectSection,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default)]
    pub mdns: MdnsSection,
    #[serde(default)]
    pub update: UpdateSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeSection {
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectNetworkSection {
    #[serde(default)]
    pub open: bool,
    #[serde(default, rename = "keep-alive")]
    pub keep_alive: bool,
    #[serde(default)]
    pub firewall: DirectFirewallSection,
    #[serde(default)]
    pub dns: DirectDnsSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectFirewallSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<TomlFirewallRule>,
    #[serde(default)]
    pub version: u64,
}

impl Default for DirectFirewallSection {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: vec![],
            version: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlFirewallRule {
    pub direction: String,
    pub protocol: String,
    #[serde(default = "default_allow")]
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<TomlPort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<TomlPort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

fn default_allow() -> String {
    "allow".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TomlPort {
    Single(u16),
    Range(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectDnsSection {
    #[serde(default = "default_magic_ip", rename = "magic-ip")]
    pub magic_ip: Ipv4Addr,
    #[serde(default = "default_tld")]
    pub tld: String,
    #[serde(default = "default_upstream")]
    pub upstream: Vec<IpAddr>,
}

impl Default for DirectDnsSection {
    fn default() -> Self {
        Self {
            magic_ip: default_magic_ip(),
            tld: default_tld(),
            upstream: default_upstream(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectSection {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsSection {
    /// iroh LAN address lookup (Direct mode).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cross-LAN mDNS/DNS-SD service relay over the mesh.
    #[serde(default, rename = "service-relay")]
    pub service_relay: bool,
}

impl Default for MdnsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            service_relay: false,
        }
    }
}

/// Automatic binary updates from GitHub Releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSection {
    /// When true, the agent periodically checks for and applies updates.
    #[serde(default)]
    pub enabled: bool,
    /// How often to poll GitHub Releases (hours). Default 6.
    #[serde(
        default = "default_check_interval_hours",
        rename = "check-interval-hours"
    )]
    pub check_interval_hours: u64,
    /// If the new binary exits/restarts within this window, revert to the previous binary.
    #[serde(default = "default_health_window_secs", rename = "health-window-secs")]
    pub health_window_secs: u64,
}

impl Default for UpdateSection {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_hours: default_check_interval_hours(),
            health_window_secs: default_health_window_secs(),
        }
    }
}

pub fn parse_toml<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, toml::de::Error> {
    let de = match toml::Deserializer::parse(s) {
        Ok(de) => de,
        Err(mut err) => {
            err.set_input(Some(s));
            return Err(err);
        }
    };
    T::deserialize(de).map_err(|mut err| {
        err.set_input(Some(s));
        err
    })
}

fn default_true() -> bool {
    true
}
fn default_check_interval_hours() -> u64 {
    6
}
fn default_health_window_secs() -> u64 {
    30
}
fn default_magic_ip() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 100, 53)
}
fn default_tld() -> String {
    "tuntun".into()
}
fn default_upstream() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "text".into()
}

impl TunTunConfig {
    pub fn load(paths: &StatePaths) -> anyhow::Result<Self> {
        Self::load_path(&paths.config_toml_file())
    }

    pub fn load_path(path: &Path) -> anyhow::Result<Self> {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        parse_toml(&s).with_context(|| format!("parse {}", path.display()))
    }

    pub fn try_load(paths: &StatePaths) -> anyhow::Result<Option<Self>> {
        let path = paths.config_toml_file();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Self::load_path(&path)?))
    }

    pub fn save(&self, paths: &StatePaths) -> anyhow::Result<()> {
        paths.ensure()?;
        let s = toml::to_string_pretty(self).context("serialize tuntun.toml")?;
        std::fs::write(paths.config_toml_file(), s)?;
        Ok(())
    }

    /// Load or create `tuntun.toml` from current Direct/Managed state.
    pub fn ensure(paths: &StatePaths) -> anyhow::Result<Self> {
        if let Some(cfg) = Self::try_load(paths)? {
            return Ok(cfg);
        }
        let cfg = Self::from_persisted(paths)?;
        cfg.save(paths)?;
        Ok(cfg)
    }

    pub fn from_persisted(paths: &StatePaths) -> anyhow::Result<Self> {
        let mut cfg = Self::default();
        let Some(state) = PersistedState::try_load(paths)? else {
            return Ok(cfg);
        };
        match state {
            PersistedState::Direct { networks } => {
                if let Some(d) = networks.first() {
                    cfg.node.hostname = d.hostname.clone();
                }
                for d in &networks {
                    cfg.direct.insert(
                        d.network_name.clone(),
                        DirectNetworkSection {
                            open: d.open,
                            keep_alive: false,
                            firewall: DirectFirewallSection::default(),
                            dns: DirectDnsSection::default(),
                        },
                    );
                }
            }
            PersistedState::Managed(_) => {}
        }
        Ok(cfg)
    }

    /// Upsert Direct network section (create/join). Secrets live in `state.enc`.
    pub fn upsert_direct(
        &mut self,
        network_name: &str,
        hostname: &str,
        open: bool,
        keep_alive: bool,
    ) {
        self.node.hostname = hostname.to_string();
        let entry = self
            .direct
            .entry(network_name.to_string())
            .or_insert_with(|| DirectNetworkSection {
                open,
                keep_alive,
                firewall: DirectFirewallSection::default(),
                dns: DirectDnsSection::default(),
            });
        entry.open = open;
        entry.keep_alive = keep_alive;
    }

    pub fn dns_for_network(&self, network_name: &str) -> DnsConfig {
        self.direct
            .get(network_name)
            .map(|n| n.dns.to_dns_config())
            .unwrap_or_default()
    }

    pub fn firewall_for_network(&self, network_name: &str) -> FirewallConfig {
        self.direct
            .get(network_name)
            .map(|n| n.firewall.to_engine())
            .unwrap_or_else(default_firewall)
    }

    pub fn set_firewall_for_network(&mut self, network_name: &str, fw: &FirewallConfig) {
        let section = self.direct.entry(network_name.to_string()).or_default();
        section.firewall = DirectFirewallSection::from_engine(fw);
    }

    pub fn connect_allowlist(&self) -> HashSet<String> {
        self.connect.allow.iter().cloned().collect()
    }

    pub fn set_connect_allowlist(&mut self, allow: impl IntoIterator<Item = String>) {
        self.connect.allow = allow.into_iter().collect();
        self.connect.allow.sort();
        self.connect.allow.dedup();
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();

        if !self.node.hostname.is_empty() {
            let h = self.node.hostname.as_str();
            if h.len() > 63 || h.contains('.') || h.contains(' ') || h.contains('/') {
                errs.push(format!("invalid hostname: {h}"));
            }
        }

        for (name, net) in &self.direct {
            if net.dns.tld.trim().is_empty() {
                errs.push(format!("direct.{name}.dns: tld must not be empty"));
            }
            for (i, rule) in net.firewall.rules.iter().enumerate() {
                if let Err(e) = rule.validate() {
                    errs.push(format!("direct.{name}.firewall.rules[{i}]: {e}"));
                }
            }
            let mut seen: BTreeMap<String, String> = BTreeMap::new();
            for rule in &net.firewall.rules {
                for pk in rule.port_keys() {
                    let key = format!(
                        "{}|{}|{}|{}",
                        rule.direction,
                        rule.protocol,
                        pk,
                        rule.peer.as_deref().unwrap_or("*")
                    );
                    if let Some(prev) = seen.get(&key)
                        && prev != &rule.action
                    {
                        errs.push(format!(
                            "direct.{name}.firewall: conflicting {prev}/{} for {key}",
                            rule.action
                        ));
                    }
                    seen.insert(key, rule.action.clone());
                }
            }
        }

        for (i, id) in self.connect.allow.iter().enumerate() {
            if let Err(e) = parse_contact_id(id) {
                errs.push(format!("connect.allow[{i}]: {e}"));
            }
        }

        let level = self.logging.level.to_ascii_lowercase();
        if !matches!(
            level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error" | "off"
        ) {
            errs.push(format!("logging.level: invalid level {level}"));
        }
        let fmt = self.logging.format.to_ascii_lowercase();
        if !matches!(fmt.as_str(), "text" | "json") {
            errs.push(format!("logging.format: want text or json, got {fmt}"));
        }

        if self.update.check_interval_hours == 0 {
            errs.push("update.check-interval-hours: must be >= 1".into());
        }
        if self.update.health_window_secs == 0 {
            errs.push("update.health-window-secs: must be >= 1".into());
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }
}

impl DirectDnsSection {
    pub fn to_dns_config(&self) -> DnsConfig {
        DnsConfig {
            suffix: self.tld.clone(),
            upstream: if self.upstream.is_empty() {
                default_upstream()
            } else {
                self.upstream.clone()
            },
            synthetic_base: DnsConfig::default().synthetic_base,
            magic_ip: self.magic_ip,
        }
    }
}

impl DirectFirewallSection {
    pub fn from_engine(fw: &FirewallConfig) -> Self {
        Self {
            enabled: fw.enabled,
            version: fw.version,
            rules: fw.rules.iter().map(TomlFirewallRule::from_engine).collect(),
        }
    }

    pub fn to_engine(&self) -> FirewallConfig {
        let mut rules = Vec::new();
        for r in &self.rules {
            match r.to_engine() {
                Ok(rule) => rules.push(rule),
                Err(e) => tracing::warn!(?e, "skip invalid firewall rule in tuntun.toml"),
            }
        }
        FirewallConfig {
            enabled: self.enabled,
            rules,
            version: self.version.max(1),
        }
    }
}

impl TomlFirewallRule {
    fn from_engine(r: &FirewallRule) -> Self {
        let direction = match r.direction {
            FirewallDirection::In => "in",
            FirewallDirection::Out => "out",
        }
        .to_string();
        let action = match r.action {
            FirewallAction::Allow => "allow",
            FirewallAction::Deny => "deny",
            FirewallAction::Reject => "reject",
        }
        .to_string();
        let protocol = match r.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Any => "any",
        }
        .to_string();
        let ports: Vec<TomlPort> = r
            .ports
            .iter()
            .map(|p| {
                if p.start == p.end {
                    TomlPort::Single(p.start)
                } else {
                    TomlPort::Range(format!("{}-{}", p.start, p.end))
                }
            })
            .collect();
        let peer = match &r.peer {
            PeerFilter::Any => None,
            PeerFilter::Endpoint(s) | PeerFilter::Hostname(s) | PeerFilter::NetworkId(s) => {
                Some(s.clone())
            }
        };
        Self {
            direction,
            protocol,
            action,
            port: None,
            ports,
            peer,
        }
    }

    fn port_keys(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = &self.port {
            out.push(p.key());
        }
        for p in &self.ports {
            out.push(p.key());
        }
        if out.is_empty() {
            out.push("*".into());
        }
        out
    }

    fn validate(&self) -> anyhow::Result<()> {
        match self.direction.to_ascii_lowercase().as_str() {
            "in" | "out" | "inbound" | "outbound" => {}
            other => anyhow::bail!("invalid direction {other}"),
        }
        match self.protocol.to_ascii_lowercase().as_str() {
            "tcp" | "udp" | "icmp" | "any" | "*" => {}
            other => anyhow::bail!("invalid protocol {other}"),
        }
        match self.action.to_ascii_lowercase().as_str() {
            "allow" | "deny" | "reject" => {}
            other => anyhow::bail!("invalid action {other}"),
        }
        if let Some(p) = &self.port {
            p.validate()?;
        }
        for p in &self.ports {
            p.validate()?;
        }
        Ok(())
    }

    fn to_engine(&self) -> anyhow::Result<FirewallRule> {
        let direction = match self.direction.to_ascii_lowercase().as_str() {
            "in" | "inbound" => FirewallDirection::In,
            "out" | "outbound" => FirewallDirection::Out,
            other => anyhow::bail!("invalid direction {other}"),
        };
        let action = match self.action.to_ascii_lowercase().as_str() {
            "allow" => FirewallAction::Allow,
            "deny" => FirewallAction::Deny,
            "reject" => FirewallAction::Reject,
            other => anyhow::bail!("invalid action {other}"),
        };
        let protocol = match self.protocol.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            "any" | "*" => Protocol::Any,
            other => anyhow::bail!("invalid protocol {other}"),
        };
        let mut ports = Vec::new();
        if let Some(p) = &self.port {
            ports.push(p.to_range()?);
        }
        for p in &self.ports {
            ports.push(p.to_range()?);
        }
        let peer = match self.peer.as_deref().unwrap_or("*") {
            "*" | "" | "any" => PeerFilter::Any,
            s if s.starts_with("tt_")
                || (s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) =>
            {
                PeerFilter::Endpoint(s.to_string())
            }
            s => PeerFilter::Hostname(s.to_string()),
        };
        Ok(FirewallRule {
            direction,
            action,
            protocol,
            ports,
            peer,
        })
    }
}

impl TomlPort {
    fn key(&self) -> String {
        match self {
            TomlPort::Single(p) => p.to_string(),
            TomlPort::Range(s) => s.clone(),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        let _ = self.to_range()?;
        Ok(())
    }

    fn to_range(&self) -> anyhow::Result<PortRange> {
        match self {
            TomlPort::Single(p) => {
                if *p == 0 {
                    anyhow::bail!("port must be 1-65535");
                }
                Ok(PortRange { start: *p, end: *p })
            }
            TomlPort::Range(s) => {
                let (a, b) = s
                    .split_once('-')
                    .with_context(|| format!("port range want N-M, got {s}"))?;
                let start: u16 = a.parse().context("port start")?;
                let end: u16 = b.parse().context("port end")?;
                if start == 0 || end == 0 || start > end {
                    anyhow::bail!("invalid port range {s}");
                }
                Ok(PortRange { start, end })
            }
        }
    }
}

/// DNS for the first Direct network, or defaults.
pub fn load_dns(paths: &StatePaths) -> DnsConfig {
    let Ok(cfg) = TunTunConfig::ensure(paths) else {
        return DnsConfig::default();
    };
    if let Ok(Some(PersistedState::Direct { networks })) = PersistedState::try_load(paths)
        && let Some(d) = networks.first()
    {
        return cfg.dns_for_network(&d.network_name);
    }
    cfg.direct
        .values()
        .next()
        .map(|n| n.dns.to_dns_config())
        .unwrap_or_default()
}

/// Firewall for a Direct network by name (from `tuntun.toml` only).
pub fn load_firewall_for(paths: &StatePaths, network_name: &str) -> FirewallConfig {
    let Ok(cfg) = TunTunConfig::ensure(paths) else {
        return default_firewall();
    };
    cfg.firewall_for_network(network_name)
}

/// Firewall for the first Direct network (from `tuntun.toml` only).
pub fn load_firewall(paths: &StatePaths) -> FirewallConfig {
    let Ok(Some(PersistedState::Direct { networks })) = PersistedState::try_load(paths) else {
        return default_firewall();
    };
    let Some(d) = networks.first() else {
        return default_firewall();
    };
    load_firewall_for(paths, &d.network_name)
}

pub fn save_firewall(
    paths: &StatePaths,
    network_name: &str,
    fw: &FirewallConfig,
) -> anyhow::Result<()> {
    let mut cfg = TunTunConfig::ensure(paths)?;
    cfg.set_firewall_for_network(network_name, fw);
    cfg.save(paths)
}

pub fn load_connect_allowlist(paths: &StatePaths) -> HashSet<String> {
    TunTunConfig::ensure(paths)
        .map(|c| c.connect_allowlist())
        .unwrap_or_default()
}

pub fn save_connect_allowlist(
    paths: &StatePaths,
    allow: impl IntoIterator<Item = String>,
) -> anyhow::Result<()> {
    let mut cfg = TunTunConfig::ensure(paths)?;
    cfg.set_connect_allowlist(allow);
    cfg.save(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ok_minimal() {
        let cfg = TunTunConfig {
            node: NodeSection {
                hostname: "laptop".into(),
            },
            direct: BTreeMap::from([(
                "home".into(),
                DirectNetworkSection {
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_port() {
        let cfg = TunTunConfig {
            direct: BTreeMap::from([(
                "home".into(),
                DirectNetworkSection {
                    firewall: DirectFirewallSection {
                        enabled: true,
                        version: 1,
                        rules: vec![TomlFirewallRule {
                            direction: "in".into(),
                            protocol: "tcp".into(),
                            action: "allow".into(),
                            port: Some(TomlPort::Range("70000-70001".into())),
                            ports: vec![],
                            peer: None,
                        }],
                    },
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
