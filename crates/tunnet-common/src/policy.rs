use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::posture::PostureEnforcementConfig;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Network access mode: Open = Allow, Restricted = Deny.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Allow,
    Deny,
}

impl From<DefaultAction> for Action {
    fn from(value: DefaultAction) -> Self {
        match value {
            DefaultAction::Allow => Action::Allow,
            DefaultAction::Deny => Action::Deny,
        }
    }
}

/// How ICMP is handled before/alongside ACL evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IcmpPolicy {
    /// Always allow ICMP (default; ping/PMTU work out of the box).
    #[default]
    Allow,
    /// Evaluate ICMP through the normal ACL phases.
    Acl,
    /// Always deny ICMP.
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleScope {
    Organization,
    #[default]
    Network,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvalReason {
    OrgDeny,
    NetworkDeny,
    NetworkAllow,
    DefaultAllow,
    DefaultDeny,
    IcmpPolicy,
    PostureSkip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalVerdict {
    pub action: Action,
    pub reason: EvalReason,
    pub rule_slug: Option<String>,
    pub scope: Option<RuleScope>,
}

impl EvalVerdict {
    fn icmp(action: Action) -> Self {
        Self {
            action,
            reason: EvalReason::IcmpPolicy,
            rule_slug: None,
            scope: None,
        }
    }

    fn default_action(default: DefaultAction) -> Self {
        match default {
            DefaultAction::Allow => Self {
                action: Action::Allow,
                reason: EvalReason::DefaultAllow,
                rule_slug: None,
                scope: None,
            },
            DefaultAction::Deny => Self {
                action: Action::Deny,
                reason: EvalReason::DefaultDeny,
                rule_slug: None,
                scope: None,
            },
        }
    }

    fn rule(action: Action, reason: EvalReason, rule: &PolicyRule) -> Self {
        Self {
            action,
            reason,
            rule_slug: rule.slug.clone(),
            scope: Some(rule.scope),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    /// Policy wildcard. Never produced by the packet parser.
    Any,
    /// Concrete IP protocol number that is not TCP/UDP/ICMP(v6).
    Other(u8),
}

impl Protocol {
    pub fn from_ip_number(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    pub fn ip_number(self) -> Option<u8> {
        match self {
            Self::Tcp => Some(6),
            Self::Udp => Some(17),
            Self::Icmp => Some(1),
            Self::Icmpv6 => Some(58),
            Self::Any => None,
            Self::Other(n) => Some(n),
        }
    }

    /// `Any` / unset rule protocol matches everything; otherwise require equality.
    pub fn matches_rule(self, rule: Option<Self>) -> bool {
        match rule {
            None | Some(Self::Any) => true,
            Some(p) => p == self,
        }
    }

    pub fn is_icmp(self) -> bool {
        matches!(self, Self::Icmp | Self::Icmpv6)
    }
}

/// Stable selector kinds for Policy-as-Code (IR + wire).
/// Syntax in documents: `tag:X`, `user:email`, `network:name`, CIDR literals.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Selector {
    Any,
    Endpoint(String),
    Tag(String),
    Network(String),
    Cidr(ipnet::IpNet),
    /// User email or id (`user:<email>`).
    User(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub src: Selector,
    pub dst: Selector,
    pub action: Action,
    /// Empty means "any port".
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    /// Legacy priority; `order_index` is primary within an evaluation phase.
    pub priority: i32,
    /// Ascending order within an evaluation phase (first match wins).
    #[serde(default)]
    pub order_index: i32,
    #[serde(default)]
    pub scope: RuleScope,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// Posture definition names required on the source device (OR semantics).
    #[serde(default)]
    pub src_posture: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, p: u16) -> bool {
        p >= self.start && p <= self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub rules: Vec<PolicyRule>,
    /// Application-level SSH access rules (separate from L3/L4 ACL).
    #[serde(default)]
    pub ssh_rules: Vec<SshPolicyRule>,
    pub version: u64,
    /// base64 Ed25519 signature by the control plane's policy key.
    #[serde(default)]
    pub signature: String,
    /// Network access mode when no ACL rule matches.
    #[serde(default)]
    pub default_action: DefaultAction,
    /// ICMP handling before ACL evaluation.
    #[serde(default)]
    pub icmp_policy: IcmpPolicy,
    /// Org posture definitions: name → assertion strings.
    #[serde(default)]
    pub postures: HashMap<String, Vec<String>>,
    /// Default posture names applied to ACL rules without `src_posture`.
    #[serde(default)]
    pub default_src_posture: Vec<String>,
    #[serde(default)]
    pub posture_enforcement: Option<PostureEnforcementConfig>,
}

impl Default for PolicyBundle {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            ssh_rules: Vec::new(),
            version: 0,
            signature: String::new(),
            default_action: DefaultAction::Allow,
            icmp_policy: IcmpPolicy::Allow,
            postures: HashMap::new(),
            default_src_posture: Vec::new(),
            posture_enforcement: None,
        }
    }
}

pub const AUTOGROUP_NONROOT: &str = "autogroup:nonroot";
pub const AUTOGROUP_LOCAL: &str = "autogroup:local";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SshAction {
    Accept,
    Check,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshPolicyRule {
    pub src: Selector,
    pub dst: Selector,
    pub action: SshAction,
    /// POSIX users the src may connect as (literals or autogroups).
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub record: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder: Option<Selector>,
    #[serde(default)]
    pub enforce_recorder: bool,
    /// For `action=check`: how long an IdP re-auth remains valid (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_period_secs: Option<u64>,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct SshEvalCtx<'a> {
    pub src_endpoint_hex: &'a str,
    pub src_tags: &'a [String],
    pub src_network: &'a str,
    pub dst_endpoint_hex: &'a str,
    pub dst_tags: &'a [String],
    pub dst_network: &'a str,
    pub requested_user: &'a str,
    pub local_user: &'a str,
}

/// First matching SSH rule by priority (desc). `None` means implicit deny.
pub fn evaluate_ssh<'a>(
    rules: &'a [SshPolicyRule],
    ctx: &SshEvalCtx<'_>,
) -> Option<&'a SshPolicyRule> {
    let mut sorted: Vec<&SshPolicyRule> = rules.iter().collect();
    sorted.sort_by_key(|rule| std::cmp::Reverse(rule.priority));

    for rule in sorted {
        if !ssh_rule_matches(rule, ctx) {
            continue;
        }
        return Some(rule);
    }
    None
}

fn ssh_rule_matches(rule: &SshPolicyRule, ctx: &SshEvalCtx<'_>) -> bool {
    let src_ok =
        rule.src
            .matches_endpoint(ctx.src_endpoint_hex, ctx.src_tags, ctx.src_network, None);
    let dst_ok =
        rule.dst
            .matches_endpoint(ctx.dst_endpoint_hex, ctx.dst_tags, ctx.dst_network, None);
    if !src_ok || !dst_ok {
        return false;
    }
    ssh_user_allowed(&rule.users, ctx.requested_user, ctx.local_user)
}

fn ssh_user_allowed(users: &[String], requested: &str, local_user: &str) -> bool {
    if users.is_empty() {
        return false;
    }
    users.iter().any(|u| {
        if u == AUTOGROUP_NONROOT {
            requested != "root"
        } else if u == AUTOGROUP_LOCAL {
            requested == local_user
        } else {
            u == requested
        }
    })
}

/// Runtime facts needed to evaluate a rule against a packet or connection.
#[derive(Debug, Clone)]
pub struct EvalCtx<'a> {
    pub self_endpoint_hex: &'a str,
    pub self_ip: Ipv4Addr,
    pub self_tags: &'a [String],
    pub self_network: &'a str,
    pub peer_endpoint_hex: &'a str,
    pub peer_ip: Option<Ipv4Addr>,
    pub peer_tags: &'a [String],
    pub peer_network: &'a str,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    /// When false, rules with non-empty `src_posture` do not match.
    pub src_posture_ok: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv6EvalCtx<'a> {
    pub self_endpoint_hex: &'a str,
    pub self_ipv6: Ipv6Addr,
    pub self_tags: &'a [String],
    pub self_network: &'a str,
    pub peer_endpoint_hex: &'a str,
    pub peer_ipv6: Option<Ipv6Addr>,
    pub peer_tags: &'a [String],
    pub peer_network: &'a str,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    /// When false, rules with non-empty `src_posture` do not match.
    pub src_posture_ok: bool,
}

impl Selector {
    pub fn matches_endpoint(
        &self,
        endpoint_hex: &str,
        tags: &[String],
        network: &str,
        ip: Option<Ipv4Addr>,
    ) -> bool {
        match self {
            Selector::Any => true,
            Selector::Endpoint(id) => id.eq_ignore_ascii_case(endpoint_hex),
            Selector::Tag(t) => tags.iter().any(|x| x == t),
            Selector::Network(n) => n == network,
            Selector::Cidr(net) => ip.is_some_and(|ip| net.contains(&std::net::IpAddr::V4(ip))),
            Selector::User(id) => {
                let marker = format!("user:{id}");
                tags.iter()
                    .any(|x| x == &marker || x.eq_ignore_ascii_case(id))
            }
        }
    }

    pub fn matches_ipv6_endpoint(
        &self,
        endpoint_hex: &str,
        tags: &[String],
        network: &str,
        ipv6: Option<Ipv6Addr>,
    ) -> bool {
        match self {
            Selector::Any => true,
            Selector::Endpoint(id) => id.eq_ignore_ascii_case(endpoint_hex),
            Selector::Tag(t) => tags.iter().any(|x| x == t),
            Selector::Network(n) => n == network,
            Selector::Cidr(net) => ipv6.is_some_and(|ip| net.contains(&std::net::IpAddr::V6(ip))),
            Selector::User(id) => {
                let marker = format!("user:{id}");
                tags.iter()
                    .any(|x| x == &marker || x.eq_ignore_ascii_case(id))
            }
        }
    }
}

/// Merge org-scoped and network-scoped bundles into one effective ruleset.
/// Network `default_action` / `icmp_policy` win; rule scopes are preserved.
pub fn merge_policy_bundles(org: &PolicyBundle, network: &PolicyBundle) -> PolicyBundle {
    let mut rules = Vec::with_capacity(org.rules.len() + network.rules.len());
    for mut rule in org.rules.iter().cloned() {
        rule.scope = RuleScope::Organization;
        rules.push(rule);
    }
    for mut rule in network.rules.iter().cloned() {
        rule.scope = RuleScope::Network;
        rules.push(rule);
    }

    let mut ssh_rules = Vec::with_capacity(org.ssh_rules.len() + network.ssh_rules.len());
    ssh_rules.extend(org.ssh_rules.iter().cloned());
    ssh_rules.extend(network.ssh_rules.iter().cloned());

    let mut postures = org.postures.clone();
    for (k, v) in &network.postures {
        postures.insert(k.clone(), v.clone());
    }

    let default_src_posture = if !network.default_src_posture.is_empty() {
        network.default_src_posture.clone()
    } else {
        org.default_src_posture.clone()
    };

    PolicyBundle {
        rules,
        ssh_rules,
        version: org.version.max(network.version),
        signature: String::new(),
        default_action: network.default_action,
        icmp_policy: network.icmp_policy,
        postures,
        default_src_posture,
        posture_enforcement: network
            .posture_enforcement
            .clone()
            .or_else(|| org.posture_enforcement.clone()),
    }
}

/// Canonical bytes signed by the control plane for a policy bundle.
pub fn policy_bundle_sign_bytes(bundle: &PolicyBundle) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&(
        &bundle.rules,
        &bundle.ssh_rules,
        bundle.version,
        bundle.default_action,
        bundle.icmp_policy,
    ))
}

/// Verify Ed25519 signature on a policy bundle. Empty signature is allowed only
/// when both rule lists are empty (open default). On failure keep last-good.
pub fn verify_policy_bundle_signature(
    bundle: &PolicyBundle,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), crate::ProtocolError> {
    use base64::Engine;
    use ed25519_dalek::Verifier;

    if bundle.signature.is_empty() {
        if bundle.rules.is_empty() && bundle.ssh_rules.is_empty() {
            return Ok(());
        }
        return Err(crate::ProtocolError::BadSignature);
    }

    let sign_bytes =
        policy_bundle_sign_bytes(bundle).map_err(|_| crate::ProtocolError::BadSignature)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(bundle.signature.as_bytes())
        .map_err(|_| crate::ProtocolError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::ProtocolError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&sign_bytes, &sig)
        .map_err(|_| crate::ProtocolError::BadSignature)
}

/// Content hash for drift detection (blake3 hex of canonical IR JSON).
pub fn policy_content_hash(canonical_ir_json: &[u8]) -> String {
    hex::encode(blake3::hash(canonical_ir_json).as_bytes())
}

pub fn evaluate(bundle: &PolicyBundle, ctx: &EvalCtx<'_>, direction: Direction) -> Action {
    evaluate_detailed(bundle, ctx, direction).action
}

/// Structured ACL evaluation (deny always beats allow).
///
/// 1. Organization Deny matches → Deny  
/// 2. Network Deny matches → Deny  
/// 3. Network Allow matches → Allow  
/// 4. Else → network.default_action  
///
/// ICMP is gated by `bundle.icmp_policy` before phases (unless `acl`).
pub fn evaluate_detailed(
    bundle: &PolicyBundle,
    ctx: &EvalCtx<'_>,
    direction: Direction,
) -> EvalVerdict {
    if ctx.protocol == Protocol::Icmp {
        match bundle.icmp_policy {
            IcmpPolicy::Allow => return EvalVerdict::icmp(Action::Allow),
            IcmpPolicy::Deny => return EvalVerdict::icmp(Action::Deny),
            IcmpPolicy::Acl => {}
        }
    }
    evaluate_phases(
        bundle,
        |r, dir| rule_matches_v4(r, ctx, dir),
        direction,
        ctx.src_posture_ok,
    )
}

pub fn evaluate_ipv6(bundle: &PolicyBundle, ctx: &Ipv6EvalCtx<'_>, direction: Direction) -> Action {
    evaluate_ipv6_detailed(bundle, ctx, direction).action
}

pub fn evaluate_ipv6_detailed(
    bundle: &PolicyBundle,
    ctx: &Ipv6EvalCtx<'_>,
    direction: Direction,
) -> EvalVerdict {
    if ctx.protocol == Protocol::Icmp {
        match bundle.icmp_policy {
            IcmpPolicy::Allow => return EvalVerdict::icmp(Action::Allow),
            IcmpPolicy::Deny => return EvalVerdict::icmp(Action::Deny),
            IcmpPolicy::Acl => {}
        }
    }
    evaluate_phases(
        bundle,
        |r, dir| rule_matches_v6(r, ctx, dir),
        direction,
        ctx.src_posture_ok,
    )
}

fn evaluate_phases<F>(
    bundle: &PolicyBundle,
    mut matcher: F,
    direction: Direction,
    src_posture_ok: bool,
) -> EvalVerdict
where
    F: FnMut(&PolicyRule, Direction) -> bool,
{
    let mut posture_skip: Option<&PolicyRule> = None;

    // Phase 1: Organization Deny
    if let Some(rule) = first_matching_in_phase(
        &bundle.rules,
        RuleScope::Organization,
        Action::Deny,
        &mut matcher,
        direction,
        src_posture_ok,
        &mut posture_skip,
    ) {
        return EvalVerdict::rule(Action::Deny, EvalReason::OrgDeny, rule);
    }

    // Phase 2: Network Deny
    if let Some(rule) = first_matching_in_phase(
        &bundle.rules,
        RuleScope::Network,
        Action::Deny,
        &mut matcher,
        direction,
        src_posture_ok,
        &mut posture_skip,
    ) {
        return EvalVerdict::rule(Action::Deny, EvalReason::NetworkDeny, rule);
    }

    // Phase 3: Network Allow (org Allow is not supported in v1)
    if let Some(rule) = first_matching_in_phase(
        &bundle.rules,
        RuleScope::Network,
        Action::Allow,
        &mut matcher,
        direction,
        src_posture_ok,
        &mut posture_skip,
    ) {
        return EvalVerdict::rule(Action::Allow, EvalReason::NetworkAllow, rule);
    }

    if let Some(rule) = posture_skip {
        return EvalVerdict {
            action: bundle.default_action.into(),
            reason: EvalReason::PostureSkip,
            rule_slug: rule.slug.clone(),
            scope: Some(rule.scope),
        };
    }

    EvalVerdict::default_action(bundle.default_action)
}

fn first_matching_in_phase<'a, F>(
    rules: &'a [PolicyRule],
    scope: RuleScope,
    action: Action,
    matcher: &mut F,
    direction: Direction,
    src_posture_ok: bool,
    posture_skip: &mut Option<&'a PolicyRule>,
) -> Option<&'a PolicyRule>
where
    F: FnMut(&PolicyRule, Direction) -> bool,
{
    let mut candidates: Vec<&PolicyRule> = rules
        .iter()
        .filter(|r| r.enabled && r.scope == scope && r.action == action)
        .collect();
    candidates.sort_by(|a, b| {
        a.order_index
            .cmp(&b.order_index)
            .then_with(|| a.priority.cmp(&b.priority))
    });

    for rule in candidates {
        if !matcher(rule, direction) {
            continue;
        }
        if !rule.src_posture.is_empty() && !src_posture_ok {
            if posture_skip.is_none() {
                *posture_skip = Some(rule);
            }
            continue;
        }
        return Some(rule);
    }
    None
}

fn rule_matches_v4(r: &PolicyRule, ctx: &EvalCtx<'_>, direction: Direction) -> bool {
    let (src_ok, dst_ok) = match direction {
        Direction::Inbound => (
            r.src.matches_endpoint(
                ctx.peer_endpoint_hex,
                ctx.peer_tags,
                ctx.peer_network,
                ctx.peer_ip,
            ),
            r.dst.matches_endpoint(
                ctx.self_endpoint_hex,
                ctx.self_tags,
                ctx.self_network,
                Some(ctx.self_ip),
            ),
        ),
        Direction::Outbound => (
            r.src.matches_endpoint(
                ctx.self_endpoint_hex,
                ctx.self_tags,
                ctx.self_network,
                Some(ctx.self_ip),
            ),
            r.dst.matches_endpoint(
                ctx.peer_endpoint_hex,
                ctx.peer_tags,
                ctx.peer_network,
                ctx.peer_ip,
            ),
        ),
    };
    if !src_ok || !dst_ok {
        return false;
    }
    proto_port_ok(r, ctx.protocol, ctx.dst_port)
}

fn rule_matches_v6(r: &PolicyRule, ctx: &Ipv6EvalCtx<'_>, direction: Direction) -> bool {
    let (src_ok, dst_ok) = match direction {
        Direction::Inbound => (
            r.src.matches_ipv6_endpoint(
                ctx.peer_endpoint_hex,
                ctx.peer_tags,
                ctx.peer_network,
                ctx.peer_ipv6,
            ),
            r.dst.matches_ipv6_endpoint(
                ctx.self_endpoint_hex,
                ctx.self_tags,
                ctx.self_network,
                Some(ctx.self_ipv6),
            ),
        ),
        Direction::Outbound => (
            r.src.matches_ipv6_endpoint(
                ctx.self_endpoint_hex,
                ctx.self_tags,
                ctx.self_network,
                Some(ctx.self_ipv6),
            ),
            r.dst.matches_ipv6_endpoint(
                ctx.peer_endpoint_hex,
                ctx.peer_tags,
                ctx.peer_network,
                ctx.peer_ipv6,
            ),
        ),
    };
    if !src_ok || !dst_ok {
        return false;
    }
    proto_port_ok(r, ctx.protocol, ctx.dst_port)
}

fn proto_port_ok(r: &PolicyRule, protocol: Protocol, dst_port: Option<u16>) -> bool {
    if !protocol.matches_rule(r.protocol) {
        return false;
    }
    // ICMP has no L4 port; port-restricted rules must not silently fail to match
    // when the rule protocol is `any` / unset.
    if protocol.is_icmp() {
        return true;
    }
    // Unknown IP protocols have no ports; they only match rules without a port list.
    if matches!(protocol, Protocol::Other(_)) {
        return r.ports.is_empty();
    }
    if !r.ports.is_empty() {
        match dst_port {
            Some(p) if r.ports.iter().any(|pr| pr.contains(p)) => {}
            _ => return false,
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn base_ctx(protocol: Protocol, port: Option<u16>) -> EvalCtx<'static> {
        EvalCtx {
            self_endpoint_hex: "aa",
            self_ip: Ipv4Addr::new(10, 7, 0, 1),
            self_tags: &[],
            self_network: "",
            peer_endpoint_hex: "bb",
            peer_ip: Some(Ipv4Addr::new(10, 7, 0, 2)),
            peer_tags: &[],
            peer_network: "",
            dst_port: port,
            protocol,
            src_posture_ok: true,
        }
    }

    fn rule(
        scope: RuleScope,
        action: Action,
        order_index: i32,
        src: Selector,
        protocol: Option<Protocol>,
    ) -> PolicyRule {
        PolicyRule {
            src,
            dst: Selector::Any,
            action,
            ports: vec![],
            protocol,
            priority: 0,
            order_index,
            scope,
            enabled: true,
            slug: None,
            src_posture: vec![],
        }
    }

    #[test]
    fn empty_policy_uses_default_allow() {
        let ctx = base_ctx(Protocol::Tcp, Some(80));
        let verdict = evaluate_detailed(&PolicyBundle::default(), &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Allow);
        assert_eq!(verdict.reason, EvalReason::DefaultAllow);
    }

    #[test]
    fn empty_policy_uses_default_deny_when_restricted() {
        let ctx = base_ctx(Protocol::Tcp, Some(80));
        let bundle = PolicyBundle {
            default_action: DefaultAction::Deny,
            ..PolicyBundle::default()
        };
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Deny);
        assert_eq!(verdict.reason, EvalReason::DefaultDeny);
    }

    #[test]
    fn icmp_policy_allow_bypasses_acl() {
        let bundle = PolicyBundle {
            default_action: DefaultAction::Deny,
            icmp_policy: IcmpPolicy::Allow,
            rules: vec![rule(
                RuleScope::Network,
                Action::Deny,
                0,
                Selector::Any,
                None,
            )],
            ..PolicyBundle::default()
        };
        let ctx = base_ctx(Protocol::Icmp, None);
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Allow);
        assert_eq!(verdict.reason, EvalReason::IcmpPolicy);
    }

    #[test]
    fn icmp_policy_deny_blocks() {
        let bundle = PolicyBundle {
            icmp_policy: IcmpPolicy::Deny,
            ..PolicyBundle::default()
        };
        let ctx = base_ctx(Protocol::Icmp, None);
        assert_eq!(
            evaluate_detailed(&bundle, &ctx, Direction::Outbound).action,
            Action::Deny
        );
    }

    #[test]
    fn icmp_policy_acl_evaluates_rules() {
        let bundle = PolicyBundle {
            default_action: DefaultAction::Deny,
            icmp_policy: IcmpPolicy::Acl,
            rules: vec![rule(
                RuleScope::Network,
                Action::Allow,
                0,
                Selector::Any,
                Some(Protocol::Icmp),
            )],
            ..PolicyBundle::default()
        };
        let ctx = base_ctx(Protocol::Icmp, None);
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Allow);
        assert_eq!(verdict.reason, EvalReason::NetworkAllow);
    }

    #[test]
    fn org_deny_beats_network_allow() {
        let bundle = PolicyBundle {
            rules: vec![
                rule(
                    RuleScope::Organization,
                    Action::Deny,
                    10,
                    Selector::Any,
                    None,
                ),
                rule(RuleScope::Network, Action::Allow, 0, Selector::Any, None),
            ],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        };
        let ctx = base_ctx(Protocol::Tcp, Some(80));
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Deny);
        assert_eq!(verdict.reason, EvalReason::OrgDeny);
    }

    #[test]
    fn network_deny_beats_network_allow() {
        let bundle = PolicyBundle {
            rules: vec![
                rule(RuleScope::Network, Action::Deny, 5, Selector::Any, None),
                rule(RuleScope::Network, Action::Allow, 0, Selector::Any, None),
            ],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        };
        let ctx = base_ctx(Protocol::Tcp, Some(80));
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.action, Action::Deny);
        assert_eq!(verdict.reason, EvalReason::NetworkDeny);
    }

    #[test]
    fn order_index_ascending_first_match() {
        let mut early = rule(
            RuleScope::Network,
            Action::Allow,
            1,
            Selector::Tag("a".into()),
            None,
        );
        early.slug = Some("first".into());
        let mut late = rule(
            RuleScope::Network,
            Action::Allow,
            2,
            Selector::Tag("a".into()),
            None,
        );
        late.slug = Some("second".into());
        let bundle = PolicyBundle {
            rules: vec![late, early],
            default_action: DefaultAction::Deny,
            ..PolicyBundle::default()
        };
        let mut ctx = base_ctx(Protocol::Tcp, Some(80));
        let tags = vec!["a".to_string()];
        ctx.self_tags = &tags;
        let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
        assert_eq!(verdict.rule_slug.as_deref(), Some("first"));
    }

    #[test]
    fn unmatched_network_allow_falls_to_default() {
        let ctx = base_ctx(Protocol::Tcp, Some(80));
        let bundle = PolicyBundle {
            rules: vec![rule(
                RuleScope::Network,
                Action::Allow,
                0,
                Selector::Tag("admin".into()),
                None,
            )],
            default_action: DefaultAction::Deny,
            ..PolicyBundle::default()
        };
        assert_eq!(evaluate(&bundle, &ctx, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn ipv6_uses_same_default_action() {
        let ctx = Ipv6EvalCtx {
            self_endpoint_hex: "aa",
            self_ipv6: Ipv6Addr::LOCALHOST,
            self_tags: &[],
            self_network: "",
            peer_endpoint_hex: "bb",
            peer_ipv6: Some(Ipv6Addr::LOCALHOST),
            peer_tags: &[],
            peer_network: "",
            dst_port: None,
            protocol: Protocol::Any,
            src_posture_ok: true,
        };
        assert_eq!(
            evaluate_ipv6(&PolicyBundle::default(), &ctx, Direction::Outbound),
            Action::Allow
        );
        let restricted = PolicyBundle {
            default_action: DefaultAction::Deny,
            ..PolicyBundle::default()
        };
        assert_eq!(
            evaluate_ipv6(&restricted, &ctx, Direction::Outbound),
            Action::Deny
        );
    }

    #[test]
    fn ssh_tag_rule_accepts_matching_user() {
        let rules = vec![SshPolicyRule {
            src: Selector::Tag("admin".into()),
            dst: Selector::Tag("server".into()),
            action: SshAction::Accept,
            users: vec!["root".into()],
            record: false,
            recorder: None,
            enforce_recorder: false,
            check_period_secs: None,
            priority: 10,
        }];
        let ctx = SshEvalCtx {
            src_endpoint_hex: "aa",
            src_tags: &["admin".into()],
            src_network: "prod",
            dst_endpoint_hex: "bb",
            dst_tags: &["server".into()],
            dst_network: "prod",
            requested_user: "root",
            local_user: "oriel",
        };
        let matched = evaluate_ssh(&rules, &ctx).unwrap();
        assert_eq!(matched.action, SshAction::Accept);
    }

    #[test]
    fn ssh_autogroup_nonroot_rejects_root() {
        let rules = vec![SshPolicyRule {
            src: Selector::Any,
            dst: Selector::Any,
            action: SshAction::Accept,
            users: vec![AUTOGROUP_NONROOT.into()],
            record: false,
            recorder: None,
            enforce_recorder: false,
            check_period_secs: None,
            priority: 1,
        }];
        let ctx = SshEvalCtx {
            src_endpoint_hex: "aa",
            src_tags: &[],
            src_network: "prod",
            dst_endpoint_hex: "bb",
            dst_tags: &[],
            dst_network: "prod",
            requested_user: "root",
            local_user: "oriel",
        };
        assert!(evaluate_ssh(&rules, &ctx).is_none());
    }

    fn sample_rule(tag: &str, priority: i32) -> PolicyRule {
        PolicyRule {
            src: Selector::Tag(tag.into()),
            dst: Selector::Any,
            action: Action::Allow,
            ports: vec![],
            protocol: None,
            priority,
            order_index: 0,
            scope: RuleScope::Network,
            enabled: true,
            slug: None,
            src_posture: vec![],
        }
    }

    #[test]
    fn merge_policy_bundles_sets_scopes_and_network_defaults() {
        let mut org_postures = HashMap::new();
        org_postures.insert("os".into(), vec!["linux".into()]);
        let mut network_postures = HashMap::new();
        network_postures.insert("disk".into(), vec!["encrypted".into()]);

        let org = PolicyBundle {
            rules: vec![sample_rule("org", 10)],
            ssh_rules: vec![],
            version: 3,
            signature: "org-sig".into(),
            default_action: DefaultAction::Allow,
            icmp_policy: IcmpPolicy::Allow,
            postures: org_postures,
            default_src_posture: vec!["os".into()],
            posture_enforcement: None,
        };
        let network = PolicyBundle {
            rules: vec![sample_rule("net", 20)],
            ssh_rules: vec![],
            version: 7,
            signature: "net-sig".into(),
            default_action: DefaultAction::Deny,
            icmp_policy: IcmpPolicy::Acl,
            postures: network_postures,
            default_src_posture: vec![],
            posture_enforcement: None,
        };

        let merged = merge_policy_bundles(&org, &network);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].scope, RuleScope::Organization);
        assert_eq!(merged.rules[1].scope, RuleScope::Network);
        assert_eq!(merged.default_action, DefaultAction::Deny);
        assert_eq!(merged.icmp_policy, IcmpPolicy::Acl);
        assert_eq!(merged.version, 7);
        assert_eq!(merged.signature, "");
        assert_eq!(merged.default_src_posture, vec!["os".to_string()]);
    }

    #[test]
    fn verify_policy_bundle_signature_round_trip_and_tamper() {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let mut bundle = PolicyBundle {
            rules: vec![sample_rule("admin", 5)],
            ssh_rules: vec![],
            version: 2,
            signature: String::new(),
            default_action: DefaultAction::Allow,
            icmp_policy: IcmpPolicy::Allow,
            postures: HashMap::new(),
            default_src_posture: vec![],
            posture_enforcement: None,
        };

        let sign_bytes = policy_bundle_sign_bytes(&bundle).unwrap();
        let sig = signing_key.sign(&sign_bytes);
        bundle.signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        assert!(verify_policy_bundle_signature(&bundle, &verifying_key).is_ok());

        bundle.rules[0].priority = 99;
        assert!(matches!(
            verify_policy_bundle_signature(&bundle, &verifying_key),
            Err(crate::ProtocolError::BadSignature)
        ));
    }

    #[test]
    fn verify_empty_signature_only_ok_with_empty_rules() {
        use ed25519_dalek::SigningKey;

        let verifying_key = SigningKey::generate(&mut rand::rng()).verifying_key();

        let empty = PolicyBundle::default();
        assert!(verify_policy_bundle_signature(&empty, &verifying_key).is_ok());

        let nonempty = PolicyBundle {
            rules: vec![sample_rule("x", 1)],
            ssh_rules: vec![],
            version: 1,
            signature: String::new(),
            default_action: DefaultAction::Allow,
            icmp_policy: IcmpPolicy::Allow,
            postures: HashMap::new(),
            default_src_posture: vec![],
            posture_enforcement: None,
        };
        assert!(matches!(
            verify_policy_bundle_signature(&nonempty, &verifying_key),
            Err(crate::ProtocolError::BadSignature)
        ));
    }
}
