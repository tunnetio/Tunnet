use std::collections::HashMap;
use std::net::Ipv4Addr;

use tunnet_common::policy::{
    Action, DefaultAction, Direction, EvalCtx, EvalReason, EvalVerdict, IcmpPolicy, PolicyBundle,
    PolicyRule, PortRange, Protocol, RuleScope, evaluate_detailed,
};

use crate::ir::PolicyDocument;
use crate::selector::{self, ParsedSelector};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SimulateResult {
    pub verdict: String,
    pub reason: String,
    pub matched_rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub fn simulate(
    doc: &PolicyDocument,
    src: &str,
    dst: &str,
    port: Option<u16>,
    proto: &str,
) -> SimulateResult {
    let (bundle, rule_names) = compile_acl_bundle(doc);
    let protocol = parse_protocol(proto);
    let src_parsed = selector::parse_selector(src).unwrap_or(ParsedSelector::Any);
    let dst_parsed = selector::parse_selector(dst).unwrap_or(ParsedSelector::Any);

    let self_endpoint = selector::simulation_endpoint(&src_parsed)
        .unwrap_or_else(|| "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let peer_endpoint = selector::simulation_endpoint(&dst_parsed)
        .unwrap_or_else(|| "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());

    let self_tags = selector::simulation_tags(&src_parsed);
    let peer_tags = selector::simulation_tags(&dst_parsed);

    let ctx = EvalCtx {
        self_endpoint_hex: &self_endpoint,
        self_ip: Ipv4Addr::new(10, 0, 0, 1),
        self_tags: &self_tags,
        self_network: "",
        peer_endpoint_hex: &peer_endpoint,
        peer_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
        peer_tags: &peer_tags,
        peer_network: "",
        dst_port: port,
        protocol,
        src_posture: tunnet_common::PeerPosture::Unknown,
    };

    let verdict = evaluate_detailed(&bundle, &ctx, Direction::Outbound);
    let matched_rules = matched_names(&verdict, &rule_names, &bundle.rules);
    SimulateResult {
        verdict: match verdict.action {
            Action::Allow => "allow".into(),
            Action::Deny => "deny".into(),
        },
        reason: reason_str(verdict.reason).into(),
        matched_rules,
        rule_slug: verdict.rule_slug,
        scope: verdict.scope.map(|s| match s {
            RuleScope::Organization => "organization".into(),
            RuleScope::Network => "network".into(),
        }),
    }
}

fn reason_str(reason: EvalReason) -> &'static str {
    match reason {
        EvalReason::OrgDeny => "org_deny",
        EvalReason::NetworkDeny => "network_deny",
        EvalReason::NetworkAllow => "network_allow",
        EvalReason::DefaultAllow => "default_allow",
        EvalReason::DefaultDeny => "default_deny",
        EvalReason::IcmpPolicy => "icmp_policy",
        EvalReason::PostureSkip => "posture_skip",
    }
}

fn matched_names(verdict: &EvalVerdict, names: &[String], rules: &[PolicyRule]) -> Vec<String> {
    if matches!(
        verdict.reason,
        EvalReason::DefaultAllow | EvalReason::DefaultDeny
    ) {
        return vec![];
    }
    if verdict.reason == EvalReason::IcmpPolicy {
        return vec!["builtin:icmp".into()];
    }
    if let Some(slug) = &verdict.rule_slug {
        return vec![slug.clone()];
    }
    // Fall back to index lookup when slug missing.
    for (idx, rule) in rules.iter().enumerate() {
        if Some(rule.scope) == verdict.scope
            && matches!(
                (verdict.reason, rule.action),
                (EvalReason::OrgDeny | EvalReason::NetworkDeny, Action::Deny)
                    | (EvalReason::NetworkAllow, Action::Allow)
            )
            && let Some(name) = names.get(idx)
        {
            return vec![name.clone()];
        }
    }
    vec![]
}

pub fn compile_acl_bundle(doc: &PolicyDocument) -> (PolicyBundle, Vec<String>) {
    let mut rules = Vec::new();
    let mut names = Vec::new();
    let postures: HashMap<String, Vec<String>> = doc
        .postures
        .iter()
        .map(|p| (p.name.clone(), p.assertions.clone()))
        .collect();

    for acl in doc.acls.iter().filter(|a| a.enabled) {
        let srcs = if acl.src.is_empty() {
            vec!["*".to_string()]
        } else {
            acl.src.clone()
        };
        let dsts = if acl.dst.is_empty() {
            vec!["*".to_string()]
        } else {
            acl.dst.clone()
        };

        for src in &srcs {
            for dst in &dsts {
                let src_sel = selector::parse_selector(src)
                    .map(|p| selector::to_policy_selector(&p))
                    .unwrap_or(tunnet_common::policy::Selector::Any);
                let dst_sel = selector::parse_selector(dst)
                    .map(|p| selector::to_policy_selector(&p))
                    .unwrap_or(tunnet_common::policy::Selector::Any);

                let scope = match acl.scope.as_deref() {
                    Some("organization") => RuleScope::Organization,
                    _ => RuleScope::Network,
                };

                rules.push(PolicyRule {
                    src: src_sel,
                    dst: dst_sel,
                    action: if acl.action == "deny" {
                        Action::Deny
                    } else {
                        Action::Allow
                    },
                    ports: parse_ports(&acl.ports),
                    protocol: acl.protocol.as_deref().map(parse_protocol),
                    priority: acl.priority,
                    order_index: acl.order_index,
                    scope,
                    enabled: acl.enabled,
                    slug: Some(acl.key().to_string()),
                    src_posture: acl.posture.clone(),
                });
                names.push(acl.key().to_string());
            }
        }
    }

    let default_action = match doc.default_action.as_deref() {
        Some("deny") => DefaultAction::Deny,
        _ => DefaultAction::Allow,
    };
    let icmp_policy = match doc.icmp_policy.as_deref() {
        Some("acl") => IcmpPolicy::Acl,
        Some("deny") => IcmpPolicy::Deny,
        _ => IcmpPolicy::Allow,
    };

    (
        PolicyBundle {
            rules,
            ssh_rules: vec![],
            version: 1,
            signature: String::new(),
            default_action,
            icmp_policy,
            postures,
            default_src_posture: vec![],
            posture_enforcement: None,
        },
        names,
    )
}

fn parse_ports(specs: &[String]) -> Vec<PortRange> {
    let mut out = Vec::new();
    for spec in specs {
        if let Ok(p) = spec.parse::<u16>() {
            out.push(PortRange { start: p, end: p });
        } else if let Some((a, b)) = spec.split_once('-')
            && let (Ok(start), Ok(end)) = (a.parse::<u16>(), b.parse::<u16>())
        {
            out.push(PortRange { start, end });
        }
    }
    out
}

fn parse_protocol(proto: &str) -> Protocol {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "icmpv6" => Protocol::Icmpv6,
        other => other
            .parse::<u8>()
            .map(Protocol::Other)
            .unwrap_or(Protocol::Any),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{AclRule, TagDefinition};

    fn sample_doc() -> PolicyDocument {
        PolicyDocument {
            tags: vec![
                TagDefinition {
                    name: "eng".into(),
                    owners: vec![],
                },
                TagDefinition {
                    name: "staging".into(),
                    owners: vec![],
                },
            ],
            acls: vec![AclRule {
                name: "allow-eng-staging".into(),
                slug: None,
                action: "allow".into(),
                src: vec!["tag:eng".into()],
                dst: vec!["tag:staging".into()],
                ports: vec!["443".into()],
                protocol: Some("tcp".into()),
                priority: 100,
                order_index: 0,
                scope: Some("network".into()),
                posture: vec![],
                labels: Default::default(),
                enabled: true,
            }],
            default_action: Some("deny".into()),
            icmp_policy: Some("allow".into()),
            ..Default::default()
        }
    }

    #[test]
    fn simulate_allow_matching_rule() {
        let doc = sample_doc();
        let result = simulate(&doc, "tag:eng", "tag:staging", Some(443), "tcp");
        assert_eq!(result.verdict, "allow");
        assert_eq!(result.reason, "network_allow");
        assert_eq!(result.matched_rules, vec!["allow-eng-staging"]);
    }

    #[test]
    fn simulate_deny_when_no_match() {
        let doc = PolicyDocument {
            acls: vec![AclRule {
                name: "allow-admin".into(),
                slug: None,
                action: "allow".into(),
                src: vec!["tag:admin".into()],
                dst: vec!["*".into()],
                ports: vec![],
                protocol: None,
                priority: 10,
                order_index: 0,
                scope: Some("network".into()),
                posture: vec![],
                labels: Default::default(),
                enabled: true,
            }],
            default_action: Some("deny".into()),
            ..Default::default()
        };
        let result = simulate(&doc, "tag:guest", "tag:staging", Some(443), "tcp");
        assert_eq!(result.verdict, "deny");
        assert_eq!(result.reason, "default_deny");
    }

    #[test]
    fn org_deny_beats_network_allow() {
        let doc = PolicyDocument {
            acls: vec![
                AclRule {
                    name: "org-deny".into(),
                    slug: None,
                    action: "deny".into(),
                    src: vec!["*".into()],
                    dst: vec!["*".into()],
                    ports: vec![],
                    protocol: None,
                    priority: 0,
                    order_index: 0,
                    scope: Some("organization".into()),
                    posture: vec![],
                    labels: Default::default(),
                    enabled: true,
                },
                AclRule {
                    name: "net-allow".into(),
                    slug: None,
                    action: "allow".into(),
                    src: vec!["*".into()],
                    dst: vec!["*".into()],
                    ports: vec![],
                    protocol: None,
                    priority: 0,
                    order_index: 0,
                    scope: Some("network".into()),
                    posture: vec![],
                    labels: Default::default(),
                    enabled: true,
                },
            ],
            default_action: Some("allow".into()),
            ..Default::default()
        };
        let result = simulate(&doc, "tag:eng", "tag:staging", Some(443), "tcp");
        assert_eq!(result.verdict, "deny");
        assert_eq!(result.reason, "org_deny");
    }
}
