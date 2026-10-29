use std::net::Ipv4Addr;
use std::time::Instant;

use tunnet_core::forward::frame::{frame, unframe};
use tunnet_core::{ForwardingStore, PolicyEngine, outbound};
use tunnet_core::{RoutingTable, SelfIdentity};
use uuid::Uuid;

const NET: Uuid = Uuid::from_u128(7);
const SELF_HEX: &str = "aa";
const PEER_HEX: &str = "bb";

fn hex(c: &str) -> String {
    c.repeat(32)
}

fn tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let b =
        etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(sport, dport, 1, 1000);
    let mut out = Vec::new();
    b.write(&mut out, payload).unwrap();
    out
}

fn setup() -> (ForwardingStore, PolicyEngine, RoutingTable) {
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
    store.set_managed_bundle(
        &routes,
        NET,
        tunnet_common::policy::PolicyBundle {
            rules: vec![tunnet_common::policy::PolicyRule {
                src: tunnet_common::policy::Selector::Any,
                dst: tunnet_common::policy::Selector::Any,
                action: tunnet_common::policy::Action::Allow,
                ports: vec![],
                protocol: Some(tunnet_common::policy::Protocol::Tcp),
                priority: 100,
                order_index: 0,
                scope: tunnet_common::policy::RuleScope::Network,
                enabled: true,
                slug: Some("bench".into()),
                src_posture: vec![],
            }],
            ssh_rules: vec![],
            version: 1,
            signature: String::new(),
            default_action: tunnet_common::policy::DefaultAction::Deny,
            icmp_policy: tunnet_common::policy::IcmpPolicy::Allow,
            postures: Default::default(),
            default_src_posture: vec![],
            posture_enforcement: None,
        },
        SelfIdentity {
            endpoint_hex: hex(SELF_HEX),
            ip: Ipv4Addr::new(100, 64, 0, 1),
            tags: vec![],
            network: "net".into(),
            posture: tunnet_common::PeerPosture::Unknown,
        },
    );
    (store, PolicyEngine::new(), routes)
}

fn bench(name: &str, iters: u64, f: impl Fn()) {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let dt = start.elapsed();
    println!(
        "{name}: {iters} iters in {:.2}s = {:.0} pkt/s ({:.0} ns/pkt)",
        dt.as_secs_f64(),
        iters as f64 / dt.as_secs_f64(),
        dt.as_nanos() as f64 / iters as f64
    );
}

fn main() {
    let iters = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    println!("tunnet dataplane pipeline bench ({iters} iters)");

    let raw = tcp_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        52_000,
        80,
        &[0u8; 1000],
    );
    bench("packet::parse", iters, || {
        std::hint::black_box(tunnet_common::packet::parse(&raw).unwrap());
    });

    let (store, policy, _routes) = setup();
    let snap = store.load();
    bench("outbound flow-hit", iters, || {
        std::hint::black_box(outbound(&snap, &policy, &raw));
    });

    bench("frame+unframe", iters, || {
        let framed = frame(NET, &raw);
        let (_, ip) = unframe(&framed).unwrap();
        std::hint::black_box(ip.len());
    });
}
