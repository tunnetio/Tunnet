use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Instant;

use bytes::Bytes;
use tunnet_core::forward::frame::{frame, unframe};
use tunnet_core::{ForwardingStore, PeerManager, PolicyEngine, outbound};
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        queue_bench(&raw, iters.min(50_000)).await;
        transport_bench().await;
    });
}

async fn queue_bench(raw: &[u8], iters: u64) {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .bind()
        .await
        .expect("bind bench endpoint");
    let peers = PeerManager::new(endpoint, b"tunnet/bench");
    peers.activate(1, tokio_util::sync::CancellationToken::new());
    let ids: Vec<iroh::EndpointId> = (0..256)
        .map(|_| iroh::SecretKey::generate().public())
        .collect();
    let start = Instant::now();
    let mut admitted = 0u64;
    for i in 0..iters {
        let varied = ids[(i as usize) % ids.len()];
        let out = peers.send_batch(varied, vec![Bytes::copy_from_slice(&raw[..128])]);
        admitted += out.admitted as u64;
    }
    let dt = start.elapsed();
    println!(
        "session queue admit: {iters} iters in {:.2}s = {:.0} pkt/s ({admitted} admitted)",
        dt.as_secs_f64(),
        iters as f64 / dt.as_secs_f64(),
    );
}

async fn transport_bench() {
    const ALPN: &[u8] = b"tunnet/bench";
    const COUNT: usize = 500;
    const SIZE: usize = 1000;
    let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind server");
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .bind()
        .await
        .expect("bind client");
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<usize>(1);
    tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.await.expect("handshake");
            let mut batch: [Bytes; 32] = std::array::from_fn(|_| Bytes::new());
            let mut total = 0usize;
            let mut bytes = 0u64;
            while total < COUNT {
                let n = conn.read_many_datagrams(&mut batch).await.expect("read");
                for dg in &batch[..n] {
                    total += 1;
                    bytes += dg.len() as u64;
                }
                batch[n..].fill(Bytes::new());
            }
            let _ = done_tx.send(bytes as usize).await;
        }
    });
    let conn = client.connect(server.addr(), ALPN).await.expect("connect");
    println!(
        "quic loopback max_datagram_size: {:?}",
        conn.max_datagram_size()
    );
    let mut queue: VecDeque<Bytes> = (0..COUNT).map(|_| Bytes::from(vec![0u8; SIZE])).collect();
    let start = Instant::now();
    let out = tunnet_core::peer::send_datagram_batch(&conn, &mut queue).await;
    let dt = start.elapsed();
    let bytes = done_rx.recv().await.unwrap_or(0);
    assert_eq!(out.accepted, COUNT);
    assert_eq!(bytes, COUNT * SIZE);
    let mbps = bytes as f64 * 8.0 / dt.as_secs_f64() / 1e6;
    println!(
        "quic loopback batch drain: {COUNT}x{SIZE}B in {:.2}s = {:.1} Mbps ({:.0} pkt/s)",
        dt.as_secs_f64(),
        mbps,
        COUNT as f64 / dt.as_secs_f64()
    );
}
