use super::*;
use iroh::address_lookup::memory::MemoryLookup;
use std::net::Ipv4Addr;
use tunnet_common::{DnsConfig, PeerEntry};
use tunnet_core::{AclEngine, PolicyRuntime, RoutingTable, SelfIdentity};
use uuid::Uuid;

const NET_A: Uuid = Uuid::from_u128(10);
const NET_B: Uuid = Uuid::from_u128(11);

fn context(
    local: &Endpoint,
    remote: &Endpoint,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
) -> InboundContext {
    let routes = RoutingTable::new();
    for (network, ip) in [
        (NET_A, remote_ip),
        (NET_B, Ipv4Addr::new(10, 8, 0, remote_ip.octets()[3])),
    ] {
        routes.replace_network(
            network,
            network.as_u128() as u64,
            &[PeerEntry {
                ip,
                endpoint_id: remote.id().to_string(),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            &DnsConfig::default(),
            "test",
            &local.id().to_string(),
            1,
        );
    }
    let identity = SelfIdentity {
        endpoint_hex: local.id().to_string(),
        ip: local_ip,
        tags: vec![],
        network: "test".into(),
    };
    let bundle = tunnet_common::policy::PolicyBundle::default();
    let runtime = PolicyRuntime::bootstrap(&bundle, &HashMap::new(), &identity, true, false);
    let acl = AclEngine::new(identity, routes.clone(), bundle);
    acl.attach_runtime(runtime.clone());
    routes.peer_registry().relink_policy(&runtime);
    InboundContext {
        pool: tunnet_core::ConnPool::new(local.clone(), b"test/stream"),
        routes,
        runtime,
        acl,
        spoofs: HashMap::new(),
        bufs: tunnet_common::packet::PacketPool::new(16),
        metrics: AgentMetrics::for_tests(),
        auth: None,
    }
}

fn packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> LogicalPacket {
    let builder = etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(4242, 4243);
    let mut bytes = Vec::new();
    builder.write(&mut bytes, &vec![7; payload_len]).unwrap();
    LogicalPacket::from_vec(bytes).unwrap()
}

#[test]
fn tie_break_all_orientations() {
    let a = iroh::SecretKey::generate().public();
    let b = iroh::SecretKey::generate().public();
    for (local, remote) in [(a, b), (b, a)] {
        for current in [false, true] {
            for candidate in [false, true] {
                let expected = if current == candidate {
                    !candidate
                } else {
                    candidate == (local < remote)
                };
                assert_eq!(
                    prefer_candidate(local, remote, current, candidate),
                    expected
                );
                if current != candidate {
                    assert_eq!(
                        prefer_candidate(local, remote, current, candidate),
                        prefer_candidate(remote, local, !current, !candidate)
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn queue_is_byte_bounded_and_cancelled_generation_rejects() {
    let metrics = AgentMetrics::for_tests();
    let sender = PeerSender {
        queue: Arc::new(Mutex::new(Queue::default())),
        ready: Arc::new(Notify::new()),
        cancel: CancellationToken::new(),
        metrics,
    };
    let registry = tunnet_core::peers::PeerRegistry::new();
    let endpoint = iroh::SecretKey::generate().public();
    let member = registry.ensure_membership(Arc::new(tunnet_core::peers::PeerIdentity {
        endpoint,
        endpoint_hex: endpoint.to_string(),
        hostname: "peer".into(),
        ip: Ipv4Addr::new(10, 7, 0, 2),
        tags: vec![],
        network_id: NET_A,
        network_name: "test".into(),
    }));
    for _ in 0..1000 {
        sender.enqueue(
            &member,
            packet(Ipv4Addr::new(10, 7, 0, 1), member.identity.read().ip, 1072),
        );
    }
    assert!(sender.queue.lock().bytes <= QUEUE_BYTES);
    assert_eq!(sender.queue.lock().packets.len(), QUEUE_BYTES / 1100);
    drop(sender.next().await);
    assert!(
        sender
            .metrics
            .render()
            .lines()
            .any(|line| line.contains("connection_interrupted") && line.ends_with(" 1")),
        "an unresolved packet is counted once when dropped"
    );
    sender.cancel.cancel();
    sender.clear();
    sender.enqueue(
        &member,
        packet(Ipv4Addr::new(10, 7, 0, 1), member.identity.read().ip, 10),
    );
    assert!(sender.queue.lock().packets.is_empty());
}

async fn receive(rx: &mut mpsc::Receiver<Bytes>) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("packet delivery deadline")
        .expect("TUN sink open")
}

fn accept_loop(
    endpoint: Endpoint,
    peers: PeerTransports,
    stop: CancellationToken,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<Connection>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let incoming = tokio::select! { biased; _ = stop.cancelled() => return, incoming = endpoint.accept() => incoming };
            let Some(incoming) = incoming else {
                return;
            };
            let conn = tokio::select! { biased; _ = stop.cancelled() => return, conn = incoming => conn.expect("handshake") };
            tx.send(conn.clone()).unwrap();
            peers.accept(conn);
        }
    });
    (task, rx)
}

#[tokio::test]
async fn real_iroh_both_directions_network_binding_failure_redial_and_shutdown() {
    let lookup = MemoryLookup::new();
    let profile = tunnet_core::transport_profile::TunnetTransportProfile::default();
    let a = profile
        .apply(Endpoint::builder(iroh::endpoint::presets::Minimal))
        .address_lookup(lookup.clone())
        .alpns(vec![tunnet_common::TUNNEL_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let b = profile
        .apply(Endpoint::builder(iroh::endpoint::presets::Minimal))
        .address_lookup(lookup.clone())
        .alpns(vec![tunnet_common::TUNNEL_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    lookup.add_endpoint_info(a.addr());
    lookup.add_endpoint_info(b.addr());
    let ai = Ipv4Addr::new(10, 7, 0, 1);
    let bi = Ipv4Addr::new(10, 7, 0, 2);
    let ac = context(&a, &b, ai, bi);
    let bc = context(&b, &a, bi, ai);
    let am = ac
        .routes
        .peer_registry()
        .get_membership(b.id(), NET_A)
        .unwrap();
    let bm = bc
        .routes
        .peer_registry()
        .get_membership(a.id(), NET_A)
        .unwrap();
    let am_b = ac
        .routes
        .peer_registry()
        .get_membership(b.id(), NET_B)
        .unwrap();
    let (atx, mut arx) = mpsc::channel(4);
    let (btx, mut brx) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let ap = PeerTransports::new(
        a.clone(),
        ac.clone(),
        TunWriterHandle::new(atx, ac.metrics.clone()),
        stop.child_token(),
        Arc::new(|e| panic!("{e}")),
    );
    let bp = PeerTransports::new(
        b.clone(),
        bc.clone(),
        TunWriterHandle::new(btx, bc.metrics.clone()),
        stop.child_token(),
        Arc::new(|e| panic!("{e}")),
    );
    let (accept_a, _a_connections) = accept_loop(a.clone(), ap.clone(), stop.clone());
    let (accept_b, mut b_connections) = accept_loop(b.clone(), bp.clone(), stop.clone());
    enqueue_packet(&ap, &am, packet(ai, bi, 1072));
    assert_eq!(receive(&mut brx).await.len(), 1100);
    let first = b_connections.recv().await.unwrap();
    assert!(
        first.max_datagram_size().unwrap() >= 1117,
        "minimum configured path must carry MTU plus framing"
    );
    enqueue_packet(&bp, &bm, packet(bi, ai, 8));
    assert_eq!(receive(&mut arx).await.len(), 36);
    enqueue_packet(
        &ap,
        &am_b,
        packet(Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(10, 8, 0, 2), 9),
    );
    assert_eq!(&receive(&mut brx).await[12..16], &[10, 8, 0, 1]);

    // The receiving TUN queue is full; it must not prevent reverse traffic.
    for _ in 0..16 {
        enqueue_packet(&ap, &am, packet(ai, bi, 10));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while brx.len() < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    enqueue_packet(&bp, &bm, packet(bi, ai, 11));
    assert_eq!(receive(&mut arx).await.len(), 39);
    tokio::time::timeout(Duration::from_secs(5), async {
        while am.transport.tx_packets.load(Ordering::Relaxed) < 18 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    first.close(0u32.into(), b"test_failure");
    tokio::time::timeout(Duration::from_secs(5), async {
        while am.transport.connected.load(Ordering::Relaxed)
            || bm.transport.connected.load(Ordering::Relaxed)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    while brx.try_recv().is_ok() {}
    enqueue_packet(&ap, &am, packet(ai, bi, 12));
    assert_eq!(receive(&mut brx).await.len(), 40);
    let second = b_connections.recv().await.unwrap();
    assert_ne!(first.stable_id(), second.stable_id());
    enqueue_packet(&bp, &bm, packet(bi, ai, 13));
    assert_eq!(receive(&mut arx).await.len(), 41);
    ap.shutdown().await;
    bp.shutdown().await;
    assert!(ap.0.peers.lock().is_empty());
    assert!(bp.0.peers.lock().is_empty());
    enqueue_packet(&ap, &am, packet(ai, bi, 14));
    assert!(brx.try_recv().is_err());
    stop.cancel();
    accept_a.await.unwrap();
    accept_b.await.unwrap();
    a.close().await;
    b.close().await;
}
