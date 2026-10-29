use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Semaphore;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;

use super::types::LocalService;
use crate::forward::{ForwardingStore, PolicyEngine};

const MAX_LISTENERS: usize = 128;
const MAX_SESSIONS: usize = 64;

struct ActiveProxy {
    lan_ip: Ipv4Addr,
    task: AbortOnDropHandle<()>,
}

pub struct ServiceProxy {
    mesh_ip: Ipv4Addr,
    inner: HashMap<u16, ActiveProxy>,
    capacity: Arc<Semaphore>,
    authority: Arc<ProxyAuthority>,
}

struct ProxyAuthority {
    network: uuid::Uuid,
    forwarding: ForwardingStore,
    policy: PolicyEngine,
    tcp: [Option<iroh::endpoint::TcpSocketConfig>; 2],
}

impl ServiceProxy {
    pub fn new(
        mesh_ip: Ipv4Addr,
        network: uuid::Uuid,
        forwarding: ForwardingStore,
        policy: PolicyEngine,
        tcp: [Option<iroh::endpoint::TcpSocketConfig>; 2],
    ) -> Self {
        Self {
            mesh_ip,
            inner: HashMap::new(),
            capacity: Arc::new(Semaphore::new(256)),
            authority: Arc::new(ProxyAuthority {
                network,
                forwarding,
                policy,
                tcp,
            }),
        }
    }

    pub fn ensure(&mut self, svc: &LocalService) {
        self.inner.retain(|_, proxy| !proxy.task.is_finished());
        if self
            .inner
            .get(&svc.port)
            .is_some_and(|proxy| proxy.lan_ip == svc.lan_ip)
        {
            return;
        }
        self.inner.remove(&svc.port);
        if self.inner.len() >= MAX_LISTENERS {
            return;
        }
        match self.start(svc.port, svc.lan_ip) {
            Ok(task) => {
                self.inner.insert(
                    svc.port,
                    ActiveProxy {
                        lan_ip: svc.lan_ip,
                        task,
                    },
                );
            }
            Err(error) => tracing::warn!(port = svc.port, ?error, "service proxy start failed"),
        }
    }

    pub fn remove_for(&mut self, svc: &LocalService) {
        if self
            .inner
            .get(&svc.port)
            .is_some_and(|proxy| proxy.lan_ip == svc.lan_ip)
        {
            self.inner.remove(&svc.port);
        }
    }

    pub async fn shutdown(&mut self) {
        for (_, mut proxy) in self.inner.drain() {
            proxy.task.abort();
            let _ = (&mut proxy.task).await;
        }
    }

    fn start(&self, port: u16, lan_ip: Ipv4Addr) -> anyhow::Result<AbortOnDropHandle<()>> {
        let listener = std::net::TcpListener::bind(SocketAddr::from((self.mesh_ip, port)))?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        Ok(AbortOnDropHandle::new(tokio::spawn(run_listener(
            listener,
            lan_ip,
            port,
            self.capacity.clone(),
            self.authority.clone(),
        ))))
    }
}

async fn run_listener(
    listener: TcpListener,
    lan_ip: Ipv4Addr,
    port: u16,
    capacity: Arc<Semaphore>,
    authority: Arc<ProxyAuthority>,
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept(), if sessions.len() < MAX_SESSIONS => {
                let Ok((inbound, peer)) = accepted else { break };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue };
                let authority = authority.clone();
                sessions.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = proxy_one(inbound, peer, lan_ip, port, &authority).await {
                        tracing::debug!(%peer, ?error, "service proxy session ended");
                    }
                });
            }
        }
    }
}

async fn proxy_one(
    mut inbound: TcpStream,
    source: SocketAddr,
    lan_ip: Ipv4Addr,
    port: u16,
    authority: &ProxyAuthority,
) -> anyhow::Result<()> {
    let source = match source.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => anyhow::bail!("unsupported service source family"),
    };
    let snapshot = authority.forwarding.load();
    let peer = snapshot
        .tables
        .by_network_ip
        .get(&(authority.network, source))
        .ok_or_else(|| anyhow::anyhow!("service source is not a network member"))?
        .endpoint;
    let epoch = snapshot.auth_epoch(authority.network);
    let peer_hex = peer.to_string();
    let allowed = || {
        let snapshot = authority.forwarding.load();
        snapshot.auth_epoch(authority.network) == epoch
            && snapshot.address_isolated(authority.network, lan_ip)
            && crate::stream_proxy::stream_authorization(
                &snapshot,
                &authority.policy,
                authority.network,
                &peer_hex,
                Some(lan_ip),
                port,
            )
            .is_some()
    };
    let config = authority.tcp[0]
        .ok_or_else(|| anyhow::anyhow!("service target has no authorized underlay"))?;
    let proxy = async {
        let mut outbound = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            iroh::endpoint::connect_tcp(SocketAddr::from((lan_ip, port)), config),
        )
        .await??;
        inbound.set_nodelay(true)?;
        outbound.set_nodelay(true)?;
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        anyhow::Ok(())
    };
    tokio::pin!(proxy);
    let guarded = std::future::poll_fn(|cx| {
        let gate = authority.forwarding.authorization_gate();
        let _guard = gate.read();
        if !allowed() {
            return std::task::Poll::Ready(Err(anyhow::anyhow!("service authorization revoked")));
        }
        proxy.as_mut().poll(cx)
    });
    tokio::pin!(guarded);
    let mut changes = authority.forwarding.subscribe_changes();
    let mut expiry_check = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            result = &mut guarded => return result,
            result = changes.changed() => if result.is_err() || !allowed() { anyhow::bail!("service authorization revoked"); },
            _ = expiry_check.tick() => if !allowed() { anyhow::bail!("service authorization expired"); },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[tokio::test]
    async fn listener_owner_and_revocation_close_existing_sessions(#[case] revoke: bool) {
        let routes = crate::routing::RoutingTable::new();
        let network = uuid::Uuid::nil();
        let peer = iroh::SecretKey::from_bytes(&[42; 32]).public().to_string();
        let self_id = iroh::SecretKey::from_bytes(&[43; 32]).public().to_string();
        routes.replace(
            &[tunnet_common::PeerEntry {
                ip: Ipv4Addr::LOCALHOST,
                endpoint_id: peer,
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &[],
            &[],
            &[],
            &Default::default(),
            &Default::default(),
            "test",
            network,
            &self_id,
            1,
        );
        let forwarding = ForwardingStore::new();
        forwarding.set_managed_bundle(
            &routes,
            network,
            Default::default(),
            crate::forward::SelfIdentity {
                endpoint_hex: self_id,
                ip: "127.0.0.2".parse().unwrap(),
                tags: vec![],
                network: "test".into(),
                posture: tunnet_common::PeerPosture::Unknown,
            },
        );
        let authority = Arc::new(ProxyAuthority {
            network,
            forwarding: forwarding.clone(),
            policy: PolicyEngine::new(),
            tcp: [Some(iroh::endpoint::TcpSocketConfig::default()), None],
        });
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = AbortOnDropHandle::new(tokio::spawn(run_listener(
            listener,
            Ipv4Addr::LOCALHOST,
            port,
            Arc::new(Semaphore::new(256)),
            authority,
        )));
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = target.accept().await.unwrap();
        client.write_all(b"open").await.unwrap();
        let mut buffer = [0; 4];
        server.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"open");
        if revoke {
            forwarding.clear_managed(&routes, network);
        } else {
            task.abort();
        }
        for socket in [&mut client, &mut server] {
            let end =
                tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut buffer))
                    .await
                    .unwrap();
            assert!(matches!(end, Ok(0) | Err(_)));
        }
        task.abort();
        let _ = task.await;
        let replacement = TcpListener::bind(address).await.unwrap();
        assert_eq!(replacement.local_addr().unwrap(), address);
    }
}
