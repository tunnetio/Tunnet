use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use hickory_resolver::net::runtime::{
    QuicSocketBinder, RuntimeProvider, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd,
};
use netwatch::{SocketConfig, TcpSocketConfig};
use socket2::{Domain, Socket, Type};

type IoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

#[derive(Clone, Default)]
pub struct NativeHickoryRuntimeProvider {
    executor: TokioRuntimeProvider,
    udp: Option<[Option<SocketConfig>; 2]>,
    tcp: Option<[Option<TcpSocketConfig>; 2]>,
}

impl NativeHickoryRuntimeProvider {
    pub fn new(udp: [Option<SocketConfig>; 2], tcp: [Option<TcpSocketConfig>; 2]) -> Self {
        Self {
            executor: TokioRuntimeProvider::default(),
            udp: Some(udp),
            tcp: Some(tcp),
        }
    }

    pub(crate) fn fresh(&self) -> Self {
        Self {
            executor: TokioRuntimeProvider::default(),
            udp: self.udp,
            tcp: self.tcp,
        }
    }

    fn udp_socket(&self, local: SocketAddr, server: SocketAddr) -> io::Result<std::net::UdpSocket> {
        if local.is_ipv6() != server.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS bind and server families differ",
            ));
        }
        let config = match self.udp {
            Some(configs) => configs[usize::from(server.is_ipv6())].ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no authorized DNS UDP underlay for address family",
                )
            })?,
            None => SocketConfig::default(),
        };
        netwatch::bind_udp(local, server, config)
    }
}

impl RuntimeProvider for NativeHickoryRuntimeProvider {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.executor.create_handle()
    }

    fn bind_udp(&self, local: SocketAddr, server: SocketAddr) -> IoFuture<Self::Udp> {
        let this = self.clone();
        Box::pin(async move { tokio::net::UdpSocket::from_std(this.udp_socket(local, server)?) })
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        wait: Option<Duration>,
    ) -> IoFuture<Self::Tcp> {
        let this = self.clone();
        Box::pin(async move {
            if bind.is_some_and(|bind| bind.is_ipv6() != server.is_ipv6()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS bind and server families differ",
                ));
            }
            let config = match this.tcp {
                Some(configs) => configs[usize::from(server.is_ipv6())].ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "no authorized DNS TCP underlay for address family",
                    )
                })?,
                None => TcpSocketConfig::default(),
            };
            let socket: std::net::TcpStream = Socket::new(
                Domain::for_address(server),
                Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?
            .into();
            netwatch::configure_tcp_socket(&socket, server, config)?;
            socket.set_nonblocking(true)?;
            let socket = tokio::net::TcpSocket::from_std_stream(socket);
            if let Some(bind) = bind {
                socket.bind(bind)?;
            }
            socket.set_nodelay(true)?;
            let stream = tokio::time::timeout(
                wait.unwrap_or(Duration::from_secs(5)),
                socket.connect(server),
            )
            .await??;
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(self)
    }
}

impl QuicSocketBinder for NativeHickoryRuntimeProvider {
    fn bind_quic(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        use quinn::Runtime;
        quinn::TokioRuntime.wrap_udp_socket(self.udp_socket(local, server)?)
    }
}

impl std::fmt::Debug for NativeHickoryRuntimeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeHickoryRuntimeProvider")
            .field("udp", &self.udp)
            .field("tcp", &self.tcp)
            .finish_non_exhaustive()
    }
}
