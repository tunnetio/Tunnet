use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use netwatch::{SocketConfig, UdpSocket};

/// Resolves to pending if the inner is `None`.
#[derive(Debug)]
pub(crate) struct MaybeFuture<T> {
    /// Future to be polled.
    pub inner: Option<T>,
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        MaybeFuture { inner: None }
    }
}

impl<T: Future + Unpin> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner {
            Some(ref mut t) => Pin::new(t).poll(cx),
            None => Poll::Pending,
        }
    }
}

pub(crate) fn bind_nat_socket(
    local_ip: Ipv4Addr,
    udp: Option<SocketConfig>,
) -> std::io::Result<UdpSocket> {
    let addr = SocketAddr::from((local_ip, 0));
    match udp {
        Some(config) => UdpSocket::bind_full_with_config(addr, config),
        None => UdpSocket::bind_full(addr),
    }
}

pub(crate) fn authorized_udp(
    udp: Option<[Option<SocketConfig>; 2]>,
) -> std::io::Result<Option<SocketConfig>> {
    match udp {
        None => Ok(None),
        Some(slots) => {
            let config = slots[0].ok_or_else(missing_ipv4)?;
            if config.interface.is_none() && config.initialize.is_none() {
                return Err(missing_ipv4());
            }
            Ok(Some(config))
        }
    }
}

pub(crate) fn authorized_tcp(
    tcp: Option<[Option<netwatch::TcpSocketConfig>; 2]>,
) -> std::io::Result<Option<netwatch::TcpSocketConfig>> {
    match tcp {
        None => Ok(None),
        Some(slots) => {
            let config = slots[0].ok_or_else(missing_ipv4)?;
            if config.interface.is_none() && config.initialize.is_none() {
                return Err(missing_ipv4());
            }
            Ok(Some(config))
        }
    }
}

fn missing_ipv4() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "no authorized NAT underlay for IPv4",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    static DENY: AtomicBool = AtomicBool::new(false);

    fn gate(_: &std::net::UdpSocket) -> std::io::Result<()> {
        if DENY.load(Ordering::SeqCst) {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            ))
        } else {
            Ok(())
        }
    }

    #[tokio::test]
    async fn nat_socket_authority_survives_rebind_and_missing_family() {
        let missing = authorized_udp(Some([None, None])).unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::PermissionDenied);
        let unprotected = authorized_udp(Some([Some(SocketConfig::default()), None])).unwrap_err();
        assert_eq!(unprotected.kind(), std::io::ErrorKind::PermissionDenied);

        DENY.store(false, Ordering::SeqCst);
        let config = Some(SocketConfig {
            interface: None,
            initialize: Some(gate),
        });
        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let socket = bind_nat_socket(Ipv4Addr::LOCALHOST, config).unwrap();
        socket.connect(server.local_addr().unwrap()).unwrap();
        socket.send(b"map").await.unwrap();
        let mut buf = [0; 4];
        let length = tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..length], b"map");

        DENY.store(true, Ordering::SeqCst);
        assert_eq!(
            socket.rebind().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(socket.send(b"again").await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), server.recv(&mut buf))
                .await
                .is_err()
        );
        assert_eq!(
            bind_nat_socket(Ipv4Addr::LOCALHOST, config)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let interface = netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.is_loopback() && iface.index != 0)
            .unwrap();
        let binding =
            netwatch::InterfaceBinding::new(std::num::NonZeroU32::new(interface.index).unwrap())
                .unwrap();
        DENY.store(false, Ordering::SeqCst);
        let socket = bind_nat_socket(
            Ipv4Addr::LOCALHOST,
            Some(SocketConfig {
                interface: Some(binding),
                initialize: None,
            }),
        )
        .unwrap();
        socket.connect(server.local_addr().unwrap()).unwrap();
        socket.send(b"lo").await.unwrap();
        let length = tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..length], b"lo");
    }
}
