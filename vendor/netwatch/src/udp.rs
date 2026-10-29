#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, RwLock, RwLockReadGuard, TryLockError,
        atomic::{AtomicBool, AtomicUsize},
    },
    task::{Context, Poll},
};

use atomic_waker::AtomicWaker;
use noq_udp::Transmit;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Wrapper around a tokio UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<SocketState>,
    config: SocketConfig,
    gso_limit: AtomicUsize,
    recv_waker: AtomicWaker,
    send_waker: AtomicWaker,
    /// Set to true, when an error occurred, that means we need to rebind the socket.
    is_broken: AtomicBool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InterfaceBinding {
    index: NonZeroU32,
    #[cfg(windows)]
    luid: u64,
    #[cfg(not(windows))]
    name: [libc::c_char; libc::IF_NAMESIZE],
}

impl InterfaceBinding {
    pub fn ipv4_address(self) -> io::Result<std::net::Ipv4Addr> {
        self.index_for_family(IpFamily::V4)?;
        #[cfg(netdev)]
        {
            netdev::get_interfaces()
                .into_iter()
                .find(|iface| iface.index == self.index.get())
                .and_then(|iface| iface.ipv4.first().map(|ip| ip.addr()))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "underlay IPv4 address disappeared")
                })
        }
        #[cfg(not(netdev))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interface address discovery unsupported",
        ))
    }
    fn for_destination(self, destination: SocketAddr) -> io::Result<Self> {
        if !destination.ip().is_loopback() {
            return Ok(self);
        }
        #[cfg(netdev)]
        {
            let index = netdev::get_interfaces()
                .into_iter()
                .find(|iface| {
                    iface.is_loopback()
                        && iface.is_up()
                        && if destination.is_ipv4() {
                            !iface.ipv4.is_empty()
                        } else {
                            !iface.ipv6.is_empty()
                        }
                })
                .and_then(|iface| NonZeroU32::new(iface.index))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no loopback underlay interface")
                })?;
            Self::new(index)
        }
        #[cfg(not(netdev))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "loopback interface discovery unsupported",
        ))
    }

    pub fn new(index: NonZeroU32) -> io::Result<Self> {
        #[cfg(windows)]
        {
            use windows::Win32::NetworkManagement::{
                IpHelper::ConvertInterfaceIndexToLuid, Ndis::NET_LUID_LH,
            };
            let mut luid = NET_LUID_LH::default();
            let error = unsafe { ConvertInterfaceIndexToLuid(index.get(), &mut luid) };
            if error.0 != 0 {
                return Err(io::Error::from_raw_os_error(error.0 as i32));
            }
            Ok(Self {
                index,
                luid: unsafe { luid.Value },
            })
        }
        #[cfg(not(windows))]
        {
            let mut name = [0; libc::IF_NAMESIZE];
            if unsafe { libc::if_indextoname(index.get(), name.as_mut_ptr()) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { index, name })
        }
    }

    pub fn index_for_family(self, family: IpFamily) -> io::Result<NonZeroU32> {
        let current = Self::new(self.index)?;
        #[cfg(not(windows))]
        {
            let _ = family;
            if current.name != self.name {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "underlay interface identity changed",
                ));
            }
            Ok(self.index)
        }
        #[cfg(windows)]
        {
            use windows::Win32::{
                NetworkManagement::{
                    IpHelper::{GetIpInterfaceEntry, MIB_IPINTERFACE_ROW},
                    Ndis::NET_LUID_LH,
                },
                Networking::WinSock::{AF_INET, AF_INET6},
            };
            if current.luid != self.luid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "underlay interface identity changed",
                ));
            }
            let mut row = MIB_IPINTERFACE_ROW {
                Family: if family == IpFamily::V4 {
                    AF_INET
                } else {
                    AF_INET6
                },
                InterfaceLuid: NET_LUID_LH { Value: self.luid },
                ..Default::default()
            };
            let error = unsafe { GetIpInterfaceEntry(&mut row) };
            if error.0 != 0 {
                return Err(io::Error::from_raw_os_error(error.0 as i32));
            }
            NonZeroU32::new(row.InterfaceIndex).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "underlay address family disappeared",
                )
            })
        }
    }
}

/// Applied before exposing each newly created or rebound socket.
#[derive(Debug, Copy, Clone, Default)]
pub struct SocketConfig {
    /// The native interface used for UDP egress.
    pub interface: Option<InterfaceBinding>,
    /// Platform socket authorization, including Android VpnService protection.
    pub initialize: Option<fn(&std::net::UdpSocket) -> io::Result<()>>,
}

#[derive(Debug, Copy, Clone, Default)]
pub struct TcpSocketConfig {
    pub interface: Option<InterfaceBinding>,
    pub initialize: Option<fn(&std::net::TcpStream) -> io::Result<()>>,
}

pub fn configure_udp_socket(
    socket: &std::net::UdpSocket,
    family: IpFamily,
    config: SocketConfig,
) -> io::Result<()> {
    if let Some(interface) = config.interface {
        bind_interface(
            &socket2::SockRef::from(socket),
            family,
            interface.index_for_family(family)?,
        )?;
    }
    if let Some(initialize) = config.initialize {
        initialize(socket)?;
    }
    Ok(())
}

pub fn bind_udp(
    addr: SocketAddr,
    destination: SocketAddr,
    config: SocketConfig,
) -> io::Result<std::net::UdpSocket> {
    let family = IpFamily::from(addr.ip());
    let socket = socket2::Socket::new(
        family.into(),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if family == IpFamily::V6 {
        socket.set_only_v6(true)?;
    }
    if let Some(interface) = config.interface {
        bind_interface(
            &socket,
            family,
            interface
                .for_destination(destination)?
                .index_for_family(family)?,
        )?;
    }
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    if let Some(initialize) = config.initialize {
        initialize(&socket)?;
    }
    socket2::SockRef::from(&socket).bind(&addr.into())?;
    Ok(socket)
}

pub fn configure_tcp_socket(
    socket: &std::net::TcpStream,
    destination: SocketAddr,
    config: TcpSocketConfig,
) -> io::Result<()> {
    if let Some(interface) = config.interface {
        bind_interface(
            &socket2::SockRef::from(socket),
            IpFamily::from(destination.ip()),
            interface
                .for_destination(destination)?
                .index_for_family(IpFamily::from(destination.ip()))?,
        )?;
    }
    if let Some(initialize) = config.initialize {
        initialize(socket)?;
    }
    Ok(())
}

pub async fn connect_tcp(
    addr: SocketAddr,
    config: TcpSocketConfig,
) -> io::Result<tokio::net::TcpStream> {
    let family = IpFamily::from(addr.ip());
    let socket = socket2::Socket::new(
        family.into(),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    let socket: std::net::TcpStream = socket.into();
    configure_tcp_socket(&socket, addr, config)?;
    tokio::net::TcpSocket::from_std_stream(socket)
        .connect(addr)
        .await
}

#[cfg(target_os = "linux")]
fn bind_interface(socket: &socket2::Socket, _: IpFamily, interface: NonZeroU32) -> io::Result<()> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // The array holds IF_NAMESIZE writable bytes.
    if unsafe { libc::if_indextoname(interface.get(), name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    socket.bind_device(Some(name.to_bytes()))
}

#[cfg(target_os = "windows")]
fn bind_interface(
    socket: &socket2::Socket,
    family: IpFamily,
    interface: NonZeroU32,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, WSAGetLastError,
        setsockopt,
    };
    let (level, option, value) = if family == IpFamily::V4 {
        (IPPROTO_IP.0, IP_UNICAST_IF, interface.get().to_be_bytes())
    } else {
        (
            IPPROTO_IPV6.0,
            IPV6_UNICAST_IF,
            interface.get().to_ne_bytes(),
        )
    };
    // Winsock reads the four-byte native interface option synchronously.
    if unsafe {
        setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            level,
            option,
            Some(&value),
        )
    } != 0
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn bind_interface(
    socket: &socket2::Socket,
    family: IpFamily,
    interface: NonZeroU32,
) -> io::Result<()> {
    if family == IpFamily::V4 {
        socket.bind_device_by_index_v4(Some(interface))
    } else {
        socket.bind_device_by_index_v6(Some(interface))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
)))]
fn bind_interface(_: &socket2::Socket, _: IpFamily, _: NonZeroU32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native interface binding unsupported; supply platform socket initialization",
    ))
}

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the max supported by a default configuration of macOS. Some platforms will silently clamp the value.
const SOCKET_BUFFER_SIZE: usize = 7 << 20;

/// Opts the socket in to receiving on restricted interfaces.
///
/// Apple delivers traffic arriving on restricted interfaces, AWDL (`awdl0`)
/// among them, only to sockets that set `SO_RECV_ANYIF`. Without it a peer
/// dialing our `fe80::…%awdl0` address never reaches us, even though the link
/// itself works.
#[cfg(target_vendor = "apple")]
fn set_recv_anyif(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    /// From `<sys/socket.h>`; not exported by `libc`.
    const SO_RECV_ANYIF: libc::c_int = 0x1104;
    let one: libc::c_int = 1;
    // SAFETY: the fd is open for the lifetime of `socket`, and `optval` points
    // to a `c_int` of the length passed.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RECV_ANYIF,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(
    rustdoc::broken_intra_doc_links,
    reason = "AsFd and AsSocket are only conditionally imported based on the target"
)]
/// A socket that is about to be bound, handed to the hook set with
/// [`BindOptions::configure_socket`].
///
/// It implements [`AsFd`] on unix and [`AsSocket`] on Windows, which is what
/// socket wrappers take, so the hook can set options with the socket crate of
/// its choice: `socket2::SockRef::from(&socket)`, or plain `libc::setsockopt`
/// on the raw fd.
#[derive(Debug)]
pub struct SocketRef<'a>(&'a socket2::Socket);

#[cfg(unix)]
impl AsFd for SocketRef<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(windows)]
impl AsSocket for SocketRef<'_> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.0.as_socket()
    }
}

/// The hook set with [`BindOptions::configure_socket`].
type Configurator = Arc<dyn Fn(SocketRef<'_>, IpFamily) -> io::Result<()> + Send + Sync>;

/// Options to bind a [`UdpSocket`] with.
///
/// Used by [`UdpSocket::bind_with`]. The default options match what the other
/// `bind_*` constructors use.
#[derive(derive_more::Debug, Default, Clone)]
pub struct BindOptions {
    #[debug(skip)]
    configure: Option<Configurator>,
}

impl BindOptions {
    /// Creates the default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a hook to run on the socket just before it is bound.
    ///
    /// This is the escape hatch for socket options this crate does not model
    /// itself, like `SO_MARK` on Linux or `IP_BOUND_IF` on Apple platforms. The
    /// hook runs on every bind, including the rebinds [`UdpSocket`] does to
    /// recover from network changes, since each of those creates a new socket.
    /// That also lets the hook pick up state that changed in between, like the
    /// interface the default route now points at.
    ///
    /// An error from the hook fails the bind, rather than leaving a socket that
    /// silently missed its configuration.
    ///
    /// ```no_run
    /// use std::net::{Ipv4Addr, SocketAddr};
    ///
    /// use netwatch::{BindOptions, UdpSocket};
    ///
    /// let opts = BindOptions::new().configure_socket(|socket, _family| {
    ///     socket2::SockRef::from(&socket).set_recv_buffer_size(1 << 20)
    /// });
    /// let socket = UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn configure_socket(
        mut self,
        configure: impl Fn(SocketRef<'_>, IpFamily) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.configure = Some(Arc::new(configure));
        self
    }
}

impl UdpSocket {
    /// Bind only Ipv4 on any interface.
    pub fn bind_v4(port: u16) -> io::Result<Self> {
        Self::bind(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on any interface.
    pub fn bind_v6(port: u16) -> io::Result<Self> {
        Self::bind(IpFamily::V6, port)
    }

    /// Bind only Ipv4 on localhost.
    pub fn bind_local_v4(port: u16) -> io::Result<Self> {
        Self::bind_local(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on localhost.
    pub fn bind_local_v6(port: u16) -> io::Result<Self> {
        Self::bind_local(IpFamily::V6, port)
    }

    /// Bind to the given port only on localhost.
    pub fn bind_local(network: IpFamily, port: u16) -> io::Result<Self> {
        let addr = SocketAddr::new(network.local_addr(), port);
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to the given port and listen on all interfaces.
    pub fn bind(network: IpFamily, port: u16) -> io::Result<Self> {
        let addr = SocketAddr::new(network.unspecified_addr(), port);
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to any provided [`SocketAddr`].
    pub fn bind_full(addr: impl Into<SocketAddr>) -> io::Result<Self> {
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to any provided [`SocketAddr`], using the given [`BindOptions`].
    pub fn bind_with(addr: impl Into<SocketAddr>, opts: BindOptions) -> io::Result<Self> {
        let socket = SocketState::bind(addr.into(), SocketConfig::default(), opts.configure)?;

        Ok(UdpSocket {
            socket: RwLock::new(socket),
            config: SocketConfig::default(),
            gso_limit: AtomicUsize::new(usize::MAX),
            recv_waker: AtomicWaker::default(),
            send_waker: AtomicWaker::default(),
            is_broken: AtomicBool::new(false),
        })
    }

    /// Binds a socket whose native configuration survives every rebind.
    pub fn bind_full_with_config(
        addr: impl Into<SocketAddr>,
        config: SocketConfig,
    ) -> io::Result<Self> {
        let socket = SocketState::bind(addr.into(), config, None)?;
        Ok(Self {
            socket: RwLock::new(socket),
            config,
            gso_limit: AtomicUsize::new(usize::MAX),
            recv_waker: AtomicWaker::default(),
            send_waker: AtomicWaker::default(),
            is_broken: AtomicBool::new(false),
        })
    }

    /// Is the socket broken and needs a rebind?
    pub fn is_broken(&self) -> bool {
        self.is_broken.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Marks this socket as needing a rebind
    fn mark_broken(&self) {
        self.is_broken
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Rebind the underlying socket.
    pub fn rebind(&self) -> io::Result<()> {
        {
            let mut guard = self.socket.write().unwrap();
            self.gso_limit.fetch_min(
                guard.max_gso_segments().get(),
                std::sync::atomic::Ordering::Relaxed,
            );
            guard.rebind(self.config)?;

            // Clear errors
            self.is_broken
                .store(false, std::sync::atomic::Ordering::Release);

            drop(guard);
        }

        // wakeup
        self.wake_all();

        Ok(())
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    pub fn recv<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFut<'a, 'b> {
        RecvFut {
            socket: self,
            buffer,
        }
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    pub fn recv_from<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFromFut<'a, 'b> {
        RecvFromFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    ///
    /// # Return
    ///
    /// On success, the number of bytes sent is returned, otherwise, the
    /// encountered error is returned.
    pub fn send<'a, 'b>(&'b self, buffer: &'a [u8]) -> SendFut<'a, 'b> {
        SendFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    pub fn send_to<'a, 'b>(&'b self, buffer: &'a [u8], to: SocketAddr) -> SendToFut<'a, 'b> {
        SendToFut {
            socket: self,
            buffer,
            to,
        }
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via `recv` from the address specified in
    /// `addr`.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        trace!(%addr, "connecting");
        let guard = self.socket.read().unwrap();
        let (socket_tokio, _state) = guard.try_get_connected()?;

        let sock_ref = socket2::SockRef::from(&socket_tokio);
        sock_ref.connect(&socket2::SockAddr::from(addr))?;

        Ok(())
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let (socket, _state) = guard.try_get_connected()?;

        socket.local_addr()
    }

    /// Closes the socket, and waits for the underlying `libc::close` call to be finished.
    pub async fn close(&self) {
        let socket = self.socket.write().unwrap().close();
        self.wake_all();
        if let Some((sock, _)) = socket {
            let std_sock = sock.into_std();
            let res = tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    // Calls libc::close, which can block
                    drop(std_sock);
                })
                .await;
            if let Err(err) = res {
                warn!("failed to close socket: {:?}", err);
            }
        }
    }

    /// Check if this socket is closed.
    pub fn is_closed(&self) -> bool {
        self.socket.read().unwrap().is_closed()
    }

    /// Handle potential read errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_read_error(&self, error: io::Error) -> Option<io::Error> {
        match error.kind() {
            io::ErrorKind::NotConnected => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            // A transient receive error leaves the socket healthy with the next datagram still queued,
            // so we drop the error poll again rather than surface a spurious failure.
            _ if is_transient_read_error(&error) => None,
            _ => Some(error),
        }
    }

    /// Handle potential write errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_write_error(&self, error: io::Error) -> Option<io::Error> {
        match error.kind() {
            io::ErrorKind::BrokenPipe => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            _ => Some(error),
        }
    }

    /// Try to get a read lock for the sockets, but don't block for trying to acquire it.
    fn poll_read_socket(
        &self,
        waker: &AtomicWaker,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<RwLockReadGuard<'_, SocketState>> {
        let guard = match self.socket.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => {
                waker.register(cx.waker());

                match self.socket.try_read() {
                    Ok(guard) => {
                        // we're actually fine, no need to cause a spurious wakeup
                        waker.take();
                        guard
                    }
                    Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
                    Err(TryLockError::WouldBlock) => {
                        // Ok fine, we registered our waker, the lock is really closed,
                        // we can return pending.
                        return Poll::Pending;
                    }
                }
            }
        };
        Poll::Ready(guard)
    }

    fn wake_all(&self) {
        self.recv_waker.wake();
        self.send_waker.wake();
    }

    /// Checks if the socket needs a rebind, and if so does it.
    ///
    /// Returns an error if the rebind is needed, but failed.
    fn maybe_rebind(&self) -> io::Result<()> {
        if !self.is_broken() {
            return Ok(());
        }

        let mut guard = self.socket.write().unwrap_or_else(|e| e.into_inner());

        // Re-check after acquiring the write lock — another caller may have
        // already completed the rebind while we were waiting.
        if !self.is_broken() {
            return Ok(());
        }

        self.gso_limit.fetch_min(
            guard.max_gso_segments().get(),
            std::sync::atomic::Ordering::Relaxed,
        );
        guard.rebind(self.config)?;
        self.is_broken
            .store(false, std::sync::atomic::Ordering::Release);
        drop(guard);
        self.wake_all();
        Ok(())
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = std::task::ready!(self.poll_read_socket(&self.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }

    /// Send a noq based `Transmit`.
    pub fn try_send_noq(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        loop {
            self.maybe_rebind()?;

            let guard = match self.socket.try_read() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(e)) => {
                    panic!("lock poisoned: {e:?}");
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "locked"));
                }
            };
            let (socket, state) = guard.try_get_connected()?;

            let res = socket.try_io(Interest::WRITABLE, || state.try_send(socket.into(), transmit));

            match res {
                Ok(()) => return Ok(()),
                Err(err) => match self.handle_write_error(err) {
                    Some(err) => return Err(err),
                    None => {
                        continue;
                    }
                },
            }
        }
    }

    /// poll send a noq based `Transmit`.
    pub fn poll_send_noq(&self, cx: &mut Context, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(self.poll_read_socket(&self.send_waker, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res =
                        socket.try_io(Interest::WRITABLE, || state.try_send(socket.into(), transmit));
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }

                        if let Some(err) = self.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }

    /// noq based `poll_recv`
    pub fn poll_recv_noq(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(self.poll_read_socket(&self.recv_waker, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    // We are ready to read, continue
                }
                Poll::Ready(Err(err)) => match self.handle_read_error(err) {
                    Some(err) => return Poll::Ready(Err(err)),
                    None => {
                        continue;
                    }
                },
            }

            let res = socket.try_io(Interest::READABLE, || state.recv(socket.into(), bufs, meta));
            match res {
                Ok(count) => {
                    for meta in meta.iter().take(count) {
                        trace!(
                            src = %meta.addr,
                            len = meta.len,
                            count = meta.len.checked_div(meta.stride).unwrap_or(0),
                            dst = %meta.dst_ip.map(|x| x.to_string()).unwrap_or_default(),
                            "UDP recv"
                        );
                    }
                    return Poll::Ready(Ok(count));
                }
                Err(err) => {
                    // ignore spurious wakeups
                    if err.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    match self.handle_read_error(err) {
                        Some(err) => return Poll::Ready(Err(err)),
                        None => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Creates a [`UdpSender`] sender.
    pub fn create_sender(self: Arc<Self>) -> UdpSender {
        UdpSender::new(self)
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Returns `false` on targets which employ e.g. the `IPV6_DONTFRAG` socket option.
    pub fn may_fragment(&self) -> bool {
        let guard = self.socket.read().unwrap();
        guard.may_fragment()
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    pub fn max_gso_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        let current = guard.max_gso_segments().get();
        let previous = self
            .gso_limit
            .fetch_min(current, std::sync::atomic::Ordering::Relaxed);
        NonZeroUsize::new(previous.min(current)).unwrap()
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    pub fn gro_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        guard.gro_segments()
    }
}

/// `WSAENETRESET` (Winsock error 10052).
///
/// On a UDP socket Windows returns this from a recv when a previously sent datagram
/// could not be delivered because its TTL expired in transit, which the network
/// reports back as an ICMP Time Exceeded message. It describes the fate of that one
/// datagram, not the state of the socket: the socket stays usable and the error is
/// cleared once read, so the next recv proceeds normally. The Rust standard library
/// does not map this code to an [`io::ErrorKind`] (unlike `WSAECONNRESET`), so we match
/// it by its raw OS value.
#[cfg(windows)]
const WSAENETRESET: i32 = 10052;

/// Whether a read error is a transient condition that should be retried rather than
/// surfaced to the caller as a failure.
///
/// On Windows the stack reports the fate of a *previously sent* datagram against the
/// next recv on the same socket, so an ICMP reply surfaces as a recv error even though
/// the socket is healthy. `WSAECONNRESET` reports an ICMP Port Unreachable, meaning the
/// destination had no listener. `WSAENETRESET` reports an ICMP Time Exceeded, meaning a
/// datagram's TTL expired in transit. Both are transient for the same reason: each
/// describes a single datagram and is delivered exactly once, so reading it clears the
/// condition and the following recv returns real data.
///
/// We treat `ConnectionReset` as transient on every platform, not only Windows:
/// ECONNRESET is undefined in QUIC and can be injected by an attacker, so
/// it must never tear down the receive path.
fn is_transient_read_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::ConnectionReset {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(WSAENETRESET) {
        return true;
    }
    false
}

/// Receive future
#[derive(Debug)]
pub struct RecvFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(socket.poll_read_socket(&socket.recv_waker, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv(buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFromFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFromFut<'_, '_> {
    type Output = io::Result<(usize, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(socket.poll_read_socket(&socket.recv_waker, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv_from(buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Send future
#[derive(Debug)]
pub struct SendFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
}

impl Future for SendFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send(self.buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Send future
#[derive(Debug)]
pub struct SendToFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
    to: SocketAddr,
}

impl Future for SendToFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send_to(self.buffer, self.to);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }

                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(derive_more::Debug)]
enum SocketState {
    Connected {
        socket: tokio::net::UdpSocket,
        state: noq_udp::UdpSocketState,
        /// The addr we are binding to.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
    },
    Closed {
        /// The addr to rebind to when recovering.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
        last_max_gso_segments: NonZeroUsize,
        last_gro_segments: NonZeroUsize,
        last_may_fragment: bool,
    },
}

impl SocketState {
    fn try_get_connected(&self) -> io::Result<(&tokio::net::UdpSocket, &noq_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                socket,
                state,
                addr: _,
                configure: _,
            } => Ok((socket, state)),
            Self::Closed { .. } => {
                warn!("socket closed");
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            }
        }
    }

    fn bind(addr: SocketAddr, config: SocketConfig, configure: Option<Configurator>) -> io::Result<Self> {
        let network = IpFamily::from(addr.ip());
        let socket = socket2::Socket::new(
            network.into(),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set recv_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set send_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if network == IpFamily::V6 {
            // Avoid dualstack
            socket.set_only_v6(true)?;
        }
        #[cfg(target_vendor = "apple")]
        if let Err(err) = set_recv_anyif(&socket) {
            debug!("failed to set SO_RECV_ANYIF: {:?}", err);
        }

        // Let the caller configure the socket before it is bound. An error here
        // fails the bind: a socket that silently missed its configuration would
        // send traffic where the caller did not want it.
        if let Some(configure) = &configure {
            configure(SocketRef(&socket), network)?;
        }

        if let Some(interface) = config.interface {
            bind_interface(&socket, network, interface.index_for_family(network)?)?;
        }

        socket.set_nonblocking(true)?;

        let socket: std::net::UdpSocket = socket.into();
        if let Some(initialize) = config.initialize {
            initialize(&socket)?;
        }

        socket2::SockRef::from(&socket).bind(&addr.into())?;

        // Convert into tokio UdpSocket
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        let socket_ref = noq_udp::UdpSockRef::from(&socket);
        let socket_state = noq_udp::UdpSocketState::new(socket_ref)?;

        let local_addr = socket.local_addr()?;
        if addr.port() != 0 && local_addr.port() != addr.port() {
            return Err(io::Error::other(format!(
                "wrong port bound: {:?}: wanted: {} got {}",
                network,
                addr.port(),
                local_addr.port(),
            )));
        }

        Ok(Self::Connected {
            socket,
            state: socket_state,
            addr: local_addr,
            configure,
        })
    }

    fn rebind(&mut self, config: SocketConfig) -> io::Result<()> {
        let (addr, configure) = match self {
            Self::Connected {
                addr, configure, ..
            }
            | Self::Closed {
                addr, configure, ..
            } => (*addr, configure.clone()),
        };
        debug!("rebinding {}", addr);

        // Transition to Closed first to drop the old socket.
        // This is needed so the port is released before we try to bind again.
        if let Self::Connected { state, .. } = self {
            *self = SocketState::Closed {
                addr,
                configure: configure.clone(),
                last_max_gso_segments: state.max_gso_segments(),
                last_gro_segments: state.gro_segments(),
                last_may_fragment: state.may_fragment(),
            };
        }

        match Self::bind(addr, config, configure) {
            Ok(new_state) => {
                *self = new_state;
                Ok(())
            }
            Err(err) => {
                // Stay in Closed state but allow future rebind attempts
                debug!("rebind failed, will retry on next attempt: {}", err);
                Err(err)
            }
        }
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    fn close(&mut self) -> Option<(tokio::net::UdpSocket, noq_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                state,
                addr,
                configure,
                ..
            } => {
                let s = SocketState::Closed {
                    addr: *addr,
                    configure: configure.clone(),
                    last_max_gso_segments: state.max_gso_segments(),
                    last_gro_segments: state.gro_segments(),
                    last_may_fragment: state.may_fragment(),
                };
                let Self::Connected { socket, state, .. } = std::mem::replace(self, s) else {
                    unreachable!("just checked");
                };
                Some((socket, state))
            }
            Self::Closed { .. } => None,
        }
    }

    fn may_fragment(&self) -> bool {
        match self {
            Self::Connected { state, .. } => state.may_fragment(),
            Self::Closed {
                last_may_fragment, ..
            } => *last_may_fragment,
        }
    }

    fn max_gso_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.max_gso_segments(),
            Self::Closed {
                last_max_gso_segments,
                ..
            } => *last_max_gso_segments,
        }
    }

    fn gro_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.gro_segments(),
            Self::Closed {
                last_gro_segments, ..
            } => *last_gro_segments,
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Some((socket, _)) = self.socket.write().unwrap().close()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            // No wakeup after dropping write lock here, since we're getting dropped.
            // this will be empty if `close` was called before
            let std_sock = socket.into_std();
            handle.spawn_blocking(move || {
                // Calls libc::close, which can block
                drop(std_sock);
            });
        }
    }
}

pin_project_lite::pin_project! {
    pub struct UdpSender {
        socket: Arc<UdpSocket>,
        #[pin]
        fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync + 'static>>>,
    }
}

impl Clone for UdpSender {
    fn clone(&self) -> Self {
        self.socket.clone().create_sender()
    }
}

impl std::fmt::Debug for UdpSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UdpSender")
    }
}

impl UdpSender {
    /// Current native send capability, including learned offload failures.
    pub fn max_gso_segments(&self) -> NonZeroUsize {
        self.socket.max_gso_segments()
    }

    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket, fut: None }
    }

    /// Async sending
    pub fn send<'a, 'b>(&self, transmit: &'a noq_udp::Transmit<'b>) -> SendFutNoq<'a, 'b> {
        SendFutNoq {
            socket: self.socket.clone(),
            transmit,
        }
    }

    /// Poll send
    pub fn poll_send(
        self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if let Err(err) = this.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(this.socket.poll_read_socket(&this.socket.send_waker, cx));

            if this.fut.is_none() {
                let socket = this.socket.clone();
                this.fut.set(Some(Box::pin(async move {
                    n0_future::future::poll_fn(|cx| socket.poll_writable(cx)).await
                })));
            }
            // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
            // obtain an `&mut Fut` after storing it in `this.fut` when `this` is already behind `Pin`,
            // and if we didn't store it then we wouldn't be able to keep it alive between
            // `poll_writable` calls.
            let result = n0_future::ready!(this.fut.as_mut().as_pin_mut().unwrap().poll(cx));

            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);

            // If .writable() fails, propagate the error
            result?;

            let (socket, state) = guard.try_get_connected()?;
            let result = socket.try_io(Interest::WRITABLE, || state.try_send(socket.into(), transmit));

            match result {
                // We thought the socket was writable, but it wasn't, then retry so that either another
                // `writable().await` call determines that the socket is indeed not writable and
                // registers us for a wakeup, or the send succeeds if this really was just a
                // transient failure.
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // In all other cases, either propagate the error or we're Ok
                _ => return Poll::Ready(result),
            }
        }
    }

    /// Best effort sending
    pub fn try_send(&self, transmit: &noq_udp::Transmit) -> io::Result<()> {
        self.socket.maybe_rebind()?;

        match self.socket.socket.try_read() {
            Ok(guard) => {
                let (socket, state) = guard.try_get_connected()?;
                socket.try_io(Interest::WRITABLE, || state.try_send(socket.into(), transmit))
            }
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "locked"))
            }
        }
    }
}

/// Send future noq
#[derive(Debug)]
pub struct SendFutNoq<'a, 'b> {
    socket: Arc<UdpSocket>,
    transmit: &'a noq_udp::Transmit<'b>,
}

impl Future for SendFutNoq<'_, '_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_io(Interest::WRITABLE, || {
                        state.try_send(socket.into(), self.transmit)
                    });

                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_vendor = "apple")]
    use std::net::Ipv6Addr;
    use std::{
        net::Ipv4Addr,
        sync::atomic::Ordering,
    };
    #[tokio::test]
    async fn existing_senders_retain_reduced_gso_after_rebind() {
        let socket = Arc::new(UdpSocket::bind_local_v4(0).unwrap());
        let sender = socket.clone().create_sender();
        {
            let mut native = socket.socket.write().unwrap();
            native.close();
            if let SocketState::Closed {
                last_max_gso_segments,
                ..
            } = &mut *native
            {
                *last_max_gso_segments = NonZeroUsize::MIN;
            } else {
                panic!("socket did not close");
            }
        }
        socket.rebind().unwrap();
        assert_eq!(sender.max_gso_segments(), NonZeroUsize::MIN);
        socket.mark_broken();
        socket.maybe_rebind().unwrap();
        assert_eq!(sender.max_gso_segments(), NonZeroUsize::MIN);
    }

    use testresult::TestResult;

    use super::*;

    #[cfg(netdev)]
    #[rstest::rstest]
    #[case(IpFamily::V4)]
    #[case(IpFamily::V6)]
    #[tokio::test]
    async fn protected_sockets_reach_loopback_resolvers(#[case] family: IpFamily) {
        let interface = netdev::get_interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && iface.index != 0)
            .min_by_key(|iface| iface.is_loopback())
            .unwrap();
        let binding = InterfaceBinding::new(NonZeroU32::new(interface.index).unwrap()).unwrap();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(family.local_addr(), 0))
            .await
            .unwrap();
        let destination = listener.local_addr().unwrap();
        let server = tokio::net::UdpSocket::bind(destination).await.unwrap();
        let socket = bind_udp(
            SocketAddr::new(family.unspecified_addr(), 0),
            destination,
            SocketConfig {
                interface: Some(binding),
                initialize: None,
            },
        )
        .unwrap();
        socket.send_to(b"query", destination).unwrap();
        let mut bytes = [0; 5];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..length], b"query");
        let _client = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            connect_tcp(
                destination,
                TcpSocketConfig {
                    interface: Some(binding),
                    initialize: None,
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
    }

    #[rstest::rstest]
    #[case(IpFamily::V4)]
    #[case(IpFamily::V6)]
    #[tokio::test]
    async fn socket_authorization_is_required_on_every_bind(#[case] family: IpFamily) {
        use std::sync::atomic::Ordering;
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        fn authorize(socket: &std::net::UdpSocket) -> io::Result<()> {
            assert!(socket.local_addr().map_or(true, |addr| addr.port() == 0));
            match CALLS.fetch_add(1, Ordering::SeqCst) {
                1 | 3 => Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
                _ => Ok(()),
            }
        }
        let _serial = SERIAL.lock().await;
        CALLS.store(0, Ordering::SeqCst);
        let addr = SocketAddr::new(family.local_addr(), 0);
        let config = SocketConfig {
            interface: None,
            initialize: Some(authorize),
        };
        let socket = UdpSocket::bind_full_with_config(addr, config).unwrap();
        assert_eq!(
            socket.rebind().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(socket.socket.read().unwrap().is_closed());
        socket.rebind().unwrap();
        assert_eq!(
            UdpSocket::bind_full_with_config(addr, config)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    #[rstest::rstest]
    #[case(IpFamily::V4)]
    #[case(IpFamily::V6)]
    #[tokio::test]
    async fn native_interface_binding_survives_rebind(#[case] family: IpFamily) {
        #[cfg(target_os = "linux")]
        let interface = NonZeroU32::new(unsafe { libc::if_nametoindex(c"lo".as_ptr()) }).unwrap();
        #[cfg(target_os = "windows")]
        let interface = NonZeroU32::new(1).unwrap();
        let mut socket = UdpSocket::bind_full_with_config(
            SocketAddr::new(family.local_addr(), 0),
            SocketConfig {
                interface: Some(InterfaceBinding::new(interface).unwrap()),
                initialize: None,
            },
        )
        .unwrap();
        for _ in 0..2 {
            {
                let guard = socket.socket.read().unwrap();
                let SocketState::Connected { socket, .. } = &*guard else {
                    panic!("socket closed")
                };
                #[cfg(target_os = "linux")]
                {
                    let sock = socket2::SockRef::from(socket);
                    assert_eq!(sock.device().unwrap().as_deref(), Some(b"lo".as_slice()));
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::io::AsRawSocket;
                    use windows::Win32::Networking::WinSock::{
                        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET,
                        getsockopt,
                    };
                    let (level, option) = if family == IpFamily::V4 {
                        (IPPROTO_IP.0, IP_UNICAST_IF)
                    } else {
                        (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
                    };
                    let mut value = [0u8; 4];
                    let mut length = 4;
                    assert_eq!(
                        unsafe {
                            getsockopt(
                                SOCKET(socket.as_raw_socket() as usize),
                                level,
                                option,
                                windows::core::PSTR(value.as_mut_ptr()),
                                &mut length,
                            )
                        },
                        0
                    );
                    let actual = u32::from_ne_bytes(value);
                    assert_eq!(actual, interface.get());
                }
            }
            socket.rebind().unwrap();
        }
        let mut replaced = socket.config.interface.unwrap();
        #[cfg(windows)]
        {
            replaced.luid ^= 1;
        }
        #[cfg(target_os = "linux")]
        {
            replaced.name[0] ^= 1;
        }
        socket.config.interface = Some(replaced);
        assert_eq!(
            socket.rebind().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(socket.socket.read().unwrap().is_closed());
    }

    #[tokio::test]
    async fn test_reconnect() -> TestResult {
        let (s_b, mut r_b) = tokio::sync::mpsc::channel(16);
        let handle_a = tokio::task::spawn(async move {
            let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
            let addr = socket.local_addr()?;
            s_b.send(addr).await?;
            println!("socket bound to {addr:?}");

            let mut buffer = [0u8; 16];
            for i in 0..100 {
                println!("-- tick {i}");
                let read = socket.recv_from(&mut buffer).await;
                match read {
                    Ok((count, addr)) => {
                        println!("got {:?}", &buffer[..count]);
                        println!("sending {:?} to {:?}", &buffer[..count], addr);
                        socket.send_to(&buffer[..count], addr).await?;
                    }
                    Err(err) => {
                        eprintln!("error reading: {err:?}");
                    }
                }
            }
            socket.close().await;
            Ok::<_, testresult::TestError>(())
        });

        let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let first_addr = socket.local_addr()?;
        println!("socket2 bound to {:?}", socket.local_addr()?);
        let addr = r_b.recv().await.unwrap();

        let mut buffer = [0u8; 16];
        for i in 0u8..100 {
            println!("round one - {i}");
            socket.send_to(&[i][..], addr).await?;
            let (count, from) = socket.recv_from(&mut buffer).await?;
            assert_eq!(addr, from);
            assert_eq!(count, 1);
            assert_eq!(buffer[0], i);

            // check for errors
            assert!(!socket.is_broken());

            // rebind
            socket.rebind()?;

            // check that the socket has the same address as before
            assert_eq!(socket.local_addr()?, first_addr);
        }

        handle_a.await.ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_configure_socket_runs_on_every_bind() -> TestResult {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let opts = BindOptions::new().configure_socket(move |socket, family| {
            assert_eq!(family, IpFamily::V4);
            // The hook gets a real socket, before it is bound.
            socket2::SockRef::from(&socket).set_reuse_address(true)?;
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let socket = UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), opts)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook did not run on bind");

        socket.rebind()?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "hook did not run again on rebind"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_configure_socket_error_fails_the_bind() -> TestResult {
        let opts =
            BindOptions::new().configure_socket(|_socket, _family| Err(io::Error::other("nope")));

        assert!(
            UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), opts).is_err(),
            "a failing hook must fail the bind"
        );

        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn test_bind_sets_recv_anyif() -> TestResult {
        use std::os::fd::AsRawFd;

        // The hook runs after netwatch's own options, so it sees what bind set.
        let opts = BindOptions::new().configure_socket(|socket, _family| {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: `value` and `len` are valid for writes of the sizes given.
            let rc = unsafe {
                libc::getsockopt(
                    socket.as_fd().as_raw_fd(),
                    libc::SOL_SOCKET,
                    0x1104,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(value, 1, "SO_RECV_ANYIF not set");
            Ok(())
        });
        UdpSocket::bind_with(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), opts.clone())?;
        UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), opts)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_mark_broken() -> TestResult {
        let socket_a = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_a = socket_a.local_addr()?;
        println!("socket bound to {addr_a:?}");

        let socket_b = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_b = socket_b.local_addr()?;
        println!("socket bound to {addr_b:?}");

        let handle = tokio::task::spawn(async move {
            let mut buffer = [0u8; 16];
            for _ in 0..2 {
                match socket_b.recv_from(&mut buffer).await {
                    Ok((count, addr)) => {
                        println!("got {:?} from {:?}", &buffer[..count], addr);
                    }
                    Err(err) => {
                        eprintln!("error recv: {err:?}");
                    }
                }
            }
        });
        socket_a.send_to(&[0][..], addr_b).await?;
        socket_a.mark_broken();
        assert!(socket_a.is_broken());
        socket_a.send_to(&[0][..], addr_b).await?;
        assert!(!socket_a.is_broken());

        handle.await?;
        Ok(())
    }

    /// Regression test for the Windows behavior handled by [`is_transient_read_error`].
    ///
    /// A recv call must survive an ICMP error caused by an earlier send on the same socket.
    ///
    /// On Windows, sending a UDP datagram to a port with no listener draws an ICMP
    /// port-unreachable, and the OS reports it against the *next* recv on that socket as
    /// WSAECONNRESET. Before the fix our recv loop surfaced that error, so a perfectly
    /// good datagram waiting behind it was lost and the recv failed. After the fix the
    /// error is ignored and the real datagram is delivered.
    ///
    /// This only exercises the bug on Windows. Other platforms do not deliver the ICMP
    /// error to an unconnected recv, so the recv just returns the datagram and the test
    /// passes whether or not the fix is present.
    #[tokio::test]
    async fn test_recv_survives_icmp_unreachable_from_prior_send() -> TestResult {
        use std::time::Duration;

        // The socket under test, plus a legitimate peer to deliver a real datagram.
        let receiver = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let receiver_addr = receiver.local_addr()?;
        let sender = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let sender_addr = sender.local_addr()?;

        // A definitely-closed port: bind a socket, take its address, then close it.
        let closed_addr = {
            let tmp = UdpSocket::bind_local(IpFamily::V4, 0)?;
            let addr = tmp.local_addr()?;
            tmp.close().await;
            addr
        };

        // The receiver pokes the closed port. On Windows the ICMP port-unreachable that
        // comes back arms WSAECONNRESET against the receiver's next recv.
        receiver.send_to(b"void", closed_addr).await?;

        // Give the ICMP reply time to arrive, so the error is pending before the real
        // datagram and the recv.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The peer sends a real datagram that the receiver must deliver.
        sender.send_to(b"hello", receiver_addr).await?;

        // Before the fix this recv returns WSAECONNRESET on Windows instead of "hello".
        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut buf))
            .await
            .expect("recv must not hang")?;

        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, sender_addr);

        Ok(())
    }
}
