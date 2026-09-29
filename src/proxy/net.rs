use crate::MasquePacketStream;
use bytes::Bytes;
use futures::{future::poll_fn, SinkExt, StreamExt};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{dns, tcp},
    time::Instant as SmolInstant,
    wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address},
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{watch, Notify};

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const FIRST_EPHEMERAL_PORT: u16 = 49_152;
const LAST_EPHEMERAL_PORT: u16 = 65_535;
const DNS_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const REACTOR_TICK: Duration = Duration::from_millis(10);
const RETIRED_SOCKET_GRACE: Duration = Duration::from_secs(30);

/// A dual-stack userspace TCP/IP stack carried by a single CONNECT-IP session.
pub struct VirtualNet {
    shared: Arc<Shared>,
    reactor: tokio::task::AbortHandle,
}

struct Shared {
    inner: Mutex<Stack>,
    activity: Notify,
    closed: AtomicBool,
    closed_tx: watch::Sender<bool>,
    next_port: AtomicU16,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
}

struct Stack {
    iface: Interface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    retired: Vec<(SocketHandle, Instant)>,
}

struct PacketDevice {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
    caps: DeviceCapabilities,
}

struct PacketRxToken(Bytes);

struct PacketTxToken<'a>(&'a mut VecDeque<Bytes>);

fn lock_stack(shared: &Shared) -> std::sync::MutexGuard<'_, Stack> {
    shared
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.closed_tx.send_replace(true);

        let mut inner = lock_stack(self);
        for (_, socket) in inner.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(socket) = socket {
                socket.abort();
            }
        }
    }

    fn closed_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "userspace network reactor is closed",
        )
    }
}

impl PacketDevice {
    fn new(mtu: usize) -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = mtu;
        caps.max_burst_size = Some(64);
        Self {
            rx: VecDeque::with_capacity(64),
            tx: VecDeque::with_capacity(64),
            caps,
        }
    }

    fn push_rx(&mut self, packet: Bytes) {
        self.rx.push_back(packet);
    }

    fn drain_tx(&mut self, out: &mut Vec<Bytes>) {
        out.extend(self.tx.drain(..));
    }
}

impl RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.0.push_back(Bytes::from(packet));
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a>
        = PacketRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx
            .pop_front()
            .map(|packet| (PacketRxToken(packet), PacketTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PacketTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

impl Stack {
    fn poll(&mut self) {
        let now = SmolInstant::now();
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.reap_retired();
    }

    fn retire(&mut self, handle: SocketHandle, abort: bool) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if abort {
            socket.abort();
        } else {
            socket.close();
        }
        self.retired.push((handle, Instant::now()));
    }

    fn reap_retired(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.retired.len() {
            let (handle, retired_at) = self.retired[index];
            let finished = !self.sockets.get::<tcp::Socket>(handle).is_open();

            if finished || now.duration_since(retired_at) >= RETIRED_SOCKET_GRACE {
                let _ = self.sockets.remove(handle);
                self.retired.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }
}

impl Drop for VirtualNet {
    fn drop(&mut self) {
        self.shared.shutdown();
        self.reactor.abort();
    }
}

impl VirtualNet {
    pub fn start(
        packet_stream: MasquePacketStream,
        local_v4: Option<Ipv4Addr>,
        local_v6: Option<Ipv6Addr>,
        mtu: usize,
    ) -> io::Result<Arc<Self>> {
        if local_v4.is_none() && local_v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy stack requires at least one local WARP address",
            ));
        }

        let mut device = PacketDevice::new(mtu);
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = seed();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());

        let mut address_table_full = false;
        iface.update_ip_addrs(|addresses| {
            if let Some(address) = local_v4 {
                address_table_full |= addresses
                    .push(IpCidr::new(IpAddress::Ipv4(address), 32))
                    .is_err();
            }
            if let Some(address) = local_v6 {
                address_table_full |= addresses
                    .push(IpCidr::new(IpAddress::Ipv6(address), 128))
                    .is_err();
            }
        });
        if address_table_full {
            return Err(io::Error::other(
                "smoltcp address table is too small for configured WARP addresses",
            ));
        }

        if local_v4.is_some() {
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
                .map_err(|error| {
                    io::Error::other(format!("failed to add IPv4 route: {error:?}"))
                })?;
        }
        if local_v6.is_some() {
            iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
                .map_err(|error| {
                    io::Error::other(format!("failed to add IPv6 route: {error:?}"))
                })?;
        }

        let (closed_tx, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            inner: Mutex::new(Stack {
                iface,
                device,
                sockets: SocketSet::new(Vec::new()),
                retired: Vec::new(),
            }),
            activity: Notify::new(),
            closed: AtomicBool::new(false),
            closed_tx,
            next_port: AtomicU16::new(FIRST_EPHEMERAL_PORT),
            local_v4,
            local_v6,
        });
        let reactor_shared = shared.clone();
        let reactor = tokio::spawn(async move {
            let result = run_reactor(packet_stream, reactor_shared.clone()).await;
            reactor_shared.shutdown();
            if let Err(error) = result {
                log::error!("userspace proxy stack stopped: {error}");
            }
        });
        let net = Arc::new(Self {
            shared,
            reactor: reactor.abort_handle(),
        });

        Ok(net)
    }

    pub async fn wait_closed(&self) {
        let mut closed = self.shared.closed_tx.subscribe();
        if *closed.borrow() {
            return;
        }
        let _ = closed.wait_for(|is_closed| *is_closed).await;
    }

    pub async fn dial_host(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> io::Result<VirtualTcpStream> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.dial_tcp(SocketAddr::new(ip, port)).await;
        }

        let addresses = self.resolve_all(host).await?;
        let mut last_error = None;
        for address in addresses {
            match self.dial_tcp(SocketAddr::new(address, port)).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {host}"))
        }))
    }

    pub async fn dial_tcp(self: &Arc<Self>, remote: SocketAddr) -> io::Result<VirtualTcpStream> {
        let local_ip = match remote.ip() {
            IpAddr::V4(_) => self.shared.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.shared.local_v6.map(IpAddr::V6),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no WARP address for {}", remote.ip()),
            )
        })?;

        let handle = {
            let mut inner = lock_stack(&self.shared);
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(Shared::closed_error());
            }
            let local_port = self.allocate_port(&inner)?;
            let rx = tcp::SocketBuffer::new(vec![0_u8; TCP_BUFFER_SIZE]);
            let tx = tcp::SocketBuffer::new(vec![0_u8; TCP_BUFFER_SIZE]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.set_nagle_enabled(false);
            let Stack { iface, sockets, .. } = &mut *inner;
            socket
                .connect(iface.context(), remote, (local_ip, local_port))
                .map_err(|error| io::Error::other(format!("TCP connect setup failed: {error}")))?;
            sockets.add(socket)
        };

        self.shared.activity.notify_one();
        let mut guard = ConnectGuard {
            shared: self.shared.clone(),
            handle: Some(handle),
        };

        tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            poll_fn(|cx| {
                if self.shared.closed.load(Ordering::Acquire) {
                    return Poll::Ready(Err(Shared::closed_error()));
                }
                let mut inner = lock_stack(&self.shared);
                let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::Established => Poll::Ready(Ok(())),
                    tcp::State::Closed | tcp::State::TimeWait => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "userspace TCP connection closed during handshake",
                    ))),
                    _ => {
                        socket.register_recv_waker(cx.waker());
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                }
            }),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("userspace TCP connect to {remote} timed out"),
            )
        })??;

        guard.handle = None;
        Ok(VirtualTcpStream {
            shared: self.shared.clone(),
            handle: Some(handle),
        })
    }

    pub async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let (v6, v4) = tokio::join!(
            self.resolve_type(host, DnsQueryType::Aaaa),
            self.resolve_type(host, DnsQueryType::A)
        );

        let mut addresses = Vec::new();
        if let Ok(v6) = v6 {
            addresses.extend(v6);
        }
        if let Ok(v4) = v4 {
            addresses.extend(v4);
        }

        if addresses.is_empty() {
            let v6_error = v6.err().map(|error| error.to_string());
            let v4_error = v4.err().map(|error| error.to_string());
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "DNS lookup failed for {host}: AAAA={}; A={}",
                    v6_error.as_deref().unwrap_or("no answers"),
                    v4_error.as_deref().unwrap_or("no answers")
                ),
            ));
        }
        Ok(addresses)
    }

    async fn resolve_type(&self, host: &str, query_type: DnsQueryType) -> io::Result<Vec<IpAddr>> {
        let servers = self.dns_servers();
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no address family available for DNS",
            ));
        }

        let socket_handle = {
            let mut inner = lock_stack(&self.shared);
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(Shared::closed_error());
            }
            inner.sockets.add(dns::Socket::new(&servers, vec![None; 1]))
        };
        let _socket_guard = DnsSocketGuard {
            shared: self.shared.clone(),
            handle: socket_handle,
        };
        let query_handle = {
            let mut inner = lock_stack(&self.shared);
            let Stack { iface, sockets, .. } = &mut *inner;
            sockets
                .get_mut::<dns::Socket>(socket_handle)
                .start_query(iface.context(), host, query_type)
                .map_err(|error| io::Error::other(format!("DNS query setup failed: {error}")))?
        };
        self.shared.activity.notify_one();

        tokio::time::timeout(
            DNS_TIMEOUT,
            poll_fn(|cx| {
                let mut inner = lock_stack(&self.shared);
                let socket = inner.sockets.get_mut::<dns::Socket>(socket_handle);
                match socket.get_query_result(query_handle) {
                    Ok(addresses) => {
                        Poll::Ready(Ok(addresses.into_iter().map(smoltcp_to_std_ip).collect()))
                    }
                    Err(dns::GetQueryResultError::Pending) => {
                        socket.register_query_waker(query_handle, cx.waker());
                        Poll::Pending
                    }
                    Err(dns::GetQueryResultError::Failed) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("DNS query failed for {host}"),
                    ))),
                }
            }),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("DNS timeout for {host}")))?
    }

    fn dns_servers(&self) -> Vec<IpAddress> {
        let mut servers = Vec::with_capacity(2);
        if self.shared.local_v6.is_some() {
            servers.push(IpAddress::Ipv6(Ipv6Address::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
            )));
        }
        if self.shared.local_v4.is_some() {
            servers.push(IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)));
        }
        servers
    }

    fn next_port(&self) -> u16 {
        self.shared
            .next_port
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |port| {
                Some(if port == LAST_EPHEMERAL_PORT {
                    FIRST_EPHEMERAL_PORT
                } else {
                    port + 1
                })
            })
            .unwrap_or(FIRST_EPHEMERAL_PORT)
    }

    fn allocate_port(&self, stack: &Stack) -> io::Result<u16> {
        for _ in FIRST_EPHEMERAL_PORT..=LAST_EPHEMERAL_PORT {
            let candidate = self.next_port();
            let in_use = stack.sockets.iter().any(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket
                    .local_endpoint()
                    .is_some_and(|endpoint| endpoint.port == candidate),
                _ => false,
            });
            if !in_use {
                return Ok(candidate);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "userspace TCP ephemeral port range exhausted",
        ))
    }
}

async fn run_reactor(mut packet_stream: MasquePacketStream, shared: Arc<Shared>) -> io::Result<()> {
    let mut outbound = Vec::with_capacity(64);

    loop {
        tokio::select! {
            packet = packet_stream.next() => {
                match packet {
                    Some(Ok(packet)) => {
                        let mut inner = lock_stack(&shared);
                        inner.device.push_rx(packet);
                    }
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
            }
            () = shared.activity.notified() => {}
            () = tokio::time::sleep(REACTOR_TICK) => {}
        }

        {
            let mut inner = lock_stack(&shared);
            inner.poll();
            inner.device.drain_tx(&mut outbound);
        }

        if !outbound.is_empty() {
            for packet in outbound.drain(..) {
                packet_stream.feed(packet).await?;
            }
            packet_stream.flush().await?;
        }
    }
}

pub struct VirtualTcpStream {
    shared: Arc<Shared>,
    handle: Option<SocketHandle>,
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(Shared::closed_error()));
        }
        let Some(handle) = self.handle else {
            return Poll::Ready(Ok(()));
        };

        let mut inner = lock_stack(&self.shared);
        let socket = inner.sockets.get_mut::<tcp::Socket>(handle);

        if socket.can_recv() {
            let target = buffer.initialize_unfilled();
            return match socket.recv_slice(target) {
                Ok(read) => {
                    buffer.advance(read);
                    Poll::Ready(Ok(()))
                }
                Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
                Err(error) => Poll::Ready(Err(io::Error::other(error))),
            };
        }

        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(Shared::closed_error()));
        }
        let Some(handle) = self.handle else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP stream is closed",
            )));
        };

        let mut inner = lock_stack(&self.shared);
        let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
        if socket.can_send() {
            let written = socket.send_slice(buffer).map_err(io::Error::other)?;
            drop(inner);
            self.shared.activity.notify_one();
            return Poll::Ready(Ok(written));
        }
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP peer closed",
            )));
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(Shared::closed_error()));
        }
        let Some(handle) = self.handle else {
            return Poll::Ready(Ok(()));
        };

        let mut inner = lock_stack(&self.shared);
        let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
        if socket.send_queue() == 0 {
            Poll::Ready(Ok(()))
        } else {
            socket.register_send_waker(cx.waker());
            drop(inner);
            self.shared.activity.notify_one();
            Poll::Pending
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(handle) = self.handle.take() {
            let mut inner = lock_stack(&self.shared);
            inner.retire(handle, false);
            drop(inner);
            self.shared.activity.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for VirtualTcpStream {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let mut inner = lock_stack(&self.shared);
            inner.retire(handle, true);
            drop(inner);
            self.shared.activity.notify_one();
        }
    }
}

struct DnsSocketGuard {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl Drop for DnsSocketGuard {
    fn drop(&mut self) {
        let mut inner = lock_stack(&self.shared);
        let _ = inner.sockets.remove(self.handle);
    }
}

struct ConnectGuard {
    shared: Arc<Shared>,
    handle: Option<SocketHandle>,
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let mut inner = lock_stack(&self.shared);
            inner.retire(handle, true);
            drop(inner);
            self.shared.activity.notify_one();
        }
    }
}

fn smoltcp_to_std_ip(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
        IpAddress::Ipv6(address) => IpAddr::V6(address),
    }
}

fn seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_nanos() as u64 ^ u64::from(std::process::id())
}
