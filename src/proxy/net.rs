use crate::MasquePacketStream;
use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::poll_fn, stream::FuturesUnordered};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{dns, tcp, udp},
    time::Instant as SmolInstant,
    wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address},
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, watch};

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const UDP_PACKET_SLOTS: usize = 64;
const UDP_BUFFER_SIZE: usize = 256 * 1024;
const FIRST_EPHEMERAL_PORT: u16 = 49_152;
const LAST_EPHEMERAL_PORT: u16 = 65_535;
const DNS_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const REACTOR_IDLE_SLEEP: Duration = Duration::from_secs(60);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsFamilyPlan {
    DualStack,
    Ipv4Only,
    Ipv6Only,
    None,
}

const fn dns_family_plan(local_v4: Option<Ipv4Addr>, local_v6: Option<Ipv6Addr>) -> DnsFamilyPlan {
    match (local_v4.is_some(), local_v6.is_some()) {
        (true, true) => DnsFamilyPlan::DualStack,
        (true, false) => DnsFamilyPlan::Ipv4Only,
        (false, true) => DnsFamilyPlan::Ipv6Only,
        (false, false) => DnsFamilyPlan::None,
    }
}

fn should_reap_retired(state: tcp::State, age: Duration) -> bool {
    state == tcp::State::Closed || age >= RETIRED_SOCKET_GRACE
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0_u8; TCP_BUFFER_SIZE]);
    let tx = tcp::SocketBuffer::new(vec![0_u8; TCP_BUFFER_SIZE]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket.set_congestion_control(tcp::CongestionControl::Reno);
    socket
}

fn new_udp_socket() -> udp::Socket<'static> {
    let rx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
        vec![0_u8; UDP_BUFFER_SIZE],
    );
    let tx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
        vec![0_u8; UDP_BUFFER_SIZE],
    );
    udp::Socket::new(rx, tx)
}

fn interleave_address_families(v6: Vec<IpAddr>, v4: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut v6 = v6.into_iter();
    let mut v4 = v4.into_iter();
    let mut addresses = Vec::with_capacity(v6.len() + v4.len());

    loop {
        let next_v6 = v6.next();
        let next_v4 = v4.next();
        if next_v6.is_none() && next_v4.is_none() {
            break;
        }
        if let Some(address) = next_v6 {
            addresses.push(address);
        }
        if let Some(address) = next_v4 {
            addresses.push(address);
        }
    }

    addresses
}

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
            match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                smoltcp::socket::Socket::Udp(socket) => socket.close(),
                smoltcp::socket::Socket::Dns(_) => {}
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

    fn drain_tx(&mut self, out: &mut VecDeque<Bytes>) {
        out.append(&mut self.tx);
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
        let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
        if abort {
            socket.abort();
        } else {
            socket.close();
        }
        self.retired.push((handle, Instant::now()));
    }

    fn next_poll_delay(&mut self) -> Duration {
        let protocol_delay = self
            .iface
            .poll_delay(SmolInstant::now(), &self.sockets)
            .map_or(REACTOR_IDLE_SLEEP, |delay| {
                Duration::from_micros(delay.total_micros()).min(REACTOR_IDLE_SLEEP)
            });

        let now = Instant::now();
        let retirement_delay = self
            .retired
            .iter()
            .map(|(_, retired_at)| {
                RETIRED_SOCKET_GRACE.saturating_sub(now.saturating_duration_since(*retired_at))
            })
            .min()
            .unwrap_or(REACTOR_IDLE_SLEEP);

        protocol_delay.min(retirement_delay)
    }

    fn reap_retired(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.retired.len() {
            let (handle, retired_at) = self.retired[index];
            let state = self.sockets.get::<tcp::Socket<'_>>(handle).state();
            if should_reap_retired(state, now.duration_since(retired_at)) {
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
    /// Start a userspace TCP/IP stack over an established CONNECT-IP packet stream.
    ///
    /// # Errors
    /// Returns an error if no WARP address family is enabled or the smoltcp
    /// interface cannot install the requested addresses/routes.
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
            let result = Box::pin(run_reactor(packet_stream, reactor_shared.clone())).await;
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

    /// Resolve `host` inside the userspace stack and connect to the first reachable address.
    ///
    /// # Errors
    /// Returns DNS, address-family, timeout, or TCP connection errors when no
    /// resolved address can be reached.
    pub async fn dial_host(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> io::Result<VirtualTcpStream> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.dial_tcp(SocketAddr::new(ip, port)).await;
        }

        let addresses = self.resolve_all(host).await?;
        let mut attempts = FuturesUnordered::new();

        for (index, address) in addresses.into_iter().enumerate() {
            let net = Arc::clone(self);
            let delay =
                HAPPY_EYEBALLS_DELAY.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
            attempts.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let remote = SocketAddr::new(address, port);
                (remote, net.dial_tcp(remote).await)
            });
        }

        let mut last_error = None;
        while let Some((remote, result)) = attempts.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    log::debug!("proxy TCP connect to {remote} failed: {error}");
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {host}"))
        }))
    }

    /// Open a userspace TCP connection to `remote`.
    ///
    /// # Errors
    /// Returns an error when the matching WARP address family is unavailable,
    /// socket setup fails, the peer refuses the connection, or the connect times out.
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
            let mut socket = new_tcp_socket();
            let Stack { iface, sockets, .. } = &mut *inner;
            socket
                .connect(iface.context(), remote, (local_ip, local_port))
                .map_err(|error| io::Error::other(format!("TCP connect setup failed: {error}")))?;
            let handle = sockets.add(socket);
            drop(inner);
            handle
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
                let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(handle);
                let result = match socket.state() {
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
                };
                drop(inner);
                result
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

    /// Bind a dual-stack userspace UDP socket to an ephemeral WARP-side port.
    ///
    /// # Errors
    /// Returns an error if the virtual network is closed, no ephemeral port is
    /// available, or smoltcp cannot bind the UDP socket.
    pub fn bind_udp(self: &Arc<Self>) -> io::Result<VirtualUdpSocket> {
        let (handle, local_port) = {
            let mut inner = lock_stack(&self.shared);
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(Shared::closed_error());
            }
            let local_port = self.allocate_port(&inner)?;
            let mut socket = new_udp_socket();
            socket
                .bind(local_port)
                .map_err(|error| io::Error::other(format!("UDP bind failed: {error}")))?;
            let handle = inner.sockets.add(socket);
            drop(inner);
            (handle, local_port)
        };

        self.shared.activity.notify_one();
        Ok(VirtualUdpSocket {
            shared: self.shared.clone(),
            handle: Some(handle),
            local_port,
        })
    }

    /// Resolve all usable IP addresses for `host` through tunneled DNS.
    ///
    /// # Errors
    /// Returns an error when no WARP address family is enabled or all DNS
    /// queries fail or return no usable addresses.
    pub async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let (v6, v4) = match dns_family_plan(self.shared.local_v4, self.shared.local_v6) {
            DnsFamilyPlan::DualStack => tokio::join!(
                self.resolve_type(host, DnsQueryType::Aaaa),
                self.resolve_type(host, DnsQueryType::A)
            ),
            DnsFamilyPlan::Ipv6Only => (
                self.resolve_type(host, DnsQueryType::Aaaa).await,
                Ok(Vec::new()),
            ),
            DnsFamilyPlan::Ipv4Only => (
                Ok(Vec::new()),
                self.resolve_type(host, DnsQueryType::A).await,
            ),
            DnsFamilyPlan::None => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no WARP address family available for DNS",
                ));
            }
        };

        let v6_error = v6.as_ref().err().map(ToString::to_string);
        let v4_error = v4.as_ref().err().map(ToString::to_string);
        let addresses = interleave_address_families(v6.unwrap_or_default(), v4.unwrap_or_default());

        if addresses.is_empty() {
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

        let mut queries = FuturesUnordered::new();
        for server in servers {
            queries.push(self.resolve_type_on_server(host, query_type, server));
        }

        let mut last_error = None;
        while let Some(result) = queries.next().await {
            match result {
                Ok(addresses) => return Ok(addresses),
                Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {
                    return Err(error);
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS query failed for {host}"),
            )
        }))
    }

    async fn resolve_type_on_server(
        &self,
        host: &str,
        query_type: DnsQueryType,
        server: IpAddress,
    ) -> io::Result<Vec<IpAddr>> {
        let socket_handle = {
            let mut inner = lock_stack(&self.shared);
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(Shared::closed_error());
            }
            let queries = vec![None::<dns::DnsQuery>];
            inner.sockets.add(dns::Socket::new(&[server], queries))
        };
        let _socket_guard = DnsSocketGuard {
            shared: self.shared.clone(),
            handle: socket_handle,
        };
        let query_handle = {
            let mut inner = lock_stack(&self.shared);
            let Stack { iface, sockets, .. } = &mut *inner;
            let query_handle = sockets
                .get_mut::<dns::Socket<'_>>(socket_handle)
                .start_query(iface.context(), host, query_type)
                .map_err(|error| {
                    io::Error::other(format!("DNS query setup via {server} failed: {error}"))
                })?;
            drop(inner);
            query_handle
        };
        self.shared.activity.notify_one();

        let query = poll_fn(|cx| {
            let mut inner = lock_stack(&self.shared);
            let socket = inner.sockets.get_mut::<dns::Socket<'_>>(socket_handle);
            let result = match socket.get_query_result(query_handle) {
                Ok(addresses) => {
                    Poll::Ready(Ok(addresses.into_iter().map(smoltcp_to_std_ip).collect()))
                }
                Err(dns::GetQueryResultError::Pending) => {
                    socket.register_query_waker(query_handle, cx.waker());
                    Poll::Pending
                }
                Err(dns::GetQueryResultError::Failed) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DNS query via {server} failed for {host}"),
                ))),
            };
            drop(inner);
            result
        });

        tokio::select! {
            result = tokio::time::timeout(DNS_TIMEOUT, query) => result.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DNS timeout for {host} via {server}"),
                )
            })?,
            () = self.wait_closed() => Err(Shared::closed_error()),
        }
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
        let mut port = self.shared.next_port.load(Ordering::Relaxed);
        loop {
            let next = if port == LAST_EPHEMERAL_PORT {
                FIRST_EPHEMERAL_PORT
            } else {
                port + 1
            };
            match self.shared.next_port.compare_exchange_weak(
                port,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return port,
                Err(observed) => port = observed,
            }
        }
    }

    fn allocate_port(&self, stack: &Stack) -> io::Result<u16> {
        for _ in FIRST_EPHEMERAL_PORT..=LAST_EPHEMERAL_PORT {
            let candidate = self.next_port();
            let in_use = stack.sockets.iter().any(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket
                    .local_endpoint()
                    .is_some_and(|endpoint| endpoint.port == candidate),
                smoltcp::socket::Socket::Udp(socket) => socket.endpoint().port == candidate,
                smoltcp::socket::Socket::Dns(_) => false,
            });
            if !in_use {
                return Ok(candidate);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "userspace ephemeral port range exhausted",
        ))
    }
}

async fn run_reactor(mut packet_stream: MasquePacketStream, shared: Arc<Shared>) -> io::Result<()> {
    let mut outbound = VecDeque::with_capacity(64);
    let mut next_poll = tokio::time::Instant::now();

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
            () = tokio::time::sleep_until(next_poll) => {}
        }

        let poll_delay = {
            let mut inner = lock_stack(&shared);
            inner.poll();
            inner.device.drain_tx(&mut outbound);
            inner.next_poll_delay()
        };
        next_poll = tokio::time::Instant::now() + poll_delay;

        if !outbound.is_empty() {
            while let Some(packet) = outbound.pop_front() {
                packet_stream.feed(packet).await?;
            }
            packet_stream.flush().await?;
        }
    }
}

pub struct VirtualUdpSocket {
    shared: Arc<Shared>,
    handle: Option<SocketHandle>,
    local_port: u16,
}

impl VirtualUdpSocket {
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Send one datagram through the WARP-side userspace stack.
    ///
    /// # Errors
    /// Returns an error if the stack is closed, the datagram can never fit in
    /// the configured buffer, or smoltcp rejects the destination.
    pub async fn send_to(&self, data: &[u8], remote: SocketAddr) -> io::Result<()> {
        poll_fn(|cx| {
            if self.shared.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(Shared::closed_error()));
            }
            let Some(handle) = self.handle else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "virtual UDP socket is closed",
                )));
            };

            let mut inner = lock_stack(&self.shared);
            let socket = inner.sockets.get_mut::<udp::Socket<'_>>(handle);
            if data.len() > socket.payload_send_capacity() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP datagram exceeds virtual socket buffer capacity",
                )));
            }

            match socket.send_slice(data, remote) {
                Ok(()) => {
                    drop(inner);
                    self.shared.activity.notify_one();
                    Poll::Ready(Ok(()))
                }
                Err(udp::SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(io::Error::other(error))),
            }
        })
        .await
    }

    /// Receive one datagram from the WARP-side userspace stack.
    ///
    /// # Errors
    /// Returns an error if the stack is closed or the caller-provided buffer
    /// is too small for the next datagram.
    pub async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            if self.shared.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(Shared::closed_error()));
            }
            let Some(handle) = self.handle else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "virtual UDP socket is closed",
                )));
            };

            let mut inner = lock_stack(&self.shared);
            let socket = inner.sockets.get_mut::<udp::Socket<'_>>(handle);
            if socket.can_recv() {
                let result = match socket.recv_slice(buffer) {
                    Ok((size, metadata)) => Ok((
                        size,
                        SocketAddr::new(
                            smoltcp_to_std_ip(metadata.endpoint.addr),
                            metadata.endpoint.port,
                        ),
                    )),
                    Err(udp::RecvError::Truncated) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP receive buffer is too small for datagram",
                    )),
                    Err(udp::RecvError::Exhausted) => {
                        socket.register_recv_waker(cx.waker());
                        return Poll::Pending;
                    }
                };
                drop(inner);
                self.shared.activity.notify_one();
                return Poll::Ready(result);
            }

            socket.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl Drop for VirtualUdpSocket {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let mut inner = lock_stack(&self.shared);
            let _ = inner.sockets.remove(handle);
            drop(inner);
            self.shared.activity.notify_one();
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
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(handle);

        if socket.can_recv() {
            let target = buffer.initialize_unfilled();
            let result = match socket.recv_slice(target) {
                Ok(read) => {
                    buffer.advance(read);
                    Ok(())
                }
                Err(tcp::RecvError::Finished) => Ok(()),
                Err(error) => Err(io::Error::other(error)),
            };
            drop(inner);
            self.shared.activity.notify_one();
            return Poll::Ready(result);
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
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(handle);
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(Shared::closed_error()));
        }
        if self.handle.is_some() {
            self.shared.activity.notify_one();
        }
        Poll::Ready(Ok(()))
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

const fn smoltcp_to_std_ip(address: IpAddress) -> IpAddr {
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
    now.as_secs() ^ u64::from(now.subsec_nanos()) ^ u64::from(std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_family_plan_matches_enabled_warp_addresses() {
        let v4 = Some(Ipv4Addr::new(172, 16, 0, 2));
        let v6 = Some(Ipv6Addr::LOCALHOST);

        assert_eq!(dns_family_plan(v4, v6), DnsFamilyPlan::DualStack);
        assert_eq!(dns_family_plan(v4, None), DnsFamilyPlan::Ipv4Only);
        assert_eq!(dns_family_plan(None, v6), DnsFamilyPlan::Ipv6Only);
        assert_eq!(dns_family_plan(None, None), DnsFamilyPlan::None);
    }

    #[test]
    fn happy_eyeballs_interleaves_address_families() {
        let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let v6_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let v4_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(
            interleave_address_families(vec![v6_a, v6_b], vec![v4_a]),
            vec![v6_a, v4_a, v6_b]
        );
    }

    #[test]
    fn outbound_tcp_socket_uses_reno_without_nagle() {
        let socket = new_tcp_socket();

        assert_eq!(socket.congestion_control(), tcp::CongestionControl::Reno);
        assert!(!socket.nagle_enabled());
    }

    #[test]
    fn time_wait_is_retained_until_grace_expires() {
        assert!(should_reap_retired(tcp::State::Closed, Duration::ZERO));
        assert!(!should_reap_retired(
            tcp::State::TimeWait,
            RETIRED_SOCKET_GRACE.saturating_sub(Duration::from_millis(1))
        ));
        assert!(should_reap_retired(
            tcp::State::TimeWait,
            RETIRED_SOCKET_GRACE
        ));
    }
}
