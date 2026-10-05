use anyhow::{Context, Result, bail};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
    time::Instant,
};

use crate::{config, tls, udp_socket::bind_udp_socket};

const MAX_QUIC_DATAGRAM_SIZE: usize = 1350;
const CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const STREAM_BRIDGE_BYTES: usize = 128 * 1024;
const STREAM_CHUNK_BYTES: usize = 32 * 1024;
const COMMAND_QUEUE: usize = 1024;
const DEFAULT_DNS_CACHE_ENTRIES: usize = 4096;
const L4_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

#[derive(Clone, Debug)]
pub struct L4Config {
    pub connect_port: u16,
    pub use_ipv6_endpoint: bool,
    pub source_ip: Option<IpAddr>,
    pub keepalive_period: Duration,
    pub dns_servers: Vec<IpAddr>,
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            connect_port: 443,
            use_ipv6_endpoint: false,
            source_ip: None,
            keepalive_period: Duration::from_secs(30),
            dns_servers: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct L4Client {
    command_tx: mpsc::Sender<Command>,
    dns_servers: Arc<Vec<IpAddr>>,
    dns_cache: Arc<Mutex<HashMap<String, CachedAddress>>>,
}

#[derive(Clone, Copy)]
struct CachedAddress {
    address: IpAddr,
    expires_at: StdInstant,
}

struct DriverConfig {
    config: Arc<config::Config>,
    endpoint: SocketAddr,
    bind: SocketAddr,
    keepalive_period: Duration,
}

enum Command {
    Open {
        authority: String,
        reply: oneshot::Sender<io::Result<DuplexStream>>,
    },
    Write {
        stream_id: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Finish {
        stream_id: u64,
    },
    Read {
        stream_id: u64,
        reply: oneshot::Sender<io::Result<Option<Vec<u8>>>>,
    },
}

struct PendingWrite {
    data: Vec<u8>,
    offset: usize,
    reply: oneshot::Sender<io::Result<()>>,
}

struct StreamState {
    authority: String,
    open_reply: Option<oneshot::Sender<io::Result<DuplexStream>>>,
    pending_read: Option<oneshot::Sender<io::Result<Option<Vec<u8>>>>>,
    pending_write: Option<PendingWrite>,
    readable: bool,
    remote_finished: bool,
    local_finish_requested: bool,
    local_finished: bool,
    opened: bool,
    open_deadline: Instant,
}

struct Session {
    socket: tokio::net::UdpSocket,
    conn: quiche::Connection,
    h3: quiche::h3::Connection,
    out: Vec<u8>,
    recv: Vec<u8>,
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    keepalive_period: Duration,
    next_keepalive: Instant,
    streams: HashMap<u64, StreamState>,
}

impl L4Client {
    /// Establish the shared outer HTTP/3 connection used by direct L4 proxy streams.
    ///
    /// # Errors
    /// Returns an error for malformed configuration, address-family mismatch,
    /// TLS/QUIC handshake failure, or endpoint key mismatch.
    pub async fn connect(config_path: &str, l4: &L4Config) -> Result<Arc<Self>> {
        if l4.keepalive_period.is_zero() {
            bail!("keepalive period must be greater than zero");
        }

        let config = Arc::new(config::Config::load_async(config_path).await?);
        let endpoint_ip: IpAddr = if l4.use_ipv6_endpoint {
            config.endpoint_v6.parse()?
        } else {
            config.endpoint_v4.parse()?
        };
        let endpoint = SocketAddr::new(endpoint_ip, l4.connect_port);
        let bind_ip = l4.source_ip.unwrap_or_else(|| match endpoint_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
        if bind_ip.is_ipv4() != endpoint_ip.is_ipv4() {
            bail!(
                "source IP {bind_ip} and MASQUE endpoint {endpoint_ip} use different address families"
            );
        }
        let bind = SocketAddr::new(bind_ip, 0);
        let driver_config = Arc::new(DriverConfig {
            config,
            endpoint,
            bind,
            keepalive_period: l4.keepalive_period,
        });

        // Fail startup immediately when the outer transport cannot be established.
        let initial_session = Session::connect(&driver_config).await?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
        tokio::spawn(run_driver(
            driver_config,
            initial_session,
            command_rx,
            command_tx.clone(),
        ));

        let dns_servers = if l4.dns_servers.is_empty() {
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        } else {
            l4.dns_servers.clone()
        };

        Ok(Arc::new(Self {
            command_tx,
            dns_servers: Arc::new(dns_servers),
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    /// Dial an IP endpoint directly over an HTTP/3 CONNECT stream.
    pub async fn dial_addr(&self, address: SocketAddr) -> io::Result<DuplexStream> {
        self.open(authority_for(address)).await
    }

    /// Resolve a hostname through DNS-over-TCP over WARP, then dial it over L4.
    pub async fn dial_host(&self, host: &str, port: u16) -> io::Result<DuplexStream> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.dial_addr(SocketAddr::new(ip, port)).await;
        }
        let address = self.resolve(host).await?;
        self.dial_addr(SocketAddr::new(address, port)).await
    }

    async fn open(&self, authority: String) -> io::Result<DuplexStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Open {
                authority,
                reply: reply_tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "L4 session stopped"))?;
        reply_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "L4 session stopped"))?
    }

    async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        if let Some(address) = self.cached(host)? {
            return Ok(address);
        }

        let name = Name::from_ascii(host)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut queries = tokio::task::JoinSet::new();
        for server in self.dns_servers.iter().copied() {
            for record_type in [RecordType::A, RecordType::AAAA] {
                let client = self.clone();
                let name = name.clone();
                queries.spawn(async move { client.query_dns(server, &name, record_type).await });
            }
        }

        let mut last_error = None;
        while let Some(result) = queries.join_next().await {
            match result {
                Ok(Ok(Some((address, ttl)))) => {
                    queries.abort_all();
                    if !ttl.is_zero() {
                        self.cache(host, address, ttl)?;
                    }
                    return Ok(address);
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => last_error = Some(error),
                Err(error) => {
                    last_error = Some(io::Error::other(format!("DNS query task failed: {error}")))
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS returned no address for {host}"),
            )
        }))
    }

    fn cached(&self, host: &str) -> io::Result<Option<IpAddr>> {
        let mut cache = self
            .dns_cache
            .lock()
            .map_err(|_| io::Error::other("DNS cache lock poisoned"))?;
        let Some(entry) = cache.get(host).copied() else {
            return Ok(None);
        };
        if entry.expires_at > StdInstant::now() {
            return Ok(Some(entry.address));
        }
        cache.remove(host);
        Ok(None)
    }

    fn cache(&self, host: &str, address: IpAddr, ttl: Duration) -> io::Result<()> {
        let mut cache = self
            .dns_cache
            .lock()
            .map_err(|_| io::Error::other("DNS cache lock poisoned"))?;
        if cache.len() >= DEFAULT_DNS_CACHE_ENTRIES && !cache.contains_key(host) {
            cache.retain(|_, entry| entry.expires_at > StdInstant::now());
            if cache.len() >= DEFAULT_DNS_CACHE_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(
            host.to_owned(),
            CachedAddress {
                address,
                expires_at: StdInstant::now() + ttl.max(Duration::from_secs(1)),
            },
        );
        Ok(())
    }

    async fn query_dns(
        &self,
        server: IpAddr,
        name: &Name,
        record_type: RecordType,
    ) -> io::Result<Option<(IpAddr, Duration)>> {
        let mut stream = self.dial_addr(SocketAddr::new(server, 53)).await?;
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), record_type));
        let request_id = request.metadata.id;
        let payload = request
            .to_vec()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let length = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS request too large"))?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;

        let mut length_buf = [0_u8; 2];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut length_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
        let response_len = usize::from(u16::from_be_bytes(length_buf));
        let mut response = vec![0_u8; response_len];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS response timed out"))??;
        let message = Message::from_vec(&response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if message.metadata.id != request_id
            || message.metadata.message_type != MessageType::Response
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response does not match the request",
            ));
        }
        if message.metadata.response_code != ResponseCode::NoError {
            return Err(io::Error::other(format!(
                "DNS server returned {}",
                message.metadata.response_code
            )));
        }

        for record in &message.answers {
            let address = match record.data() {
                RData::A(value) => Some(IpAddr::V4(value.0)),
                RData::AAAA(value) => Some(IpAddr::V6(value.0)),
                _ => None,
            };
            if let Some(address) = address {
                return Ok(Some((
                    address,
                    Duration::from_secs(u64::from(record.ttl())),
                )));
            }
        }
        Ok(None)
    }
}

impl Session {
    async fn connect(config: &DriverConfig) -> Result<Self> {
        let tls_material = tls::prepare_tls_material(config.config.as_ref())?;
        let mut quic_config = tls::build_l4_quic_config(&tls_material, MAX_QUIC_DATAGRAM_SIZE)?;
        let socket = bind_udp_socket(config.bind, "masque-l4")?;
        socket.connect(config.endpoint).await?;
        let local_addr = socket.local_addr()?;

        let mut scid = [0_u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(
            Some(L4_SNI),
            &scid,
            local_addr,
            config.endpoint,
            &mut quic_config,
        )?;
        let mut out = vec![0_u8; 65_535];
        let mut recv = vec![0_u8; 65_535];
        flush_conn_send(&socket, &mut conn, &mut out).await?;
        complete_handshake(
            &socket,
            &mut conn,
            &mut out,
            &mut recv,
            local_addr,
            config.endpoint,
        )
        .await?;

        let peer_cert = conn
            .peer_cert()
            .ok_or_else(|| anyhow::anyhow!("peer did not provide a certificate"))?;
        if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
            bail!("peer certificate public key does not match pinned endpoint key");
        }

        // Basic HTTP CONNECT does not require SETTINGS_ENABLE_CONNECT_PROTOCOL;
        // that setting is for extended CONNECT protocols such as CONNECT-IP.
        let h3_config = quiche::h3::Config::new()?;
        let h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
        let keepalive_period = config.keepalive_period;
        Ok(Self {
            socket,
            conn,
            h3,
            out,
            recv,
            local_addr,
            endpoint: config.endpoint,
            keepalive_period,
            next_keepalive: Instant::now() + keepalive_period,
            streams: HashMap::new(),
        })
    }

    async fn run(
        &mut self,
        command_rx: &mut mpsc::Receiver<Command>,
        command_tx: &mpsc::Sender<Command>,
    ) -> Result<bool> {
        loop {
            let now = Instant::now();
            let quic_deadline = self.conn.timeout().map(|timeout| now + timeout);
            let mut wake_at = quic_deadline.map_or(self.next_keepalive, |deadline| {
                deadline.min(self.next_keepalive)
            });
            if let Some(open_deadline) = self
                .streams
                .values()
                .filter(|state| !state.opened)
                .map(|state| state.open_deadline)
                .min()
            {
                wake_at = wake_at.min(open_deadline);
            }

            tokio::select! {
                biased;
                command = command_rx.recv() => {
                    let Some(command) = command else { return Ok(false); };
                    self.handle_command(command)?;
                }
                received = self.socket.recv(&mut self.recv) => {
                    let len = received.context("L4 UDP receive failed")?;
                    let info = quiche::RecvInfo { to: self.local_addr, from: self.endpoint };
                    if let Err(error) = self.conn.recv(&mut self.recv[..len], info) {
                        log::debug!("dropping L4 UDP packet rejected by QUIC: {error}");
                    }
                }
                () = tokio::time::sleep_until(wake_at) => {
                    let now = Instant::now();
                    if quic_deadline.is_some_and(|deadline| now >= deadline) {
                        self.conn.on_timeout();
                    }
                    if now >= self.next_keepalive {
                        self.conn.send_ack_eliciting()
                            .map_err(|error| anyhow::anyhow!("failed to schedule L4 keepalive: {error}"))?;
                        self.next_keepalive = now + self.keepalive_period;
                    }
                }
            }

            self.process_h3_events(command_tx)?;
            self.expire_connects();
            self.progress_streams()?;
            flush_conn_send(&self.socket, &mut self.conn, &mut self.out).await?;
            self.prune_finished();

            if self.conn.is_closed() {
                bail!("L4 QUIC connection closed");
            }
        }
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Open { authority, reply } => {
                // RFC 9114 basic CONNECT carries only :method and :authority.
                // :scheme/:path belong to extended CONNECT (such as CONNECT-IP),
                // not the TCP tunnel used by Cloudflare's L4 endpoint.
                let headers = [
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b""),
                ];
                match self.h3.send_request(&mut self.conn, &headers, false) {
                    Ok(stream_id) => {
                        self.streams.insert(
                            stream_id,
                            StreamState {
                                authority,
                                open_reply: Some(reply),
                                pending_read: None,
                                pending_write: None,
                                readable: false,
                                remote_finished: false,
                                local_finish_requested: false,
                                local_finished: false,
                                opened: false,
                                open_deadline: Instant::now() + STREAM_CONNECT_TIMEOUT,
                            },
                        );
                    }
                    Err(error) => {
                        let _ = reply.send(Err(io::Error::other(format!(
                            "failed to open L4 CONNECT stream: {error}"
                        ))));
                    }
                }
            }
            Command::Write {
                stream_id,
                data,
                reply,
            } => {
                let Some(state) = self.streams.get_mut(&stream_id) else {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "L4 stream is closed",
                    )));
                    return Ok(());
                };
                if state.pending_write.is_some() || state.local_finish_requested {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "L4 stream already has a pending write",
                    )));
                } else {
                    state.pending_write = Some(PendingWrite {
                        data,
                        offset: 0,
                        reply,
                    });
                }
            }
            Command::Finish { stream_id } => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.local_finish_requested = true;
                }
            }
            Command::Read { stream_id, reply } => {
                let Some(state) = self.streams.get_mut(&stream_id) else {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "L4 stream is closed",
                    )));
                    return Ok(());
                };
                if state.remote_finished {
                    let _ = reply.send(Ok(None));
                } else if state.pending_read.is_some() {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "L4 stream already has a pending read",
                    )));
                } else {
                    state.pending_read = Some(reply);
                }
            }
        }
        Ok(())
    }

    fn process_h3_events(&mut self, command_tx: &mpsc::Sender<Command>) -> Result<()> {
        loop {
            match self.h3.poll(&mut self.conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                    let status = status_code(&list);
                    let Some(state) = self.streams.get_mut(&stream_id) else {
                        continue;
                    };
                    if state.opened {
                        continue;
                    }
                    match status {
                        Some(code) if (200..300).contains(&code) && more_frames => {
                            state.opened = true;
                            let (application, bridge) = tokio::io::duplex(STREAM_BRIDGE_BYTES);
                            spawn_stream_bridge(stream_id, bridge, command_tx.clone());
                            if let Some(reply) = state.open_reply.take() {
                                let _ = reply.send(Ok(application));
                            }
                            log::debug!(
                                "L4 CONNECT {} opened on H3 stream {stream_id}",
                                state.authority
                            );
                        }
                        Some(code) => {
                            fail_open(
                                state,
                                io::Error::other(format!("CONNECT rejected with status {code}")),
                            );
                            state.remote_finished = true;
                            state.local_finished = true;
                        }
                        None => {}
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    if let Some(state) = self.streams.get_mut(&stream_id) {
                        state.readable = true;
                    }
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(state) = self.streams.get_mut(&stream_id) {
                        if !state.opened {
                            fail_open(
                                state,
                                io::Error::new(
                                    io::ErrorKind::ConnectionReset,
                                    "CONNECT stream finished before response",
                                ),
                            );
                        }
                        state.remote_finished = true;
                        if let Some(reply) = state.pending_read.take() {
                            let _ = reply.send(Ok(None));
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                    if let Some(state) = self.streams.get_mut(&stream_id) {
                        fail_stream(
                            state,
                            io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("L4 stream reset by peer: {code}"),
                            ),
                        );
                        state.remote_finished = true;
                        state.local_finished = true;
                    }
                }
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate | quiche::h3::Event::GoAway)) => {
                }
                Err(quiche::h3::Error::Done) => break,
                Err(error) => bail!("L4 HTTP/3 poll failed: {error}"),
            }
        }
        Ok(())
    }

    fn expire_connects(&mut self) {
        let now = Instant::now();
        let expired = self
            .streams
            .iter()
            .filter_map(|(&stream_id, state)| {
                (!state.opened && now >= state.open_deadline).then_some(stream_id)
            })
            .collect::<Vec<_>>();
        let error_code = quiche::h3::WireErrorCode::RequestCancelled as u64;
        for stream_id in expired {
            if let Some(state) = self.streams.get_mut(&stream_id) {
                fail_open(
                    state,
                    io::Error::new(io::ErrorKind::TimedOut, "L4 CONNECT timed out"),
                );
                state.local_finished = true;
                state.remote_finished = true;
            }
            let _ = self
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Read, error_code);
            let _ = self
                .conn
                .stream_shutdown(stream_id, quiche::Shutdown::Write, error_code);
        }
    }

    fn progress_streams(&mut self) -> Result<()> {
        let ids = self.streams.keys().copied().collect::<Vec<_>>();
        for stream_id in ids {
            self.progress_read(stream_id)?;
            self.progress_write(stream_id)?;
            self.progress_finish(stream_id)?;
        }
        Ok(())
    }

    fn progress_read(&mut self, stream_id: u64) -> Result<()> {
        let should_read = self.streams.get(&stream_id).is_some_and(|state| {
            state.opened && state.readable && state.pending_read.is_some() && !state.remote_finished
        });
        if !should_read {
            return Ok(());
        }

        let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
        match self.h3.recv_body(&mut self.conn, stream_id, &mut buffer) {
            Ok(0) | Err(quiche::h3::Error::Done) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.readable = false;
                }
            }
            Ok(read) => {
                buffer.truncate(read);
                if let Some(state) = self.streams.get_mut(&stream_id)
                    && let Some(reply) = state.pending_read.take()
                {
                    let _ = reply.send(Ok(Some(buffer)));
                }
            }
            Err(error) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    fail_stream(
                        state,
                        io::Error::other(format!("L4 stream read failed: {error}")),
                    );
                    state.remote_finished = true;
                    state.local_finished = true;
                }
            }
        }
        Ok(())
    }

    fn progress_write(&mut self, stream_id: u64) -> Result<()> {
        let pending = self
            .streams
            .get_mut(&stream_id)
            .and_then(|state| state.pending_write.take());
        let Some(mut pending) = pending else {
            return Ok(());
        };
        match self.h3.send_body(
            &mut self.conn,
            stream_id,
            &pending.data[pending.offset..],
            false,
        ) {
            Ok(written) => {
                pending.offset += written;
                if pending.offset == pending.data.len() {
                    let _ = pending.reply.send(Ok(()));
                } else if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.pending_write = Some(pending);
                }
            }
            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.pending_write = Some(pending);
                }
            }
            Err(error) => {
                let _ = pending.reply.send(Err(io::Error::other(format!(
                    "L4 stream write failed: {error}"
                ))));
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.remote_finished = true;
                    state.local_finished = true;
                }
            }
        }
        Ok(())
    }

    fn progress_finish(&mut self, stream_id: u64) -> Result<()> {
        let should_finish = self.streams.get(&stream_id).is_some_and(|state| {
            state.opened
                && state.local_finish_requested
                && !state.local_finished
                && state.pending_write.is_none()
        });
        if !should_finish {
            return Ok(());
        }
        match self.h3.send_body(&mut self.conn, stream_id, &[], true) {
            Ok(_) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.local_finished = true;
                }
            }
            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
            Err(error) => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    fail_stream(
                        state,
                        io::Error::other(format!("L4 stream finish failed: {error}")),
                    );
                    state.local_finished = true;
                    state.remote_finished = true;
                }
            }
        }
        Ok(())
    }

    fn prune_finished(&mut self) {
        self.streams
            .retain(|_, state| !(state.local_finished && state.remote_finished));
    }

    fn fail_all(&mut self, message: &str) {
        for state in self.streams.values_mut() {
            fail_stream(
                state,
                io::Error::new(io::ErrorKind::ConnectionReset, message.to_owned()),
            );
            state.remote_finished = true;
            state.local_finished = true;
        }
        self.streams.clear();
    }
}

async fn run_driver(
    config: Arc<DriverConfig>,
    mut session: Session,
    mut command_rx: mpsc::Receiver<Command>,
    command_tx: mpsc::Sender<Command>,
) {
    loop {
        match session.run(&mut command_rx, &command_tx).await {
            Ok(false) => return,
            Ok(true) => {}
            Err(error) => log::warn!("L4 session disconnected: {error:#}"),
        }
        session.fail_all("L4 outer connection disconnected");

        loop {
            tokio::time::sleep(RECONNECT_DELAY).await;
            match Session::connect(&config).await {
                Ok(new_session) => {
                    session = new_session;
                    break;
                }
                Err(error) => log::warn!("L4 reconnect failed: {error:#}"),
            }
        }
    }
}

fn spawn_stream_bridge(stream_id: u64, bridge: DuplexStream, command_tx: mpsc::Sender<Command>) {
    tokio::spawn(async move {
        let (mut from_application, mut to_application) = tokio::io::split(bridge);
        let write_tx = command_tx.clone();
        let write_side = async move {
            let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
            loop {
                match from_application.read(&mut buffer).await {
                    Ok(0) => {
                        let _ = write_tx.send(Command::Finish { stream_id }).await;
                        return;
                    }
                    Ok(read) => {
                        let (reply_tx, reply_rx) = oneshot::channel();
                        if write_tx
                            .send(Command::Write {
                                stream_id,
                                data: buffer[..read].to_vec(),
                                reply: reply_tx,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        match reply_rx.await {
                            Ok(Ok(())) => {}
                            _ => return,
                        }
                    }
                    Err(_) => {
                        let _ = write_tx.send(Command::Finish { stream_id }).await;
                        return;
                    }
                }
            }
        };

        let read_side = async move {
            loop {
                let (reply_tx, reply_rx) = oneshot::channel();
                if command_tx
                    .send(Command::Read {
                        stream_id,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    let _ = to_application.shutdown().await;
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(Some(data))) => {
                        if to_application.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                    Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                        let _ = to_application.shutdown().await;
                        return;
                    }
                }
            }
        };

        tokio::join!(write_side, read_side);
    });
}

fn fail_open(state: &mut StreamState, error: io::Error) {
    if let Some(reply) = state.open_reply.take() {
        let _ = reply.send(Err(error));
    }
}

fn fail_stream(state: &mut StreamState, error: io::Error) {
    let message = error.to_string();
    fail_open(state, io::Error::new(error.kind(), message.clone()));
    if let Some(reply) = state.pending_read.take() {
        let _ = reply.send(Err(io::Error::new(error.kind(), message.clone())));
    }
    if let Some(pending) = state.pending_write.take() {
        let _ = pending
            .reply
            .send(Err(io::Error::new(error.kind(), message)));
    }
}

fn status_code(headers: &[quiche::h3::Header]) -> Option<u16> {
    headers.iter().find_map(|header| {
        (header.name() == b":status")
            .then(|| std::str::from_utf8(header.value()).ok()?.parse().ok())
            .flatten()
    })
}

fn authority_for(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(_) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    recv: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
) -> Result<()> {
    let deadline = Instant::now() + CONNECTION_SETUP_TIMEOUT;
    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => bail!("timed out during L4 QUIC handshake"),
            received = socket.recv(recv) => {
                let len = received.context("UDP receive during L4 handshake failed")?;
                let info = quiche::RecvInfo { to: local_addr, from: endpoint };
                if let Err(error) = conn.recv(&mut recv[..len], info) {
                    log::debug!("dropping UDP packet rejected during L4 handshake: {error}");
                }
            }
            () = tokio::time::sleep(timeout) => conn.on_timeout(),
        }
        flush_conn_send(socket, conn, out).await?;
        if conn.is_established() {
            return Ok(());
        }
        if conn.is_closed() {
            bail!("L4 QUIC connection closed during handshake");
        }
    }
}

async fn flush_conn_send(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((written, info)) => {
                socket.send_to(&out[..written], info.to).await?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => bail!("L4 QUIC send failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv6_authority_with_brackets() {
        assert_eq!(
            authority_for(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443)),
            "[::1]:443"
        );
    }

    #[test]
    fn default_config_keeps_direct_l4_separate_from_tun_options() {
        let config = L4Config::default();
        assert_eq!(config.connect_port, 443);
        assert!(!config.use_ipv6_endpoint);
        assert!(config.source_ip.is_none());
    }
}
