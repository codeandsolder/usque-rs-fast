use anyhow::{Result, bail};
use bytes::Bytes;
use futures::{Future, Sink, Stream};
use octets::Octets;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

use crate::config::Config;
use crate::packet;
use crate::tls;
use crate::udp_socket::bind_udp_socket;

const MAX_DATAGRAM_SIZE: usize = 1350;
const CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_QUEUE_CAPACITY: usize = 1024;
const H3_BODY_DRAIN_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct PacketSessionConfig {
    pub endpoint: SocketAddr,
    pub bind: Option<SocketAddr>,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSessionState {
    Idle,
    Connecting,
    Handshaking,
    Ready,
    Reconnecting,
    Closed,
}

#[derive(Debug, Clone)]
enum SessionLoopOutcome {
    Reconnect(String),
}

#[derive(Debug, Clone, Copy)]
enum SessionTimerKind {
    Quic,
    Keepalive,
    Both,
}

impl SessionLoopOutcome {
    fn into_message(self) -> String {
        match self {
            Self::Reconnect(reason) => reason,
        }
    }
}

pub struct MasquePacketStream {
    socket: tokio::net::UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    connect_stream_id: u64,
    flow_id: u64,
    flow_prefix: Vec<u8>,
    outbound_queue: VecDeque<Bytes>,
    inbound_queue: VecDeque<Bytes>,
    out: Vec<u8>,
    buf: Vec<u8>,
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    keepalive_period: Duration,
    mtu: usize,
    state: PacketSessionState,
    timeout: Pin<Box<Sleep>>,
    timer_kind: SessionTimerKind,
    pending_send: Option<PendingUdpSend>,
    terminal_error: Option<String>,
    emitted_terminal_error: bool,
}

struct PendingUdpSend {
    len: usize,
    to: SocketAddr,
}

#[derive(Clone, Copy)]
struct DatagramPath {
    local_addr: SocketAddr,
    endpoint: SocketAddr,
}

fn connect_request_headers() -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ]
}

impl MasquePacketStream {
    /// Establish a reusable MASQUE CONNECT-IP packet stream.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid session configuration, socket/TLS/QUIC
    /// failures, endpoint-key mismatch, or CONNECT rejection.
    pub async fn connect(config: Arc<Config>, session_cfg: PacketSessionConfig) -> Result<Self> {
        if session_cfg.keepalive_period.is_zero() {
            bail!("keepalive period must be greater than zero");
        }

        let tls_material = tls::prepare_tls_material(config.as_ref())?;
        let mut quic_config = tls::build_quic_config(&tls_material, MAX_DATAGRAM_SIZE)?;

        let bind_addr: SocketAddr =
            session_cfg
                .bind
                .unwrap_or_else(|| match session_cfg.endpoint {
                    SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                    SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                });

        let socket = bind_udp_socket(bind_addr, "masque-packet-stream")?;
        socket.connect(session_cfg.endpoint).await?;
        let local_addr = socket.local_addr()?;

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let scid = quiche::ConnectionId::from_ref(&scid);

        let mut conn = quiche::connect(
            Some(&session_cfg.sni),
            &scid,
            local_addr,
            session_cfg.endpoint,
            &mut quic_config,
        )?;

        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut buf = vec![0u8; 65535];

        flush_conn_send(&socket, &mut conn, &mut out).await?;

        if let Some(outcome) = complete_handshake(
            &socket,
            &mut conn,
            &mut out,
            &mut buf,
            local_addr,
            session_cfg.endpoint,
        )
        .await
        {
            return Err(anyhow::anyhow!(outcome.into_message()));
        }

        let peer_cert = conn
            .peer_cert()
            .ok_or_else(|| anyhow::anyhow!("peer did not provide a certificate"))?;
        if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
            bail!("peer certificate public key does not match pinned endpoint key");
        }

        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.enable_extended_connect(true);

        let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;

        let req = connect_request_headers();
        let stream_id = h3_conn.send_request(&mut conn, &req, false)?;
        let flow_id = stream_id / 4;

        flush_conn_send(&socket, &mut conn, &mut out).await?;

        if let Some(outcome) = wait_for_connect_response(
            &socket,
            &mut conn,
            &mut h3_conn,
            &mut out,
            &mut buf,
            DatagramPath {
                local_addr,
                endpoint: session_cfg.endpoint,
            },
            stream_id,
        )
        .await
        {
            return Err(anyhow::anyhow!(outcome.into_message()));
        }

        let mut stream = Self {
            socket,
            conn,
            h3_conn,
            connect_stream_id: stream_id,
            flow_id,
            flow_prefix: build_flow_prefix(flow_id)?,
            outbound_queue: VecDeque::new(),
            inbound_queue: VecDeque::new(),
            out,
            buf,
            local_addr,
            endpoint: session_cfg.endpoint,
            keepalive_period: session_cfg.keepalive_period,
            mtu: usize::try_from(session_cfg.mtu)
                .map_err(|_| anyhow::anyhow!("MTU does not fit usize"))?,
            state: PacketSessionState::Ready,
            timeout: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            timer_kind: SessionTimerKind::Keepalive,
            pending_send: None,
            terminal_error: None,
            emitted_terminal_error: false,
        };
        stream.reset_timeout();
        Ok(stream)
    }

    pub const fn state(&self) -> PacketSessionState {
        self.state
    }

    /// Close the packet stream and flush QUIC shutdown traffic.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if shutdown or final packet transmission fails.
    pub async fn close(&mut self) -> io::Result<()> {
        futures::future::poll_fn(|cx| Pin::new(&mut *self).poll_close(cx)).await
    }

    fn reset_timeout(&mut self) {
        let (delay, kind) = match self.conn.timeout() {
            Some(quic_timeout) => match quic_timeout.cmp(&self.keepalive_period) {
                std::cmp::Ordering::Less => (quic_timeout, SessionTimerKind::Quic),
                std::cmp::Ordering::Equal => (quic_timeout, SessionTimerKind::Both),
                std::cmp::Ordering::Greater => (self.keepalive_period, SessionTimerKind::Keepalive),
            },
            None => (self.keepalive_period, SessionTimerKind::Keepalive),
        };
        self.timer_kind = kind;
        self.timeout.as_mut().reset(Instant::now() + delay);
    }

    fn set_terminal_error(&mut self, error: impl Into<String>) {
        self.state = PacketSessionState::Closed;
        if self.terminal_error.is_none() {
            self.terminal_error = Some(error.into());
        }
    }

    fn terminal_io_error(&self) -> io::Error {
        io::Error::other(
            self.terminal_error
                .clone()
                .unwrap_or_else(|| "MASQUE stream closed".to_string()),
        )
    }

    fn closed_io_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE stream closed")
    }

    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut progressed = false;

        loop {
            let mut made_progress = false;

            made_progress |=
                flush_pending_queue(&mut self.conn, &self.flow_prefix, &mut self.outbound_queue)?;
            match self.poll_flush_conn_send(cx) {
                Poll::Ready(Ok(flushed)) => made_progress |= flushed,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            match self.poll_recv_udp(cx) {
                Poll::Ready(Ok(received)) => made_progress |= received,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            made_progress |= self.poll_h3_events()?;
            made_progress |= self.poll_incoming_datagrams()?;

            if self.timeout.as_mut().poll(cx).is_ready() {
                match self.timer_kind {
                    SessionTimerKind::Quic => self.conn.on_timeout(),
                    SessionTimerKind::Keepalive => self
                        .conn
                        .send_ack_eliciting()
                        .map_err(|error| io::Error::other(error.to_string()))?,
                    SessionTimerKind::Both => {
                        self.conn.on_timeout();
                        self.conn
                            .send_ack_eliciting()
                            .map_err(|error| io::Error::other(error.to_string()))?;
                    }
                }
                self.reset_timeout();
                made_progress = true;
            }

            match self.poll_flush_conn_send(cx) {
                Poll::Ready(Ok(flushed)) => made_progress |= flushed,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            if self.conn.is_closed() {
                return Poll::Ready(Err(io::Error::other("MASQUE connection closed")));
            }

            if !made_progress {
                return if progressed {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            }

            progressed = true;
        }
    }

    fn poll_recv_udp(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut received = false;

        loop {
            match self.socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return if received {
                        Poll::Ready(Ok(true))
                    } else {
                        Poll::Pending
                    };
                }
            }

            loop {
                match self.socket.try_recv(&mut self.buf) {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo {
                            to: self.local_addr,
                            from: self.endpoint,
                        };
                        if let Err(error) = self.conn.recv(&mut self.buf[..len], recv_info) {
                            log::debug!("quic recv error: {error}");
                        }
                        received = true;
                        self.reset_timeout();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
    }

    fn poll_flush_conn_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut flushed = false;

        loop {
            if self.pending_send.is_none() {
                match self.socket.poll_send_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        return if flushed {
                            Poll::Ready(Ok(true))
                        } else {
                            Poll::Pending
                        };
                    }
                }

                let (write, send_info) = match self.conn.send(&mut self.out) {
                    Ok(result) => result,
                    Err(quiche::Error::Done) => return Poll::Ready(Ok(flushed)),
                    Err(error) => return Poll::Ready(Err(io::Error::other(error.to_string()))),
                };

                self.pending_send = Some(PendingUdpSend {
                    len: write,
                    to: send_info.to,
                });
                self.reset_timeout();
            }

            let Some(pending) = self.pending_send.as_ref() else {
                return Poll::Ready(Err(io::Error::other(
                    "internal error: pending UDP send missing after initialization",
                )));
            };
            if pending.to != self.endpoint {
                return Poll::Ready(Err(io::Error::other(format!(
                    "unexpected QUIC send target {} (expected {})",
                    pending.to, self.endpoint
                ))));
            }

            match self.socket.try_send(&self.out[..pending.len]) {
                Ok(sent) if sent == pending.len => {
                    self.pending_send = None;
                    flushed = true;
                }
                Ok(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial UDP send",
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return if flushed {
                        Poll::Ready(Ok(true))
                    } else {
                        Poll::Pending
                    };
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_h3_events(&mut self) -> io::Result<bool> {
        let mut progressed = false;

        loop {
            match self.h3_conn.poll(&mut self.conn) {
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    progressed = true;
                    drain_h3_body(&mut self.h3_conn, &mut self.conn, stream_id)?;
                }
                Ok((stream_id, quiche::h3::Event::Finished))
                    if stream_id == self.connect_stream_id =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "CONNECT request stream closed by peer",
                    ));
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code)))
                    if stream_id == self.connect_stream_id =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("CONNECT request stream reset by peer: {error_code}"),
                    ));
                }
                Ok(_) => progressed = true,
                Err(quiche::h3::Error::Done) => return Ok(progressed),
                Err(error) => return Err(io::Error::other(format!("h3 poll error: {error}"))),
            }
        }
    }

    fn poll_incoming_datagrams(&mut self) -> io::Result<bool> {
        let mut progressed = false;

        loop {
            if self.inbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
                return Ok(progressed);
            }

            match self.conn.dgram_recv_buf() {
                Ok(dgram) => {
                    progressed = true;
                    if let Some(offset) = parse_datagram_offset(&dgram, self.flow_id) {
                        let dgram = Bytes::from(dgram);
                        let packet = dgram.slice(offset..);
                        if packet::validate_incoming(packet.as_ref()).is_ok() {
                            self.inbound_queue.push_back(packet);
                        }
                    }
                }
                Err(quiche::Error::Done) => return Ok(progressed),
                Err(error) => {
                    log::debug!("dgram recv error: {error}");
                    return Ok(progressed);
                }
            }
        }
    }
}

impl Stream for MasquePacketStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(packet) = self.inbound_queue.pop_front() {
                return Poll::Ready(Some(Ok(packet)));
            }

            if self.emitted_terminal_error {
                return Poll::Ready(None);
            }

            if self.terminal_error.is_some() {
                self.emitted_terminal_error = true;
                return Poll::Ready(Some(Err(self.terminal_io_error())));
            }

            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Bytes> for MasquePacketStream {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state == PacketSessionState::Closed {
            return Poll::Ready(Err(Self::closed_io_error()));
        }

        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }

        if self.outbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.outbound_queue.len() < DEFAULT_QUEUE_CAPACITY {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        if self.state == PacketSessionState::Closed {
            return Err(Self::closed_io_error());
        }

        if self.terminal_error.is_some() {
            return Err(self.terminal_io_error());
        }

        if item.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet size {} exceeds configured MTU {}",
                    item.len(),
                    self.mtu
                ),
            ));
        }

        if self.outbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MASQUE outbound queue is full",
            ));
        }

        self.outbound_queue.push_back(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.terminal_error.is_some() {
                return Poll::Ready(Err(self.terminal_io_error()));
            }

            let queue_before = self.outbound_queue.len();
            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => {
                    if self.outbound_queue.is_empty() {
                        match self.poll_flush_conn_send(cx) {
                            Poll::Ready(Ok(_)) => return Poll::Ready(Ok(())),
                            Poll::Ready(Err(error)) => {
                                self.set_terminal_error(error.to_string());
                                return Poll::Ready(Err(error));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    if self.outbound_queue.len() == queue_before {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }

        if self.state != PacketSessionState::Closed {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }

            if let Err(error) = self.conn.close(true, 0, b"stream closed") {
                let error = io::Error::other(error.to_string());
                self.set_terminal_error(error.to_string());
                return Poll::Ready(Err(error));
            }
            self.state = PacketSessionState::Closed;
        }

        match self.poll_flush_conn_send(cx) {
            Poll::Ready(Ok(_)) => {
                self.emitted_terminal_error = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.set_terminal_error(error.to_string());
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
) -> Option<SessionLoopOutcome> {
    let deadline = Instant::now() + CONNECTION_SETUP_TIMEOUT;

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => {
                return Some(SessionLoopOutcome::Reconnect(
                    "timed out during QUIC handshake".to_string(),
                ));
            }
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo {
                            to: local_addr,
                            from: endpoint,
                        };
                        if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                            log::debug!("dropping UDP packet rejected by QUIC: {error}");
                        }
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv during handshake failed: {error}"))),
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during handshake failed: {error}"
            )));
        }

        if conn.is_established() {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed during handshake".to_string(),
            ));
        }
    }
}

async fn wait_for_connect_response(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    path: DatagramPath,
    stream_id: u64,
) -> Option<SessionLoopOutcome> {
    let deadline = Instant::now() + CONNECTION_SETUP_TIMEOUT;
    let mut connect_established = false;

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => {
                return Some(SessionLoopOutcome::Reconnect(
                    "timed out waiting for CONNECT response".to_string(),
                ));
            }
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo {
                            to: path.local_addr,
                            from: path.endpoint,
                        };
                        if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                            log::debug!("dropping UDP packet rejected by QUIC: {error}");
                        }
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv before CONNECT response failed: {error}"))),
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match h3_conn.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, more_frames })) if sid == stream_id => {
                    for header in &list {
                        if header.name() == b":status" {
                            let status = std::str::from_utf8(header.value()).unwrap_or("?");
                            if status.starts_with('2') {
                                connect_established = true;
                                if !more_frames {
                                    return Some(SessionLoopOutcome::Reconnect(
                                        "CONNECT response closed the request stream".to_string(),
                                    ));
                                }
                            } else {
                                return Some(SessionLoopOutcome::Reconnect(format!(
                                    "CONNECT rejected with status {status}"
                                )));
                            }
                        }
                    }
                }
                Ok((sid, quiche::h3::Event::Data)) => {
                    if let Err(error) = drain_h3_body(h3_conn, conn, sid) {
                        return Some(SessionLoopOutcome::Reconnect(format!(
                            "failed to drain HTTP/3 body: {error}"
                        )));
                    }
                }
                Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => {
                    return Some(SessionLoopOutcome::Reconnect(
                        "CONNECT request stream closed before tunnel use".to_string(),
                    ));
                }
                Ok((sid, quiche::h3::Event::Reset(error_code))) if sid == stream_id => {
                    return Some(SessionLoopOutcome::Reconnect(format!(
                        "CONNECT request stream reset by peer: {error_code}"
                    )));
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    return Some(SessionLoopOutcome::Reconnect(format!(
                        "h3 poll error: {error}"
                    )));
                }
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during CONNECT wait failed: {error}"
            )));
        }

        if connect_established {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed before CONNECT response".to_string(),
            ));
        }
    }
}

fn drain_h3_body(
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_id: u64,
) -> io::Result<()> {
    let mut body = [0_u8; H3_BODY_DRAIN_SIZE];

    loop {
        match h3_conn.recv_body(conn, stream_id, &mut body) {
            Ok(0) | Err(quiche::h3::Error::Done) => return Ok(()),
            Ok(read) => log::trace!("discarded {read} HTTP/3 body bytes on stream {stream_id}"),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "HTTP/3 body receive failed on stream {stream_id}: {error}"
                )));
            }
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
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => bail!("{error}"),
        }
    }
    Ok(())
}

fn flush_pending_queue(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    queue: &mut VecDeque<Bytes>,
) -> io::Result<bool> {
    let mut progressed = false;

    while let Some(packet) = queue.front() {
        let Some(dgram) = build_flow_datagram(flow_prefix, packet) else {
            let _ = queue.pop_front();
            progressed = true;
            log::trace!("dropping outgoing packet before MASQUE send");
            continue;
        };

        match conn.dgram_send_buf(dgram) {
            Ok(()) => {
                let _ = queue.pop_front();
                progressed = true;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => {
                return Err(io::Error::other(format!("datagram send failed: {error}")));
            }
        }
    }

    Ok(progressed)
}

fn build_flow_datagram(flow_prefix: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    packet::validate_outgoing(packet).ok()?;
    let mut dgram = Vec::with_capacity(flow_prefix.len() + packet.len());
    dgram.extend_from_slice(flow_prefix);
    dgram.extend_from_slice(packet);
    Some(dgram)
}

fn build_flow_prefix(flow_id: u64) -> Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(16);
    let mut tmp = [0u8; 8];
    let len = {
        let mut builder = octets::OctetsMut::with_slice(&mut tmp);
        builder
            .put_varint(flow_id)
            .map_err(|error| anyhow::anyhow!("flow ID does not fit a QUIC varint: {error}"))?;
        builder.off()
    };
    prefix.extend_from_slice(&tmp[..len]);
    prefix.push(0x00);
    Ok(prefix)
}

fn parse_datagram_offset(dgram: &[u8], expected_flow_id: u64) -> Option<usize> {
    let mut bytes = Octets::with_slice(dgram);
    let flow_id = bytes.get_varint().ok()?;
    if flow_id != expected_flow_id {
        return None;
    }
    let context_id = bytes.get_varint().ok()?;
    if context_id != 0 {
        return None;
    }
    let offset = bytes.off();
    if offset >= dgram.len() {
        return None;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(value: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let len = {
            let mut builder = octets::OctetsMut::with_slice(&mut tmp);
            assert!(builder.put_varint(value).is_ok());
            builder.off()
        };
        tmp[..len].to_vec()
    }

    #[test]
    fn parse_datagram_offset_valid() -> Result<()> {
        let payload = b"hello";
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(payload);

        let offset = parse_datagram_offset(&datagram, 0)
            .ok_or_else(|| anyhow::anyhow!("test datagram should parse"))?;
        assert_eq!(&datagram[offset..], payload);
        Ok(())
    }

    #[test]
    fn build_flow_datagram_preserves_endpoint_generated_ttl() -> Result<()> {
        let flow_prefix = build_flow_prefix(0)?;
        let packet = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 64, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10,
            0, 0, 2,
        ]);
        let datagram = build_flow_datagram(&flow_prefix, &packet)
            .ok_or_else(|| anyhow::anyhow!("test packet should produce a flow datagram"))?;
        assert_eq!(datagram[flow_prefix.len() + 8], 64);
        Ok(())
    }
}
