use anyhow::{bail, Result};
use datagram_socket::DatagramSocketRecvExt;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::ReadBuf;
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::config::Config;
use crate::icmp;
use crate::packet;
use crate::tls;
use crate::udp_socket::{bind_udp_socket, detect_udp_gso, send_udp_gso};

const MAX_DATAGRAM_SIZE: usize = 1350;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Configuration for a MASQUE tunnel session.
pub struct TunnelConfig {
    pub endpoint: SocketAddr,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    fn one_decimal(value: u64, unit: u64, suffix: &str) -> String {
        let whole = value / unit;
        let remainder = value % unit;
        let rounded_tenths = (remainder * 10 + unit / 2) / unit;
        if rounded_tenths == 10 {
            format!("{}.0 {suffix}", whole + 1)
        } else {
            format!("{whole}.{rounded_tenths} {suffix}")
        }
    }

    if bytes >= GIB {
        one_decimal(bytes, GIB, "GiB")
    } else if bytes >= MIB {
        one_decimal(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        one_decimal(bytes, KIB, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }
}

async fn send_tun_batch(
    tun_dev: &tun_rs::AsyncDevice,
    gro_table: &mut GROTable,
    bufs: &mut [Vec<u8>],
) -> Result<()> {
    if bufs.is_empty() {
        return Ok(());
    }

    tun_dev
        .send_multiple(gro_table, bufs, VIRTIO_NET_HDR_LEN)
        .await
        .map_err(|e| anyhow::anyhow!("failed to write packet batch to TUN: {e}"))?;
    Ok(())
}

fn stage_tun_packet(buf: &mut Vec<u8>, packet: &[u8]) {
    buf.clear();
    buf.resize(VIRTIO_NET_HDR_LEN, 0);
    buf.extend_from_slice(packet);
}

const MAX_UDP_BATCH_BYTES: usize = 65_507;
const UDP_GSO_MAX_SEGMENTS: usize = 64;
const UDP_RECV_BATCH_SIZE: usize = 32;

fn reset_udp_read_bufs(bufs: &mut [ReadBuf<'_>]) {
    for buf in bufs {
        buf.clear();
    }
}

fn process_udp_batch<H>(
    conn: &mut quiche::Connection,
    bufs: &mut [ReadBuf<'_>],
    count: usize,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    datagram_handler: &mut H,
) where
    H: FnMut(&[u8]) -> bool,
{
    for buf in &mut bufs[..count] {
        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from: peer_addr,
        };
        if let Err(error) =
            conn.recv_with_dgram_handler(buf.filled_mut(), recv_info, datagram_handler)
        {
            log::debug!("dropping UDP packet rejected by QUIC: {error}");
        }
    }
}

async fn flush_quic_packets(
    conn: &mut quiche::Connection,
    socket: &tokio::net::UdpSocket,
    out: &mut [u8],
    udp_gso: bool,
) -> Result<()> {
    loop {
        let first_cap = MAX_DATAGRAM_SIZE.min(out.len());
        let (first_len, first_info) = match conn.send(&mut out[..first_cap]) {
            Ok(v) => v,
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => bail!("quic send error: {e}"),
        };

        let segment_size = first_len;
        let mut total = first_len;
        let mut done = false;

        if udp_gso && segment_size > 0 {
            // Linux UDP GSO supports at most 64 segments per super-buffer.
            // Byte/send-quantum limits alone can exceed that for small QUIC
            // ACK/control packets and cause sendmsg(UDP_SEGMENT) to fail EINVAL.
            let burst_limit = conn
                .send_quantum()
                .max(segment_size)
                .min(out.len())
                .min(segment_size.saturating_mul(UDP_GSO_MAX_SEGMENTS));

            while total + segment_size <= burst_limit {
                match conn.send(&mut out[total..total + segment_size]) {
                    Ok((write, send_info)) => {
                        // Active migration is disabled in our QUIC config, so all
                        // packets in a burst must target the same peer.
                        if send_info.to != first_info.to {
                            bail!("QUIC destination changed inside a GSO burst");
                        }

                        total += write;
                        if write < segment_size {
                            // UDP GSO permits the final segment to be shorter.
                            break;
                        }
                    }
                    Err(quiche::Error::BufferTooShort) => {
                        // A control packet may need a larger buffer than the
                        // current data segment. Flush this burst and retry it
                        // with the full configured packet size.
                        break;
                    }
                    Err(quiche::Error::Done) => {
                        done = true;
                        break;
                    }
                    Err(e) => bail!("quic send error: {e}"),
                }
            }
        }

        if udp_gso && total > segment_size {
            send_udp_gso(socket, &out[..total], segment_size, first_info.to)
                .await
                .map_err(|e| anyhow::anyhow!("UDP GSO send failed: {e}"))?;
        } else {
            socket
                .send_to(&out[..first_len], first_info.to)
                .await
                .map_err(|e| anyhow::anyhow!("UDP send failed: {e}"))?;
        }

        if done {
            return Ok(());
        }
    }
}

/// Run the MASQUE tunnel, reconnecting on-demand when traffic arrives.
///
/// # Errors
///
/// Returns an error if the TUN device cannot be read or the tunnel cannot be
/// initialized before entering the reconnect loop.
pub async fn maintain_tunnel(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_dev: tun_rs::AsyncDevice,
) -> Result<()> {
    if tunnel_cfg.keepalive_period.is_zero() {
        bail!("keepalive period must be greater than zero");
    }

    let mtu = usize::try_from(tunnel_cfg.mtu)
        .map_err(|_| anyhow::anyhow!("configured MTU does not fit usize"))?;
    let packet_capacity = mtu + 128;
    let mut pending_packets = VecDeque::new();

    let mut idle_raw = vec![0u8; VIRTIO_NET_HDR_LEN + 65_535];
    let mut idle_bufs = vec![vec![0u8; packet_capacity]; IDEAL_BATCH_SIZE];
    let mut idle_sizes = vec![0usize; IDEAL_BATCH_SIZE];

    loop {
        if pending_packets.is_empty() {
            eprint!("\r\x1b[2K[idle] Waiting for traffic...");
            let count = tun_dev
                .recv_multiple(&mut idle_raw, &mut idle_bufs, &mut idle_sizes, 0)
                .await
                .map_err(|e| anyhow::anyhow!("failed to read TUN device while idle: {e}"))?;
            if count == 0 {
                bail!("TUN device closed");
            }
            for i in 0..count {
                pending_packets.push_back(idle_bufs[i][..idle_sizes[i]].to_vec());
            }
        }

        eprintln!("\r\x1b[2K[connecting] {} ...", tunnel_cfg.endpoint);

        match Box::pin(run_tunnel_session(
            config,
            tunnel_cfg,
            &tun_dev,
            &mut pending_packets,
        ))
        .await
        {
            Ok(()) => {
                eprintln!("\r\x1b[2K[disconnected] Session ended");
            }
            Err(e) => {
                eprintln!("\r\x1b[2K[error] {e:#}");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

struct NativeQuic {
    socket: tokio::net::UdpSocket,
    conn: quiche::Connection,
    out: Vec<u8>,
    buf: Vec<u8>,
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    udp_gso: bool,
}

struct NativeSession {
    quic: NativeQuic,
    h3_conn: quiche::h3::Connection,
    flow_id: u64,
}

struct ForwardBuffers {
    tun_raw: Vec<u8>,
    tun_packets: Vec<Vec<u8>>,
    tun_sizes: Vec<usize>,
    gro_table: GROTable,
    inbound_packets: Vec<Vec<u8>>,
    icmp_packet: Vec<Vec<u8>>,
}

impl ForwardBuffers {
    fn new(packet_capacity: usize) -> Self {
        Self {
            tun_raw: vec![0u8; VIRTIO_NET_HDR_LEN + 65_535],
            tun_packets: vec![vec![0u8; packet_capacity]; IDEAL_BATCH_SIZE],
            tun_sizes: vec![0usize; IDEAL_BATCH_SIZE],
            gro_table: GROTable::default(),
            inbound_packets: (0..IDEAL_BATCH_SIZE)
                .map(|_| Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet_capacity))
                .collect(),
            icmp_packet: vec![Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet_capacity)],
        }
    }
}

struct TunnelStats {
    session_start: Instant,
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    dropped: u64,
}

impl TunnelStats {
    fn new() -> Self {
        Self {
            session_start: Instant::now(),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            dropped: 0,
        }
    }

    fn print(&self, conn: &quiche::Connection) {
        let qs = conn.stats();
        let connected_for = format_duration(self.session_start.elapsed());
        let tx_size = format_bytes(self.tx_bytes);
        let rx_size = format_bytes(self.rx_bytes);
        let lost = qs.lost;
        let retrans = qs.retrans;
        eprint!(
            "\r\x1b[2K[connected {connected_for}] tx: {} ({tx_size})  rx: {} ({rx_size})  drop: {}  lost: {lost}  retrans: {retrans}",
            self.tx_packets, self.rx_packets, self.dropped
        );
    }
}

async fn open_native_quic(config: &Config, tunnel_cfg: &TunnelConfig) -> Result<NativeQuic> {
    let tls_material = tls::prepare_tls_material(config)?;
    let mut quic_config = tls::build_quic_config(&tls_material, MAX_DATAGRAM_SIZE)?;
    let bind_addr = match tunnel_cfg.endpoint {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };

    let socket = bind_udp_socket(bind_addr, "masque-native-tunnel")?;
    socket.connect(tunnel_cfg.endpoint).await?;
    let local_addr = socket.local_addr()?;
    let udp_gso = detect_udp_gso(&socket, MAX_DATAGRAM_SIZE);
    log::info!("UDP GSO enabled: {udp_gso}");

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::connect(
        Some(&tunnel_cfg.sni),
        &scid,
        local_addr,
        tunnel_cfg.endpoint,
        &mut quic_config,
    )
    .map_err(|e| anyhow::anyhow!("quiche connect: {e}"))?;

    let mut quic = NativeQuic {
        socket,
        conn,
        out: vec![0u8; MAX_UDP_BATCH_BYTES],
        buf: vec![0u8; 65_535],
        local_addr,
        endpoint: tunnel_cfg.endpoint,
        udp_gso,
    };
    flush_quic_packets(&mut quic.conn, &quic.socket, &mut quic.out, false).await?;
    complete_native_handshake(&mut quic).await?;

    let peer_cert = quic
        .conn
        .peer_cert()
        .ok_or_else(|| anyhow::anyhow!("peer did not provide a certificate"))?;
    if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
        bail!("peer certificate public key does not match pinned endpoint key");
    }
    log::debug!("Endpoint key pinning verified");
    Ok(quic)
}

async fn complete_native_handshake(quic: &mut NativeQuic) -> Result<()> {
    loop {
        let timeout = quic.conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = quic.socket.recv(&mut quic.buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: quic.local_addr,
                    from: quic.endpoint,
                };
                if let Err(error) = quic.conn.recv(&mut quic.buf[..len], recv_info) {
                    log::debug!("dropping UDP packet rejected by QUIC: {error}");
                }
            }
            () = tokio::time::sleep(timeout) => {
                quic.conn.on_timeout();
            }
        }

        flush_quic_packets(&mut quic.conn, &quic.socket, &mut quic.out, false).await?;
        if quic.conn.is_established() {
            return Ok(());
        }
        if quic.conn.is_closed() {
            bail!("connection closed during handshake");
        }
    }
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

async fn establish_connect_ip(mut quic: NativeQuic) -> Result<NativeSession> {
    let mut h3_config = quiche::h3::Config::new().map_err(|e| anyhow::anyhow!("h3 config: {e}"))?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn = quiche::h3::Connection::with_transport(&mut quic.conn, &h3_config)
        .map_err(|e| anyhow::anyhow!("h3 connection: {e}"))?;

    let request = connect_request_headers();
    let stream_id = h3_conn
        .send_request(&mut quic.conn, &request, false)
        .map_err(|e| anyhow::anyhow!("send CONNECT request: {e}"))?;
    let flow_id = stream_id / 4;
    log::debug!("CONNECT request sent on stream {stream_id}, flow_id={flow_id}");

    flush_quic_packets(&mut quic.conn, &quic.socket, &mut quic.out, false).await?;
    wait_for_connect_response(&mut quic, &mut h3_conn, stream_id).await?;

    Ok(NativeSession {
        quic,
        h3_conn,
        flow_id,
    })
}

async fn wait_for_connect_response(
    quic: &mut NativeQuic,
    h3_conn: &mut quiche::h3::Connection,
    stream_id: u64,
) -> Result<()> {
    for _ in 0..100 {
        let timeout = quic.conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = quic.socket.recv(&mut quic.buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: quic.local_addr,
                    from: quic.endpoint,
                };
                if let Err(error) = quic.conn.recv(&mut quic.buf[..len], recv_info) {
                    log::debug!("dropping UDP packet rejected by QUIC: {error}");
                }
            }
            () = tokio::time::sleep(timeout) => {
                quic.conn.on_timeout();
            }
        }

        let established = connect_response_ready(h3_conn, &mut quic.conn, stream_id)?;
        flush_quic_packets(&mut quic.conn, &quic.socket, &mut quic.out, false).await?;
        if established {
            return Ok(());
        }
        if quic.conn.is_closed() {
            bail!("connection closed before CONNECT response");
        }
    }

    bail!("timed out waiting for CONNECT response")
}

fn connect_response_ready(
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_id: u64,
) -> Result<bool> {
    loop {
        match h3_conn.poll(conn) {
            Ok((response_stream_id, quiche::h3::Event::Headers { list, .. }))
                if response_stream_id == stream_id =>
            {
                for header in &list {
                    if header.name() == b":status" {
                        let status = std::str::from_utf8(header.value()).unwrap_or("?");
                        log::debug!("CONNECT response status: {status}");
                        if status.starts_with('2') {
                            return Ok(true);
                        }
                        bail!("CONNECT rejected with status {status}");
                    }
                }
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => return Ok(false),
            Err(e) => bail!("h3 poll error: {e}"),
        }
    }
}

fn build_flow_prefix(flow_id: u64) -> Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(16);
    let mut tmp = [0u8; 8];
    let mut buf = octets::OctetsMut::with_slice(&mut tmp);
    buf.put_varint(flow_id)
        .map_err(|error| anyhow::anyhow!("flow ID does not fit a QUIC varint: {error}"))?;
    let len = buf.off();
    prefix.extend_from_slice(&tmp[..len]);
    prefix.push(0);
    Ok(prefix)
}

fn queue_pending_packets(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    pending_packets: &mut VecDeque<Vec<u8>>,
    stats: &mut TunnelStats,
) -> Result<()> {
    while let Some(mut packet) = pending_packets.pop_front() {
        if packet::prepare_outgoing(&mut packet).is_err() {
            continue;
        }

        let mut datagram = Vec::with_capacity(flow_prefix.len() + packet.len());
        datagram.extend_from_slice(flow_prefix);
        datagram.extend_from_slice(&packet);
        let packet_len = u64::try_from(packet.len())
            .map_err(|_| anyhow::anyhow!("packet length does not fit u64"))?;
        if conn.dgram_send_buf(datagram).is_ok() {
            stats.tx_packets += 1;
            stats.tx_bytes += packet_len;
        }
    }
    Ok(())
}

async fn forward_tun_batch(
    conn: &mut quiche::Connection,
    tun_dev: &tun_rs::AsyncDevice,
    flow_prefix: &[u8],
    buffers: &mut ForwardBuffers,
    count: usize,
    stats: &mut TunnelStats,
) -> Result<()> {
    for index in 0..count {
        let packet_len = buffers.tun_sizes[index];
        let packet = &mut buffers.tun_packets[index][..packet_len];
        if let Err(error) = packet::prepare_outgoing(packet) {
            stats.dropped += 1;
            log::trace!("dropping outgoing packet: {error}");
            continue;
        }

        let mut datagram = Vec::with_capacity(flow_prefix.len() + packet_len);
        datagram.extend_from_slice(flow_prefix);
        datagram.extend_from_slice(packet);
        match conn.dgram_send_buf(datagram) {
            Ok(()) => {
                stats.tx_packets += 1;
                stats.tx_bytes += u64::try_from(packet_len)
                    .map_err(|_| anyhow::anyhow!("packet length does not fit u64"))?;
            }
            Err(quiche::Error::InvalidState) => {
                log::warn!("datagram send: peer doesn't support datagrams");
            }
            Err(quiche::Error::Done) => {
                stats.dropped += 1;
                log::trace!("datagram send queue full, dropping packet");
            }
            Err(error) => {
                stats.dropped += 1;
                log::debug!("datagram send error: {error}, generating ICMP");
                if let Some(icmp) = icmp::compose_icmp_too_large(packet, 1280) {
                    stage_tun_packet(&mut buffers.icmp_packet[0], &icmp);
                    send_tun_batch(tun_dev, &mut buffers.gro_table, &mut buffers.icmp_packet)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

fn drain_h3_events(h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection) {
    loop {
        match h3_conn.poll(conn) {
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(error) => {
                log::warn!("h3 poll error: {error}");
                break;
            }
        }
    }
}

async fn drain_inbound_datagrams(
    conn: &mut quiche::Connection,
    tun_dev: &tun_rs::AsyncDevice,
    flow_id: u64,
    buffers: &mut ForwardBuffers,
    stats: &mut TunnelStats,
    inbound_count: &mut usize,
) -> Result<()> {
    // Synchronous DATAGRAM delivery may already have filled the batch. Flush it
    // before draining any overflow that fell back to quiche's receive queue.
    if *inbound_count == buffers.inbound_packets.len() {
        send_tun_batch(
            tun_dev,
            &mut buffers.gro_table,
            &mut buffers.inbound_packets[..*inbound_count],
        )
        .await?;
        *inbound_count = 0;
    }

    loop {
        match conn.dgram_recv_buf() {
            Ok(datagram) => {
                let Some(ip_payload) = parse_datagram(&datagram, flow_id) else {
                    continue;
                };
                if packet::validate_incoming(ip_payload).is_err() {
                    continue;
                }

                stats.rx_packets += 1;
                stats.rx_bytes += u64::try_from(ip_payload.len())
                    .map_err(|_| anyhow::anyhow!("packet length does not fit u64"))?;
                stage_tun_packet(&mut buffers.inbound_packets[*inbound_count], ip_payload);
                *inbound_count += 1;

                if *inbound_count == buffers.inbound_packets.len() {
                    send_tun_batch(
                        tun_dev,
                        &mut buffers.gro_table,
                        &mut buffers.inbound_packets[..*inbound_count],
                    )
                    .await?;
                    *inbound_count = 0;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => {
                log::debug!("dgram recv error: {error}");
                break;
            }
        }
    }

    if *inbound_count > 0 {
        send_tun_batch(
            tun_dev,
            &mut buffers.gro_table,
            &mut buffers.inbound_packets[..*inbound_count],
        )
        .await?;
        *inbound_count = 0;
    }
    Ok(())
}

fn handle_session_timeout(
    conn: &mut quiche::Connection,
    quic_timeout: Option<Duration>,
    keepalive_interval: Duration,
) -> Result<()> {
    if quic_timeout.is_some_and(|duration| duration <= keepalive_interval) {
        conn.on_timeout();
    }
    if quic_timeout.is_none_or(|duration| keepalive_interval <= duration) {
        conn.send_ack_eliciting()
            .map_err(|error| anyhow::anyhow!("failed to schedule QUIC keepalive: {error}"))?;
    }
    Ok(())
}

async fn forward_native_session(
    session: &mut NativeSession,
    tun_dev: &tun_rs::AsyncDevice,
    pending_packets: &mut VecDeque<Vec<u8>>,
    mtu: usize,
    keepalive_interval: Duration,
) -> Result<()> {
    let flow_prefix = build_flow_prefix(session.flow_id)?;
    let mut stats = TunnelStats::new();
    queue_pending_packets(
        &mut session.quic.conn,
        &flow_prefix,
        pending_packets,
        &mut stats,
    )?;

    let mut buffers = ForwardBuffers::new(mtu + 128);
    let mut udp_recv_storage = vec![vec![0u8; MAX_DATAGRAM_SIZE]; UDP_RECV_BATCH_SIZE];
    let mut udp_recv_bufs = udp_recv_storage
        .iter_mut()
        .map(|storage| ReadBuf::new(storage.as_mut_slice()))
        .collect::<Vec<_>>();
    let mut stats_interval = tokio::time::interval(Duration::from_secs(1));
    stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stats_interval.tick().await;

    loop {
        // DATAGRAMs consumed synchronously by quiche are staged directly into
        // this preallocated batch. Overflow remains queued in quiche and is
        // drained into the same batch below.
        let mut inbound_count = 0usize;
        let quic_timeout = session.quic.conn.timeout();
        let timeout = quic_timeout
            .unwrap_or(keepalive_interval)
            .min(keepalive_interval);

        tokio::select! {
            biased;
            result = async {
                reset_udp_read_bufs(&mut udp_recv_bufs);
                session.quic.socket.recv_many(&mut udp_recv_bufs).await
            } => {
                let count = result?;
                process_udp_batch(
                    &mut session.quic.conn,
                    &mut udp_recv_bufs,
                    count,
                    session.quic.local_addr,
                    session.quic.endpoint,
                    &mut |dgram| {
                        if inbound_count == buffers.inbound_packets.len() {
                            return false;
                        }
                        let Some(ip_payload) = parse_datagram(dgram, session.flow_id) else {
                            return false;
                        };
                        if packet::validate_incoming(ip_payload).is_err() {
                            return false;
                        }
                        let Ok(packet_len) = u64::try_from(ip_payload.len()) else {
                            return false;
                        };

                        stats.rx_packets += 1;
                        stats.rx_bytes += packet_len;
                        stage_tun_packet(
                            &mut buffers.inbound_packets[inbound_count],
                            ip_payload,
                        );
                        inbound_count += 1;
                        true
                    },
                );
            }
            result = tun_dev.recv_multiple(
                &mut buffers.tun_raw,
                &mut buffers.tun_packets,
                &mut buffers.tun_sizes,
                0,
            ) => {
                let count = result
                    .map_err(|e| anyhow::anyhow!("failed to read packet batch from TUN: {e}"))?;
                if count == 0 {
                    bail!("TUN device closed");
                }
                forward_tun_batch(
                    &mut session.quic.conn,
                    tun_dev,
                    &flow_prefix,
                    &mut buffers,
                    count,
                    &mut stats,
                ).await?;
            }
            () = tokio::time::sleep(timeout) => {
                handle_session_timeout(
                    &mut session.quic.conn,
                    quic_timeout,
                    keepalive_interval,
                )?;
            }
            _ = stats_interval.tick() => stats.print(&session.quic.conn),
        }

        drain_h3_events(&mut session.h3_conn, &mut session.quic.conn);
        drain_inbound_datagrams(
            &mut session.quic.conn,
            tun_dev,
            session.flow_id,
            &mut buffers,
            &mut stats,
            &mut inbound_count,
        )
        .await?;
        flush_quic_packets(
            &mut session.quic.conn,
            &session.quic.socket,
            &mut session.quic.out,
            session.quic.udp_gso,
        )
        .await?;

        if session.quic.conn.is_closed() {
            return Ok(());
        }
    }
}

async fn run_tunnel_session(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_dev: &tun_rs::AsyncDevice,
    pending_packets: &mut VecDeque<Vec<u8>>,
) -> Result<()> {
    let quic = open_native_quic(config, tunnel_cfg).await?;
    let session = Box::pin(establish_connect_ip(quic)).await?;
    let mut session = Box::new(session);
    eprintln!("\r\x1b[2K[connected] MASQUE tunnel established");

    let mtu = usize::try_from(tunnel_cfg.mtu)
        .map_err(|_| anyhow::anyhow!("configured MTU does not fit usize"))?;
    Box::pin(forward_native_session(
        &mut session,
        tun_dev,
        pending_packets,
        mtu,
        tunnel_cfg.keepalive_period,
    ))
    .await
}

/// Parse an H3 datagram: `varint(flow_id)` + `varint(context_id)` + IP packet
/// Returns the IP payload slice if `flow_id` matches and `context_id` == 0.
fn parse_datagram(dgram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let mut b = octets::Octets::with_slice(dgram);

    let fid = b.get_varint().ok()?;
    if fid != expected_flow_id {
        return None;
    }

    let ctx_id = b.get_varint().ok()?;
    if ctx_id != 0 {
        return None;
    }

    let off = b.off();
    if off >= dgram.len() {
        return None;
    }

    Some(&dgram[off..])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_datagram tests ----

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        assert!(b.put_varint(val).is_ok());
        let len = b.off();
        tmp[..len].to_vec()
    }

    fn make_datagram(flow_id: u64, context_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut dgram = Vec::new();
        dgram.extend_from_slice(&encode_varint(flow_id));
        dgram.extend_from_slice(&encode_varint(context_id));
        dgram.extend_from_slice(payload);
        dgram
    }

    #[test]
    fn parse_datagram_valid() {
        let payload = b"hello world";
        let dgram = make_datagram(0, 0, payload);
        let result = parse_datagram(&dgram, 0);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_flow_id_mismatch() {
        let dgram = make_datagram(1, 0, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_nonzero_context() {
        let dgram = make_datagram(0, 1, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_empty_payload() {
        let dgram = make_datagram(0, 0, b"");
        // Empty payload means off == dgram.len(), should return None
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_large_flow_id() {
        // flow_id that requires 4-byte varint encoding
        let flow_id = 16384;
        let payload = vec![0xABu8; 1300];
        let dgram = make_datagram(flow_id, 0, &payload);
        let result = parse_datagram(&dgram, flow_id);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_truncated() {
        // Just a single byte - can't even decode flow_id
        let dgram = vec![0xFF];
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    // ---- format_bytes tests ----

    #[test]
    fn format_bytes_values() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
    }

    // ---- format_duration tests ----

    #[test]
    fn format_duration_values() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 00m 00s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 01m 01s");
    }
}
