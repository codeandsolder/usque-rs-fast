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

fn process_udp_batch(
    conn: &mut quiche::Connection,
    bufs: &mut [ReadBuf<'_>],
    count: usize,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) {
    for buf in &mut bufs[..count] {
        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from: peer_addr,
        };
        if let Err(error) = conn.recv(buf.filled_mut(), recv_info) {
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

        match run_tunnel_session(config, tunnel_cfg, &tun_dev, &mut pending_packets).await {
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

#[expect(
    clippy::too_many_lines,
    reason = "single QUIC/TUN event loop keeps transport state and select branches co-located"
)]
async fn run_tunnel_session(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_dev: &tun_rs::AsyncDevice,
    pending_packets: &mut VecDeque<Vec<u8>>,
) -> Result<()> {
    let tls_material = tls::prepare_tls_material(config)?;

    let mut quic_config = tls::build_quic_config(&tls_material, MAX_DATAGRAM_SIZE)?;

    let bind_addr: SocketAddr = match tunnel_cfg.endpoint {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };

    let mut socket = bind_udp_socket(bind_addr, "masque-native-tunnel")?;
    socket.connect(tunnel_cfg.endpoint).await?;
    let local_addr = socket.local_addr()?;
    let udp_gso = detect_udp_gso(&socket, MAX_DATAGRAM_SIZE);
    log::info!("UDP GSO enabled: {udp_gso}");

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some(&tunnel_cfg.sni),
        &scid,
        local_addr,
        tunnel_cfg.endpoint,
        &mut quic_config,
    )
    .map_err(|e| anyhow::anyhow!("quiche connect: {e}"))?;

    let mut out = vec![0u8; MAX_UDP_BATCH_BYTES];
    let mut buf = vec![0u8; 65535];

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|e| anyhow::anyhow!("initial send: {e}"))?;
    socket.send_to(&out[..write], send_info.to).await?;

    // Complete handshake
    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(&mut buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: tunnel_cfg.endpoint,
                };
                if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                log::debug!("dropping UDP packet rejected by QUIC: {error}");
            }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("send during handshake: {e}"),
            }
        }

        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed during handshake");
        }
    }

    // Verify endpoint key pinning.
    let peer_cert = conn
        .peer_cert()
        .ok_or_else(|| anyhow::anyhow!("peer did not provide a certificate"))?;
    if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
        bail!("peer certificate public key does not match pinned endpoint key");
    }
    log::debug!("Endpoint key pinning verified");

    // Set up HTTP/3
    let mut h3_config = quiche::h3::Config::new().map_err(|e| anyhow::anyhow!("h3 config: {e}"))?;
    h3_config.enable_extended_connect(true);

    let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| anyhow::anyhow!("h3 connection: {e}"))?;

    // Send CONNECT request for cf-connect-ip
    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ];

    let stream_id = h3_conn
        .send_request(&mut conn, &req, false)
        .map_err(|e| anyhow::anyhow!("send CONNECT request: {e}"))?;

    let flow_id = stream_id / 4;
    log::debug!("CONNECT request sent on stream {stream_id}, flow_id={flow_id}");

    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => bail!("send after CONNECT: {e}"),
        }
    }

    // Wait for 2xx
    let mut connect_established = false;
    for _ in 0..100 {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(&mut buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: tunnel_cfg.endpoint,
                };
                if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                log::debug!("dropping UDP packet rejected by QUIC: {error}");
            }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match h3_conn.poll(&mut conn) {
                Ok((response_stream_id, quiche::h3::Event::Headers { list, .. }))
                    if response_stream_id == stream_id =>
                {
                    for h in &list {
                        if h.name() == b":status" {
                            let status = std::str::from_utf8(h.value()).unwrap_or("?");
                            log::debug!("CONNECT response status: {status}");
                            if status.starts_with('2') {
                                connect_established = true;
                            } else {
                                bail!("CONNECT rejected with status {status}");
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => bail!("h3 poll error: {e}"),
            }
        }

        // Flush
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("send during CONNECT wait: {e}"),
            }
        }

        if connect_established {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed before CONNECT response");
        }
    }

    if !connect_established {
        bail!("timed out waiting for CONNECT response");
    }

    eprintln!("\r\x1b[2K[connected] MASQUE tunnel established");

    let session_start = Instant::now();
    let mut tx_packets = 0u64;
    let mut rx_packets = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    let mut dropped = 0u64;

    let mut stats_interval = tokio::time::interval(Duration::from_secs(1));
    stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Tokio intervals tick immediately once; consume that initial tick so the
    // first display update happens after one second of useful work.
    stats_interval.tick().await;

    // Build the flow_id varint prefix + context_id zero
    let mut flow_prefix = Vec::with_capacity(16);
    {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(flow_id)
            .map_err(|error| anyhow::anyhow!("flow ID does not fit a QUIC varint: {error}"))?;
        let len = b.off();
        flow_prefix.extend_from_slice(&tmp[..len]);
    }
    flow_prefix.push(0x00);

    while let Some(mut pkt) = pending_packets.pop_front() {
        if packet::prepare_outgoing(&mut pkt).is_ok() {
            let mut dgram = Vec::with_capacity(flow_prefix.len() + pkt.len());
            dgram.extend_from_slice(&flow_prefix);
            dgram.extend_from_slice(&pkt);
            let pkt_len = u64::try_from(pkt.len())
                .map_err(|_| anyhow::anyhow!("packet length does not fit u64"))?;
            if conn.dgram_send_buf(dgram).is_ok() {
                tx_packets += 1;
                tx_bytes += pkt_len;
            }
        }
    }

    // Main data forwarding loop. Linux offload lets one TUN read contain a
    // large GSO packet, which tun-rs splits into a burst of MTU-sized packets.
    // Received CONNECT-IP packets are drained into a GRO batch before crossing
    // back into the kernel.
    let mtu = usize::try_from(tunnel_cfg.mtu)
        .map_err(|_| anyhow::anyhow!("configured MTU does not fit usize"))?;
    let packet_capacity = mtu + 128;
    let mut tun_raw = vec![0u8; VIRTIO_NET_HDR_LEN + 65_535];
    let mut tun_packets = vec![vec![0u8; packet_capacity]; IDEAL_BATCH_SIZE];
    let mut tun_sizes = vec![0usize; IDEAL_BATCH_SIZE];

    let mut gro_table = GROTable::default();
    let mut inbound_packets = (0..IDEAL_BATCH_SIZE)
        .map(|_| Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet_capacity))
        .collect::<Vec<_>>();
    let mut icmp_packet = vec![Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet_capacity)];

    let keepalive_interval = tunnel_cfg.keepalive_period;

    let mut udp_recv_storage = vec![vec![0u8; MAX_DATAGRAM_SIZE]; UDP_RECV_BATCH_SIZE];
    let mut udp_recv_bufs = udp_recv_storage
        .iter_mut()
        .map(|storage| ReadBuf::new(storage.as_mut_slice()))
        .collect::<Vec<_>>();

    let result: Result<()> = async {
        loop {
            let quic_timeout = conn.timeout();
            let timeout = quic_timeout
                .unwrap_or(keepalive_interval)
                .min(keepalive_interval);

            tokio::select! {
            biased;

            // Read a batch from the QUIC UDP socket with recvmmsg().
            result = async {
                reset_udp_read_bufs(&mut udp_recv_bufs);
                socket.recv_many(&mut udp_recv_bufs).await
            } => {
                let count = result?;
                process_udp_batch(
                    &mut conn,
                    &mut udp_recv_bufs,
                    count,
                    local_addr,
                    tunnel_cfg.endpoint,
                );
            }

            // Read from TUN -> send a burst of CONNECT-IP datagrams.
            result = tun_dev.recv_multiple(&mut tun_raw, &mut tun_packets, &mut tun_sizes, 0) => {
                let count = result
                    .map_err(|e| anyhow::anyhow!("failed to read packet batch from TUN: {e}"))?;
                if count == 0 {
                    bail!("TUN device closed");
                }

                for i in 0..count {
                    let n = tun_sizes[i];
                    let pkt = &mut tun_packets[i][..n];
                    match packet::prepare_outgoing(pkt) {
                        Ok(_) => {
                            let pkt_len = n as u64;
                            let mut dgram = Vec::with_capacity(flow_prefix.len() + n);
                            dgram.extend_from_slice(&flow_prefix);
                            dgram.extend_from_slice(pkt);

                            match conn.dgram_send_buf(dgram) {
                                Ok(()) => {
                                    tx_packets += 1;
                                    tx_bytes += pkt_len;
                                }
                                Err(quiche::Error::InvalidState) => {
                                    log::warn!("datagram send: peer doesn't support datagrams");
                                }
                                Err(quiche::Error::Done) => {
                                    dropped += 1;
                                    log::trace!("datagram send queue full, dropping packet");
                                }
                                Err(e) => {
                                    dropped += 1;
                                    log::debug!("datagram send error: {e}, generating ICMP");
                                    if let Some(icmp) = icmp::compose_icmp_too_large(pkt, 1280) {
                                        stage_tun_packet(&mut icmp_packet[0], &icmp);
                                        send_tun_batch(tun_dev, &mut gro_table, &mut icmp_packet).await?;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            dropped += 1;
                            log::trace!("dropping outgoing packet: {e}");
                        }
                    }
                }
            }

            // QUIC loss-recovery timeout and idle keepalive share the wakeup.
            () = tokio::time::sleep(timeout) => {
                if quic_timeout.is_some_and(|duration| duration <= keepalive_interval) {
                    conn.on_timeout();
                }
                if quic_timeout.is_none_or(|duration| keepalive_interval <= duration) {
                    conn.send_ack_eliciting()
                        .map_err(|error| anyhow::anyhow!("failed to schedule QUIC keepalive: {error}"))?;
                }
            }

            // Status is sampled once per second instead of maintaining shared
            // atomics and querying QUIC stats on every packet/event.
            _ = stats_interval.tick() => {
                let qs = conn.stats();
                let connected_for = format_duration(session_start.elapsed());
                let tx_size = format_bytes(tx_bytes);
                let rx_size = format_bytes(rx_bytes);
                let lost = qs.lost;
                let retrans = qs.retrans;
                eprint!(
                    "\r\x1b[2K[connected {connected_for}] tx: {tx_packets} ({tx_size})  rx: {rx_packets} ({rx_size})  drop: {dropped}  lost: {lost}  retrans: {retrans}"
                );
            }
        }

        // Process H3 events (capsules, etc.)
        loop {
            match h3_conn.poll(&mut conn) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    log::warn!("h3 poll error: {e}");
                    break;
                }
            }
        }

        // Drain received datagrams -> one GRO-capable TUN batch.
        let mut inbound_count = 0usize;
        loop {
            match conn.dgram_recv_buf() {
                Ok(dgram) => {
                    if let Some(ip_payload) = parse_datagram(&dgram, flow_id) {
                        if packet::validate_incoming(ip_payload).is_ok() {
                            rx_packets += 1;
                            rx_bytes += ip_payload.len() as u64;

                            stage_tun_packet(
                                &mut inbound_packets[inbound_count],
                                ip_payload,
                            );
                            inbound_count += 1;

                            if inbound_count == inbound_packets.len() {
                                send_tun_batch(
                                    tun_dev,
                                    &mut gro_table,
                                    &mut inbound_packets[..inbound_count],
                                )
                                .await?;
                                inbound_count = 0;
                            }
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    log::debug!("dgram recv error: {e}");
                    break;
                }
            }
        }

        if inbound_count > 0 {
            send_tun_batch(
                tun_dev,
                &mut gro_table,
                &mut inbound_packets[..inbound_count],
            )
            .await?;
        }

        // Always flush outgoing QUIC packets. When Linux UDP GSO is available,
        // collect a send quantum into one UDP_SEGMENT super-buffer.
        if let Err(e) = flush_quic_packets(&mut conn, &socket, &mut out, udp_gso).await {
            log::error!("{e:#}");
            bail!("{e}");
        }

        if conn.is_closed() {
            break Ok(());
        }
    }
    }
    .await;

    result
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
