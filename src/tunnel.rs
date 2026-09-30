use anyhow::{Result, bail};
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
const TUN_READY_DRAIN_MAX_READS: usize = 8;
const TUN_DRAIN_INITIAL_SAMPLES_PER_MODE: u8 = 3;
const TUN_DRAIN_CHALLENGE_INTERVAL_SECS: u16 = 30;

fn u64_as_f64(value: u64) -> f64 {
    let bytes = value.to_le_bytes();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

#[derive(Clone, Copy, Debug, Default)]
struct CpuPerPacketStats {
    samples: u8,
    mean_ns: f64,
    m2_ns: f64,
}

impl CpuPerPacketStats {
    fn add(&mut self, cpu_ns: u64, packets: u64) {
        if packets == 0 {
            return;
        }

        let sample = u64_as_f64(cpu_ns) / u64_as_f64(packets);
        self.samples = self.samples.saturating_add(1);
        let delta = sample - self.mean_ns;
        self.mean_ns += delta / f64::from(self.samples);
        let delta2 = sample - self.mean_ns;
        self.m2_ns = delta.mul_add(delta2, self.m2_ns);
    }

    fn standard_error(&self) -> f64 {
        if self.samples < 2 {
            return f64::INFINITY;
        }

        let variance = self.m2_ns / f64::from(self.samples - 1);
        (variance / f64::from(self.samples)).sqrt()
    }
}

#[derive(Debug)]
struct TunDrainTuner {
    calibrating: bool,
    selected: bool,
    off: CpuPerPacketStats,
    on: CpuPerPacketStats,
    challenge_countdown: u16,
    challenge_baseline_ns: Option<f64>,
}

impl TunDrainTuner {
    fn new() -> Self {
        Self {
            calibrating: true,
            selected: false,
            off: CpuPerPacketStats::default(),
            on: CpuPerPacketStats::default(),
            challenge_countdown: TUN_DRAIN_CHALLENGE_INTERVAL_SECS,
            challenge_baseline_ns: None,
        }
    }

    fn observe(&mut self, mode: bool, cpu_ns: u64, packets: u64) -> bool {
        if packets == 0 {
            return mode;
        }

        let sample_ns = u64_as_f64(cpu_ns) / u64_as_f64(packets);

        if self.calibrating {
            if mode {
                self.on.add(cpu_ns, packets);
            } else {
                self.off.add(cpu_ns, packets);
            }

            if self.off.samples >= TUN_DRAIN_INITIAL_SAMPLES_PER_MODE
                && self.on.samples >= TUN_DRAIN_INITIAL_SAMPLES_PER_MODE
            {
                // Prefer ready-drain only when its measured improvement is
                // larger than the observed sample noise. Ambiguous cases
                // conservatively stay off.
                let uncertainty = self.off.standard_error().hypot(self.on.standard_error());
                self.selected = self.on.mean_ns + uncertainty < self.off.mean_ns;
                self.calibrating = false;
                self.challenge_countdown = TUN_DRAIN_CHALLENGE_INTERVAL_SECS;
                return self.selected;
            }

            let opposite_needs_sample = if mode {
                self.off.samples < TUN_DRAIN_INITIAL_SAMPLES_PER_MODE
            } else {
                self.on.samples < TUN_DRAIN_INITIAL_SAMPLES_PER_MODE
            };

            return if opposite_needs_sample { !mode } else { mode };
        }

        if let Some(baseline_ns) = self.challenge_baseline_ns.take() {
            // This interval ran in the opposite mode. Switch only if that
            // immediately-adjacent challenger beat the selected-mode sample.
            if sample_ns < baseline_ns {
                self.selected = mode;
            }
            self.challenge_countdown = TUN_DRAIN_CHALLENGE_INTERVAL_SECS;
            return self.selected;
        }

        if mode == self.selected {
            if self.challenge_countdown > 0 {
                self.challenge_countdown -= 1;
            }

            if self.challenge_countdown == 0 {
                self.challenge_baseline_ns = Some(sample_ns);
                return !self.selected;
            }
        }

        self.selected
    }
}

#[cfg(target_os = "linux")]
fn process_cpu_time_ns() -> Option<u64> {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID).ok()?;
    let secs = u64::try_from(ts.tv_sec()).ok()?;
    let nanos = u64::try_from(ts.tv_nsec()).ok()?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(not(target_os = "linux"))]
fn process_cpu_time_ns() -> Option<u64> {
    None
}

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

const fn should_flush_tun_write_batch(
    packet_count: usize,
    packet_target: usize,
    deadline_expired: bool,
    pure_rx_iteration: bool,
) -> bool {
    packet_count > 0 && (packet_count >= packet_target || deadline_expired || !pure_rx_iteration)
}

#[derive(Debug)]
struct TunWriteBatchGate {
    adaptive: bool,
    active: bool,
    packet_target: usize,
    activation_span: Duration,
    last_dense_event: Option<Instant>,
    dense_events: u8,
    slow_batches: u8,
}

impl TunWriteBatchGate {
    const DENSE_EVENTS_TO_ENABLE: u8 = 3;
    const SLOW_BATCHES_TO_DISABLE: u8 = 3;

    fn new(adaptive: bool, packet_target: usize, max_delay: Duration) -> Self {
        Self {
            adaptive,
            active: !adaptive && packet_target > 1,
            packet_target,
            activation_span: max_delay / 2,
            last_dense_event: None,
            dense_events: 0,
            slow_batches: 0,
        }
    }

    const fn effective_target(&self) -> usize {
        if self.packet_target > 1 && self.active {
            self.packet_target
        } else {
            1
        }
    }

    fn observe_arrivals(&mut self, packet_count: usize) {
        if !self.arrivals_can_advance(packet_count) {
            return;
        }

        self.observe_dense_event(Instant::now());
    }

    const fn arrivals_can_advance(&mut self, packet_count: usize) -> bool {
        if !self.adaptive || self.packet_target <= 1 || self.active {
            return false;
        }

        // Most low-rate receive events are too small to contribute to
        // activation. Reject and reset them before reading the monotonic clock;
        // clock_gettime is measurable on low-end targets such as MT7621.
        if packet_count < self.packet_target {
            self.last_dense_event = None;
            self.dense_events = 0;
            return false;
        }

        true
    }

    fn observe_dense_event(&mut self, now: Instant) {
        // A single recv_multiple() wake may contain many packets that all share
        // this observation timestamp. Count it as one dense event rather than
        // several zero-time packet windows; otherwise one occasional kernel
        // burst can enable cross-iteration retention at a low sustained rate.
        if self
            .last_dense_event
            .is_some_and(|last| now.saturating_duration_since(last) <= self.activation_span)
        {
            self.dense_events = self.dense_events.saturating_add(1);
        } else {
            self.dense_events = 1;
        }
        self.last_dense_event = Some(now);

        if self.dense_events >= Self::DENSE_EVENTS_TO_ENABLE {
            self.active = true;
            self.slow_batches = 0;
            self.last_dense_event = None;
            self.dense_events = 0;
        }
    }

    #[cfg(test)]
    fn observe_arrivals_at(&mut self, now: Instant, packet_count: usize) {
        if self.arrivals_can_advance(packet_count) {
            self.observe_dense_event(now);
        }
    }

    fn observe_flush(
        &mut self,
        packet_count: usize,
        elapsed: Option<Duration>,
        deadline_expired: bool,
    ) {
        if !self.adaptive || !self.active || self.packet_target <= 1 {
            return;
        }

        let slow = deadline_expired
            || (packet_count >= self.packet_target
                && elapsed.is_some_and(|duration| duration > self.activation_span));

        if slow {
            self.slow_batches = self.slow_batches.saturating_add(1);
            if self.slow_batches >= Self::SLOW_BATCHES_TO_DISABLE {
                self.active = false;
                self.slow_batches = 0;
                self.dense_events = 0;
                self.last_dense_event = None;
            }
        } else if packet_count >= self.packet_target {
            self.slow_batches = 0;
        }
    }
}

#[derive(Debug)]
struct TunWriteState {
    gate: TunWriteBatchGate,
    inbound_count: usize,
    started_at: Option<Instant>,
    deadline: Option<Instant>,
    max_delay: Duration,
}

impl TunWriteState {
    fn new(adaptive: bool, packet_target: usize, max_delay: Duration) -> Self {
        Self {
            gate: TunWriteBatchGate::new(adaptive, packet_target, max_delay),
            inbound_count: 0,
            started_at: None,
            deadline: None,
            max_delay,
        }
    }

    const fn effective_target(&self) -> usize {
        self.gate.effective_target()
    }

    fn start_batch_if_needed(&mut self, now: Instant, target: usize) {
        if self.inbound_count == 0 && target > 1 {
            self.started_at = Some(now);
            self.deadline = Some(now + self.max_delay);
        }
    }

    const fn clear_batch(&mut self) {
        self.inbound_count = 0;
        self.started_at = None;
        self.deadline = None;
    }

    fn deadline_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    fn elapsed(&self, now: Instant) -> Option<Duration> {
        self.started_at
            .map(|started| now.saturating_duration_since(started))
    }
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

// Returning false is part of the correctness contract: quiche then queues the
// DATAGRAM and suppresses direct handling of newer DATAGRAMs until that queue is
// drained, preserving FIFO order across the direct and fallback paths.
fn try_stage_inbound_datagram(
    dgram: &[u8],
    expected_flow_id: u64,
    inbound_packets: &mut [Vec<u8>],
    inbound_count: &mut usize,
    stats: &mut TunnelStats,
) -> bool {
    let Some(slot) = inbound_packets.get_mut(*inbound_count) else {
        return false;
    };
    let Some(ip_payload) = parse_datagram(dgram, expected_flow_id) else {
        return false;
    };
    if packet::validate_incoming(ip_payload).is_err() {
        return false;
    }
    let Ok(packet_len) = u64::try_from(ip_payload.len()) else {
        return false;
    };

    stage_tun_packet(slot, ip_payload);
    *inbound_count += 1;
    stats.rx_packets += 1;
    stats.rx_bytes += packet_len;
    true
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

async fn flush_inbound_batch(
    tun_dev: &tun_rs::AsyncDevice,
    buffers: &mut ForwardBuffers,
    tun_write: &mut TunWriteState,
    deadline_expired: bool,
) -> Result<()> {
    if tun_write.inbound_count == 0 {
        return Ok(());
    }

    let target = tun_write.effective_target();
    if target > 1 {
        let now = Instant::now();
        tun_write.gate.observe_flush(
            tun_write.inbound_count,
            tun_write.elapsed(now),
            deadline_expired,
        );
    }

    send_tun_batch(
        tun_dev,
        &mut buffers.gro_table,
        &mut buffers.inbound_packets[..tun_write.inbound_count],
    )
    .await?;
    tun_write.clear_batch();
    Ok(())
}

async fn drain_inbound_datagrams(
    conn: &mut quiche::Connection,
    tun_dev: &tun_rs::AsyncDevice,
    flow_id: u64,
    buffers: &mut ForwardBuffers,
    stats: &mut TunnelStats,
    tun_write: &mut TunWriteState,
) -> Result<usize> {
    if tun_write.inbound_count == buffers.inbound_packets.len() {
        flush_inbound_batch(tun_dev, buffers, tun_write, false).await?;
    }

    let mut accepted_inbound = 0usize;
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

                let target = tun_write.effective_target();
                tun_write.start_batch_if_needed(Instant::now(), target);
                stage_tun_packet(
                    &mut buffers.inbound_packets[tun_write.inbound_count],
                    ip_payload,
                );
                tun_write.inbound_count += 1;
                accepted_inbound += 1;

                if tun_write.inbound_count == buffers.inbound_packets.len() {
                    flush_inbound_batch(tun_dev, buffers, tun_write, false).await?;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => {
                log::debug!("dgram recv error: {error}");
                break;
            }
        }
    }

    Ok(accepted_inbound)
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

struct ForwardRuntime {
    flow_prefix: Vec<u8>,
    stats: TunnelStats,
    buffers: ForwardBuffers,
    stats_interval: tokio::time::Interval,
    tun_ready_drain: bool,
    tun_drain_tuner: TunDrainTuner,
    tune_tx_packets: u64,
    tune_process_cpu_ns: Option<u64>,
    tun_write: TunWriteState,
}

impl ForwardRuntime {
    fn new(
        flow_prefix: Vec<u8>,
        stats: TunnelStats,
        buffer_size: usize,
        tun_write: TunWriteState,
    ) -> Self {
        let tune_tx_packets = stats.tx_packets;
        let mut stats_interval = tokio::time::interval(Duration::from_secs(1));
        stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            flow_prefix,
            stats,
            buffers: ForwardBuffers::new(buffer_size),
            stats_interval,
            tun_ready_drain: false,
            tun_drain_tuner: TunDrainTuner::new(),
            tune_tx_packets,
            tune_process_cpu_ns: process_cpu_time_ns(),
            tun_write,
        }
    }
}

enum ForwardEvent {
    Udp(usize),
    Tun(usize),
    Wake,
    Stats,
}

fn tun_write_config() -> (usize, u64, bool) {
    let packet_target = std::env::var("USQUE_TUN_WRITE_PACKETS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, IDEAL_BATCH_SIZE);
    let max_delay_us = std::env::var("USQUE_TUN_WRITE_MAX_US")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000)
        .clamp(1, 1_000);
    let adaptive = std::env::var("USQUE_TUN_WRITE_ADAPTIVE").is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    });
    (packet_target, max_delay_us, adaptive)
}

async fn enforce_tun_write_deadline(
    tun_dev: &tun_rs::AsyncDevice,
    runtime: &mut ForwardRuntime,
) -> Result<()> {
    if runtime.tun_write.inbound_count == 0 {
        return Ok(());
    }

    let now = Instant::now();
    if runtime.tun_write.deadline_expired(now) {
        flush_inbound_batch(tun_dev, &mut runtime.buffers, &mut runtime.tun_write, true).await?;
    }
    Ok(())
}

async fn next_forward_event(
    session: &mut NativeSession,
    tun_dev: &tun_rs::AsyncDevice,
    udp_recv_bufs: &mut [ReadBuf<'_>],
    runtime: &mut ForwardRuntime,
    keepalive_interval: Duration,
) -> Result<ForwardEvent> {
    let quic_timeout = session.quic.conn.timeout();
    let protocol_timeout = quic_timeout
        .unwrap_or(keepalive_interval)
        .min(keepalive_interval);
    let tun_write_timeout = runtime
        .tun_write
        .deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()));
    let wake_timeout = tun_write_timeout.map_or(protocol_timeout, |tun_timeout| {
        protocol_timeout.min(tun_timeout)
    });
    let protocol_wakes_first =
        tun_write_timeout.is_none_or(|tun_timeout| protocol_timeout <= tun_timeout);

    reset_udp_read_bufs(udp_recv_bufs);
    let event = tokio::select! {
        biased;
        result = session.quic.socket.recv_many(udp_recv_bufs) => {
            ForwardEvent::Udp(result?)
        }
        result = tun_dev.recv_multiple(
            &mut runtime.buffers.tun_raw,
            &mut runtime.buffers.tun_packets,
            &mut runtime.buffers.tun_sizes,
            0,
        ) => {
            let count = result
                .map_err(|error| anyhow::anyhow!("failed to read packet batch from TUN: {error}"))?;
            if count == 0 {
                bail!("TUN device closed");
            }
            ForwardEvent::Tun(count)
        }
        () = tokio::time::sleep(wake_timeout) => {
            if protocol_wakes_first {
                handle_session_timeout(
                    &mut session.quic.conn,
                    quic_timeout,
                    keepalive_interval,
                )?;
            }
            ForwardEvent::Wake
        }
        _ = runtime.stats_interval.tick() => ForwardEvent::Stats
    };
    Ok(event)
}

fn handle_udp_event(
    session: &mut NativeSession,
    udp_recv_bufs: &mut [ReadBuf<'_>],
    count: usize,
    runtime: &mut ForwardRuntime,
    tun_write_target: usize,
) {
    let ForwardRuntime {
        buffers,
        stats,
        tun_write,
        ..
    } = runtime;
    let mut accepted_inbound = 0usize;
    process_udp_batch(
        &mut session.quic.conn,
        udp_recv_bufs,
        count,
        session.quic.local_addr,
        session.quic.endpoint,
        &mut |dgram| {
            let batch_was_empty = tun_write.inbound_count == 0;
            if !try_stage_inbound_datagram(
                dgram,
                session.flow_id,
                &mut buffers.inbound_packets,
                &mut tun_write.inbound_count,
                stats,
            ) {
                return false;
            }

            if batch_was_empty && tun_write_target > 1 {
                let now = Instant::now();
                tun_write.started_at = Some(now);
                tun_write.deadline = Some(now + tun_write.max_delay);
            }
            accepted_inbound += 1;
            true
        },
    );
    if accepted_inbound > 0 {
        tun_write.gate.observe_arrivals(accepted_inbound);
    }
}

async fn handle_tun_event(
    session: &mut NativeSession,
    tun_dev: &tun_rs::AsyncDevice,
    runtime: &mut ForwardRuntime,
    mut count: usize,
) -> Result<()> {
    let mut reads = 0usize;
    loop {
        reads += 1;
        forward_tun_batch(
            &mut session.quic.conn,
            tun_dev,
            &runtime.flow_prefix,
            &mut runtime.buffers,
            count,
            &mut runtime.stats,
        )
        .await?;

        if !runtime.tun_ready_drain
            || reads >= TUN_READY_DRAIN_MAX_READS
            || session.quic.conn.dgram_send_queue_len() > tls::DGRAM_QUEUE_LEN - IDEAL_BATCH_SIZE
        {
            break;
        }

        match tun_dev.try_recv_multiple(
            &mut runtime.buffers.tun_raw,
            &mut runtime.buffers.tun_packets,
            &mut runtime.buffers.tun_sizes,
            0,
        ) {
            Ok(0) => break,
            Ok(next_count) => count = next_count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to drain ready TUN packet batch: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn handle_stats_event(session: &NativeSession, runtime: &mut ForwardRuntime) {
    let current_cpu_ns = process_cpu_time_ns();
    if let (Some(previous_cpu_ns), Some(current_cpu_ns)) =
        (runtime.tune_process_cpu_ns, current_cpu_ns)
    {
        let cpu_delta = current_cpu_ns.saturating_sub(previous_cpu_ns);
        let packet_delta = runtime
            .stats
            .tx_packets
            .saturating_sub(runtime.tune_tx_packets);
        runtime.tun_ready_drain =
            runtime
                .tun_drain_tuner
                .observe(runtime.tun_ready_drain, cpu_delta, packet_delta);
    }
    runtime.tune_process_cpu_ns = current_cpu_ns;
    runtime.tune_tx_packets = runtime.stats.tx_packets;
    runtime.stats.print(&session.quic.conn);
}

async fn finish_forward_iteration(
    session: &mut NativeSession,
    tun_dev: &tun_rs::AsyncDevice,
    runtime: &mut ForwardRuntime,
    pure_rx_iteration: bool,
) -> Result<bool> {
    drain_h3_events(&mut session.h3_conn, &mut session.quic.conn);
    let fallback_inbound = drain_inbound_datagrams(
        &mut session.quic.conn,
        tun_dev,
        session.flow_id,
        &mut runtime.buffers,
        &mut runtime.stats,
        &mut runtime.tun_write,
    )
    .await?;
    if fallback_inbound > 0 {
        runtime.tun_write.gate.observe_arrivals(fallback_inbound);
    }

    let now = Instant::now();
    let deadline_expired = runtime.tun_write.deadline_expired(now);
    let target = runtime.tun_write.effective_target();
    if should_flush_tun_write_batch(
        runtime.tun_write.inbound_count,
        target,
        deadline_expired,
        pure_rx_iteration,
    ) {
        flush_inbound_batch(
            tun_dev,
            &mut runtime.buffers,
            &mut runtime.tun_write,
            deadline_expired,
        )
        .await?;
    }

    flush_quic_packets(
        &mut session.quic.conn,
        &session.quic.socket,
        &mut session.quic.out,
        session.quic.udp_gso,
    )
    .await?;

    if session.quic.conn.is_closed() {
        flush_inbound_batch(tun_dev, &mut runtime.buffers, &mut runtime.tun_write, false).await?;
        return Ok(true);
    }

    Ok(false)
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

    let (packet_target, max_delay_us, adaptive) = tun_write_config();
    let max_delay = Duration::from_micros(max_delay_us);
    log::info!(
        "TUN write batching: packet_target={packet_target} max_delay_us={max_delay_us} adaptive={adaptive}"
    );

    let tun_write = TunWriteState::new(adaptive, packet_target, max_delay);
    let mut runtime = ForwardRuntime::new(flow_prefix, stats, mtu + 128, tun_write);
    runtime.stats_interval.tick().await;

    let mut udp_recv_storage = vec![vec![0u8; MAX_DATAGRAM_SIZE]; UDP_RECV_BATCH_SIZE];
    let mut udp_recv_bufs = udp_recv_storage
        .iter_mut()
        .map(|storage| ReadBuf::new(storage.as_mut_slice()))
        .collect::<Vec<_>>();

    loop {
        enforce_tun_write_deadline(tun_dev, &mut runtime).await?;
        let tun_write_target = runtime.tun_write.effective_target();
        let event = next_forward_event(
            session,
            tun_dev,
            &mut udp_recv_bufs,
            &mut runtime,
            keepalive_interval,
        )
        .await?;

        let pure_rx_iteration = match event {
            ForwardEvent::Udp(count) => {
                handle_udp_event(
                    session,
                    &mut udp_recv_bufs,
                    count,
                    &mut runtime,
                    tun_write_target,
                );
                true
            }
            ForwardEvent::Tun(count) => {
                handle_tun_event(session, tun_dev, &mut runtime, count).await?;
                false
            }
            ForwardEvent::Wake => false,
            ForwardEvent::Stats => {
                handle_stats_event(session, &mut runtime);
                false
            }
        };

        if finish_forward_iteration(session, tun_dev, &mut runtime, pure_rx_iteration).await? {
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

    // ---- TUN write batching policy tests ----

    fn minimal_ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet
    }

    #[test]
    fn direct_datagram_stages_valid_payload_and_updates_stats_once() {
        let packet = minimal_ipv4_packet();
        let dgram = make_datagram(7, 0, &packet);
        let mut inbound_packets = (0..2)
            .map(|_| Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet.len()))
            .collect::<Vec<_>>();
        let mut inbound_count = 0;
        let mut stats = TunnelStats::new();

        assert!(try_stage_inbound_datagram(
            &dgram,
            7,
            &mut inbound_packets,
            &mut inbound_count,
            &mut stats,
        ));
        assert_eq!(inbound_count, 1);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.rx_bytes, 20);
        assert_eq!(&inbound_packets[0][VIRTIO_NET_HDR_LEN..], packet.as_slice());
        assert!(
            inbound_packets[0][..VIRTIO_NET_HDR_LEN]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn direct_datagram_full_batch_falls_back_without_mutation() {
        let packet = minimal_ipv4_packet();
        let dgram = make_datagram(7, 0, &packet);
        let mut inbound_packets = vec![vec![0xA5; VIRTIO_NET_HDR_LEN + packet.len()]];
        let original = inbound_packets.clone();
        let mut inbound_count = inbound_packets.len();
        let mut stats = TunnelStats::new();

        assert!(!try_stage_inbound_datagram(
            &dgram,
            7,
            &mut inbound_packets,
            &mut inbound_count,
            &mut stats,
        ));
        assert_eq!(inbound_packets, original);
        assert_eq!(inbound_count, 1);
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.rx_bytes, 0);
    }

    #[test]
    fn direct_datagram_rejected_payload_falls_back_without_mutation() {
        let invalid_ip = [0x10, 0, 0, 0];
        let wrong_flow = make_datagram(8, 0, &minimal_ipv4_packet());
        let invalid_packet = make_datagram(7, 0, &invalid_ip);
        let mut inbound_packets = vec![Vec::new(); 2];
        let mut inbound_count = 0;
        let mut stats = TunnelStats::new();

        assert!(!try_stage_inbound_datagram(
            &wrong_flow,
            7,
            &mut inbound_packets,
            &mut inbound_count,
            &mut stats,
        ));
        assert!(!try_stage_inbound_datagram(
            &invalid_packet,
            7,
            &mut inbound_packets,
            &mut inbound_count,
            &mut stats,
        ));
        assert_eq!(inbound_count, 0);
        assert!(inbound_packets.iter().all(Vec::is_empty));
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.rx_bytes, 0);
    }

    #[test]
    fn tun_write_batch_default_flushes_each_packet() {
        assert!(should_flush_tun_write_batch(1, 1, false, true));
    }

    #[test]
    fn tun_write_batch_retains_small_pure_rx_batch() {
        assert!(!should_flush_tun_write_batch(3, 4, false, true));
    }

    #[test]
    fn tun_write_batch_flushes_on_target_deadline_or_non_rx_event() {
        assert!(should_flush_tun_write_batch(4, 4, false, true));
        assert!(should_flush_tun_write_batch(1, 4, true, true));
        assert!(should_flush_tun_write_batch(1, 4, false, false));
        assert!(!should_flush_tun_write_batch(0, 4, true, false));
    }

    #[test]
    fn adaptive_tun_write_gate_stays_off_for_sparse_receive_events() {
        let mut gate = TunWriteBatchGate::new(true, 4, Duration::from_micros(1_000));
        let start = Instant::now();
        for i in 0..6 {
            gate.observe_arrivals_at(start + Duration::from_micros(i * 750), 4);
        }
        assert_eq!(gate.effective_target(), 1);
    }

    #[test]
    fn adaptive_tun_write_gate_single_large_receive_does_not_enable() {
        let mut gate = TunWriteBatchGate::new(true, 4, Duration::from_micros(1_000));
        gate.observe_arrivals_at(Instant::now(), 32);
        assert_eq!(gate.effective_target(), 1);
    }

    #[test]
    fn adaptive_tun_write_gate_partial_receive_resets_dense_streak() {
        let mut gate = TunWriteBatchGate::new(true, 4, Duration::from_micros(1_000));
        let start = Instant::now();
        gate.observe_arrivals_at(start, 4);
        gate.observe_arrivals_at(start + Duration::from_micros(100), 4);
        gate.observe_arrivals_at(start + Duration::from_micros(200), 3);
        gate.observe_arrivals_at(start + Duration::from_micros(300), 4);
        gate.observe_arrivals_at(start + Duration::from_micros(400), 4);
        assert_eq!(gate.effective_target(), 1);
    }

    #[test]
    fn adaptive_tun_write_gate_enables_for_dense_receive_events() {
        let mut gate = TunWriteBatchGate::new(true, 4, Duration::from_micros(1_000));
        let start = Instant::now();
        for i in 0..3 {
            gate.observe_arrivals_at(start + Duration::from_micros(i * 100), 4);
        }
        assert_eq!(gate.effective_target(), 4);
    }

    #[test]
    fn adaptive_tun_write_gate_disables_after_repeated_slow_batches() {
        let mut gate = TunWriteBatchGate::new(true, 4, Duration::from_micros(1_000));
        let start = Instant::now();
        for i in 0..3 {
            gate.observe_arrivals_at(start + Duration::from_micros(i * 100), 4);
        }
        assert_eq!(gate.effective_target(), 4);

        for _ in 0..3 {
            gate.observe_flush(4, Some(Duration::from_micros(700)), false);
        }
        assert_eq!(gate.effective_target(), 1);
    }

    #[test]
    fn fixed_tun_write_gate_remains_enabled() {
        let mut gate = TunWriteBatchGate::new(false, 4, Duration::from_micros(1_000));
        assert_eq!(gate.effective_target(), 4);
        gate.observe_flush(4, Some(Duration::from_micros(900)), true);
        assert_eq!(gate.effective_target(), 4);
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
